//go:build linux

package vpnclient

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"

	"github.com/mhsanaei/3x-ui/v3/internal/amneziawg"
	"github.com/mhsanaei/3x-ui/v3/internal/amneziawgnet"
	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
	"github.com/mhsanaei/3x-ui/v3/internal/logger"
	wgutil "github.com/mhsanaei/3x-ui/v3/internal/util/wireguard"
)

// WireGuard 客户端的隔离选择（RELAY_DESIGN.md §7.1 要求 per-RouterLink 独立 Manager/key 隔离）：
//
// 候选有三：
//  1. amneziawgnet.GetManager() —— inbound 服务端单例。ensureLocked 会给每个 Device
//     attach SocksRelay + PortForwardSet + UDP 中继（"把客户端流量送公网"的服务端语义），
//     且 key 是 inbound id。任务明确要求不许 attach SocksRelay。出局。
//  2. amneziawgnet.GetOutboundManager() —— 进程级单例，ensureLocked 把 Device 注册进
//     egress SOCKS 服务器（GetEgressServer().SetStack），同样是服务端语义；且 key 是
//     全局 tag 字符串，会与面板自身的 outbound 命名空间冲突。出局。
//  3. 本 Manager 内 per-Link 独占 *amneziawgnet.Device，经导出的 amneziawgnet.NewDevice()
//     构造。该函数只建 gVisor stack + 下发 UAPI 配置，不挂任何 forwarder/relay
//     （见其文档注释 "It does not attach a forwarder or start relaying traffic"），
//     天然满足"不许 attach SocksRelay"。
//
// 采用 3。隔离面：
//   - 每个 RouterLink 独立的 Device + 独立 gVisor stack + 独立密钥对，
//     生命周期与 linkHandle 绑定（重拨/删除即 Close）；
//   - peer 的 AllowedIPs 只填 LanSubnet（绝不用 0.0.0.0/0），非 LanSubnet 的包被
//     amneziawg-go 的 cryptokey 路由直接丢弃在用户态；
//   - 宿主机零感知：没有真实网卡、不写主机路由、不碰 iptables（用户态网卡）；
//   - 转发 dial 经该连接独占 stack（wgStackDialFunc），多连接内网段重叠天然无冲突。
//
// 注意 B 组已在 amneziawg.Peer 加了 Endpoint/PersistentKeepalive 字段，
// buildUAPIConfig 会条件性下发 endpoint=/persistent_keepalive_interval=，
// 因此直接用 amneziawg.Instance 形状即可表达客户端角色（WireGuard 握手是对称的，
// "客户端"只是"带 endpoint 的配置"，不是另一种协议）。

// defaultWgKeepalive：路由器若在 NAT 后，保活维持 NAT 会话（RELAY_DESIGN.md §7.1）。
const defaultWgKeepalive = 25

// wgUpStaleAfter：握手超过这么久未刷新视为"正在重连"（dialing），而非 up。
const wgUpStaleAfter = 10 * time.Minute

// buildWGInstance 把 RouterLink 组装成客户端形状的 amneziawg.Instance。
func buildWGInstance(link model.RouterLink, auth routerAuth) (amneziawg.Instance, error) {
	if strings.TrimSpace(auth.PrivateKey) == "" {
		return amneziawg.Instance{}, errors.New("wireguard：缺少 privateKey")
	}
	if strings.TrimSpace(auth.PeerPublicKey) == "" {
		return amneziawg.Instance{}, errors.New("wireguard：缺少 peerPublicKey")
	}
	var addrs []string
	if strings.TrimSpace(link.TunnelAddress) != "" {
		addrs = []string{normalizeTunnelAddress(link.TunnelAddress)}
	}
	ka := link.PersistentKeepalive
	if ka <= 0 {
		ka = defaultWgKeepalive
	}
	return amneziawg.Instance{
		Id:            link.Id,
		Tag:           fmt.Sprintf("rl-%d", link.Id),
		InterfaceName: fmt.Sprintf("rl-wg-%d", link.Id),
		PrivateKey:    auth.PrivateKey,
		Address:       addrs,
		Peers: []amneziawg.Peer{{
			PublicKey:           auth.PeerPublicKey,
			PresharedKey:        auth.PresharedKey,
			AllowedIPs:          []string{link.LanSubnet}, // 路由 lanSubnet；若为 0.0.0.0/0 则经路由器出公网（用户明确要求）
			Endpoint:            net.JoinHostPort(link.RemoteHost, strconv.Itoa(link.RemotePort)),
			PersistentKeepalive: ka,
		}},
	}, nil
}

// normalizeTunnelAddress 把 "192.168.225.6" 补成 "192.168.225.6/32"
// （hostAddresses 要求 CIDR 形式）。
func normalizeTunnelAddress(s string) string {
	s = strings.TrimSpace(s)
	if strings.Contains(s, "/") {
		return s
	}
	if strings.Contains(s, ":") {
		return s + "/128"
	}
	return s + "/32"
}

// dialWGLocked 启动 WireGuard 客户端设备（非阻塞：握手在后台进行）。
func (m *Manager) dialWGLocked(h *linkHandle, link model.RouterLink, auth routerAuth) error {
	inst, err := buildWGInstance(link, auth)
	if err != nil {
		return err
	}
	dev, err := amneziawgnet.NewDevice(inst, amneziawgnet.DeviceOptions{})
	if err != nil {
		return fmt.Errorf("wireguard：建设备失败: %w", err)
	}
	h.wgDev = dev
	h.peerKey = auth.PeerPublicKey
	h.iface = inst.InterfaceName // 用户态设备，无宿主机接口；显示逻辑名
	return nil
}

// probeWGLocked 探测 WG 隧道状态（m.mu 持有中调用）。
func (m *Manager) probeWGLocked(h *linkHandle) {
	if h.wgDev == nil {
		return
	}
	hs, rx, tx, err := wgPeerStats(h.wgDev, h.peerKey)
	if err != nil {
		logger.Warningf("vpnclient: 连接 %d wireguard 状态采集失败: %v", h.id, err)
		return
	}
	h.rxBytes, h.txBytes = int64(rx), int64(tx)
	switch {
	case hs.IsZero():
		// 从未握手：还在拨号。
		if h.status == StatusUp {
			h.status = StatusDialing
		}
	case time.Since(hs) > wgUpStaleAfter:
		if h.status == StatusUp {
			h.status = StatusDialing
			h.message = "握手超时，正在重连"
		}
	default:
		h.status = StatusUp
		h.message = ""
		h.handshakeAt = hs
	}
}

// wgPeerStats 从 Device 的 UAPI dump 里解析指定对端的握手时间与字节计数。
// amneziawgnet 的 parseUAPIDump 未导出，这里按同一格式自实现（只读，不写设备）。
func wgPeerStats(dev *amneziawgnet.Device, peerPublicKey string) (handshake time.Time, rx, tx uint64, err error) {
	hexKey, err := wgutil.KeyToHex(peerPublicKey)
	if err != nil {
		return time.Time{}, 0, 0, fmt.Errorf("对端公钥格式错误: %w", err)
	}
	dump, err := dev.IpcGet()
	if err != nil {
		return time.Time{}, 0, 0, err
	}
	var inBlock, sawBlock bool
	var hsSec int64
	for _, line := range strings.Split(dump, "\n") {
		if strings.HasPrefix(line, "public_key=") {
			inBlock = line == "public_key="+hexKey
			if inBlock {
				sawBlock = true
			}
			continue
		}
		if !inBlock {
			continue
		}
		switch {
		case strings.HasPrefix(line, "last_handshake_time_sec="):
			hsSec, _ = strconv.ParseInt(strings.TrimPrefix(line, "last_handshake_time_sec="), 10, 64)
		case strings.HasPrefix(line, "rx_bytes="):
			rx, _ = strconv.ParseUint(strings.TrimPrefix(line, "rx_bytes="), 10, 64)
		case strings.HasPrefix(line, "tx_bytes="):
			tx, _ = strconv.ParseUint(strings.TrimPrefix(line, "tx_bytes="), 10, 64)
		}
	}
	if !sawBlock {
		return time.Time{}, 0, 0, errors.New("UAPI dump 中未找到该对端")
	}
	if hsSec > 0 {
		handshake = time.Unix(hsSec, 0)
	}
	return handshake, rx, tx, nil
}

// wgStackDialFunc 返回经该连接独占 gVisor stack 拨号的 DialFunc。
// 目标 lanIP:lanPort 走 stack 内 cryptokey 路由（AllowedIPs=lanSubnet）进入隧道。
func wgStackDialFunc(dev *amneziawgnet.Device) DialFunc {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		host, portStr, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		port, err := strconv.Atoi(portStr)
		if err != nil || port < 1 || port > 65535 {
			return nil, fmt.Errorf("非法端口 %q", portStr)
		}
		addr, err := netip.ParseAddr(host)
		if err != nil {
			return nil, fmt.Errorf("非法目标地址 %q", host)
		}
		var proto tcpip.NetworkProtocolNumber = ipv4.ProtocolNumber
		if addr.Is6() {
			proto = ipv6.ProtocolNumber
		}
		// NIC 1：createNetTUNWithStack 只注册这一张 NIC（与 portfwd.go 的
		// tunnelFullAddress 一致）。
		full := tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFromSlice(addr.AsSlice()), Port: uint16(port)}
		switch network {
		case "tcp":
			return gonet.DialContextTCP(ctx, dev.Stack, full, proto)
		case "udp":
			// raddr 是 tcpip.FullAddress（与 portfwd_udp.go 的用法一致）。
			return gonet.DialUDP(dev.Stack, nil, &full, proto)
		default:
			return nil, fmt.Errorf("不支持的协议 %q", network)
		}
	}
}
