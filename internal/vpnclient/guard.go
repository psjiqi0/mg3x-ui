//go:build linux

package vpnclient

import (
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/mhsanaei/3x-ui/v3/internal/logger"
)

// 路由护栏（RELAY_DESIGN.md §4.2）：隧道只承载 LanSubnet，默认路由是服务器公网
// 出入的命脉，任何客户端都不许碰。护栏做三件事：
//  1. 拨号前 snapshotDefaultRoute() 快照默认路由；
//  2. 隧道 up 后 CheckDefaultRouteUnchanged(snapshot) 对比，不一致就 hangup + 告警；
//  3. Manager.GuardCheckAll() 供 job 每 tick 复检。
//
// "默认路由"取指纹而非逐字节比较：输出里的 proto/expires 等易变字段不影响判定，
// 只关心 via/dev/metric。

// snapshotDefaultRoute 返回当前默认路由的规范指纹。
// 优先用 `ip route show default`（设计文档原话）；若 ip 不可用（极简容器），
// 降级解析 /proc/net/route。两种路径输出同一规范格式。
func snapshotDefaultRoute() (string, error) {
	if out, err := exec.Command("ip", "route", "show", "default").Output(); err == nil {
		return fingerprintIPRouteDefault(string(out)), nil
	} else {
		logger.Warningf("vpnclient: `ip` 命令不可用，改用 /proc/net/route 做路由快照: %v", err)
	}
	data, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return "", fmt.Errorf("路由快照失败（ip 命令与 /proc/net/route 均不可用）: %w", err)
	}
	return fingerprintProcNetRouteDefault(string(data)), nil
}

// CheckDefaultRouteUnchanged 对比当前默认路由与快照；不一致返回告警 error。
// 供隧道 up 后的断言与 job 周期复检（对外契约，签名不许改）。
func CheckDefaultRouteUnchanged(snapshot string) error {
	cur, err := snapshotDefaultRoute()
	if err != nil {
		return fmt.Errorf("vpnclient: 路由护栏自检失败: %w", err)
	}
	if cur != snapshot {
		return fmt.Errorf("vpnclient: 默认路由发生变化（护栏告警）: 拨号前=%q 当前=%q", snapshot, cur)
	}
	return nil
}

// fingerprintIPRouteDefault 把 `ip route show default` 输出规范化为指纹。
// 纯函数，可单测。
func fingerprintIPRouteDefault(out string) string {
	var parts []string
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		f := strings.Fields(line)
		if len(f) == 0 || f[0] != "default" {
			continue
		}
		var dev, via, metric string
		for i := 0; i < len(f); i++ {
			switch f[i] {
			case "dev":
				if i+1 < len(f) {
					dev = f[i+1]
				}
			case "via":
				if i+1 < len(f) {
					via = f[i+1]
				}
			case "metric":
				if i+1 < len(f) {
					metric = f[i+1]
				}
			}
		}
		parts = append(parts, strings.Join([]string{dev, via, metric}, "|"))
	}
	sort.Strings(parts)
	return strings.Join(parts, ";")
}

// kernelRoute 是 /proc/net/route 的一行解析结果。
type kernelRoute struct {
	Iface   string
	Dest    netip.Addr
	Bits    int
	Gateway netip.Addr
	Metric  int
}

// parseProcNetRoute 解析 /proc/net/route 内容。
// 注意：Destination/Gateway/Mask 字段是小端序 hex（192.168.1.0 显示为 "0001A8C0"）。
// 纯函数，可单测。
func parseProcNetRoute(data string) []kernelRoute {
	var out []kernelRoute
	for _, line := range strings.Split(data, "\n") {
		f := strings.Fields(line)
		if len(f) < 11 || f[0] == "Iface" {
			continue
		}
		dest, ok1 := leHexAddr(f[1])
		gw, ok2 := leHexAddr(f[2])
		mask, ok3 := leHexAddr(f[7])
		if !ok1 || !ok2 || !ok3 {
			continue
		}
		metric, _ := strconv.Atoi(f[6])
		out = append(out, kernelRoute{
			Iface:   f[0],
			Dest:    dest,
			Bits:    maskPrefixLen(mask),
			Gateway: gw,
			Metric:  metric,
		})
	}
	return out
}

// leHexAddr 解析 /proc/net/route 的小端 hex 地址字段。
func leHexAddr(s string) (netip.Addr, bool) {
	if len(s) != 8 {
		return netip.Addr{}, false
	}
	v, err := strconv.ParseUint(s, 16, 32)
	if err != nil {
		return netip.Addr{}, false
	}
	b := [4]byte{byte(v), byte(v >> 8), byte(v >> 16), byte(v >> 24)}
	return netip.AddrFrom4(b), true
}

// maskPrefixLen 把掩码换算成前缀长度。注意：leHexAddr 已把小端 hex 还原为
// 点分十进制字节序（如 255.255.255.0），此处按大端解释数前导 1。
func maskPrefixLen(mask netip.Addr) int {
	b := mask.As4()
	v := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	n := 0
	for i := 31; i >= 0; i-- {
		if v&(1<<uint(i)) != 0 {
			n++
		} else {
			break
		}
	}
	return n
}

// fingerprintProcNetRouteDefault 从 /proc/net/route 内容提取默认路由指纹
// （与 fingerprintIPRouteDefault 同一规范格式）。纯函数，可单测。
func fingerprintProcNetRouteDefault(data string) string {
	var parts []string
	for _, r := range parseProcNetRoute(data) {
		if !r.Dest.IsUnspecified() {
			continue
		}
		parts = append(parts, strings.Join([]string{
			r.Iface, r.Gateway.String(), strconv.Itoa(r.Metric),
		}, "|"))
	}
	sort.Strings(parts)
	return strings.Join(parts, ";")
}

// scopedRoutePresentIn 报告 lanSubnet 是否经 iface 可达（data 为 /proc/net/route 内容）。
// 纯函数，可单测；是 pptp/ovpn"只路由 LanSubnet"在运行时的断言。
func scopedRoutePresentIn(data, lanSubnet, iface string) (bool, error) {
	lan, err := netip.ParsePrefix(lanSubnet)
	if err != nil {
		return false, fmt.Errorf("lanSubnet 非法: %w", err)
	}
	lan = lan.Masked()
	for _, r := range parseProcNetRoute(data) {
		if r.Iface != iface || r.Bits == 0 {
			continue // 默认路由不算 scoped 路由（那是护栏的职责）
		}
		rn := netip.PrefixFrom(r.Dest, r.Bits).Masked()
		if rn.Bits() <= lan.Bits() && rn.Contains(lan.Addr()) {
			return true, nil
		}
	}
	return false, nil
}

// scopedRoutePresent 是 scopedRoutePresentIn 的文件版。
func scopedRoutePresent(lanSubnet, iface string) (bool, error) {
	data, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return false, err
	}
	return scopedRoutePresentIn(string(data), lanSubnet, iface)
}

// watchGuard 在隧道 up 后做一次路由护栏断言（§4.2 步骤 2）。
// 异步 goroutine：每 5s 看一次状态，最多等 guardWatchDelay；一旦 up 就对比快照，
// 不一致则 hangup + 告警（面板读 Status().Message 显示红字）。
func (m *Manager) watchGuard(id int, gen uint64) {
	deadline := time.Now().Add(guardWatchDelay)
	for time.Now().Before(deadline) {
		time.Sleep(5 * time.Second)
		m.mu.Lock()
		h := m.links[id]
		if h == nil || h.gen != gen || h.guardSnapshot == "" {
			m.mu.Unlock()
			return
		}
		// 主动探测（带 10s 节流）：不能依赖面板调 Status() 来刷新状态，
		// 否则无人查看时护栏永远等不到 up。
		m.probeLocked(h)
		up := h.status == StatusUp
		snap := h.guardSnapshot
		m.mu.Unlock()

		if !up {
			continue
		}
		if err := CheckDefaultRouteUnchanged(snap); err != nil {
			m.mu.Lock()
			if h2 := m.links[id]; h2 != nil && h2.gen == gen {
				m.stopRuntimeLocked(h2)
				h2.status = StatusError
				h2.message = "路由护栏告警：隧道建立后默认路由发生变化，已断开连接"
			}
			m.mu.Unlock()
			logger.Errorf("vpnclient: 连接 %d 路由护栏触发: %v", id, err)
			return
		}
		return // 验证通过
	}
}

// ensureScopedRoute 确保 lanSubnet 经 iface 可达；缺失则补一条（幂等）。
// 这是 ip-up.d 脚本的主路径之外的第二道：脚本没跑起来（发行版差异）时由 Manager 补。
func ensureScopedRoute(lanSubnet, iface string) error {
	ok, err := scopedRoutePresent(lanSubnet, iface)
	if err != nil {
		return err
	}
	if ok {
		return nil
	}
	out, err := exec.Command("ip", "route", "replace", lanSubnet, "dev", iface).CombinedOutput()
	if err != nil {
		return fmt.Errorf("补 scoped 路由失败: %w（%s）", err, strings.TrimSpace(string(out)))
	}
	logger.Infof("vpnclient: 已补 scoped 路由 %s dev %s", lanSubnet, iface)
	return nil
}
