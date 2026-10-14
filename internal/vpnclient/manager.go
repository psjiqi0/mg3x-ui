//go:build linux

// Package vpnclient 是 RouterLink（路由器 VPN 客户端连接）的拨号托管层。
//
// 角色：本端永远是客户端——服务器主动拨号连接用户名下各路由器的 VPN 服务端
// （openvpn | pptp | wireguard），再把服务器公网端口经隧道转发进路由器内网。
//
// 铁律（RELAY_DESIGN.md §4）：三个客户端都严禁改默认路由、严禁接受对端推送的
// 网关/DNS。隧道只承载 LanSubnet。三道防线：
//  1. 配置层：ovpn 用 route-nopull + pull-filter，pppd 用 nodefaultroute，
//     wg 的 AllowedIPs 只填 LanSubnet（绝不用 0.0.0.0/0）；
//  2. 护栏层（guard.go）：拨号前后断言默认路由不变，job 周期复检；
//  3. 转发层：转发目标运行时断言落在 LanSubnet 内。
//
// 本包是 Linux 专用的（tun/ppp/SO_BINDTODEVICE 都是 Linux 概念）。
package vpnclient

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/mhsanaei/3x-ui/v3/internal/amneziawgnet"
	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
	"github.com/mhsanaei/3x-ui/v3/internal/logger"
)

// 连接状态（对外契约，D 组面板层直接依赖）。
const (
	StatusUp      = "up"
	StatusDown    = "down"
	StatusDialing = "dialing"
	StatusError   = "error"
)

// LinkStatus 是单个 RouterLink 的实时状态（对外契约，签名不许改）。
type LinkStatus struct {
	Id              int    `json:"id"`
	Status          string `json:"status"` // up|down|dialing|error
	HandshakeAt     int64  `json:"handshakeAt"`
	RxBytes         int64  `json:"rxBytes"`
	TxBytes         int64  `json:"txBytes"`
	Message         string `json:"message"`
	Iface           string `json:"iface"`
	EgressSocksPort int    `json:"egressSocksPort"` // 独占 SOCKS5 端口（egress.go），0=未启用
}

const (
	probeInterval   = 10 * time.Second // 状态探测节流：Status() 最多每 10s 做一次真实探测
	dialBackoff     = 60 * time.Second // 拨号失败后 job 重试的退避间隔
	guardWatchDelay = 90 * time.Second // 拨号后等待隧道 up 做护栏断言的最长等待
)

// routerAuth 是 RouterLink.AuthJSON 解密后的明文形状（见 model/router_link.go 注释）。
type routerAuth struct {
	Type          string `json:"type"`
	Username      string `json:"username"`
	Password      string `json:"password"`
	CA            string `json:"ca"`
	Cert          string `json:"cert"`
	Key           string `json:"key"`
	PrivateKey    string `json:"privateKey"`
	PeerPublicKey string `json:"peerPublicKey"`
	PresharedKey  string `json:"presharedKey"`
}

// decryptAuth 解密 AuthJSON。加密未启用时透传（与 DecryptRouterLinkAuth 语义一致）。
func decryptAuth(link model.RouterLink) (routerAuth, error) {
	var a routerAuth
	enc := strings.TrimSpace(link.AuthJSON)
	if enc == "" {
		return a, nil
	}
	plain, err := model.DecryptRouterLinkAuth(enc)
	if err != nil {
		return a, fmt.Errorf("auth 解密失败: %w", err)
	}
	if strings.TrimSpace(plain) == "" {
		return a, nil
	}
	if err := json.Unmarshal([]byte(plain), &a); err != nil {
		return a, fmt.Errorf("auth JSON 解析失败: %w", err)
	}
	return a, nil
}

// validateLink 做形状校验（与拨号无关的纯检查）。
func validateLink(link model.RouterLink) error {
	switch link.Protocol {
	case "openvpn", "pptp", "wireguard":
	default:
		return fmt.Errorf("未知协议 %q", link.Protocol)
	}
	if strings.TrimSpace(link.RemoteHost) == "" {
		return errors.New("remoteHost 为空")
	}
	if link.RemotePort < 1 || link.RemotePort > 65535 {
		return fmt.Errorf("remotePort %d 非法", link.RemotePort)
	}
	if _, _, err := net.ParseCIDR(link.LanSubnet); err != nil {
		return fmt.Errorf("lanSubnet %q 非法: %w", link.LanSubnet, err)
	}
	if link.Protocol == "openvpn" && link.Proto != "" && link.Proto != "udp" && link.Proto != "tcp" {
		return fmt.Errorf("openvpn proto %q 非法（只支持 udp|tcp）", link.Proto)
	}
	return nil
}

// configFingerprint 是"配置是否变化"的判据：命中则 Ensure 走快路径（只对账转发），
// 未命中则 teardown 重拨。AuthJSON 取加密 blob——变了就说明认证变了，无需解密比较。
func configFingerprint(link model.RouterLink) string {
	h := sha256.New()
	fmt.Fprintf(h, "%s|%s|%d|%s|%s|%s|%d|%s|%s|%s",
		link.Protocol, link.RemoteHost, link.RemotePort, link.Proto,
		link.LanSubnet, link.Mppe, link.PersistentKeepalive,
		link.TunnelAddress, link.ForwardedPorts, link.AuthJSON)
	return hex.EncodeToString(h.Sum(nil))
}

// childProc 是被托管的子进程（openvpn / pppd）。
type childProc struct {
	cmd     *exec.Cmd
	done    chan struct{}
	mu      sync.Mutex
	exitErr error
}

// startChildProc 启动子进程并开始看护。调用方需预先填好 SysProcAttr{Setpgid: true}
// （stop 用进程组杀，确保 pty/脚本等子孙一起回收）。
func startChildProc(cmd *exec.Cmd) (*childProc, error) {
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	p := &childProc{cmd: cmd, done: make(chan struct{})}
	go func() {
		err := cmd.Wait()
		p.mu.Lock()
		p.exitErr = err
		p.mu.Unlock()
		close(p.done)
	}()
	return p, nil
}

func (p *childProc) running() bool {
	if p == nil {
		return false
	}
	select {
	case <-p.done:
		return false
	default:
		return true
	}
}

func (p *childProc) exitError() error {
	if p == nil {
		return errors.New("进程未启动")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.exitErr
}

// stop 先 SIGTERM 整个进程组，5s 不退出再 SIGKILL。
func (p *childProc) stop() {
	if p == nil {
		return
	}
	select {
	case <-p.done:
		return
	default:
	}
	if p.cmd.Process != nil {
		_ = syscall.Kill(-p.cmd.Process.Pid, syscall.SIGTERM)
	}
	select {
	case <-p.done:
	case <-time.After(5 * time.Second):
		if p.cmd.Process != nil {
			_ = syscall.Kill(-p.cmd.Process.Pid, syscall.SIGKILL)
		}
		<-p.done
	}
}

// linkHandle 是一个 RouterLink 的全部运行时状态。
type linkHandle struct {
	id  int
	dir string // <baseDir>/<id>

	link        model.RouterLink
	status      string
	message     string
	iface       string // 隧道接口名（ovpn: tunX；pptp: pppX；wg: rl-wg-<id> 逻辑名）
	handshakeAt time.Time
	rxBytes     int64
	txBytes     int64

	guardSnapshot string       // 拨号前的默认路由快照（护栏用）
	cfgFP         string       // 上次拨号时的配置指纹
	wantUp        bool         // 期望状态（false=用户禁用/手动挂断）
	gen           uint64       // 拨号代次（异步 goroutine 防旧代误操作）
	peerKey       string       // wg 对端公钥（状态采集用，避免每次解密）
	bindIface     atomic.Value // string：端口转发 dial 侧 SO_BINDTODEVICE 的目标接口

	lastProbe       time.Time
	lastDialAttempt time.Time
	pppBefore       []string // pptp 拨号前已有的 ppp 接口（兜底发现用）

	wgDev  *amneziawgnet.Device
	proc   *childProc
	fw     *Forwarder
	egress *egressServer // 独占 SOCKS5（egress.go），生命周期独立于隧道拨号
}

// Manager 按 RouterLink id 管理连接生命周期（对外契约，签名不许改）。
type Manager struct {
	mu      sync.Mutex
	baseDir string
	links   map[int]*linkHandle
	dialSeq uint64
}

// NewManager 创建 Manager。baseDir 存放各连接的配置文件（如 /var/lib/x-ui/routerlinks）。
func NewManager(baseDir string) *Manager {
	return &Manager{baseDir: baseDir, links: map[int]*linkHandle{}}
}

// Ensure 新建/更新连接：写配置，然后按 Enable 决定拨号/挂断。
// 已是最新配置且隧道活着时只做转发对账（快路径，供 job 高频调用）。
func (m *Manager) Ensure(link model.RouterLink) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.ensureLocked(link)
}

// Remove 挂断并删除该连接的全部配置。
func (m *Manager) Remove(id int) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	h := m.links[id]
	if h == nil {
		return nil
	}
	m.stopRuntimeLocked(h)
	m.removeEgressLocked(id)
	if h.link.Protocol == "pptp" {
		_ = syncChapSecrets(chapSecretsPath(m.baseDir), id, "")
	}
	if err := os.RemoveAll(h.dir); err != nil {
		return fmt.Errorf("vpnclient: 删除连接 %d 配置失败: %w", id, err)
	}
	delete(m.links, id)
	logger.Infof("vpnclient: 已删除连接 %d", id)
	return nil
}

// Dial 手动拨号（无视退避，直接重拨）。
func (m *Manager) Dial(id int) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	h := m.links[id]
	if h == nil {
		return fmt.Errorf("vpnclient: 未知的连接 id=%d", id)
	}
	h.wantUp = true
	h.lastDialAttempt = time.Time{} // 绕过退避
	h.status = ""                   // 强制走重拨路径
	return m.ensureLocked(h.link)
}

// Hangup 手动挂断（保留配置，job 不会自动重拨）。
func (m *Manager) Hangup(id int) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	h := m.links[id]
	if h == nil {
		return nil
	}
	h.wantUp = false
	h.gen++
	m.stopRuntimeLocked(h)
	h.status = StatusDown
	h.message = "已手动挂断"
	h.guardSnapshot = ""
	return nil
}

// Status 返回连接实时状态（带 10s 节流的真实探测）。
func (m *Manager) Status(id int) LinkStatus {
	m.mu.Lock()
	defer m.mu.Unlock()
	h := m.links[id]
	if h == nil {
		return LinkStatus{Id: id, Status: StatusDown, Message: "未管理"}
	}
	m.probeLocked(h)
	st := LinkStatus{
		Id:          id,
		Status:      h.status,
		Message:     h.message,
		Iface:       h.iface,
		HandshakeAt: h.handshakeAt.Unix(),
		RxBytes:     h.rxBytes,
		TxBytes:     h.txBytes,
	}
	if st.HandshakeAt < 0 {
		st.HandshakeAt = 0
	}
	if h.fw != nil {
		frx, ftx := h.fw.Stats()
		st.RxBytes += frx
		st.TxBytes += ftx
	}
	if h.egress != nil {
		st.EgressSocksPort = h.egress.port
	}
	return st
}

// Reconcile 对账期望状态：job 每 tick 调用；新增/更新走 Ensure，消失的走 Remove。
func (m *Manager) Reconcile(links []model.RouterLink) {
	m.mu.Lock()
	defer m.mu.Unlock()
	want := make(map[int]bool, len(links))
	for _, link := range links {
		want[link.Id] = true
		if err := m.ensureLocked(link); err != nil {
			logger.Warningf("vpnclient: 对账连接 %d (%s) 失败: %v", link.Id, link.Name, err)
		}
	}
	for id := range m.links {
		if !want[id] {
			h := m.links[id]
			m.stopRuntimeLocked(h)
			m.removeEgressLocked(id)
			if h.link.Protocol == "pptp" {
				_ = syncChapSecrets(chapSecretsPath(m.baseDir), id, "")
			}
			_ = os.RemoveAll(h.dir)
			delete(m.links, id)
			logger.Infof("vpnclient: 对账删除连接 %d", id)
		}
	}
}

// GuardCheckAll 供 vpnclient_job 每 tick 调用：复检所有已拨号连接的默认路由快照，
// 漂移即告警并撕掉连接（RELAY_DESIGN.md §4.2 步骤 3）。
func (m *Manager) GuardCheckAll() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, h := range m.links {
		if h.guardSnapshot == "" || h.status == StatusDown {
			continue
		}
		if err := CheckDefaultRouteUnchanged(h.guardSnapshot); err != nil {
			logger.Errorf("vpnclient: 连接 %d 路由护栏复检触发: %v", id, err)
			m.stopRuntimeLocked(h)
			h.status = StatusError
			h.message = "路由护栏告警（job 复检）：默认路由发生变化，已断开连接"
		}
	}
}

// StopAll 停掉全部运行时（面板退出时调用，避免 openvpn/pppd 进程残留）。
func (m *Manager) StopAll() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, h := range m.links {
		h.wantUp = false
		m.stopRuntimeLocked(h)
		m.removeEgressLocked(id)
		h.status = StatusDown
	}
}

// ---- 内部实现 ----

func (m *Manager) getOrCreateHandle(id int) *linkHandle {
	h := m.links[id]
	if h == nil {
		h = &linkHandle{
			id:     id,
			dir:    filepath.Join(m.baseDir, strconv.Itoa(id)),
			status: StatusDown,
		}
		h.bindIface.Store("")
		m.links[id] = h
	}
	return h
}

func (m *Manager) ensureLocked(link model.RouterLink) error {
	h := m.getOrCreateHandle(link.Id)
	h.link = link

	if err := validateLink(link); err != nil {
		h.status = StatusError
		h.message = err.Error()
		return err
	}
	auth, err := decryptAuth(link)
	if err != nil {
		h.status = StatusError
		h.message = err.Error()
		return err
	}
	if err := m.writeConfigsLocked(h, link, auth); err != nil {
		h.status = StatusError
		h.message = err.Error()
		return err
	}

	fp := configFingerprint(link)
	if !link.Enable {
		h.wantUp = false
		h.gen++
		m.stopRuntimeLocked(h)
		m.removeEgressLocked(link.Id)
		h.status = StatusDown
		h.message = "已禁用"
		h.guardSnapshot = ""
		return nil
	}
	h.wantUp = true

	// egress SOCKS 的启停独立于隧道拨号结果（tunnel down 时监听保持）。
	m.syncEgressLocked(link)

	// 快路径：配置未变且隧道活着，只对账端口转发。
	if h.cfgFP == fp && h.liveLocked() {
		return m.reconcileForwardsLocked(h)
	}
	// 退避：持续失败的拨号不要每 tick 都 fork/exec。
	if h.status == StatusError && h.cfgFP == fp && time.Since(h.lastDialAttempt) < dialBackoff {
		return nil
	}

	m.stopRuntimeLocked(h)
	m.dialSeq++
	h.gen = m.dialSeq
	h.cfgFP = fp
	h.status = StatusDialing
	h.message = ""
	h.iface = ""
	h.handshakeAt = time.Time{}
	h.rxBytes, h.txBytes = 0, 0
	h.lastProbe = time.Time{}
	h.bindIface.Store("")

	// 护栏步骤 1：拨号前快照默认路由。
	snap, err := snapshotDefaultRoute()
	if err != nil {
		logger.Warningf("vpnclient: 连接 %d 默认路由快照失败，护栏降级: %v", link.Id, err)
	}
	h.guardSnapshot = snap

	h.lastDialAttempt = time.Now()
	if err := m.dialLocked(h, link, auth); err != nil {
		h.status = StatusError
		h.message = err.Error()
		return err
	}
	if err := m.reconcileForwardsLocked(h); err != nil {
		logger.Warningf("vpnclient: 连接 %d 端口转发对账: %v", link.Id, err)
	}
	gen := h.gen
	go m.postDial(h.id, gen, link.Protocol)
	go m.watchGuard(h.id, gen)
	logger.Infof("vpnclient: 连接 %d (%s) 正在经 %s 拨号", link.Id, link.Name, link.Protocol)
	return nil
}

// liveLocked 是轻量存活检查（无 I/O），供 Ensure 快路径使用。
func (h *linkHandle) liveLocked() bool {
	switch h.link.Protocol {
	case "wireguard":
		return h.wgDev != nil
	default:
		return h.proc != nil && h.proc.running()
	}
}

// stopRuntimeLocked 停掉运行时（转发器/设备/子进程），保留配置与 handle。
func (m *Manager) stopRuntimeLocked(h *linkHandle) {
	if h.fw != nil {
		h.fw.Close()
		h.fw = nil
	}
	if h.wgDev != nil {
		h.wgDev.Close()
		h.wgDev = nil
	}
	if h.proc != nil {
		h.proc.stop()
		h.proc = nil
	}
	h.bindIface.Store("")
}

// dialLocked 按协议启动拨号（非阻塞：只负责把运行时拉起来）。
func (m *Manager) dialLocked(h *linkHandle, link model.RouterLink, auth routerAuth) error {
	switch link.Protocol {
	case "wireguard":
		return m.dialWGLocked(h, link, auth)
	case "openvpn":
		return m.dialOVPNLocked(h, link, auth)
	case "pptp":
		return m.dialPPTPLocked(h, link, auth)
	default:
		return fmt.Errorf("未知协议 %q", link.Protocol)
	}
}

// postDial 是拨号后的异步收尾：pptp 做接口发现+补 scoped 路由（ip-up 脚本是主路径，
// 这里是兜底）；各协议统一等待 up 然后由 watchGuard 做护栏断言。
func (m *Manager) postDial(id int, gen uint64, protocol string) {
	if protocol == "pptp" {
		m.discoverPPTPIface(id, gen)
	}
}

// probeLocked 带节流的深度探测，更新 handle 的状态/字节数/接口名。
func (m *Manager) probeLocked(h *linkHandle) {
	if time.Since(h.lastProbe) < probeInterval {
		return
	}
	h.lastProbe = time.Now()
	switch h.link.Protocol {
	case "wireguard":
		m.probeWGLocked(h)
	case "openvpn":
		m.probeOVPNLocked(h)
	case "pptp":
		m.probePPTPLocked(h)
	}
}

// writeConfigsLocked 写各协议配置文件（幂等）。wg 是纯内存设备，无文件。
func (m *Manager) writeConfigsLocked(h *linkHandle, link model.RouterLink, auth routerAuth) error {
	if err := os.MkdirAll(h.dir, 0700); err != nil {
		return fmt.Errorf("创建配置目录失败: %w", err)
	}
	switch link.Protocol {
	case "openvpn":
		return writeOpenVPNConfigs(h.dir, link, auth)
	case "pptp":
		return m.writePPTPConfigsLocked(h, link, auth)
	case "wireguard":
		return nil
	default:
		return fmt.Errorf("未知协议 %q", link.Protocol)
	}
}

// reconcileForwardsLocked 对账端口转发：解析扩展语法，逐条断言 lanIP 落在 LanSubnet 内，
// 增量增删监听器。
func (m *Manager) reconcileForwardsLocked(h *linkHandle) error {
	link := h.link
	ports, err := ParseForwardedPorts(link.ForwardedPorts)
	if err != nil {
		// 语法错误不杀隧道：记告警，本轮不转发（D 组应在保存时校验）。
		logger.Warningf("vpnclient: 连接 %d forwardedPorts 语法错误，本轮跳过转发: %v", link.Id, err)
		ports = nil
	}
	_, lanNet, err := net.ParseCIDR(link.LanSubnet)
	if err != nil {
		return err
	}
	var ok []ForwardedPort
	for _, p := range ports {
		ip := net.ParseIP(p.LanIP)
		if ip == nil || ip.IsUnspecified() || !lanNet.Contains(ip) {
			logger.Warningf("vpnclient: 连接 %d 转发规则 %d->%s:%d 的内网 IP 不在 LanSubnet %s 内，已跳过",
				link.Id, p.PubPort, p.LanIP, p.LanPort, link.LanSubnet)
			continue
		}
		ok = append(ok, p)
	}
	var dial DialFunc
	switch link.Protocol {
	case "wireguard":
		if h.wgDev == nil {
			return errors.New("wireguard 设备未就绪，转发对账推迟")
		}
		dial = wgStackDialFunc(h.wgDev)
	case "openvpn", "pptp":
		dial = bindDeviceDialFunc(&h.bindIface)
	default:
		return fmt.Errorf("未知协议 %q", link.Protocol)
	}
	if h.fw == nil {
		h.fw = NewForwarder(dial)
	}
	h.fw.Reconcile(ok)
	return nil
}

// writeFileIfChanged 内容变化时才写（幂等，避免频繁改动触发外部 watch）。
func writeFileIfChanged(path, content string, perm os.FileMode) error {
	if old, err := os.ReadFile(path); err == nil && string(old) == content {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(content), perm)
}

// ifaceBytes 读网卡统计（/sys，无需 ip 命令）。
func ifaceBytes(iface string) (rx, tx uint64) {
	rb, err1 := os.ReadFile("/sys/class/net/" + iface + "/statistics/rx_bytes")
	tb, err2 := os.ReadFile("/sys/class/net/" + iface + "/statistics/tx_bytes")
	if err1 != nil || err2 != nil {
		return 0, 0
	}
	rx, _ = strconv.ParseUint(strings.TrimSpace(string(rb)), 10, 64)
	tx, _ = strconv.ParseUint(strings.TrimSpace(string(tb)), 10, 64)
	return rx, tx
}

// readIfnameFile 读连接目录下的 ifname 文件（由 ovpn up.sh / pptp ip-up 脚本写入）。
func readIfnameFile(dir string) string {
	b, err := os.ReadFile(filepath.Join(dir, "ifname"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}
