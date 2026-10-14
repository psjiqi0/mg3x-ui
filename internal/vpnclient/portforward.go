//go:build linux

package vpnclient

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mhsanaei/3x-ui/v3/internal/logger"
)

// ForwardedPort 是一条解析后的 "pubPort->lanIP:lanPort" 规则（对外契约，签名不许改）。
type ForwardedPort struct {
	PubPort int    `json:"pubPort"`
	LanIP   string `json:"lanIP"`
	LanPort int    `json:"lanPort"`
}

// ParseForwardedPorts 解析扩展语法（RELAY_DESIGN.md §8.1）：
//
//	8080->192.168.225.10:80, 8443->192.168.225.10:443
//
// 逗号分隔、空白容忍；空输入返回空规则。任何非法 token 都会让整个解析失败
// 并返回 error（对外契约，签名不许改）。
func ParseForwardedPorts(input string) ([]ForwardedPort, error) {
	var out []ForwardedPort
	seen := map[int]bool{}
	for _, tok := range strings.Split(input, ",") {
		tok = strings.TrimSpace(tok)
		if tok == "" {
			continue
		}
		left, right, ok := strings.Cut(tok, "->")
		if !ok {
			return nil, fmt.Errorf("vpnclient: 非法转发规则 %q：缺少 \"->\"", tok)
		}
		pubPort, err := parseFwdPort(strings.TrimSpace(left))
		if err != nil {
			return nil, fmt.Errorf("vpnclient: 非法转发规则 %q：公网端口 %v", tok, err)
		}
		if seen[pubPort] {
			return nil, fmt.Errorf("vpnclient: 非法转发规则 %q：公网端口 %d 重复", tok, pubPort)
		}
		// 内网目标用 SplitHostPort 解析（IPv6 请用 [fd00::1]:80 形式）。
		host, portStr, err := net.SplitHostPort(strings.TrimSpace(right))
		if err != nil {
			return nil, fmt.Errorf("vpnclient: 非法转发规则 %q：内网目标 %v", tok, err)
		}
		if _, err := netip.ParseAddr(host); err != nil {
			return nil, fmt.Errorf("vpnclient: 非法转发规则 %q：内网 IP %v", tok, err)
		}
		lanPort, err := parseFwdPort(portStr)
		if err != nil {
			return nil, fmt.Errorf("vpnclient: 非法转发规则 %q：内网端口 %v", tok, err)
		}
		seen[pubPort] = true
		out = append(out, ForwardedPort{PubPort: pubPort, LanIP: host, LanPort: lanPort})
	}
	return out, nil
}

func parseFwdPort(s string) (int, error) {
	p, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil || p < 1 || p > 65535 {
		return 0, fmt.Errorf("%q 不是合法端口（1-65535）", s)
	}
	return p, nil
}

// DialFunc 负责把一条转发连接"拨"进隧道：network 为 "tcp"/"udp"，
// address 为 "lanIP:lanPort"。
//
//   - wireguard：经该连接独占的 gVisor stack 拨号（见 wireguard.go 的
//     wgStackDialFunc；多连接内网段重叠天然无冲突，每个 stack 是独立 sandbox）；
//   - openvpn/pptp：经 net.Dialer 拨号，socket 上做 SO_BINDTODEVICE 钉在对应
//     tunX/pppX 上（见 bindDeviceDialFunc；Linux 对绑定设备的 socket 做设备
//     作用域路由查找，重叠网段也不会串流）。
type DialFunc func(ctx context.Context, network, address string) (net.Conn, error)

const (
	fwdDialTimeout    = 10 * time.Second
	fwdUDPIdleTimeout = 2 * time.Minute
)

// Forwarder 是 Go 用户态端口转发器（RELAY_DESIGN.md §8.3 方案 b）：
// 在宿主网络命名空间监听公网端口（TCP+UDP），accept 后经 DialFunc 拨进隧道，
// io.Copy 双向转发。增量对账：Reconcile 只增删变化的监听器；关闭即 listener.Close()。
//
// 设计取舍（相对 §8.2）：amneziawgnet.PortForwardSet 的导出 API
// （NewPortForwardSet + Reconcile(amneziawg.Instance)）表达的是服务端语义——
// 目标端口恒等于监听端口、目标地址从 peer AllowedIPs 猜，无法表达
// "8080->192.168.225.10:80"（pubPort 与 lanPort 不同）。它的目标解析函数是
// 未导出的，且本包不允许改 amneziawgnet；故此处按同一监听/对账/关闭模式
// 自实现，通过 DialFunc 注入 per-协议的拨号方式（WG 走 gVisor stack，
// ovpn/pptp 走钉设备的 net.Dial）。
type Forwarder struct {
	mu    sync.Mutex
	dial  DialFunc // 创建后不再更换
	rules map[int]ForwardedPort

	tcp map[int]*tcpFwdListener
	udp map[int]*udpFwdListener

	rxBytes atomic.Int64 // 隧道->公网（panel 视角的 rx）
	txBytes atomic.Int64 // 公网->隧道（panel 视角的 tx）
}

// NewForwarder 创建转发器（空规则，调 Reconcile 生效）。
func NewForwarder(dial DialFunc) *Forwarder {
	return &Forwarder{
		dial:  dial,
		rules: map[int]ForwardedPort{},
		tcp:   map[int]*tcpFwdListener{},
		udp:   map[int]*udpFwdListener{},
	}
}

// Reconcile 增量对账：关闭不再需要的监听器，打开新增的，已有的原样保留。
// 单个端口 bind 失败只影响该条转发（记 warning，下次 Reconcile 重试），
// 不影响整体——与 amneziawgnet.PortForwardSet.Reconcile 的契约一致。
func (f *Forwarder) Reconcile(ports []ForwardedPort) {
	want := make(map[int]ForwardedPort, len(ports))
	for _, p := range ports {
		want[p.PubPort] = p
	}

	f.mu.Lock()
	for port, l := range f.tcp {
		if _, ok := want[port]; !ok {
			l.close()
			delete(f.tcp, port)
		}
	}
	for port, l := range f.udp {
		if _, ok := want[port]; !ok {
			l.close()
			delete(f.udp, port)
		}
	}
	var toOpen []ForwardedPort
	for port, p := range want {
		if _, ok := f.tcp[port]; !ok {
			toOpen = append(toOpen, p)
		}
	}
	f.rules = want
	f.mu.Unlock()

	for _, p := range toOpen {
		tl := listenTCPFwd(p.PubPort, f)
		ul := listenUDPFwd(p.PubPort, f)
		f.mu.Lock()
		if tl != nil {
			if old, ok := f.tcp[p.PubPort]; ok {
				old.close()
			}
			f.tcp[p.PubPort] = tl
		}
		if ul != nil {
			if old, ok := f.udp[p.PubPort]; ok {
				old.close()
			}
			f.udp[p.PubPort] = ul
		}
		f.mu.Unlock()
	}
}

// Close 关闭全部监听器（连接启停清理就是这一行）。
func (f *Forwarder) Close() {
	f.mu.Lock()
	tcpLs := f.tcp
	udpLs := f.udp
	f.tcp = map[int]*tcpFwdListener{}
	f.udp = map[int]*udpFwdListener{}
	f.mu.Unlock()
	for _, l := range tcpLs {
		l.close()
	}
	for _, l := range udpLs {
		l.close()
	}
}

// Stats 返回累计字节（供 LinkStatus 汇总）。
func (f *Forwarder) Stats() (rx, tx int64) {
	return f.rxBytes.Load(), f.txBytes.Load()
}

// ruleFor 取当前规则（每次 accept/建会话时重查，规则热更新零监听器抖动）。
func (f *Forwarder) ruleFor(port int) (ForwardedPort, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	p, ok := f.rules[port]
	return p, ok
}

// ---- TCP ----

type tcpFwdListener struct {
	ln        net.Listener
	closing   chan struct{}
	closeOnce sync.Once
}

func (l *tcpFwdListener) close() {
	l.closeOnce.Do(func() {
		close(l.closing)
		l.ln.Close()
	})
}

func listenTCPFwd(port int, f *Forwarder) *tcpFwdListener {
	ln, err := net.Listen("tcp", ":"+strconv.Itoa(port))
	if err != nil {
		logger.Warningf("vpnclient: 端口转发：监听 tcp :%d 失败: %v", port, err)
		return nil
	}
	l := &tcpFwdListener{ln: ln, closing: make(chan struct{})}
	logger.Infof("vpnclient: 端口转发：监听 tcp :%d", port)
	go l.acceptLoop(f, port)
	return l
}

func (l *tcpFwdListener) acceptLoop(f *Forwarder, port int) {
	for {
		c, err := l.ln.Accept()
		if err != nil {
			select {
			case <-l.closing:
			default:
				logger.Warningf("vpnclient: 端口转发：accept tcp :%d: %v", port, err)
			}
			return
		}
		go f.serveTCP(c, port)
	}
}

func (f *Forwarder) serveTCP(down net.Conn, port int) {
	rule, ok := f.ruleFor(port)
	if !ok {
		down.Close()
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), fwdDialTimeout)
	defer cancel()
	target := net.JoinHostPort(rule.LanIP, strconv.Itoa(rule.LanPort))
	up, err := f.dial(ctx, "tcp", target)
	if err != nil {
		logger.Warningf("vpnclient: 端口转发：tcp :%d -> %s 拨号失败: %v", port, target, err)
		down.Close()
		return
	}
	relayBidirectional(down, up, &f.rxBytes, &f.txBytes)
}

// relayBidirectional 双向转发；public->tunnel 计 tx，tunnel->public 计 rx。
func relayBidirectional(public, tunnel net.Conn, rx, tx *atomic.Int64) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(countingWriter{tunnel, tx}, public)
		if c, ok := tunnel.(interface{ CloseWrite() error }); ok {
			_ = c.CloseWrite()
		}
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(countingWriter{public, rx}, tunnel)
		if c, ok := public.(interface{ CloseWrite() error }); ok {
			_ = c.CloseWrite()
		}
	}()
	wg.Wait()
	public.Close()
	tunnel.Close()
}

type countingWriter struct {
	w   io.Writer
	cnt *atomic.Int64
}

func (c countingWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.cnt.Add(int64(n))
	return n, err
}

// ---- UDP ----

type udpFwdSession struct {
	conn    net.Conn // 已 connected 到 lanIP:lanPort
	lastUse atomic.Int64
}

type udpFwdListener struct {
	pc        net.PacketConn
	port      int
	f         *Forwarder
	closing   chan struct{}
	closeOnce sync.Once

	mu       sync.Mutex
	sessions map[netip.AddrPort]*udpFwdSession
}

func (l *udpFwdListener) close() {
	l.closeOnce.Do(func() {
		close(l.closing)
		l.pc.Close()
		l.mu.Lock()
		for _, s := range l.sessions {
			s.conn.Close()
		}
		l.sessions = map[netip.AddrPort]*udpFwdSession{}
		l.mu.Unlock()
	})
}

func listenUDPFwd(port int, f *Forwarder) *udpFwdListener {
	pc, err := net.ListenPacket("udp", ":"+strconv.Itoa(port))
	if err != nil {
		logger.Warningf("vpnclient: 端口转发：监听 udp :%d 失败: %v", port, err)
		return nil
	}
	l := &udpFwdListener{
		pc: pc, port: port, f: f,
		closing:  make(chan struct{}),
		sessions: map[netip.AddrPort]*udpFwdSession{},
	}
	logger.Infof("vpnclient: 端口转发：监听 udp :%d", port)
	go l.readLoop()
	go l.reapLoop()
	return l
}

func (l *udpFwdListener) readLoop() {
	buf := make([]byte, 65535)
	for {
		n, from, err := l.pc.ReadFrom(buf)
		if err != nil {
			return // closed
		}
		src, err := netip.ParseAddrPort(from.String())
		if err != nil {
			continue
		}
		sess := l.sessionFor(src)
		if sess == nil {
			continue
		}
		sess.lastUse.Store(time.Now().UnixNano())
		wn, err := sess.conn.Write(buf[:n])
		l.f.txBytes.Add(int64(wn))
		if err != nil {
			l.dropSession(src)
		}
	}
}

// sessionFor 按外网源地址取/建会话（net.ListenPacket 没有 accept 模型，
// 这里自己 demux——与 amneziawgnet/portfwd_udp.go 同一模式）。
func (l *udpFwdListener) sessionFor(src netip.AddrPort) *udpFwdSession {
	l.mu.Lock()
	if s, ok := l.sessions[src]; ok {
		l.mu.Unlock()
		return s
	}
	l.mu.Unlock()

	rule, ok := l.f.ruleFor(l.port)
	if !ok {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), fwdDialTimeout)
	defer cancel()
	target := net.JoinHostPort(rule.LanIP, strconv.Itoa(rule.LanPort))
	conn, err := l.f.dial(ctx, "udp", target)
	if err != nil {
		logger.Warningf("vpnclient: 端口转发：udp :%d -> %s 拨号失败: %v", l.port, target, err)
		return nil
	}
	s := &udpFwdSession{conn: conn}
	s.lastUse.Store(time.Now().UnixNano())
	l.mu.Lock()
	if old, ok := l.sessions[src]; ok {
		l.mu.Unlock()
		conn.Close()
		return old
	}
	l.sessions[src] = s
	l.mu.Unlock()
	go l.pumpUDP(s, src)
	return s
}

func (l *udpFwdListener) pumpUDP(s *udpFwdSession, src netip.AddrPort) {
	buf := make([]byte, 65535)
	for {
		_ = s.conn.SetReadDeadline(time.Now().Add(fwdUDPIdleTimeout))
		n, err := s.conn.Read(buf)
		if err != nil {
			l.dropSession(src)
			return
		}
		s.lastUse.Store(time.Now().UnixNano())
		l.f.rxBytes.Add(int64(n))
		if _, err := l.pc.WriteTo(buf[:n], net.UDPAddrFromAddrPort(src)); err != nil {
			l.dropSession(src)
			return
		}
	}
}

func (l *udpFwdListener) dropSession(src netip.AddrPort) {
	l.mu.Lock()
	if s, ok := l.sessions[src]; ok {
		s.conn.Close()
		delete(l.sessions, src)
	}
	l.mu.Unlock()
}

// reapLoop 定期回收空闲超时的 UDP 会话。
func (l *udpFwdListener) reapLoop() {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-l.closing:
			return
		case <-t.C:
			now := time.Now().UnixNano()
			l.mu.Lock()
			for src, s := range l.sessions {
				if now-s.lastUse.Load() > int64(fwdUDPIdleTimeout) {
					s.conn.Close()
					delete(l.sessions, src)
				}
			}
			l.mu.Unlock()
		}
	}
}
