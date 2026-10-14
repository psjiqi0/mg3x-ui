//go:build linux

package vpnclient

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
	"github.com/mhsanaei/3x-ui/v3/internal/logger"
)

// 经隧道出公网 egress（验收标准）：该连接独占的 SOCKS5 server，
// Xray 把 VLESS 入站流量经它送进隧道，从路由器公网口出去
// （出口 IP 变为路由器公网 IP，如 116.59.15.247）。
//
// 要点：
//   - 监听 127.0.0.1（不暴露到公网）；端口独占 per-连接；
//   - dial 目标：WG 走该连接独占 gVisor stack；ovpn/pptp 走 bindDeviceDialFunc
//     （SO_BINDTODEVICE 钉在**当前** tunX/pppX）；
//   - 每次 dial 都从 handle 实时解析（不缓存）：隧道重拨导致 wgDev/iface 变化时
//     自动跟随；tunnel down 时 dial 直接失败（fail-closed，绝不经默认路由外发）；
//   - tunnel down 时 SOCKS 监听本身保持（Xray 侧路由切换防黑洞，不归本包管）。

const (
	egressPortMin = 22000
	egressPortMax = 22999
)

// egressServer 是一个连接独占的 SOCKS5 server。
type egressServer struct {
	mgr     *Manager
	linkID  int
	ln      net.Listener
	port    int
	closing chan struct{}
	once    sync.Once

	rxBytes atomic.Int64
	txBytes atomic.Int64

	// dialOverride 供单测注入；为 nil 时走 mgr.egressDial(linkID) 实时解析。
	dialOverride func() (DialFunc, error)
}

func (s *egressServer) close() {
	s.once.Do(func() {
		close(s.closing)
		s.ln.Close()
	})
}

func (s *egressServer) resolveDial() (DialFunc, error) {
	if s.dialOverride != nil {
		return s.dialOverride()
	}
	return s.mgr.egressDial(s.linkID)
}

func (s *egressServer) serve() {
	for {
		c, err := s.ln.Accept()
		if err != nil {
			select {
			case <-s.closing:
			default:
				logger.Warningf("vpnclient: egress %d: accept: %v", s.linkID, err)
			}
			return
		}
		go s.serveConn(c)
	}
}

// ---- Manager 方法（冻结契约，D2 组直接依赖，签名不许改） ----

// EnsureEgress 在 127.0.0.1 上分配该连接独占的 SOCKS5 端口并启动，返回端口。
// 已在运行则直接返回现有端口（幂等）。隧道是否 up 不影响监听本身。
func (m *Manager) EnsureEgress(link model.RouterLink) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.ensureEgressLocked(link)
}

// RemoveEgress 停止该连接的 SOCKS server（幂等）。
func (m *Manager) RemoveEgress(id int) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.removeEgressLocked(id)
	return nil
}

func (m *Manager) ensureEgressLocked(link model.RouterLink) (int, error) {
	h := m.getOrCreateHandle(link.Id)
	h.link = link
	if h.egress != nil {
		return h.egress.port, nil
	}
	port, ln, err := m.allocEgressListenerLocked(link.Id, link.EgressSocksPort)
	if err != nil {
		return 0, err
	}
	srv := &egressServer{
		mgr:     m,
		linkID:  link.Id,
		ln:      ln,
		port:    port,
		closing: make(chan struct{}),
	}
	h.egress = srv
	go srv.serve()
	logger.Infof("vpnclient: 连接 %d egress SOCKS5 已监听 127.0.0.1:%d", link.Id, port)
	return port, nil
}

func (m *Manager) removeEgressLocked(id int) {
	h := m.links[id]
	if h == nil || h.egress == nil {
		return
	}
	h.egress.close()
	h.egress = nil
	logger.Infof("vpnclient: 连接 %d egress SOCKS5 已停止", id)
}

// syncEgressLocked 按 link.Enable && link.Egress 自动启停 SOCKS（独立于隧道拨号结果）。
func (m *Manager) syncEgressLocked(link model.RouterLink) {
	if link.Enable && link.Egress {
		if _, err := m.ensureEgressLocked(link); err != nil {
			logger.Warningf("vpnclient: 连接 %d egress SOCKS 启动失败: %v", link.Id, err)
		}
		return
	}
	m.removeEgressLocked(link.Id)
}

// allocEgressListenerLocked 分配独占端口并直接返回已 bind 的 listener
// （避免"探测后关闭再 bind"的 TOCTOU）。优先 link.EgressSocksPort
// （DB 持久化的值，能 bind 则用），否则在 [22000,22999] 找空闲，
// 并避开本 Manager 已分配的端口。
func (m *Manager) allocEgressListenerLocked(id, preferred int) (int, net.Listener, error) {
	tryBind := func(p int) net.Listener {
		ln, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(p))
		if err != nil {
			return nil
		}
		return ln
	}
	if preferred >= egressPortMin && preferred <= egressPortMax && !m.egressPortInUseLocked(preferred, id) {
		if ln := tryBind(preferred); ln != nil {
			return preferred, ln, nil
		}
		logger.Warningf("vpnclient: 连接 %d 期望的 egress 端口 %d 被占用，重新分配", id, preferred)
	}
	for p := egressPortMin; p <= egressPortMax; p++ {
		if m.egressPortInUseLocked(p, id) {
			continue
		}
		if ln := tryBind(p); ln != nil {
			return p, ln, nil
		}
	}
	return 0, nil, fmt.Errorf("egress: %d-%d 无可用端口", egressPortMin, egressPortMax)
}

func (m *Manager) egressPortInUseLocked(port, exceptID int) bool {
	for id, h := range m.links {
		if id == exceptID {
			continue
		}
		if h.egress != nil && h.egress.port == port {
			return true
		}
	}
	return false
}

// egressDial 实时解析该连接当前的 dial 函数（每次调用都重新解析，不缓存）。
// tunnel down 时返回 error（fail-closed：绝不经默认路由把本该进隧道的流量外发）。
func (m *Manager) egressDial(id int) (DialFunc, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	h := m.links[id]
	if h == nil {
		return nil, fmt.Errorf("egress: 未知的连接 id=%d", id)
	}
	switch h.link.Protocol {
	case "wireguard":
		if h.wgDev == nil {
			return nil, errors.New("egress: wireguard 隧道未建立")
		}
		return wgStackDialFunc(h.wgDev), nil
	case "openvpn", "pptp":
		iface, _ := h.bindIface.Load().(string)
		if iface == "" {
			return nil, errors.New("egress: 隧道接口未知（tunnel down），拒绝外发")
		}
		// bindDeviceDialFunc 的闭包每次 dial 都从 atomic 实时读 iface，
		// 隧道重拨改名后自动跟随（见 openvpn.go 注释）。
		return bindDeviceDialFunc(&h.bindIface), nil
	default:
		return nil, fmt.Errorf("egress: 未知协议 %q", h.link.Protocol)
	}
}

// ---- SOCKS5 协议（RFC 1928 最小可用子集：无认证握手 + CONNECT + UDP ASSOCIATE） ----

const (
	socksVer             = 0x05
	socksCmdConnect      = 0x01
	socksCmdUDPAssociate = 0x03
)

func (s *egressServer) serveConn(c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(30 * time.Second)) // 握手阶段超时

	// 握手：VER NMETHODS METHODS... -> VER METHOD(0x00=无认证)
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(c, hdr); err != nil || hdr[0] != socksVer {
		return
	}
	methods := make([]byte, hdr[1])
	if _, err := io.ReadFull(c, methods); err != nil {
		return
	}
	if _, err := c.Write([]byte{socksVer, 0x00}); err != nil {
		return
	}

	// 请求：VER CMD RSV ATYP DST.ADDR DST.PORT
	req := make([]byte, 4)
	if _, err := io.ReadFull(c, req); err != nil || req[0] != socksVer {
		return
	}
	target, err := readSocksAddr(c, req[3])
	if err != nil {
		return
	}
	switch req[1] {
	case socksCmdConnect:
		s.serveConnect(c, target)
	case socksCmdUDPAssociate:
		s.serveUDPAssociate(c)
	default:
		writeSocksReply(c, 0x07, "0.0.0.0", 0) // command not supported
	}
}

// readSocksAddr 按 ATYP 从连接读地址（含端口），返回 "host:port"。
func readSocksAddr(c net.Conn, atyp byte) (string, error) {
	var host string
	switch atyp {
	case 0x01: // IPv4
		b := make([]byte, 4)
		if _, err := io.ReadFull(c, b); err != nil {
			return "", err
		}
		host = net.IP(b).String()
	case 0x04: // IPv6
		b := make([]byte, 16)
		if _, err := io.ReadFull(c, b); err != nil {
			return "", err
		}
		host = net.IP(b).String()
	case 0x03: // domain
		lb := make([]byte, 1)
		if _, err := io.ReadFull(c, lb); err != nil {
			return "", err
		}
		b := make([]byte, lb[0])
		if _, err := io.ReadFull(c, b); err != nil {
			return "", err
		}
		host = string(b)
	default:
		return "", fmt.Errorf("不支持的 ATYP %d", atyp)
	}
	pb := make([]byte, 2)
	if _, err := io.ReadFull(c, pb); err != nil {
		return "", err
	}
	return net.JoinHostPort(host, strconv.Itoa(int(pb[0])<<8|int(pb[1]))), nil
}

func writeSocksReply(c net.Conn, rep byte, host string, port int) {
	var atyp byte
	var addr []byte
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			atyp, addr = 0x01, ip4
		} else {
			atyp, addr = 0x04, ip.To16()
		}
	} else {
		atyp = 0x03
		addr = append([]byte{byte(len(host))}, host...)
	}
	buf := []byte{socksVer, rep, 0x00, atyp}
	buf = append(buf, addr...)
	buf = append(buf, byte(port>>8), byte(port))
	_, _ = c.Write(buf)
}

func (s *egressServer) serveConnect(c net.Conn, target string) {
	dial, err := s.resolveDial()
	if err != nil {
		logger.Warningf("vpnclient: egress %d: CONNECT %s 被拒绝: %v", s.linkID, target, err)
		writeSocksReply(c, 0x05, "0.0.0.0", 0) // connection refused
		return
	}
	target, err = resolveEgressTarget(target)
	if err != nil {
		writeSocksReply(c, 0x04, "0.0.0.0", 0) // host unreachable
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), fwdDialTimeout)
	defer cancel()
	up, err := dial(ctx, "tcp", target)
	if err != nil {
		logger.Warningf("vpnclient: egress %d: CONNECT %s 拨号失败: %v", s.linkID, target, err)
		writeSocksReply(c, 0x05, "0.0.0.0", 0)
		return
	}
	_ = c.SetDeadline(time.Time{}) // 握手结束，清除超时（转发阶段由 copy 驱动）
	writeSocksReply(c, 0x00, "0.0.0.0", 0)
	relayBidirectional(c, up, &s.rxBytes, &s.txBytes)
}

// resolveEgressTarget 把域名在宿主侧解析成 IP（dial 进隧道需要纯 IP，
// 尤其 gVisor stack 内无 DNS）。注意：这会经过宿主 DNS，不适合强匿名场景；
// 本需求是"经隧道出公网"的中转，可接受。
func resolveEgressTarget(target string) (string, error) {
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		return "", err
	}
	if net.ParseIP(host) != nil {
		return target, nil
	}
	ips, err := net.DefaultResolver.LookupIPAddr(context.Background(), host)
	if err != nil || len(ips) == 0 {
		return "", fmt.Errorf("域名解析失败 %q: %w", host, err)
	}
	for _, ip := range ips {
		if ip.IP.To4() != nil {
			return net.JoinHostPort(ip.String(), port), nil
		}
	}
	return net.JoinHostPort(ips[0].String(), port), nil
}

// ---- UDP ASSOCIATE ----

type udpEgressSession struct {
	conn    net.Conn // 已 connected 到目标
	client  net.Addr // 该会话的外网源地址
	lastUse atomic.Int64
}

type udpEgressRelay struct {
	srv     *egressServer
	pc      net.PacketConn
	closing chan struct{}
	once    sync.Once

	mu       sync.Mutex
	sessions map[string]*udpEgressSession // key: target "host:port"
}

func (s *egressServer) serveUDPAssociate(c net.Conn) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		writeSocksReply(c, 0x01, "0.0.0.0", 0)
		return
	}
	ra := pc.LocalAddr().(*net.UDPAddr)
	writeSocksReply(c, 0x00, ra.IP.String(), ra.Port)
	_ = c.SetDeadline(time.Time{}) // ASSOCIATE 存续期 = TCP 连接存续期
	r := &udpEgressRelay{
		srv:      s,
		pc:       pc,
		closing:  make(chan struct{}),
		sessions: map[string]*udpEgressSession{},
	}
	go r.readLoop()
	go r.reapLoop()
	// 保持 TCP 连接：客户端关闭即结束本次 ASSOCIATE。
	buf := make([]byte, 1)
	for {
		if _, err := c.Read(buf); err != nil {
			break
		}
	}
	r.close()
}

func (r *udpEgressRelay) close() {
	r.once.Do(func() {
		close(r.closing)
		r.pc.Close()
		r.mu.Lock()
		for _, s := range r.sessions {
			s.conn.Close()
		}
		r.sessions = map[string]*udpEgressSession{}
		r.mu.Unlock()
	})
}

func (r *udpEgressRelay) readLoop() {
	buf := make([]byte, 65535)
	for {
		n, from, err := r.pc.ReadFrom(buf)
		if err != nil {
			return // closed
		}
		target, data, ok := parseSocksUDPHeader(buf[:n])
		if !ok {
			continue
		}
		sess := r.sessionFor(target, from)
		if sess == nil {
			continue
		}
		sess.lastUse.Store(time.Now().UnixNano())
		if _, err := sess.conn.Write(data); err != nil {
			r.dropSession(target)
		}
	}
}

func (r *udpEgressRelay) sessionFor(target string, from net.Addr) *udpEgressSession {
	r.mu.Lock()
	if s, ok := r.sessions[target]; ok {
		r.mu.Unlock()
		return s
	}
	r.mu.Unlock()

	dial, err := r.srv.resolveDial()
	if err != nil {
		logger.Warningf("vpnclient: egress %d: UDP %s 被拒绝: %v", r.srv.linkID, target, err)
		return nil
	}
	dst, err := resolveEgressTarget(target)
	if err != nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), fwdDialTimeout)
	defer cancel()
	conn, err := dial(ctx, "udp", dst)
	if err != nil {
		logger.Warningf("vpnclient: egress %d: UDP %s 拨号失败: %v", r.srv.linkID, dst, err)
		return nil
	}
	s := &udpEgressSession{conn: conn, client: from}
	s.lastUse.Store(time.Now().UnixNano())
	r.mu.Lock()
	if old, ok := r.sessions[target]; ok {
		r.mu.Unlock()
		conn.Close()
		return old
	}
	r.sessions[target] = s
	r.mu.Unlock()
	go r.pumpUDP(s, target)
	return s
}

func (r *udpEgressRelay) pumpUDP(s *udpEgressSession, target string) {
	buf := make([]byte, 65535)
	for {
		_ = s.conn.SetReadDeadline(time.Now().Add(fwdUDPIdleTimeout))
		n, err := s.conn.Read(buf)
		if err != nil {
			r.dropSession(target)
			return
		}
		s.lastUse.Store(time.Now().UnixNano())
		pkt := append(buildSocksUDPHeader(target), buf[:n]...)
		if _, err := r.pc.WriteTo(pkt, s.client); err != nil {
			r.dropSession(target)
			return
		}
	}
}

func (r *udpEgressRelay) dropSession(target string) {
	r.mu.Lock()
	if s, ok := r.sessions[target]; ok {
		s.conn.Close()
		delete(r.sessions, target)
	}
	r.mu.Unlock()
}

func (r *udpEgressRelay) reapLoop() {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-r.closing:
			return
		case <-t.C:
			now := time.Now().UnixNano()
			r.mu.Lock()
			for target, s := range r.sessions {
				if now-s.lastUse.Load() > int64(fwdUDPIdleTimeout) {
					s.conn.Close()
					delete(r.sessions, target)
				}
			}
			r.mu.Unlock()
		}
	}
}

// parseSocksUDPHeader 解析 SOCKS5 UDP 头：
// +----+------+------+----------+----------+----------+
// |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
// FRAG != 0（分片）不支持，直接丢弃。
func parseSocksUDPHeader(b []byte) (target string, data []byte, ok bool) {
	if len(b) < 4 || b[0] != 0x00 || b[1] != 0x00 || b[2] != 0x00 {
		return "", nil, false
	}
	rest := b[4:]
	var host string
	switch b[3] {
	case 0x01:
		if len(rest) < 6 {
			return "", nil, false
		}
		host, rest = net.IP(rest[:4]).String(), rest[4:]
	case 0x04:
		if len(rest) < 18 {
			return "", nil, false
		}
		host, rest = net.IP(rest[:16]).String(), rest[16:]
	case 0x03:
		if len(rest) < 1 || len(rest) < int(rest[0])+3 {
			return "", nil, false
		}
		host, rest = string(rest[1:1+rest[0]]), rest[1+rest[0]:]
	default:
		return "", nil, false
	}
	port := int(rest[0])<<8 | int(rest[1])
	return net.JoinHostPort(host, strconv.Itoa(port)), rest[2:], true
}

// buildSocksUDPHeader 为回包构造 SOCKS5 UDP 头（FRAG=0）。
func buildSocksUDPHeader(target string) []byte {
	host, portStr, err := net.SplitHostPort(target)
	port := 0
	if err == nil {
		port, _ = strconv.Atoi(portStr)
	}
	var atyp byte
	var addr []byte
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			atyp, addr = 0x01, ip4
		} else {
			atyp, addr = 0x04, ip.To16()
		}
	} else {
		atyp = 0x03
		addr = append([]byte{byte(len(host))}, host...)
	}
	hdr := []byte{0x00, 0x00, 0x00, atyp}
	hdr = append(hdr, addr...)
	return append(hdr, byte(port>>8), byte(port))
}
