//go:build linux

package vpnclient

import (
	"fmt"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
)

// newTestEgressServer 建一个 dial 走回环的 egress server（不真实拨号）。
func newTestEgressServer(t *testing.T) (*egressServer, int) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &egressServer{
		mgr:     NewManager(t.TempDir()),
		linkID:  1,
		ln:      ln,
		port:    ln.Addr().(*net.TCPAddr).Port,
		closing: make(chan struct{}),
		dialOverride: func() (DialFunc, error) {
			return loopbackDial, nil
		},
	}
	go srv.serve()
	t.Cleanup(srv.close)
	return srv, srv.port
}

// socksHandshake 做无认证握手，返回已就绪的连接。
func socksHandshake(t *testing.T, port int) net.Conn {
	t.Helper()
	c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatal(err)
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(c, resp); err != nil {
		t.Fatal(err)
	}
	if resp[0] != 0x05 || resp[1] != 0x00 {
		t.Fatalf("握手应答错误: %v", resp)
	}
	return c
}

// socksConnectReq 构造 CONNECT 请求（IPv4）。
func socksConnectReq(host string, port int) []byte {
	ip := net.ParseIP(host).To4()
	pb := []byte{0x05, 0x01, 0x00, 0x01}
	pb = append(pb, ip...)
	return append(pb, byte(port>>8), byte(port))
}

// TestEgressSocksConnect：握手 + CONNECT + TCP 回声（本地回环）。
func TestEgressSocksConnect(t *testing.T) {
	// 假目标：TCP 回声。
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		for {
			c, err := echo.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}()
		}
	}()

	_, socksPort := newTestEgressServer(t)
	c := socksHandshake(t, socksPort)
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))

	host, portStr, _ := net.SplitHostPort(echo.Addr().String())
	tport, _ := strconv.Atoi(portStr)
	if _, err := c.Write(socksConnectReq(host, tport)); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 10) // VER REP RSV ATYP(IPv4) BND.ADDR(4) BND.PORT(2)
	if _, err := io.ReadFull(c, reply); err != nil {
		t.Fatal(err)
	}
	if reply[0] != 0x05 || reply[1] != 0x00 {
		t.Fatalf("CONNECT 应答错误: %v", reply)
	}
	msg := "egress-connect-ok"
	if _, err := c.Write([]byte(msg)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatalf("回声读取失败: %v", err)
	}
	if string(buf) != msg {
		t.Fatalf("回声内容不符: %q", buf)
	}
}

// TestEgressSocksUDPAssociate：UDP ASSOCIATE + 带 SOCKS 头的回声（本地回环）。
func TestEgressSocksUDPAssociate(t *testing.T) {
	// 假目标：UDP 回声。
	uecho, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer uecho.Close()
	go func() {
		buf := make([]byte, 65535)
		for {
			n, from, err := uecho.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = uecho.WriteTo(buf[:n], from)
		}
	}()

	_, socksPort := newTestEgressServer(t)
	c := socksHandshake(t, socksPort)
	defer c.Close()
	c.SetDeadline(time.Now().Add(10 * time.Second))

	// UDP ASSOCIATE 请求（DST 填 0.0.0.0:0）。
	if _, err := c.Write([]byte{0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 10)
	if _, err := io.ReadFull(c, reply); err != nil {
		t.Fatal(err)
	}
	if reply[0] != 0x05 || reply[1] != 0x00 {
		t.Fatalf("ASSOCIATE 应答错误: %v", reply)
	}
	relay := fmt.Sprintf("127.0.0.1:%d", int(reply[8])<<8|int(reply[9]))

	// 发一包带 SOCKS 头的数据。
	uc, err := net.Dial("udp", relay)
	if err != nil {
		t.Fatal(err)
	}
	defer uc.Close()
	uc.SetDeadline(time.Now().Add(5 * time.Second))
	echoAddr := uecho.LocalAddr().String()
	payload := []byte("egress-udp-ok")
	pkt := append(buildSocksUDPHeader(echoAddr), payload...)
	var got []byte
	for i := 0; i < 10; i++ {
		if _, err := uc.Write(pkt); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 65535)
		n, err := uc.Read(buf)
		if err != nil {
			continue // 会话建立有延迟，重试
		}
		_, data, ok := parseSocksUDPHeader(buf[:n])
		if !ok {
			t.Fatalf("回包 SOCKS 头解析失败")
		}
		got = data
		break
	}
	if string(got) != string(payload) {
		t.Fatalf("UDP 回声不符: %q", got)
	}
}

// TestAllocEgressPortSkipsTaken：占住一个端口再分配，断言跳过；
// 空闲的 preferred 应被复用；本 Manager 已分配的端口应避开。
func TestAllocEgressPortSkipsTaken(t *testing.T) {
	m := NewManager(t.TempDir())

	occ, err := net.Listen("tcp", "127.0.0.1:22000")
	if err != nil {
		t.Skipf("22000 已被外部占用，跳过: %v", err)
	}
	defer occ.Close()

	m.mu.Lock()
	defer m.mu.Unlock()

	port, ln, err := m.allocEgressListenerLocked(1, 22000)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	if port == 22000 {
		t.Fatal("应跳过被占用的 22000")
	}
	if port < egressPortMin || port > egressPortMax {
		t.Fatalf("分配端口越界: %d", port)
	}

	port2, ln2, err := m.allocEgressListenerLocked(2, 22005)
	if err != nil {
		t.Fatal(err)
	}
	defer ln2.Close()
	if port2 != 22005 {
		t.Fatalf("空闲的 preferred 22005 应被复用，实际 %d", port2)
	}

	// 模拟本 Manager 已给另一个连接分配了 22006。
	m.links[9] = &linkHandle{id: 9, egress: &egressServer{port: 22006}}
	port3, ln3, err := m.allocEgressListenerLocked(3, 22006)
	if err != nil {
		t.Fatal(err)
	}
	defer ln3.Close()
	if port3 == 22006 {
		t.Fatal("应避开本 Manager 已分配的 22006")
	}
}

// TestEnsureRemoveEgressLifecycle：EnsureEgress 幂等、RemoveEgress 停止、
// Status 上报端口。
func TestEnsureRemoveEgressLifecycle(t *testing.T) {
	m := NewManager(t.TempDir())
	link := newEgressTestLink()

	p1, err := m.EnsureEgress(link)
	if err != nil {
		t.Fatal(err)
	}
	p2, err := m.EnsureEgress(link)
	if err != nil {
		t.Fatal(err)
	}
	if p1 != p2 {
		t.Fatalf("EnsureEgress 应幂等: %d != %d", p1, p2)
	}
	if st := m.Status(link.Id); st.EgressSocksPort != p1 {
		t.Fatalf("Status 应上报 egress 端口: %+v", st)
	}
	// 端口确实在监听。
	if _, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", p1), 2*time.Second); err != nil {
		t.Fatalf("egress 端口应可连接: %v", err)
	}
	if err := m.RemoveEgress(link.Id); err != nil {
		t.Fatal(err)
	}
	if st := m.Status(link.Id); st.EgressSocksPort != 0 {
		t.Fatalf("RemoveEgress 后端口应清零: %+v", st)
	}
	time.Sleep(200 * time.Millisecond)
	if _, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", p1), time.Second); err == nil {
		t.Fatal("RemoveEgress 后端口仍可连接")
	}
	// 再次 Remove 幂等。
	if err := m.RemoveEgress(link.Id); err != nil {
		t.Fatal(err)
	}
}

// newEgressTestLink 构造 egress 测试用连接。
// 注意：Egress/EgressSocksPort 字段由 D2 组并行加入 model.RouterLink，
// 此处直接引用（终验统一编译）。
func newEgressTestLink() model.RouterLink {
	return model.RouterLink{
		Id:         42,
		Name:       "egress-test",
		Protocol:   "wireguard",
		RemoteHost: "192.0.2.1",
		RemotePort: 51820,
		LanSubnet:  "192.168.99.0/24",
		Egress:     true,
		Enable:     true,
	}
}
