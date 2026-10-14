//go:build linux

package vpnclient

import (
	"context"
	"fmt"
	"io"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestParseForwardedPorts(t *testing.T) {
	got, err := ParseForwardedPorts("8080->192.168.225.10:80, 8443->192.168.225.10:443")
	if err != nil {
		t.Fatalf("正常输入不应报错: %v", err)
	}
	want := []ForwardedPort{
		{PubPort: 8080, LanIP: "192.168.225.10", LanPort: 80},
		{PubPort: 8443, LanIP: "192.168.225.10", LanPort: 443},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("解析结果不符:\n got=%+v\nwant=%+v", got, want)
	}
}

func TestParseForwardedPortsWhitespace(t *testing.T) {
	// 空白容忍：多余空格、空 token 都应跳过。
	got, err := ParseForwardedPorts("  8080  ->  192.168.225.10:80 ,,  8443->192.168.225.10:443  ,")
	if err != nil {
		t.Fatalf("空白输入不应报错: %v", err)
	}
	if len(got) != 2 || got[0].PubPort != 8080 || got[1].PubPort != 8443 {
		t.Fatalf("空白容忍解析失败: %+v", got)
	}
	// lanPort 与 pubPort 不同是合法的（扩展语法的核心）。
	if got[0].LanPort != 80 {
		t.Fatalf("lanPort 应保留 80，实际 %+v", got[0])
	}
}

func TestParseForwardedPortsEmpty(t *testing.T) {
	for _, in := range []string{"", "   ", ", ,"} {
		got, err := ParseForwardedPorts(in)
		if err != nil {
			t.Fatalf("空输入 %q 不应报错: %v", in, err)
		}
		if len(got) != 0 {
			t.Fatalf("空输入 %q 应得空规则，实际 %+v", in, got)
		}
	}
}

func TestParseForwardedPortsInvalid(t *testing.T) {
	cases := []string{
		"8080",                     // 缺少 ->
		"8080->192.168.225.10",     // 缺少内网端口
		"abc->192.168.225.10:80",   // 公网端口非数字
		"0->192.168.225.10:80",     // 端口越界
		"70000->192.168.225.10:80", // 端口越界
		"8080->999.1.1.1:80",       // 非法 IP
		"8080->192.168.225.10:0",   // 内网端口越界
		"8080->192.168.225.10:80,8080->192.168.225.10:81", // 公网端口重复
		"->192.168.225.10:80",                             // 缺公网端口
		"8080->:80",                                       // 缺内网 IP
	}
	for _, in := range cases {
		if _, err := ParseForwardedPorts(in); err == nil {
			t.Errorf("非法输入 %q 应报错，实际通过", in)
		}
	}
}

// TestForwarderTCPRelay 用回环 dial 做端到端转发验证（不拨真实 VPN、不起子进程）。
func TestForwarderTCPRelay(t *testing.T) {
	// 内网假服务：回声。
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
	echoAddr := echo.Addr().String()

	fw := NewForwarder(loopbackDial)
	defer fw.Close()
	// 找一个空闲公网端口。
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	pubPort := probe.Addr().(*net.TCPAddr).Port
	probe.Close()

	host, portStr, _ := net.SplitHostPort(echoAddr)
	fw.Reconcile([]ForwardedPort{{PubPort: pubPort, LanIP: host, LanPort: mustAtoi(portStr)}})
	time.Sleep(200 * time.Millisecond) // 等监听就绪

	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", pubPort), 3*time.Second)
	if err != nil {
		t.Fatalf("连公网监听端口失败: %v", err)
	}
	msg := "hello-vpnclient"
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte(msg)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("回声读取失败: %v", err)
	}
	conn.Close()
	if string(buf) != msg {
		t.Fatalf("回声内容不符: %q", buf)
	}
	rx, tx := fw.Stats()
	if rx == 0 || tx == 0 {
		t.Fatalf("字节统计应非零: rx=%d tx=%d", rx, tx)
	}

	// 对账移除：监听应关闭。
	fw.Reconcile(nil)
	time.Sleep(200 * time.Millisecond)
	if _, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", pubPort), time.Second); err == nil {
		t.Fatal("Reconcile(nil) 后端口仍可连接，监听未关闭")
	}
}

// loopbackDial 是测试用 DialFunc：直接连回环（模拟"已在隧道内"）。
func loopbackDial(ctx context.Context, network, address string) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, network, address)
}

func mustAtoi(s string) int {
	var n int
	fmt.Sscanf(strings.TrimSpace(s), "%d", &n)
	return n
}
