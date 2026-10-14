//go:build linux

package vpnclient

import (
	"strings"
	"testing"

	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
)

func ovpnTestLink() model.RouterLink {
	return model.RouterLink{
		Id:         3,
		Name:       "PROSCEND",
		Protocol:   "openvpn",
		RemoteHost: "116.59.15.247",
		RemotePort: 51199,
		Proto:      "udp",
		LanSubnet:  "192.168.225.0/24",
	}
}

// TestBuildOpenVPNFilesGolden：password 认证的 golden 断言。
func TestBuildOpenVPNFilesGolden(t *testing.T) {
	dir := "/tmp/vpnclient-test/3"
	auth := routerAuth{Type: "password", Username: "user1", Password: "pw1"}
	f, err := buildOpenVPNFiles(ovpnTestLink(), auth, dir)
	if err != nil {
		t.Fatal(err)
	}
	cfg := f.config
	for _, want := range []string{
		"client",
		"dev tun",
		"proto udp",
		"remote 116.59.15.247 51199",
		"route-nopull",                          // 铁律
		`pull-filter ignore "redirect-gateway"`, // 双保险
		`pull-filter ignore "dhcp-option DNS"`,  // 不要对端 DNS
		"route 192.168.225.0 255.255.255.0 vpn_gateway",    // 只路由内网段
		"data-ciphers AES-256-GCM:AES-128-GCM:AES-256-CBC", // 2026-10-14 实测必需
		"persist-tun",
		"keepalive 10 60",
		"auth-user-pass " + dir + "/auth.txt",
		"management " + dir + "/mgmt.sock unix",
		"script-security 2",
		"up " + dir + "/up.sh",
	} {
		if !strings.Contains(cfg, want) {
			t.Errorf("client.ovpn 缺少 %q\n%s", want, cfg)
		}
	}
	// 设计文档 §5.1 的 `remap` 不是合法指令（实测 openvpn 2.6.19 无此指令），
	// 必须省略，否则 openvpn 启动失败。
	for _, line := range strings.Split(cfg, "\n") {
		if strings.TrimSpace(line) == "remap" {
			t.Errorf("client.ovpn 含非法指令 remap")
		}
	}
	if f.authTxt != "user1\npw1\n" {
		t.Errorf("auth.txt 内容不符: %q", f.authTxt)
	}
	if !strings.Contains(f.upScript, `echo "$dev"`) {
		t.Errorf("up.sh 应记录 $dev:\n%s", f.upScript)
	}
}

// TestBuildOpenVPNFilesCert：cert 认证内联 ca/cert/key，不写 auth-user-pass。
func TestBuildOpenVPNFilesCert(t *testing.T) {
	dir := "/tmp/vpnclient-test/5"
	auth := routerAuth{Type: "cert", CA: "CA-PEM", Cert: "CERT-PEM", Key: "KEY-PEM"}
	f, err := buildOpenVPNFiles(ovpnTestLink(), auth, dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"<ca>\nCA-PEM\n</ca>", "<cert>\nCERT-PEM\n</cert>", "<key>\nKEY-PEM\n</key>"} {
		if !strings.Contains(f.config, want) {
			t.Errorf("cert 内联块缺失 %q\n%s", want, f.config)
		}
	}
	if strings.Contains(f.config, "auth-user-pass") {
		t.Errorf("cert 认证不应写 auth-user-pass\n%s", f.config)
	}
	if f.authTxt != "" {
		t.Errorf("cert 认证不应生成 auth.txt 内容: %q", f.authTxt)
	}
}

// TestBuildOpenVPNFilesValidation：缺认证信息应报错（不在拨号时才暴露）。
func TestBuildOpenVPNFilesValidation(t *testing.T) {
	if _, err := buildOpenVPNFiles(ovpnTestLink(), routerAuth{Type: "password"}, "/tmp/x"); err == nil {
		t.Error("缺 username/password 应报错")
	}
	if _, err := buildOpenVPNFiles(ovpnTestLink(), routerAuth{Type: "cert", CA: "x"}, "/tmp/x"); err == nil {
		t.Error("cert 缺 cert/key 应报错")
	}
	bad := ovpnTestLink()
	bad.LanSubnet = "not-a-subnet"
	if _, err := buildOpenVPNFiles(bad, routerAuth{Type: "password", Username: "u", Password: "p"}, "/tmp/x"); err == nil {
		t.Error("非法 lanSubnet 应报错")
	}
}
