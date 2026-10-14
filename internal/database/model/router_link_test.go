package model

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/mhsanaei/3x-ui/v3/internal/crypto/nodetoken"
)

// enableTestCodec installs a ModeRequired nodetoken codec so the
// Encrypt/Decrypt round-trip below actually exercises AES-256-GCM,
// and restores ModeOff afterwards so tests cannot leak state.
func enableTestCodec(t *testing.T) {
	t.Helper()
	var k [32]byte
	for i := range k {
		k[i] = byte(0xA0 + i)
	}
	ring := &nodetoken.Keyring{ActiveID: "rltest", Keys: map[string][32]byte{"rltest": k}}
	codec, err := nodetoken.NewCodec(nodetoken.ModeRequired, ring)
	if err != nil {
		t.Fatalf("new codec: %v", err)
	}
	nodetoken.Init(codec)
	t.Cleanup(func() {
		off, _ := nodetoken.NewCodec(nodetoken.ModeOff, nil)
		nodetoken.Init(off)
	})
}

func sampleLinks() []*RouterLink {
	return []*RouterLink{
		{
			Name:           "深圳-主路由",
			Protocol:       "openvpn",
			RemoteHost:     "203.0.113.44",
			RemotePort:     51194,
			Proto:          "udp",
			LanSubnet:      "192.168.225.0/24",
			ForwardedPorts: "8080->192.168.225.10:80, 8443->192.168.225.10:443",
			Enable:         true,
		},
		{
			Name:           "备用-pptp",
			Protocol:       "pptp",
			RemoteHost:     "198.51.100.7",
			RemotePort:     1723,
			LanSubnet:      "192.168.10.0/24",
			Mppe:           "require-mppe-128",
			ForwardedPorts: "3389->192.168.10.5:3389",
			Enable:         true,
		},
		{
			Name:                "wg-移动",
			Protocol:            "wireguard",
			RemoteHost:          "192.0.2.9",
			RemotePort:          51820,
			LanSubnet:           "10.9.0.0/24",
			TunnelAddress:       "10.9.0.2/24",
			PersistentKeepalive: 25,
			ForwardedPorts:      "22->10.9.0.3:22",
			Enable:              false,
		},
	}
}

func TestRouterLinkTableName(t *testing.T) {
	var l RouterLink
	if got := l.TableName(); got != "router_links" {
		t.Fatalf("TableName() = %q, want %q", got, "router_links")
	}
}

func TestRouterLinkJSONOmitsAuthPlaintext(t *testing.T) {
	for _, l := range sampleLinks() {
		// 模拟已加密入库的值：即使 AuthJSON 非空，序列化也必须不可见。
		l.AuthJSON = "enc:v1:rltest:supersecretciphertext"
		raw, err := json.Marshal(l)
		if err != nil {
			t.Fatalf("marshal %s: %v", l.Name, err)
		}
		// 注意：encoding/json 默认把 `>` 转义成 \u003e，这里先反序列化再断言。
		var m map[string]any
		if err := json.Unmarshal(raw, &m); err != nil {
			t.Fatalf("unmarshal %s: %v", l.Name, err)
		}
		for _, k := range []string{"auth", "AuthJSON", "authJSON"} {
			if _, ok := m[k]; ok {
				t.Fatalf("protocol %s: JSON leaks auth key %q: %s", l.Protocol, k, raw)
			}
		}
		if strings.Contains(string(raw), "supersecretciphertext") {
			t.Fatalf("protocol %s: JSON leaks auth ciphertext: %s", l.Protocol, raw)
		}
		// 正字段仍在且值正确：name / protocol / remoteHost / lanSubnet / forwardedPorts。
		want := map[string]string{
			"name":           l.Name,
			"protocol":       l.Protocol,
			"remoteHost":     l.RemoteHost,
			"lanSubnet":      l.LanSubnet,
			"forwardedPorts": l.ForwardedPorts,
		}
		for k, v := range want {
			if got, _ := m[k].(string); got != v {
				t.Fatalf("protocol %s: JSON[%q] = %q, want %q", l.Protocol, k, got, v)
			}
		}
	}
}

func TestRouterLinkAuthRoundTrip(t *testing.T) {
	enableTestCodec(t)
	plains := map[string]string{
		"openvpn":   `{"type":"password","username":"vpnuser","password":"s3cret"}`,
		"pptp":      `{"type":"password","username":"pptpuser","password":"p@ss"}`,
		"wireguard": `{"type":"psk","privateKey":"AAA=","peerPublicKey":"BBB=","presharedKey":"CCC="}`,
	}
	for _, l := range sampleLinks() {
		plain := plains[l.Protocol]
		enc, err := EncryptRouterLinkAuth(plain)
		if err != nil {
			t.Fatalf("protocol %s: encrypt: %v", l.Protocol, err)
		}
		if !nodetoken.IsEncrypted(enc) {
			t.Fatalf("protocol %s: encrypted value = %q, want enc: ciphertext", l.Protocol, enc)
		}
		if strings.Contains(enc, "s3cret") || strings.Contains(enc, "p@ss") {
			t.Fatalf("protocol %s: ciphertext contains plaintext", l.Protocol)
		}
		got, err := DecryptRouterLinkAuth(enc)
		if err != nil {
			t.Fatalf("protocol %s: decrypt: %v", l.Protocol, err)
		}
		if got != plain {
			t.Fatalf("protocol %s: round-trip = %q, want %q", l.Protocol, got, plain)
		}
	}
}

func TestRouterLinkAuthEmptyPassthrough(t *testing.T) {
	enableTestCodec(t)
	if got, err := EncryptRouterLinkAuth(""); err != nil || got != "" {
		t.Fatalf("encrypt empty = %q, %v; want empty passthrough", got, err)
	}
	if got, err := DecryptRouterLinkAuth(""); err != nil || got != "" {
		t.Fatalf("decrypt empty = %q, %v; want empty passthrough", got, err)
	}
}
