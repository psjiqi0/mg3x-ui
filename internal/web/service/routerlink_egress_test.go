package service

// RouterLink egress（经隧道出公网）的单测（D 组）：
// inboundTags 存取 round-trip、Xray 注入纯函数 buildEgressOutbounds 的
// outbound/rule 生成。均为纯函数测试，不依赖 DB 与 vpnclient Manager。

import (
	"encoding/json"
	"testing"
)

func TestEgressInboundTagsRoundTrip(t *testing.T) {
	cases := [][]string{
		nil,
		{},
		{"vless-8443"},
		{"vless-8443", "in-443-tcp", "  trojan-99  "},
	}
	for _, in := range cases {
		raw := marshalEgressInboundTags(in)
		// 存库形状必须是 JSON 数组字符串
		var decoded []string
		if err := json.Unmarshal([]byte(raw), &decoded); err != nil {
			t.Fatalf("marshal %v produced invalid JSON %q: %v", in, raw, err)
		}
		got := parseEgressInboundTags(raw)
		// 空格归一化后应一致
		want := marshalEgressInboundTags(got)
		if marshalEgressInboundTags(decoded) != want {
			t.Fatalf("round-trip mismatch: in=%v raw=%q got=%v", in, raw, got)
		}
	}
	// 空字符串 / 非法 JSON → 空列表（调用方按"未选"处理，不炸）
	if got := parseEgressInboundTags(""); len(got) != 0 {
		t.Fatalf("empty string should parse to empty, got %v", got)
	}
	if got := parseEgressInboundTags("not-json"); len(got) != 0 {
		t.Fatalf("invalid JSON should parse to empty, got %v", got)
	}
}

func TestRouterLinkEgressOutboundTag(t *testing.T) {
	if got := RouterLinkEgressOutboundTag(7); got != "egress-7" {
		t.Fatalf("unexpected tag: %q", got)
	}
}

func TestBuildEgressOutbounds(t *testing.T) {
	links := []EgressLinkView{
		{Id: 3, EgressSocksPort: 52103, InboundTags: []string{"vless-8443", "in-443-tcp"}},
		{Id: 4, EgressSocksPort: 0, InboundTags: []string{"vless-8443"}},    // 端口无效 → 跳过（防黑洞）
		{Id: 5, EgressSocksPort: 52104, InboundTags: nil},                   // 未选入站 → 跳过
		{Id: 6, EgressSocksPort: 52105, InboundTags: []string{"trojan-99"}}, // 正常
	}
	outbounds, rules := buildEgressOutbounds(links)
	if len(outbounds) != 2 || len(rules) != 2 {
		t.Fatalf("expected 2 outbounds + 2 rules (links 3 and 6), got %d/%d", len(outbounds), len(rules))
	}

	// outbound 形状：{"protocol":"socks","tag":"egress-3",
	//  "settings":{"servers":[{"address":"127.0.0.1","port":52103}]}}
	ob := outbounds[0]
	if ob["protocol"] != "socks" {
		t.Fatalf("outbound protocol = %v, want socks", ob["protocol"])
	}
	if ob["tag"] != "egress-3" {
		t.Fatalf("outbound tag = %v, want egress-3", ob["tag"])
	}
	settings, ok := ob["settings"].(map[string]any)
	if !ok {
		t.Fatalf("outbound settings has wrong shape: %#v", ob["settings"])
	}
	servers, ok := settings["servers"].([]any)
	if !ok || len(servers) != 1 {
		t.Fatalf("outbound servers has wrong shape: %#v", settings["servers"])
	}
	srv, ok := servers[0].(map[string]any)
	if !ok || srv["address"] != "127.0.0.1" || srv["port"] != 52103 {
		t.Fatalf("outbound server = %#v, want 127.0.0.1:52103", servers[0])
	}

	// rule 形状：{"type":"field","inboundTag":[...],"outboundTag":"egress-3"}
	rule := rules[0]
	if rule["type"] != "field" {
		t.Fatalf("rule type = %v, want field", rule["type"])
	}
	if rule["outboundTag"] != "egress-3" {
		t.Fatalf("rule outboundTag = %v, want egress-3", rule["outboundTag"])
	}
	inTags, ok := rule["inboundTag"].([]any)
	if !ok || len(inTags) != 2 || inTags[0] != "vless-8443" || inTags[1] != "in-443-tcp" {
		t.Fatalf("rule inboundTag = %#v, want [vless-8443 in-443-tcp]", rule["inboundTag"])
	}

	// 第二对：link 6
	if outbounds[1]["tag"] != "egress-6" || rules[1]["outboundTag"] != "egress-6" {
		t.Fatalf("second pair tags wrong: %#v / %#v", outbounds[1]["tag"], rules[1]["outboundTag"])
	}

	// 空输入 → 空输出
	o, r := buildEgressOutbounds(nil)
	if len(o) != 0 || len(r) != 0 {
		t.Fatalf("empty input should yield empty output, got %d/%d", len(o), len(r))
	}
}

func TestBuildEgressOutboundsJSONShape(t *testing.T) {
	// 最终序列化形状必须能被 xray-core 接受的 JSON 结构表达
	links := []EgressLinkView{{Id: 9, EgressSocksPort: 52201, InboundTags: []string{"vless-8443"}}}
	outbounds, rules := buildEgressOutbounds(links)
	raw, err := json.Marshal(map[string]any{"outbounds": outbounds, "routing": map[string]any{"rules": rules}})
	if err != nil {
		t.Fatal(err)
	}
	var parsed struct {
		Outbounds []struct {
			Protocol string `json:"protocol"`
			Tag      string `json:"tag"`
			Settings struct {
				Servers []struct {
					Address string `json:"address"`
					Port    int    `json:"port"`
				} `json:"servers"`
			} `json:"settings"`
		} `json:"outbounds"`
		Routing struct {
			Rules []struct {
				Type        string   `json:"type"`
				InboundTag  []string `json:"inboundTag"`
				OutboundTag string   `json:"outboundTag"`
			} `json:"rules"`
		} `json:"routing"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatal(err)
	}
	if parsed.Outbounds[0].Settings.Servers[0].Port != 52201 {
		t.Fatalf("port lost in JSON round-trip: %s", raw)
	}
	if parsed.Routing.Rules[0].InboundTag[0] != "vless-8443" {
		t.Fatalf("inboundTag lost in JSON round-trip: %s", raw)
	}
}
