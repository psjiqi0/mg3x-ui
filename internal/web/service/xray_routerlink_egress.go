package service

// RouterLink egress（经隧道出公网）的 Xray 配置注入（D 组）。
//
// 数据平面：C 组的 vpnclient.Manager.EnsureEgress(id) 为每条 egress 连接起一个
// 本机独占 SOCKS5（只绑 127.0.0.1），端口回写 router_links.egress_socks_port。
// 本文件只做 Xray 侧的一半：为每个「Egress=true 且隧道当前 up」的连接注入
// 一个 socks outbound（tag=egress-<id>，指向该 SOCKS5），再加一条 field rule
// 把用户选的 inboundTags 流量引过去。
//
// 验收场景：VLESS+REALITY 入站（端口 8443，宿主机 443 被 nginx 占用）的流量
// 经 PPTP 隧道从路由器公网口出去，出口 IP 变为 116.59.15.247。

import (
	"encoding/json"
	"fmt"

	"github.com/mhsanaei/3x-ui/v3/internal/database"
	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
	"github.com/mhsanaei/3x-ui/v3/internal/logger"
	"github.com/mhsanaei/3x-ui/v3/internal/util/json_util"
	"github.com/mhsanaei/3x-ui/v3/internal/xray"
)

// EgressLinkView 是注入逻辑需要的 RouterLink 最小投影：与 DB/vpnclient 解耦，
// 让 buildEgressOutbounds 保持为纯函数，可单测。
type EgressLinkView struct {
	Id              int
	EgressSocksPort int
	InboundTags     []string
}

// RouterLinkEgressOutboundTag 返回某连接 egress 桥的 xray outbound tag。
func RouterLinkEgressOutboundTag(id int) string {
	return fmt.Sprintf("egress-%d", id)
}

// buildEgressOutbounds 为每个 egress 连接视图生成一对（socks outbound,
// field rule）。纯函数：无 DB、无 Manager、无副作用。
//
// outbound 形状（任务契约冻结）：
// {"protocol":"socks","tag":"egress-<id>",
//
//	"settings":{"servers":[{"address":"127.0.0.1","port":<EgressSocksPort>}]}}
//
// rule 形状：
// {"type":"field","inboundTag":[<tags...>],"outboundTag":"egress-<id>"}
//
// 端口无效或未选入站的视图直接跳过（防黑洞的第二道闸；第一道在
// injectRouterLinkEgress 的 tunnel-up 检查）。
func buildEgressOutbounds(links []EgressLinkView) (outbounds []map[string]any, rules []map[string]any) {
	for _, l := range links {
		if l.EgressSocksPort <= 0 || len(l.InboundTags) == 0 {
			continue
		}
		tag := RouterLinkEgressOutboundTag(l.Id)
		outbounds = append(outbounds, map[string]any{
			"protocol": "socks",
			"tag":      tag,
			"settings": map[string]any{
				"servers": []any{
					map[string]any{"address": "127.0.0.1", "port": l.EgressSocksPort},
				},
			},
		})
		inTags := make([]any, 0, len(l.InboundTags))
		for _, t := range l.InboundTags {
			inTags = append(inTags, t)
		}
		rules = append(rules, map[string]any{
			"type":        "field",
			"inboundTag":  inTags,
			"outboundTag": tag,
		})
	}
	return outbounds, rules
}

// injectRouterLinkEgress 把 egress 连接的 socks outbound + field rule 注入
// 生成中的 xray.Config。由 XrayService.GetXrayConfig 在 injectNodeEgresses
// 之后调用。
//
// 防黑洞：只注入「Egress=true 且 VpnClientManager.Status(id).Status=="up"
// 且有可用 egress 端口」的连接；tunnel 非 up 时对应 outbound/rule 一个都不
// 加，选中入站保持原有路由，不会指向死桥。
//
// 规则位置：prepend 到 rules 数组最前面（与 injectNodeEgresses /
// injectMtprotoEgress / injectPanelEgress 同一惯例）。理由：把某入站选进
// egress 是用户显式的逐入站选择，必须胜过模板里泛泛的兜底规则（如直连
// freedom），否则开关开了却按规则顺序静默失效；想恢复某入站的原路由，
// 把它从 EgressInboundTags 里拿掉即可，语义明确。
func injectRouterLinkEgress(cfg *xray.Config) {
	db := database.GetDB()
	var links []model.RouterLink
	if err := db.Model(model.RouterLink{}).Where("egress = ?", true).Find(&links).Error; err != nil {
		logger.Warning("routerlink egress: load egress links failed:", err)
		return
	}

	views := make([]EgressLinkView, 0, len(links))
	for i := range links {
		// 防黑洞第一道闸：tunnel 非 up 不注入。
		if VpnClientManager.Status(links[i].Id).Status != "up" {
			continue
		}
		tags := parseEgressInboundTags(links[i].EgressInboundTags)
		views = append(views, EgressLinkView{
			Id:              links[i].Id,
			EgressSocksPort: links[i].EgressSocksPort,
			InboundTags:     tags,
		})
	}
	outbounds, rules := buildEgressOutbounds(views)
	if len(outbounds) == 0 {
		return
	}

	// 合并 outbounds：unmarshal-append-remarshal（同 mergeSubscriptionOutbounds
	// 惯例）。tag 已存在则整对跳过，保证"无 outbound 就无 rule"，不留悬空引用。
	var existing []any
	if len(cfg.OutboundConfigs) > 0 {
		if err := json.Unmarshal(cfg.OutboundConfigs, &existing); err != nil {
			logger.Warning("routerlink egress: outbounds section unparsable, skipping injection:", err)
			return
		}
	}
	usedTags := make(map[string]struct{}, len(existing))
	for _, o := range existing {
		if m, ok := o.(map[string]any); ok {
			if t, ok := m["tag"].(string); ok {
				usedTags[t] = struct{}{}
			}
		}
	}
	kept := outbounds[:0]
	for _, o := range outbounds {
		if _, dup := usedTags[o["tag"].(string)]; dup {
			logger.Warning("routerlink egress: outbound tag [", o["tag"], "] already exists, skipping its rule too")
			continue
		}
		usedTags[o["tag"].(string)] = struct{}{}
		existing = append(existing, o)
		kept = append(kept, o)
	}
	if len(kept) == 0 {
		return
	}
	newOutbounds, err := json.Marshal(existing)
	if err != nil {
		logger.Warning("routerlink egress: failed to rebuild outbounds, skipping injection:", err)
		return
	}
	cfg.OutboundConfigs = json_util.RawMessage(newOutbounds)

	// 合并 rules：prepend 到最前面（理由见函数注释）。
	routing := map[string]any{}
	if len(cfg.RouterConfig) > 0 {
		if err := json.Unmarshal(cfg.RouterConfig, &routing); err != nil {
			logger.Warning("routerlink egress: routing section unparsable, skipping injection:", err)
			return
		}
	}
	oldRules, _ := routing["rules"].([]any)
	newRules := make([]any, 0, len(rules)+len(oldRules))
	tagOf := func(o map[string]any) string { t, _ := o["tag"].(string); return t }
	keptSet := make(map[string]struct{}, len(kept))
	for _, o := range kept {
		keptSet[tagOf(o)] = struct{}{}
	}
	for _, r := range rules {
		if _, ok := keptSet[r["outboundTag"].(string)]; !ok {
			continue
		}
		newRules = append(newRules, r)
	}
	newRules = append(newRules, oldRules...)
	routing["rules"] = newRules
	newRouting, err := json.Marshal(routing)
	if err != nil {
		logger.Warning("routerlink egress: failed to rebuild routing section, skipping injection:", err)
		return
	}
	cfg.RouterConfig = json_util.RawMessage(newRouting)
}
