// Package model — RouterLink（§3.1）：路由器 VPN 客户端连接。
//
// 本端是客户端角色：服务器主动拨号连用户名下各路由器的 VPN 服务端
// （openvpn | pptp | wireguard），再把服务器公网端口经隧道转发进路由器
// 内网（forwardedPorts）。隧道一律不碰默认路由，只路由 LanSubnet。
package model

// RouterLink is a client-mode VPN connection from this panel server to a
// router-side VPN server, plus the public-port→LAN forwarding rules that
// ride the tunnel. Runtime dial state (up/down/dialing) is NOT persisted —
// the vpnclient manager reports it live (见 §3.1 / §9.1)。
//
// AuthJSON 存放加密后的认证 JSON（Auth 明文形状见下），入库前必须经
// EncryptRouterLinkAuth 加密，绝不以明文落库、绝不经 JSON 序列化输出
// （json:"-"）。
//
// Auth 明文形状：
// {"type":"password|cert|psk","username","password",
//
//	"ca","cert","key",                    // openvpn 内联证书
//	"privateKey","peerPublicKey","presharedKey"}  // wireguard
type RouterLink struct {
	Id                  int    `gorm:"primaryKey;autoIncrement" json:"id"`
	Name                string `gorm:"size:128;not null" json:"name"`
	Protocol            string `gorm:"size:16;not null" json:"protocol"` // openvpn|pptp|wireguard
	RemoteHost          string `gorm:"size:256;not null" json:"remoteHost"`
	RemotePort          int    `json:"remotePort"`
	Proto               string `gorm:"size:8" json:"proto"` // udp|tcp，仅 openvpn 用
	LanSubnet           string `gorm:"size:64;not null" json:"lanSubnet"`
	AuthJSON            string `gorm:"type:text" json:"-"`              // 加密后的认证 JSON，明文形状见上，绝不直接序列化
	TunnelAddress       string `gorm:"size:64" json:"tunnelAddress"`    // wg 客户端隧道地址，可空
	Mppe                string `gorm:"size:32" json:"mppe"`             // pptp: require-mppe-128|require-mppe|nomppe
	PersistentKeepalive int    `json:"persistentKeepalive"`             // wg，可空
	ForwardedPorts      string `gorm:"type:text" json:"forwardedPorts"` // 扩展语法 pubPort->lanIP:lanPort,逗号分隔
	Enable              bool   `json:"enable"`
	// Egress（经隧道出公网）：Enable 且 Egress 时，EgressInboundTags 列出的入站
	// 流量经本连接的隧道出公网。EgressSocksPort 为 vpnclient egress SOCKS5
	// 服务的本机端口（Manager.EnsureEgress 分配并回写）；tunnel 非 up 或端口
	// 无效时 Xray 配置注入跳过该连接（防黑洞）。
	Egress            bool   `json:"egress"`
	EgressInboundTags string `gorm:"type:text" json:"egressInboundTags"` // JSON 数组字符串，如 ["vless-8443"]
	EgressSocksPort   int    `json:"egressSocksPort"`
}

// TableName maps RouterLink to the router_links table.
func (RouterLink) TableName() string { return "router_links" }
