package service

// RouterLink 面板层（D 组）：路由器 VPN 客户端连接（中转）的 CRUD、校验、
// 端口冲突检测，以及 vpnclient.Manager 单例的装配。
//
// 角色划分：本文件只做"期望状态"的管理（DB 行 + 校验 + 把期望喂给 Manager）；
// 实际拨号/隧道/端口转发的执行与对账在 internal/vpnclient（C 组，契约冻结）。

import (
	"encoding/json"
	"fmt"
	"net"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/mhsanaei/3x-ui/v3/internal/config"
	"github.com/mhsanaei/3x-ui/v3/internal/database"
	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
	"github.com/mhsanaei/3x-ui/v3/internal/logger"
	"github.com/mhsanaei/3x-ui/v3/internal/vpnclient"
	"gorm.io/gorm"
)

// 协议常量：与 model.RouterLink.Protocol 的取值保持一致。
const (
	RouterLinkProtocolOpenVPN   = "openvpn"
	RouterLinkProtocolPPTP      = "pptp"
	RouterLinkProtocolWireGuard = "wireguard"
)

// RouterLinkAuthDTO 是 auth 明文的对外形状（冻结给 E 组前端）。
// 仅用于 add/update 的请求体；入库前必须经 model.EncryptRouterLinkAuth 加密，
// 读取时绝不解密返回（list 只给 HasAuth 布尔）。
type RouterLinkAuthDTO struct {
	Type          string `json:"type"` // password|cert|psk
	Username      string `json:"username"`
	Password      string `json:"password"`
	Ca            string `json:"ca"`
	Cert          string `json:"cert"`
	Key           string `json:"key"`
	PrivateKey    string `json:"privateKey"`
	PeerPublicKey string `json:"peerPublicKey"`
	PresharedKey  string `json:"presharedKey"`
}

// RouterLinkHasAuth 只表述"库里有没有这类凭证"，不携带任何明文。
type RouterLinkHasAuth struct {
	Password bool `json:"password"`
	Cert     bool `json:"cert"`
}

// RouterLinkDTO 是 RouterLink 的对外形状（冻结给 E 组前端）。
// Status/HandshakeAt/RxBytes/TxBytes/Message 为运行时状态，由 Manager.Status
// 实时填充，不落库。
type RouterLinkDTO struct {
	Id                  int                `json:"id"`
	Name                string             `json:"name"`
	Protocol            string             `json:"protocol"`
	RemoteHost          string             `json:"remoteHost"`
	RemotePort          int                `json:"remotePort"`
	Proto               string             `json:"proto"`
	LanSubnet           string             `json:"lanSubnet"`
	TunnelAddress       string             `json:"tunnelAddress"`
	Mppe                string             `json:"mppe"`
	PersistentKeepalive int                `json:"persistentKeepalive"`
	ForwardedPorts      string             `json:"forwardedPorts"`
	Enable              bool               `json:"enable"`
	Egress              bool               `json:"egress"`
	EgressInboundTags   []string           `json:"egressInboundTags"`
	EgressSocksPort     int                `json:"egressSocksPort"` // 只读：由 SetEgress/Ensure 回写
	Auth                *RouterLinkAuthDTO `json:"auth,omitempty"`
	HasAuth             RouterLinkHasAuth  `json:"hasAuth"`
	Status              string             `json:"status"`
	HandshakeAt         int64              `json:"handshakeAt"`
	RxBytes             int64              `json:"rxBytes"`
	TxBytes             int64              `json:"txBytes"`
	Message             string             `json:"message"`
}

// routerLinksDir 是 vpnclient.Manager 的工作目录（各隧道的配置文件、
// 密钥材料落盘处）。
//
// 选址说明：优先跟随面板配置的数据库目录 config.GetDBFolderPath()
// （默认 /etc/x-ui，可被 XUI_DB_FOLDER 环境变量覆盖），与其并列建
// routerlinks 子目录。理由：与面板数据同生命周期（备份/迁移一起走），
// 又不直接塞进 .db 文件；不用 /etc/x-ui 写死，尊重用户的自定义路径。
func routerLinksDir() string {
	return filepath.Join(config.GetDBFolderPath(), "routerlinks")
}

// VpnClientManager 是 vpnclient.Manager 的面板级单例，service 与 job 共用。
// （internal/vpnclient 由 C 组实现，方法集契约已冻结。）
var VpnClientManager = vpnclient.NewManager(routerLinksDir())

// RouterLinkService 管理 router_links 表的 CRUD 与 vpnclient 装配。
type RouterLinkService struct{}

// Add 新增一条路由器连接：校验 → 冲突检测 → auth 加密入库 → Manager.Ensure。
func (s *RouterLinkService) Add(dto *RouterLinkDTO) (int, error) {
	if dto == nil {
		return 0, fmt.Errorf("请求体为空")
	}
	if dto.Auth == nil {
		return 0, fmt.Errorf("新建连接必须提供 auth")
	}
	link := dto.toModel()
	if err := validateRouterLinkAuth(link.Protocol, dto.Auth); err != nil {
		return 0, err
	}
	fps, err := vpnclient.ParseForwardedPorts(link.ForwardedPorts)
	if err != nil {
		return 0, fmt.Errorf("forwardedPorts 解析失败: %w", err)
	}
	if err := validateRouterLinkFields(link, fps); err != nil {
		return 0, err
	}
	db := database.GetDB()
	if err := validateRouterLinkEgress(db, link); err != nil {
		return 0, err
	}
	if err := s.checkPortConflicts(db, link, fps, 0); err != nil {
		return 0, err
	}
	plain, err := json.Marshal(dto.Auth)
	if err != nil {
		return 0, fmt.Errorf("auth 序列化失败: %w", err)
	}
	enc, err := model.EncryptRouterLinkAuth(string(plain))
	if err != nil {
		return 0, fmt.Errorf("auth 加密失败: %w", err)
	}
	link.AuthJSON = enc
	if err := db.Create(link).Error; err != nil {
		return 0, err
	}
	// 装配失败不回滚 DB 行：job 每 10s 用 Reconcile 收敛期望状态，
	// 行还在，下一 tick 会重试；错误返回给前端感知。
	if err := VpnClientManager.Ensure(*link); err != nil {
		logger.Warningf("routerlink: manager Ensure(%d) failed: %v", link.Id, err)
		return link.Id, fmt.Errorf("已保存，但隧道装配失败: %w", err)
	}
	// Ensure 透调 egress 语义：Egress && Enable 的连接顺手起 egress SOCKS，
	// 端口回写 DB（隧道 up 之前 Xray 注入会跳过，防黑洞）。
	if err := s.applyEgressState(db, link); err != nil {
		logger.Warningf("routerlink: manager EnsureEgress(%d) failed: %v", link.Id, err)
		return link.Id, fmt.Errorf("已保存，但 egress 装配失败: %w", err)
	}
	// 新增的 egress 连接改变 Xray 注入集合 → 重生配置+重载。
	if link.Egress && link.Enable {
		if err := restartXrayForRouterLinkEgress(); err != nil {
			logger.Warningf("routerlink: add 后 xray 重载失败: %v", err)
		}
	}
	return link.Id, nil
}

// Update 全量更新一条路由器连接（auth 为 nil 表示保持原有凭证不动）。

// mergeRouterLinkAuth: 编辑时 auth 敏感字段留空即保持原值。
// 从 DB 解密旧 auth，dto 中为空的字段用旧值填充，返回合并后的副本。
func mergeRouterLinkAuth(oldEnc string, dto *RouterLinkAuthDTO) *RouterLinkAuthDTO {
	merged := *dto
	if oldEnc == "" {
		return &merged
	}
	plain, err := model.DecryptRouterLinkAuth(oldEnc)
	if err != nil {
		return &merged
	}
	var old RouterLinkAuthDTO
	if err := json.Unmarshal([]byte(plain), &old); err != nil {
		return &merged
	}
	if merged.Type == "" {
		merged.Type = old.Type
	}
	if merged.Username == "" {
		merged.Username = old.Username
	}
	if merged.Password == "" {
		merged.Password = old.Password
	}
	if merged.Ca == "" {
		merged.Ca = old.Ca
	}
	if merged.Cert == "" {
		merged.Cert = old.Cert
	}
	if merged.Key == "" {
		merged.Key = old.Key
	}
	if merged.PrivateKey == "" {
		merged.PrivateKey = old.PrivateKey
	}
	if merged.PeerPublicKey == "" {
		merged.PeerPublicKey = old.PeerPublicKey
	}
	if merged.PresharedKey == "" {
		merged.PresharedKey = old.PresharedKey
	}
	return &merged
}

func (s *RouterLinkService) Update(dto *RouterLinkDTO) error {
	if dto == nil || dto.Id <= 0 {
		return fmt.Errorf("缺少 id")
	}
	db := database.GetDB()
	var link model.RouterLink
	if err := db.First(&link, dto.Id).Error; err != nil {
		if database.IsNotFound(err) {
			return fmt.Errorf("路由器连接 #%d 不存在", dto.Id)
		}
		return err
	}
	updated := dto.toModel()
	updated.Id = link.Id
	updated.AuthJSON = link.AuthJSON
	if dto.Auth != nil {
		mergedAuth := mergeRouterLinkAuth(link.AuthJSON, dto.Auth)
		if err := validateRouterLinkAuth(updated.Protocol, mergedAuth); err != nil {
			return err
		}
		plain, err := json.Marshal(mergedAuth)
		if err != nil {
			return fmt.Errorf("auth 序列化失败: %w", err)
		}
		enc, err := model.EncryptRouterLinkAuth(string(plain))
		if err != nil {
			return fmt.Errorf("auth 加密失败: %w", err)
		}
		updated.AuthJSON = enc
	}
	fps, err := vpnclient.ParseForwardedPorts(updated.ForwardedPorts)
	if err != nil {
		return fmt.Errorf("forwardedPorts 解析失败: %w", err)
	}
	if err := validateRouterLinkFields(updated, fps); err != nil {
		return err
	}
	if err := validateRouterLinkEgress(db, updated); err != nil {
		return err
	}
	if err := s.checkPortConflicts(db, updated, fps, updated.Id); err != nil {
		return err
	}
	if err := db.Save(updated).Error; err != nil {
		return err
	}
	if err := VpnClientManager.Ensure(*updated); err != nil {
		logger.Warningf("routerlink: manager Ensure(%d) failed: %v", updated.Id, err)
		return fmt.Errorf("已保存，但隧道装配失败: %w", err)
	}
	wasEgress := link.Egress
	if updated.Egress && wasEgress {
		// 端口保持稳定：把 DB 旧端口带给 EnsureEgress，C 组分配器优先复用
		// （link.EgressSocksPort），避免每次 update 都换端口导致 Xray
		// outbound 频繁变更。
		updated.EgressSocksPort = link.EgressSocksPort
	}
	if !updated.Egress && wasEgress {
		// egress 被关掉：停掉独占 SOCKS5，避免残留监听端口。
		if err := VpnClientManager.RemoveEgress(updated.Id); err != nil {
			logger.Warningf("routerlink: manager RemoveEgress(%d) failed: %v", updated.Id, err)
		}
		// db.Save(updated) 已把行内 egress=false/egress_socks_port=0 落库
		// （toModel 不从 DTO 拷贝只读的 socksPort），这里只同步内存值。
		updated.EgressSocksPort = 0
	}
	if err := s.applyEgressState(db, updated); err != nil {
		logger.Warningf("routerlink: manager EnsureEgress(%d) failed: %v", updated.Id, err)
		return fmt.Errorf("已保存，但 egress 装配失败: %w", err)
	}
	// egress 开关或入站选择变化 → Xray 注入集合变化 → 重生配置+重载。
	if wasEgress != updated.Egress || link.EgressInboundTags != updated.EgressInboundTags {
		if err := restartXrayForRouterLinkEgress(); err != nil {
			logger.Warningf("routerlink: update 后 xray 重载失败: %v", err)
		}
	}
	return nil
}

// Del 删除一条路由器连接：先删 DB 行，再清 Manager 状态。
// （即使 Manager.Remove 失败，job 的 Reconcile 也会按 DB 全量收敛掉残留。）
func (s *RouterLinkService) Del(id int) error {
	if id <= 0 {
		return fmt.Errorf("缺少 id")
	}
	db := database.GetDB()
	if err := s.mustExist(db, id); err != nil {
		return err
	}
	if err := db.Delete(&model.RouterLink{}, id).Error; err != nil {
		return err
	}
	if err := VpnClientManager.Remove(id); err != nil {
		logger.Warningf("routerlink: manager Remove(%d) failed: %v", id, err)
	}
	// egress SOCKS 与隧道生命周期可能独立（契约冻结前实现细节未定），
	// 删除时顺手清掉残留的 egress 服务，失败只记日志。
	if err := VpnClientManager.RemoveEgress(id); err != nil {
		logger.Warningf("routerlink: manager RemoveEgress(%d) failed: %v", id, err)
	}
	if err := restartXrayForRouterLinkEgress(); err != nil {
		logger.Warningf("routerlink: del 后 xray 重载失败: %v", err)
	}
	return nil
}

// List 返回全部路由器连接：DB 字段 + hasAuth 布尔 + Manager 实时状态。
// auth 明文绝不解密返回；HasAuth 仅在服务端解密一次取存在性后即丢弃明文。
func (s *RouterLinkService) List() ([]*RouterLinkDTO, error) {
	db := database.GetDB()
	var links []model.RouterLink
	if err := db.Model(model.RouterLink{}).Order("id ASC").Find(&links).Error; err != nil {
		return nil, err
	}
	out := make([]*RouterLinkDTO, 0, len(links))
	for i := range links {
		dto := modelToDTO(&links[i])
		dto.HasAuth = s.deriveHasAuth(&links[i])
		st := VpnClientManager.Status(links[i].Id)
		dto.Status = st.Status
		dto.HandshakeAt = st.HandshakeAt
		dto.RxBytes = st.RxBytes
		dto.TxBytes = st.TxBytes
		dto.Message = st.Message
		out = append(out, dto)
	}
	return out, nil
}

// Dial 手动拨号（透调 Manager）。
func (s *RouterLinkService) Dial(id int) error {
	if err := s.mustExist(database.GetDB(), id); err != nil {
		return err
	}
	return VpnClientManager.Dial(id)
}

// Hangup 手动挂断（透调 Manager）。
func (s *RouterLinkService) Hangup(id int) error {
	if err := s.mustExist(database.GetDB(), id); err != nil {
		return err
	}
	return VpnClientManager.Hangup(id)
}

// Status 返回单条连接的 Manager 实时状态。
func (s *RouterLinkService) Status(id int) (vpnclient.LinkStatus, error) {
	if err := s.mustExist(database.GetDB(), id); err != nil {
		return vpnclient.LinkStatus{}, err
	}
	return VpnClientManager.Status(id), nil
}

func (s *RouterLinkService) mustExist(db *gorm.DB, id int) error {
	var n int64
	if err := db.Model(model.RouterLink{}).Where("id = ?", id).Count(&n).Error; err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("路由器连接 #%d 不存在", id)
	}
	return nil
}

// deriveHasAuth 只在服务端解密 AuthJSON 以推导凭证存在性，明文不出此函数。
func (s *RouterLinkService) deriveHasAuth(link *model.RouterLink) RouterLinkHasAuth {
	var has RouterLinkHasAuth
	if link.AuthJSON == "" {
		return has
	}
	plain, err := model.DecryptRouterLinkAuth(link.AuthJSON)
	if err != nil {
		logger.Warningf("routerlink: decrypt auth of #%d failed: %v", link.Id, err)
		return has
	}
	var auth RouterLinkAuthDTO
	if err := json.Unmarshal([]byte(plain), &auth); err != nil {
		logger.Warningf("routerlink: parse auth of #%d failed: %v", link.Id, err)
		return has
	}
	has.Password = auth.Password != ""
	has.Cert = auth.Ca != "" || auth.Cert != "" || auth.Key != ""
	return has
}

// checkPortConflicts 做两轮公网端口冲突检测，两轮都过才算过：
//
//  1. 复用 inbound 的冲突域：面板自身端口 / 各入站端口 / 各 SOCKS 中继端口
//     （inbound_amneziawg.go 的 checkForwardedPortsConflict，只读调用）。
//     扩展语法的 lanIP:lanPort 部分不参与冲突计算（那是隧道另一头），只把
//     pubPort 部分抽出来拼成旧语法（"8080,3389"）传进去。
//  2. 与其他已启用（Enable）的 RouterLink 行的 pubPort 冲突（排除自己）。
func (s *RouterLinkService) checkPortConflicts(db *gorm.DB, link *model.RouterLink, fps []vpnclient.ForwardedPort, excludeID int) error {
	if len(fps) == 0 {
		return nil
	}
	parts := make([]string, 0, len(fps))
	mine := make(map[int]struct{}, len(fps))
	for _, fp := range fps {
		parts = append(parts, strconv.Itoa(fp.PubPort))
		mine[fp.PubPort] = struct{}{}
	}
	oldSyntax := strings.Join(parts, ",")

	// 第一轮：面板/入站/SOCKS 冲突域。
	inbSvc := InboundService{}
	ctx, err := inbSvc.loadPortConflictContext(db, nil)
	if err != nil {
		return fmt.Errorf("加载端口冲突上下文失败: %w", err)
	}
	if hit := inbSvc.checkForwardedPortsConflict(ctx, oldSyntax); hit != "" {
		return fmt.Errorf("forwardedPorts 与 %s 冲突", hit)
	}

	// 第二轮：其他已启用的 RouterLink 行。
	var others []model.RouterLink
	q := db.Model(model.RouterLink{}).Where("enable = ?", true)
	if excludeID > 0 {
		q = q.Where("id <> ?", excludeID)
	}
	if err := q.Find(&others).Error; err != nil {
		return fmt.Errorf("查询其他路由器连接失败: %w", err)
	}
	for i := range others {
		if others[i].ForwardedPorts == "" {
			continue
		}
		ofps, err := vpnclient.ParseForwardedPorts(others[i].ForwardedPorts)
		if err != nil {
			// 已有行的脏数据不能成为放行的理由：fail closed。
			return fmt.Errorf("已有连接 %q 的 forwardedPorts 解析失败: %v", others[i].Name, err)
		}
		for _, fp := range ofps {
			if _, dup := mine[fp.PubPort]; dup {
				return fmt.Errorf("公网端口 %d 已被路由器连接 %q 占用", fp.PubPort, others[i].Name)
			}
		}
	}
	return nil
}

// validateRouterLinkFields 校验除 auth 明文之外的全部字段。
// fps 为已解析的 forwardedPorts（调用方先调 vpnclient.ParseForwardedPorts）。
func validateRouterLinkFields(link *model.RouterLink, fps []vpnclient.ForwardedPort) error {
	switch link.Protocol {
	case RouterLinkProtocolOpenVPN, RouterLinkProtocolPPTP, RouterLinkProtocolWireGuard:
	default:
		return fmt.Errorf("protocol 必须为 openvpn|pptp|wireguard")
	}
	if strings.TrimSpace(link.Name) == "" {
		return fmt.Errorf("name 不能为空")
	}
	if strings.TrimSpace(link.RemoteHost) == "" {
		return fmt.Errorf("remoteHost 不能为空")
	}
	if link.Protocol == RouterLinkProtocolPPTP {
		if link.RemotePort != 0 && (link.RemotePort < 1 || link.RemotePort > 65535) {
			return fmt.Errorf("remotePort 非法")
		}
	} else if link.RemotePort < 1 || link.RemotePort > 65535 {
		return fmt.Errorf("remotePort 必须为 1-65535")
	}
	if link.Protocol == RouterLinkProtocolOpenVPN && link.Proto != "" &&
		link.Proto != "udp" && link.Proto != "tcp" {
		return fmt.Errorf("proto 必须为 udp|tcp")
	}
	_, ipnet, err := net.ParseCIDR(link.LanSubnet)
	if err != nil {
		return fmt.Errorf("lanSubnet 不是合法 CIDR: %w", err)
	}
	for _, fp := range fps {
		ip := net.ParseIP(fp.LanIP)
		if ip == nil {
			return fmt.Errorf("forwardedPorts: %q 不是合法 IP", fp.LanIP)
		}
		if !ipnet.Contains(ip) {
			return fmt.Errorf("forwardedPorts: 目标 IP %s 不在 lanSubnet %s 内", fp.LanIP, link.LanSubnet)
		}
		if fp.LanPort < 1 || fp.LanPort > 65535 {
			return fmt.Errorf("forwardedPorts: 目标端口 %d 非法", fp.LanPort)
		}
	}
	if link.Protocol == RouterLinkProtocolWireGuard && link.TunnelAddress != "" {
		if _, _, err := net.ParseCIDR(link.TunnelAddress); err != nil {
			if ip := net.ParseIP(link.TunnelAddress); ip == nil {
				return fmt.Errorf("tunnelAddress 不是合法 IP/CIDR")
			}
		}
	}
	if link.Protocol == RouterLinkProtocolPPTP && link.Mppe != "" {
		switch link.Mppe {
		case "require-mppe-128", "require-mppe", "nomppe":
		default:
			return fmt.Errorf("mppe 必须为 require-mppe-128|require-mppe|nomppe")
		}
	}
	if link.PersistentKeepalive < 0 || link.PersistentKeepalive > 65535 {
		return fmt.Errorf("persistentKeepalive 非法")
	}
	return nil
}

// validateRouterLinkAuth 按协议校验 auth 明文齐备性。
func validateRouterLinkAuth(protocol string, auth *RouterLinkAuthDTO) error {
	if auth == nil {
		return fmt.Errorf("auth 不能为空")
	}
	switch protocol {
	case RouterLinkProtocolOpenVPN:
		switch auth.Type {
		case "password":
			if auth.Username == "" || auth.Password == "" {
				return fmt.Errorf("openvpn password 模式需要 username/password")
			}
		case "cert":
			if auth.Ca == "" || auth.Cert == "" || auth.Key == "" {
				return fmt.Errorf("openvpn cert 模式需要 ca/cert/key")
			}
		default:
			return fmt.Errorf("openvpn 的 auth.type 必须为 password|cert")
		}
	case RouterLinkProtocolPPTP:
		if auth.Username == "" || auth.Password == "" {
			return fmt.Errorf("pptp 需要 username/password")
		}
	case RouterLinkProtocolWireGuard:
		if auth.PrivateKey == "" || auth.PeerPublicKey == "" {
			return fmt.Errorf("wireguard 需要 privateKey/peerPublicKey")
		}
	default:
		return fmt.Errorf("protocol 必须为 openvpn|pptp|wireguard")
	}
	return nil
}

// toModel 把 DTO 转成 model 行，并补协议默认值、归一化 lanSubnet。
func (d *RouterLinkDTO) toModel() *model.RouterLink {
	lanSubnet := strings.TrimSpace(d.LanSubnet)
	if _, ipnet, err := net.ParseCIDR(lanSubnet); err == nil {
		lanSubnet = ipnet.String()
	}
	link := &model.RouterLink{
		Name:                strings.TrimSpace(d.Name),
		Protocol:            strings.TrimSpace(d.Protocol),
		RemoteHost:          strings.TrimSpace(d.RemoteHost),
		RemotePort:          d.RemotePort,
		Proto:               strings.TrimSpace(d.Proto),
		LanSubnet:           lanSubnet,
		TunnelAddress:       strings.TrimSpace(d.TunnelAddress),
		Mppe:                strings.TrimSpace(d.Mppe),
		PersistentKeepalive: d.PersistentKeepalive,
		ForwardedPorts:      strings.TrimSpace(d.ForwardedPorts),
		Enable:              d.Enable,
		Egress:              d.Egress,
		EgressInboundTags:   marshalEgressInboundTags(d.EgressInboundTags),
	}
	if link.Protocol == RouterLinkProtocolOpenVPN && link.Proto == "" {
		link.Proto = "udp"
	}
	if link.Protocol == RouterLinkProtocolPPTP {
		if link.RemotePort == 0 {
			link.RemotePort = 1723
		}
		if link.Mppe == "" {
			link.Mppe = "require-mppe-128"
		}
	}
	return link
}

// modelToDTO 把 DB 行转成对外 DTO（auth 明文不带出，Auth 字段保持 nil）。
func modelToDTO(link *model.RouterLink) *RouterLinkDTO {
	return &RouterLinkDTO{
		Id:                  link.Id,
		Name:                link.Name,
		Protocol:            link.Protocol,
		RemoteHost:          link.RemoteHost,
		RemotePort:          link.RemotePort,
		Proto:               link.Proto,
		LanSubnet:           link.LanSubnet,
		TunnelAddress:       link.TunnelAddress,
		Mppe:                link.Mppe,
		PersistentKeepalive: link.PersistentKeepalive,
		ForwardedPorts:      link.ForwardedPorts,
		Enable:              link.Enable,
		Egress:              link.Egress,
		EgressInboundTags:   parseEgressInboundTags(link.EgressInboundTags),
		EgressSocksPort:     link.EgressSocksPort,
	}
}

// ---------------------------------------------------------------------------
// Egress（经隧道出公网）语义（D 组）。
//
// 模型：RouterLink.Egress=true 且 Enable 时，EgressInboundTags 列出的入站
// （如 ["vless-8443"]）的流量经本连接的 PPTP/OpenVPN/WG 隧道从路由器公网口
// 出去，出口 IP 变为路由器公网 IP。数据平面是 vpnclient 的独占 SOCKS5
// （C 组：Manager.EnsureEgress/RemoveEgress，端口回写 EgressSocksPort）；
// Xray 侧由 GetXrayConfig 的 injectRouterLinkEgress 注入 socks outbound +
// field rule（见 xray_routerlink_egress.go）。
// ---------------------------------------------------------------------------

// parseEgressInboundTags 把 EgressInboundTags（JSON 数组字符串）解析成 tag
// 列表；空字符串/非法 JSON 返回空列表（调用方按"未选"处理）。
func parseEgressInboundTags(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	var tags []string
	if err := json.Unmarshal([]byte(raw), &tags); err != nil {
		logger.Warningf("routerlink: egress inbound tags 解析失败，忽略: %v", err)
		return nil
	}
	out := make([]string, 0, len(tags))
	for _, t := range tags {
		if t = strings.TrimSpace(t); t != "" {
			out = append(out, t)
		}
	}
	return out
}

// marshalEgressInboundTags 是 parseEgressInboundTags 的逆操作：[]string →
// 存库的 JSON 数组字符串；空列表存 "[]"（与 nil 语义一致，解析都回空列表）。
func marshalEgressInboundTags(tags []string) string {
	clean := make([]string, 0, len(tags))
	for _, t := range tags {
		if t = strings.TrimSpace(t); t != "" {
			clean = append(clean, t)
		}
	}
	raw, err := json.Marshal(clean)
	if err != nil {
		return "[]"
	}
	return string(raw)
}

// validateRouterLinkEgress 校验 egress 配置：Egress=true 时 inboundTags 必须
// 非空，且每个 tag 必须在 inbounds 表真实存在（model.Inbound.Tag 有
// gorm:"unique" 可查）。未启用 egress 的连接直接放行。
func validateRouterLinkEgress(db *gorm.DB, link *model.RouterLink) error {
	if link == nil || !link.Egress {
		return nil
	}
	tags := parseEgressInboundTags(link.EgressInboundTags)
	if len(tags) == 0 {
		return fmt.Errorf("启用 egress 时必须选择至少一个入站（egressInboundTags 不能为空）")
	}
	for _, tag := range tags {
		var n int64
		if err := db.Model(&model.Inbound{}).Where("tag = ?", tag).Count(&n).Error; err != nil {
			return fmt.Errorf("校验入站 %q 失败: %w", tag, err)
		}
		if n == 0 {
			return fmt.Errorf("入站 %q 不存在（egressInboundTags 中的 tag 必须在 inbounds 表真实存在）", tag)
		}
	}
	return nil
}

// applyEgressState 在 Manager.Ensure 之后带上 egress 语义：Egress && Enable
// 的连接调用 EnsureEgress 起独占 SOCKS5，把分配到的端口回写 DB；不满足条件
// 时直接返回（隧道 up 之前 Xray 注入会跳过，防黑洞）。
func (s *RouterLinkService) applyEgressState(db *gorm.DB, link *model.RouterLink) error {
	if link == nil || !link.Egress || !link.Enable {
		return nil
	}
	port, err := VpnClientManager.EnsureEgress(*link)
	if err != nil {
		return err
	}
	link.EgressSocksPort = port
	return db.Model(&model.RouterLink{}).Where("id = ?", link.Id).
		Update("egress_socks_port", port).Error
}

// SetEgress 开关某连接的 egress：更新 DB 三个字段 → 起/停 vpnclient 的独占
// SOCKS5 → 端口回写 DB → 触发 Xray 配置重生+重载。
//
// enable=true：inboundTags 必须非空且每个 tag 在 inbounds 表真实存在；
// 调用 Manager.EnsureEgress 拿到端口并回写 EgressSocksPort，返回该端口。
// enable=false：调用 Manager.RemoveEgress 停掉 SOCKS5 并清端口（tag 选择
// 保留，方便下次一键重开），返回 0。
func (s *RouterLinkService) SetEgress(id int, enable bool, inboundTags []string) (int, error) {
	if id <= 0 {
		return 0, fmt.Errorf("缺少 id")
	}
	db := database.GetDB()
	var link model.RouterLink
	if err := db.First(&link, id).Error; err != nil {
		if database.IsNotFound(err) {
			return 0, fmt.Errorf("路由器连接 #%d 不存在", id)
		}
		return 0, err
	}

	if enable {
		clean := marshalEgressInboundTags(inboundTags)
		link.Egress = true
		link.EgressInboundTags = clean
		if err := validateRouterLinkEgress(db, &link); err != nil {
			return 0, err
		}
		if err := db.Model(&model.RouterLink{}).Where("id = ?", id).
			Updates(map[string]any{"egress": true, "egress_inbound_tags": clean}).Error; err != nil {
			return 0, err
		}
		// 读最新行再调 EnsureEgress：Manager 侧按完整 link 起 SOCKS5。
		if err := db.First(&link, id).Error; err != nil {
			return 0, err
		}
		port, err := VpnClientManager.EnsureEgress(link)
		if err != nil {
			return 0, fmt.Errorf("egress SOCKS 启动失败: %w", err)
		}
		if err := db.Model(&model.RouterLink{}).Where("id = ?", id).
			Update("egress_socks_port", port).Error; err != nil {
			return 0, err
		}
		if err := restartXrayForRouterLinkEgress(); err != nil {
			logger.Warningf("routerlink: egress enable 后 xray 重载失败: %v", err)
		}
		return port, nil
	}

	// disable：先停 SOCKS5（失败只记日志，DB 状态照常清理），再清端口。
	if err := VpnClientManager.RemoveEgress(id); err != nil {
		logger.Warningf("routerlink: manager RemoveEgress(%d) failed: %v", id, err)
	}
	if err := db.Model(&model.RouterLink{}).Where("id = ?", id).
		Updates(map[string]any{"egress": false, "egress_socks_port": 0}).Error; err != nil {
		return 0, err
	}
	if err := restartXrayForRouterLinkEgress(); err != nil {
		logger.Warningf("routerlink: egress disable 后 xray 重载失败: %v", err)
	}
	return 0, nil
}

// restartXrayForRouterLinkEgress 触发 Xray 配置重生+重载，复用 inbound 变更时
// 同一条路径：XrayService.RestartXray(false) 会重新跑 GetXrayConfig（含
// injectRouterLinkEgress），outbound/rule 的增删走核心 gRPC 热加载，
// 热加载接不住的才重启进程。
func restartXrayForRouterLinkEgress() error {
	return (&XrayService{}).RestartXray(false)
}
