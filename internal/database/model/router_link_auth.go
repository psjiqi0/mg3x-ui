package model

import (
	"github.com/mhsanaei/3x-ui/v3/internal/crypto/nodetoken"
)

// 本文件：RouterLink.AuthJSON 的认证加解密。
//
// 放在 model 包（而非 web/service）的原因：model 是数据层，被数据库迁移、
// service、controller、vpnclient 各层引用都无 import cycle；nodetoken 包只
// 依赖标准库，不会形成循环。
//
// 复用机制：internal/crypto/nodetoken（任务描述中的 node_token_encryption
// 实现实际落在此包，web/service 下只有它的测试文件）。PIA 集成
// （internal/web/service/integration/pia.go）对非节点 secret 也是这样用
// EncryptBound/DecryptBound 的：AES-256-GCM + 版本化 key id，密钥由进程
// 启动时 NODE_TOKEN_ENCRYPTION 加载进全局 codec。没有自己发明任何加密。

// routerLinkAuthAAD 是加密/解密 AuthJSON 时的 Additional Authenticated
// Data：把密文绑定到 "router_links.auth" 域，防止跨表密文混用。
// （行级绑定需要行 id，但加解密 API 签名只收纯字符串，故用域绑定；
// 若将来需要行绑定，可在此基础上另加带 id 的变体。）
var routerLinkAuthAAD = []byte("router_links/auth")

// EncryptRouterLinkAuth encrypts a plaintext RouterLink auth JSON document
// (明文形状见 router_link.go 注释) for at-rest storage in AuthJSON.
// In ModeOff (encryption not enabled) it passes the value through unchanged,
// exactly like the nodetoken semantics it reuses.
func EncryptRouterLinkAuth(plain string) (string, error) {
	return nodetoken.EncryptBound(routerLinkAuthAAD, plain)
}

// DecryptRouterLinkAuth reverses EncryptRouterLinkAuth. Plaintext values
// stored while encryption was off (or empty strings) pass through unchanged.
func DecryptRouterLinkAuth(enc string) (string, error) {
	return nodetoken.DecryptBound(routerLinkAuthAAD, enc)
}
