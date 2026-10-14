package job

// VpnClientJob（D 组）：路由器 VPN 客户端连接（中转）的周期对账任务，
// 每 10s tick（注册见 internal/web/web.go startTask）：
//
//  1. 从 DB 读全部 RouterLink 行，喂给 VpnClientManager.Reconcile 收敛期望状态
//     （enable 的连接必须 up；被禁用/被删除的连接必须 down 并清理；
//     崩溃的隧道按 Manager 内部 backoff 重拨）；
//  2. 对 status=up 的连接做路由护栏复检（§4.2）：隧道只许路由 LanSubnet，
//     绝不许碰默认路由。

import (
	"fmt"
	"net"
	"os/exec"
	"strings"

	"github.com/mhsanaei/3x-ui/v3/internal/database"
	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
	"github.com/mhsanaei/3x-ui/v3/internal/logger"
	"github.com/mhsanaei/3x-ui/v3/internal/web/service"
)

// VpnClientJob converges router VPN client links with the running tunnels
// every tick and re-checks the route guard on every up link.
type VpnClientJob struct {
	xrayService service.XrayService
	// egressLastUp 记录每个 egress 连接上次 tick 观测到的 tunnel 是否 up，
	// 用于检测 up↔down 翻转（翻转时触发 Xray 配置重生+重载，因为注入的
	// outbound/rule 只在 tunnel up 时存在）。
	egressLastUp map[int]bool
}

// NewVpnClientJob creates a new VPN client reconcile job instance.
func NewVpnClientJob() *VpnClientJob {
	return &VpnClientJob{egressLastUp: make(map[int]bool)}
}

// Run reconciles desired router-link state with the running tunnels and
// re-checks the route guard on every link currently up.
func (j *VpnClientJob) Run() {
	db := database.GetDB()
	var links []model.RouterLink
	if err := db.Model(model.RouterLink{}).Order("id ASC").Find(&links).Error; err != nil {
		logger.Warning("vpnclient job: load router links failed:", err)
		return
	}

	// 期望状态对账：Manager 内部处理 enable/up、disable/down、缺失清理与 backoff。
	service.VpnClientManager.Reconcile(links)

	// 路由护栏复检：只查 up 的连接。
	for i := range links {
		st := service.VpnClientManager.Status(links[i].Id)
		if st.Status != "up" {
			continue
		}
		if err := checkRouterLinkRouteGuard(&links[i], st.Iface); err != nil {
			logger.Warningf("vpnclient job: route guard link #%d (%s): %v",
				links[i].Id, links[i].Name, err)
		}
	}

	// egress 翻转检测：Egress=true 的连接 tunnel 在 up↔down 间翻转时，
	// Xray 注入的 outbound/rule 集合发生变化（tunnel 非 up 时不注入，
	// 防黑洞），必须重生配置+重载核心。
	j.watchEgressFlips(links)
}

// watchEgressFlips 检测 egress 连接的 tunnel up↔down 翻转并触发 Xray 重载。
//
// 机制：job 内 map[int]bool 记住每个 egress 连接上次 tick 的 up 状态；
// 本次与上次不一致即翻转，调 XrayService.RestartXray(false)——该函数先重跑
// GetXrayConfig（含 injectRouterLinkEgress，按最新 tunnel 状态决定注入
// 集合），再走核心 gRPC 热加载（inbound/outbound/routing 可热加载），
// 热加载接不住才重启进程。首次观测只记录不触发；连接删除或 egress 关闭后
// 对应记录被清理，避免 map 无限增长。
func (j *VpnClientJob) watchEgressFlips(links []model.RouterLink) {
	seen := make(map[int]bool, len(links))
	for i := range links {
		if !links[i].Egress {
			continue
		}
		id := links[i].Id
		seen[id] = true
		up := service.VpnClientManager.Status(id).Status == "up"
		last, known := j.egressLastUp[id]
		if !known {
			j.egressLastUp[id] = up
			continue
		}
		if last == up {
			continue
		}
		j.egressLastUp[id] = up
		logger.Warningf("vpnclient job: egress link #%d (%s) tunnel flipped up=%v -> up=%v, reloading xray config",
			id, links[i].Name, last, up)
		if err := j.xrayService.RestartXray(false); err != nil {
			logger.Error("vpnclient job: egress flip restart xray failed:", err)
		}
	}
	for id := range j.egressLastUp {
		if !seen[id] {
			delete(j.egressLastUp, id)
		}
	}
}

// checkRouterLinkRouteGuard 是路由护栏（§4.2）的 job 侧轻量复检：
// 隧道 up 之后，路由表里只允许出现"LanSubnet 经本隧道接口"的路由，
// 默认路由绝不能经隧道接口（中转约束：隧道一律不碰默认路由）。
//
// 说明：C 组的 internal/vpnclient/guard.go 负责拨号时的护栏装配，但冻结的
// Manager 契约没有暴露独立的 guard 复检函数；Status().Message 也未约定告警
// 格式，故这里直接对比 `ip route` 输出做周期复检。C 组若后续暴露
// GuardCheck(link, iface) error，可直接替换本函数体。
func checkRouterLinkRouteGuard(link *model.RouterLink, iface string) error {
	if iface == "" {
		return fmt.Errorf("tunnel is up but reports no interface")
	}
	out, err := exec.Command("ip", "route", "show").Output()
	if err != nil {
		return fmt.Errorf("ip route: %w", err)
	}
	var lanOK, defaultHijacked bool
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		if f[0] == "default" {
			for i := 1; i+1 < len(f); i++ {
				if f[i] == "dev" && f[i+1] == iface {
					defaultHijacked = true
				}
			}
			continue
		}
		// 形如 "192.168.225.0/24 dev tun0 scope link ..."。
		if _, ipnet, perr := net.ParseCIDR(f[0]); perr == nil && ipnet.String() == link.LanSubnet {
			for i := 1; i+1 < len(f); i++ {
				if f[i] == "dev" && f[i+1] == iface {
					lanOK = true
				}
			}
		}
	}
	if defaultHijacked {
		return fmt.Errorf("default route goes via tunnel interface %s (must not touch default route)", iface)
	}
	if !lanOK {
		return fmt.Errorf("expected route %s via %s missing", link.LanSubnet, iface)
	}
	return nil
}
