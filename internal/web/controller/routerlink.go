package controller

// RouterLinkController（D 组）：路由器 VPN 客户端连接（中转）的 HTTP 层。
//
// 路由挂载在面板 basePath 之下：/panel/routerlink/*（路径冻结，E 组前端直接依赖）。
// 鉴权：挂载面板 session 登录中间件 BaseController.checkLogin（与面板其它
// 页面控制器同一机制）。注意与 InboundController 的区别：它的鉴权挂在父级
// /panel/api 分组的 checkAPIAuth 上（见 controller/api.go），而本路由直接位
// 于 basePath 下、不在 /panel/api 内，故在这里的分组上直接挂 checkLogin。

import (
	"strconv"

	"github.com/mhsanaei/3x-ui/v3/internal/web/service"

	"github.com/gin-gonic/gin"
)

// RouterLinkController handles HTTP requests for router VPN client links
// (relay client mode): CRUD, manual dial/hangup, live status.
type RouterLinkController struct {
	BaseController
	service service.RouterLinkService
}

// NewRouterLinkController creates a new RouterLinkController and sets up its routes.
func NewRouterLinkController(g *gin.RouterGroup) *RouterLinkController {
	a := &RouterLinkController{}
	a.initRouter(g)
	return a
}

// initRouter initializes the routes for router-link operations.
func (a *RouterLinkController) initRouter(g *gin.RouterGroup) {
	g = g.Group("/routerlink")
	g.Use(a.checkLogin)

	g.POST("/add", a.addRouterLink)
	g.POST("/update", a.updateRouterLink)
	g.POST("/del", a.delRouterLink)
	g.GET("/list", a.listRouterLinks)
	g.POST("/dial", a.dialRouterLink)
	g.POST("/hangup", a.hangupRouterLink)
	g.POST("/egress", a.setRouterLinkEgress)
	g.GET("/status/:id", a.getRouterLinkStatus)
}

// routerLinkIDForm 接收 {"id": N} 的请求体（del/dial/hangup）。
type routerLinkIDForm struct {
	Id int `json:"id"`
}

// addRouterLink 新增路由器连接。
// 请求：POST /panel/routerlink/add，body 为 RouterLinkDTO JSON（含 auth 明文）。
// 响应：{success, msg, obj:{id}}。
func (a *RouterLinkController) addRouterLink(c *gin.Context) {
	dto := &service.RouterLinkDTO{}
	if err := c.ShouldBindJSON(dto); err != nil {
		jsonMsg(c, "", err)
		return
	}
	id, err := a.service.Add(dto)
	if err != nil {
		jsonMsgObj(c, "添加失败", map[string]any{"id": id}, err)
		return
	}
	jsonMsgObj(c, "添加成功", map[string]any{"id": id}, nil)
}

// updateRouterLink 全量更新路由器连接。
// 请求：POST /panel/routerlink/update，body 为 RouterLinkDTO JSON（含 id；
// auth 为 null/缺省表示保持原有凭证不动）。
// 响应：{success, msg}。
func (a *RouterLinkController) updateRouterLink(c *gin.Context) {
	dto := &service.RouterLinkDTO{}
	if err := c.ShouldBindJSON(dto); err != nil {
		jsonMsg(c, "", err)
		return
	}
	if err := a.service.Update(dto); err != nil {
		jsonMsg(c, "保存失败", err)
		return
	}
	jsonMsg(c, "保存成功", nil)
}

// delRouterLink 删除路由器连接。
// 请求：POST /panel/routerlink/del，body {"id": N}。响应：{success, msg}。
func (a *RouterLinkController) delRouterLink(c *gin.Context) {
	form := &routerLinkIDForm{}
	if err := c.ShouldBindJSON(form); err != nil {
		jsonMsg(c, "", err)
		return
	}
	if err := a.service.Del(form.Id); err != nil {
		jsonMsg(c, "删除失败", err)
		return
	}
	jsonMsg(c, "删除成功", nil)
}

// routerLinkEgressForm 接收 {"id": N, "enable": true, "inboundTags": ["tag1", ...]}。
type routerLinkEgressForm struct {
	Id          int      `json:"id"`
	Enable      bool     `json:"enable"`
	InboundTags []string `json:"inboundTags"`
}

// setRouterLinkEgress 开关某连接的 egress（经隧道出公网）。
// 请求：POST /panel/routerlink/egress，body {id, enable, inboundTags}。
// 响应：{success, msg, obj:{socksPort}}；disable 时 socksPort 为 0。
func (a *RouterLinkController) setRouterLinkEgress(c *gin.Context) {
	form := &routerLinkEgressForm{}
	if err := c.ShouldBindJSON(form); err != nil {
		jsonMsg(c, "", err)
		return
	}
	port, err := a.service.SetEgress(form.Id, form.Enable, form.InboundTags)
	if err != nil {
		jsonMsgObj(c, "egress 设置失败", map[string]any{"socksPort": 0}, err)
		return
	}
	if form.Enable {
		jsonMsgObj(c, "egress 已开启", map[string]any{"socksPort": port}, nil)
		return
	}
	jsonMsgObj(c, "egress 已关闭", map[string]any{"socksPort": 0}, nil)
}

// listRouterLinks 返回全部路由器连接。
// 响应：{success, obj:[{...RouterLinkDTO..., status, handshakeAt, rxBytes,
// txBytes, message}]}；auth 只给 hasAuth 布尔，不给明文。每项额外带上
// egress/egressInboundTags/egressSocksPort（socksPort 以 DB 值为准）。
func (a *RouterLinkController) listRouterLinks(c *gin.Context) {
	links, err := a.service.List()
	if err != nil {
		jsonObj(c, nil, err)
		return
	}
	jsonObj(c, links, nil)
}

// dialRouterLink 手动拨号。
// 请求：POST /panel/routerlink/dial，body {"id": N}。响应：{success, msg}。
func (a *RouterLinkController) dialRouterLink(c *gin.Context) {
	form := &routerLinkIDForm{}
	if err := c.ShouldBindJSON(form); err != nil {
		jsonMsg(c, "", err)
		return
	}
	if err := a.service.Dial(form.Id); err != nil {
		jsonMsg(c, "拨号失败", err)
		return
	}
	jsonMsg(c, "已发起拨号", nil)
}

// hangupRouterLink 手动挂断。
// 请求：POST /panel/routerlink/hangup，body {"id": N}。响应：{success, msg}。
func (a *RouterLinkController) hangupRouterLink(c *gin.Context) {
	form := &routerLinkIDForm{}
	if err := c.ShouldBindJSON(form); err != nil {
		jsonMsg(c, "", err)
		return
	}
	if err := a.service.Hangup(form.Id); err != nil {
		jsonMsg(c, "挂断失败", err)
		return
	}
	jsonMsg(c, "已挂断", nil)
}

// getRouterLinkStatus 返回单条连接的实时隧道状态。
// 响应：{success, obj: LinkStatus{id,status,handshakeAt,rxBytes,txBytes,message,iface}}。
func (a *RouterLinkController) getRouterLinkStatus(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil || id <= 0 {
		jsonObj(c, nil, err)
		return
	}
	st, err := a.service.Status(id)
	if err != nil {
		jsonObj(c, nil, err)
		return
	}
	jsonObj(c, st, nil)
}
