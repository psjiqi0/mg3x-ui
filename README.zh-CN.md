# mg3x-ui

[English](README.md)

**mg3x-ui** 是 [3x-ui](https://github.com/MHSanaei/3x-ui) 的魔改版，核心功能只有一个：
**路由器中转**。

## 它是干什么的

面板不跑 VPN 服务端，而是做 **VPN 客户端**：由服务器主动拨号，连接到用户自己路由器上
跑着的 VPN 服务端（PPTP / WireGuard / OpenVPN，全部是**客户端模式**）。隧道通之后，
服务器的公网端口经隧道**转发进路由器内网**。

```
公网 → 服务器公网端口 → VPN 隧道 → 路由器内网设备
```

典型用法：把路由器内网里的设备（NAS、摄像头、管理后台）通过服务器公网 IP 发布出去，
不用动路由器防火墙，也不用求运营商给公网 IP。

## 主要特性

- **路由器连接**：管理 N 个路由器连接，服务器向每台路由器发起 VPN 拨号。
  支持三种客户端模式：**PPTP**、**WireGuard**、**OpenVPN**。
- **连接间完全隔离**：
  - PPTP：每个连接独立 `ppp` 接口（`ppp0`、`ppp1`……）。
  - WireGuard：每个连接独立的用户态 gVisor 协议栈——不建宿主机网卡、不写宿主机路由、
    不碰 iptables。
  - 多个连接的内网段重叠也不冲突。
- **端口转发**（`forwardedPorts`）：把服务器公网端口转发进路由器内网，
  例如 `8080 → 192.168.1.10:80`。
- **出口（egress）**：可选把某个入站的出站流量经隧道出去（绑定入站到连接）。
  每个连接在本地起一个 SOCKS5 代理对应其隧道。
- **Docker 部署**：单容器 all-in-one，host 网络，需要 `NET_ADMIN` +
  `/dev/net/tun` + `/dev/ppp`。

## 部署指南

要求：Docker + Docker Compose；Linux 宿主机有 `/dev/net/tun`、`/dev/ppp`
（内核 `wireguard`、`ppp_generic` 模块）。

```bash
git clone <本仓库> && cd mg3x-ui   # 分支：relay-client-mode
docker compose -f docker-compose.relay.yml build
docker compose -f docker-compose.relay.yml up -d
```

- 面板地址：`http://<服务器IP>:2053`（默认；首次登录请改掉临时密码）。
- 数据持久化：
  - `/etc/x-ui` → 宿主机 `/etc/x-ui`（SQLite `x-ui.db`；路由器连接的认证信息加密存储）。
  - `./routerlinks` → 自动生成的拨号配置（`.ovpn`、pppd options、`chap-secrets` 等）。

## 快速开始：添加路由器连接

面板 → **路由器连接** → **添加**。先从下拉框选协议，再填：

**通用字段**（三种协议都有）

| 字段 | 说明 |
|---|---|
| 名称 | 显示名，如 `home-pptp` |
| 对端地址 / 端口 | 路由器上 VPN 服务端的公网地址 |
| 路由器内网段 | 路由器 LAN 的 CIDR，如 `192.168.1.0/24` |
| 端口转发 | `公网端口 → 内网IP:内网端口` 规则（可选） |
| 经此隧道出公网 | 把绑定的入站流量经隧道出去（可选） |

**PPTP**：用户名、密码、MPPE 模式（推荐 `require-mppe-128`）。

**WireGuard**：私钥、对端公钥、预共享密钥（可选）、隧道地址（如 `10.10.10.2/32`）、
保活。与标准 `.conf` 的 `[Interface]` / `[Peer]` 段一一对应
（`Address`→隧道地址，`Endpoint`→对端地址/端口，`DNS` 不需要填）。

**OpenVPN**：密码模式（用户名/密码）或证书模式（ca/cert/key）。

编辑连接时，密码、私钥等敏感字段留空即表示保持原值，不用重填。

## 约束说明（设计如此）

- 隧道**绝不碰服务器默认路由**，**绝不动防火墙规则**。
- OpenVPN 使用 `route-nopull`；PPTP 使用 `nodefaultroute`。
- WireGuard `AllowedIPs` 默认只路由路由器内网段。设为 `0.0.0.0/0` 可让绑定的入站
  经路由器出公网（要求路由器做 NAT）；请确认理解后果后再用。

## 设计文档

完整架构说明见 [RELAY_DESIGN.md](RELAY_DESIGN.md)。

## 致谢

基于 [MHSanaei/3x-ui](https://github.com/MHSanaei/3x-ui) 修改。原面板的 VPN 服务端功能
全部保留；路由器中转是新增的能力。
