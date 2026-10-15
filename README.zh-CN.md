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

## 安装教程

### 环境要求

- Linux 服务器：Ubuntu 20.04+ / Debian 11+（x86_64 或 ARM64）
- 已安装 Docker + Docker Compose
- 内核模块：`wireguard`、`ppp_generic`（用 `modprobe wireguard ppp_generic` 加载）
- 设备节点：`/dev/net/tun` 和 `/dev/ppp` 必须存在（OpenVPN / PPTP 拨号需要）
- 开放端口：
  - `2053/TCP` —— 面板（可改）
  - 自建的入站端口（如 VLESS 9443）—— 按需在防火墙 / 云安全组放行

### 一步步安装

**1. 安装 Docker**（已安装可跳过）

```bash
curl -fsSL https://get.docker.com | sh
sudo systemctl enable --now docker
docker --version
docker compose version
```

**2. 克隆仓库**

```bash
git clone https://github.com/psjiqi0/mg3x-ui
cd mg3x-ui
# 默认分支：main
```

**3. 构建镜像**（首次构建需要几分钟）

```bash
docker compose -f docker-compose.relay.yml build
```

> **小内存机器（1G 内存）：** 前端构建需要约 2G 内存。
> 如果构建卡在 `vite build` 不动，先加 swap：
> ```bash
> sudo fallocate -l 2G /swapfile
> sudo chmod 600 /swapfile
> sudo mkswap /swapfile
> sudo swapon /swapfile
> ```
> 然后重新构建。（或者在大机器上构建好，用 `docker save`/`docker load` 搬镜像。）

**4. 启动容器**

```bash
docker compose -f docker-compose.relay.yml up -d
```

**5. 首次登录**

浏览器打开 `http://<服务器IP>:2053`，用首次启动时打印的默认账号密码登录
（`docker logs 3x-ui-src-3xui-relay-1` 可查）。**登录后立刻改密码**
（面板 → 个人资料，或 `mg3x-ui` 菜单 → 修改面板密码）。

**6. 安装 `mg3x-ui` 快捷命令**（可选，推荐）

```bash
curl -sSL https://raw.githubusercontent.com/psjiqi0/mg3x-ui/main/scripts/mg3x-ui.sh \
  -o /usr/local/bin/mg3x-ui && chmod +x /usr/local/bin/mg3x-ui
```

之后直接打 `mg3x-ui` 进交互菜单：

| 命令 | 作用 |
|---|---|
| `mg3x-ui` | 交互菜单 |
| `mg3x-ui status` | 容器 / 面板 / 路由器连接 / 隧道状态 |
| `mg3x-ui restart` | 重启面板容器 |
| `mg3x-ui logs` | 实时日志 |
| `mg3x-ui update` | 从 GitHub 拉更新、重建、重启 |
| `mg3x-ui links` | 列出路由器连接 |
| `mg3x-ui chpasswd` | 修改面板密码 |
| `mg3x-ui chport` | 修改面板端口 |

### 添加第一个路由器连接

见下文[快速开始：添加路由器连接](#快速开始添加路由器连接)。
简单说：面板 → **路由器连接** → **添加**，从下拉框选 PPTP / WireGuard / OpenVPN，
填对端地址和认证信息。以后编辑时，密码 / 私钥留空即保留原值，不用重填。

### 常见问题

**容器起不来？**
```bash
docker logs 3x-ui-src-3xui-relay-1 | tail -50
```
常见原因：2053 端口被占用、缺少 `/dev/net/tun` 或 `/dev/ppp`、
`x-ui.db` 权限问题。

**面板打不开？**
- 确认容器在运行：`docker ps | grep 3xui-relay`
- 检查防火墙 / 云安全组放行了 `2053/TCP`
- 在服务器本机试 `curl http://127.0.0.1:2053/`

**隧道拨不上？**
- PPTP：核对路由器上的用户名 / 密码 / MPPE；看容器日志里的 `pppd` 输出
- WireGuard：核对私钥 / 对端公钥 / 预共享密钥与路由器服务端一致；路由器服务端必须已添加这个客户端（peer）
- OpenVPN：核对用户名 / 密码或证书；确认路由器 OpenVPN 服务端在对应端口监听
- 确认路由器侧 VPN 服务端确实在运行、端口已放行

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
