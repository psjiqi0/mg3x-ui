# 3x-ui 中转集合地：客户端模式架构设计方案

> 状态：技术调研 / 设计文档，不含实现代码。
> 源码位置：`/root/3x-ui-src`（MHSanaei/3x-ui v3，`go.mod`：`go 1.27.2`）
> 目标服务器：`130.162.192.59`（Ubuntu 24.04，内核 `6.17.0-1020-oracle`，Docker 已装）
>
> **架构纠正（2026-10-14，用户亲口拍板，推翻 v1 版服务端假设）**：
> PPTP、标准 WireGuard、OpenVPN 全部是**客户端模式**——由服务器主动拨号连接到用户名下的
> 各路由器（路由器上跑 VPN 服务端）。**绝不在服务器上建 VPN 服务端**。
> "中转"的含义 = **服务器公网端口 → 经隧道 → 转发进路由器内网**。
>
> 决策（用户拍板）：**整个方案基于 Docker 运行（docker-compose），不直接在主机上装服务。**
>
> 实测先例：PROSCEND 路由器 OpenVPN 服务端，已有从本机 `route-nopull` 拨号成功的记录
> （隧道通，拿到 `192.168.225.6`）。

## 0. 目标与约束

面板管理 **N 个"路由器连接"**（RouterLink），每个连接由服务器向一台路由器发起 VPN 拨号，
隧道通后把服务器公网端口的流量转发进该路由器内网。

硬约束（用户要求）：

- **不得影响服务器自身网络**：不动默认路由、不动现有 iptables/nftables 规则、
  不占用已有子网。所有新增的路由/规则限定在自家作用域、可自清理。
- 已有子网（2026-10-14 服务器实测）：`10.0.0.57/24`（服务器内网）、`192.168.225.0/24`
  （路由器 OpenVPN 内网）、`172.17.0.0/16`（docker0）。宿主机 `FORWARD` 链策略为 **DROP**。
- 宿主机内核已就绪（实测）：`wireguard.ko`、`ppp_generic`(builtin)、`ip_gre.ko`、
  `/dev/ppp` 存在——容器使用这些能力**无需在主机装任何软件**。
- 只调研、不写实现代码、不装软件、不改现有源码文件。

---

## 1. 现有协议体系（v1 调研结论，保留）

### 1.1 Protocol 常量（`internal/database/model/model.go`）

```
VMESS="vmess"  VLESS="vless"  Tunnel="tunnel"  HTTP="http"  Trojan="trojan"
Shadowsocks="shadowsocks"  Mixed="mixed"  WireGuard="wireguard"  Hysteria="hysteria"
MTProto="mtproto"  AmneziaWG="amneziawg"  TUIC="tuic"  MASQUE="masque"
```

第 68 行 `Inbound.Protocol` 的 validate tag：
`oneof=vmess vless trojan shadowsocks wireguard hysteria http mixed tunnel tun mtproto amneziawg tuic masque`
—— `wireguard` 已在白名单，**新增协议只需加 `pptp`**（注意：这是给"入站"用的；
"路由器连接"是新实体，见 §9，不必复用 Inbound 表）。

### 1.2 WireGuard 目前做到哪一步（结论：只有"皮"，没有"引擎"）

| 层 | 文件 | 状态 |
|---|---|---|
| model 常量 | `internal/database/model/model.go:32` | ✅ 有 |
| 前端 schema | `frontend/src/schemas/protocols/inbound/wireguard.ts` | ✅ 有 |
| 前端表单页 | `frontend/src/pages/inbounds/form/protocols/wireguard.tsx` | ✅ 有 |
| 后端客户端辅助 | `internal/web/service/client_wireguard.go`（305 行） | ⚠️ 只有子网解析/客户端增删辅助，无专用 Go struct |
| 后端入站服务 | `internal/web/service/inbound_wireguard.go` | ❌ 不存在 |
| 实例管理器/引擎 | 对标 `internal/amneziawgnet` 的 wireguard 包 | ❌ 不存在 |
| runtime 钩子 | `internal/web/runtime/local.go` | ❌ 无 WireGuard 分支 |
| 定时收敛 job | `internal/web/job/` | ❌ 无 |

### 1.3 AmneziaWG 三层结构（保持服务端模式不变，是 WG 客户端引擎的复用模板）

```
internal/amneziawg/            ① 协议形状层（无 OS 依赖，纯函数 + DB 形状）
  types.go        Instance / Peer / Obfuscation31 / ServerSettings / InboundSettings
  instance.go     InstanceFromInbound(*model.Inbound) (Instance, bool)
  portfwd.go      ForwardedPortsInclude / ExpandForwardedPorts / MaxForwardedPorts=100
  params.go       GenerateObfuscation31 / ValidateServerObfuscation / ValidateSubnetIPv4 等

internal/amneziawgnet/         ② 嵌入式引擎层（amneziawg-go + gVisor netstack，用户态）
  manager.go      Manager 单例：GetManager / Ensure / Reconcile / Remove（按 inbound id key）
  device.go       Device / NewDevice / DeviceOptions / buildUAPIConfig（UAPI 下发配置）
  netstack.go     gVisor stack 搭建（stackTun over channel.Endpoint）
  portfwd.go      PortForwardSet：per-(email,port,tcp/udp) 监听 → 直拨 netstack
  portfwd_udp.go  UDP 转发
  forwarder.go    AttachTCPForwarder（promiscuous 模式抓隧道出方向 TCP）
  relay.go        SocksRelay：出方向流量 relay 进 Xray 的 SOCKS5（username=email 计流量）

internal/web/service/inbound_amneziawg.go   ③ 面板集成层（429 行）
internal/web/job/amneziawg_job.go           ③ 定时收敛（每 10s）
internal/web/runtime/local.go               ③ 本地 runtime 钩子
```

**与本方案相关的关键事实**：

- `DeviceOptions` 全留空时，`buildUAPIConfig` 下发的是**标准 WireGuard 配置**
  （`device.go:24-62` 注释确认：零值 = amneziawg-go 真实协议默认值）。
  即现有 `amneziawgnet` 引擎把混淆参数清零就是标准 WG 用户态引擎。
- 该引擎**完全跑在用户态**（gVisor netstack，无真实网卡、无主机路由、无 iptables），
  是"不影响服务器网络"的天然载体——客户端模式下这个性质更有价值（见 §7）。
- `amneziawgnet.Manager` 按 **inbound id** key。路由器连接是新实体，
  实现时用**独立的 Manager 实例**（或 key 命名空间隔离），与 AmneziaWG 服务端入站不冲突。

---

## 2. AmneziaWG 服务端中转调用链（v1 调研结论，保留；该路径保持服务端模式不变）

```
前端表单页 frontend/src/pages/inbounds/form/protocols/amneziawg.tsx
  → POST /panel/inbound/add
    → internal/web/service/inbound.go:1231 InboundService.AddInbound
      → inbound_amneziawg.go: normalizeAmneziaWGSettings(inbound, "")   // 生成/校验 server 块
      → inbound_amneziawg.go: amneziaWGForwardedPortsConflict           // 端口冲突预检
          → checkForwardedPortsConflict(ctx, forwardedPorts)           // 查面板端口/各入站端口/各 SOCKS 中继端口
      → db Save
      → inbound_amneziawg.go: checkAmneziaWGForwardedPorts             // 存后复检
      → inbound_node.go:45 runtimeFor(ib) → runtime.GetManager().RuntimeFor(nil)
      → internal/web/runtime/local.go:59 Local.AddInbound
          → amneziawg.InstanceFromInbound(ib)        // internal/amneziawg/instance.go
          → amneziawgnet.GetManager().Ensure(amneziawgnet.Desired{Instance, Options})
              → internal/amneziawgnet/manager.go: ensureLocked
                  → device.go: NewDevice(inst, opts)  // amneziawg-go Device + gVisor stack
                  → portfwd.go: NewPortForwardSet(gstack, inboundID)
                  → forwarder.go: AttachTCPForwarder / udp.go: AttachUDPHandler
```

转发语义（服务端模式）：host 监听 `forwardedPorts` → `gonet.DialContextTCP(gstack, …)`
直拨 peer 的隧道内地址。`PortForwardSet.Reconcile` 做增量启停，`Close()` 全关。

---

## 3. 客户端模式总架构

### 3.1 核心实体：路由器连接（RouterLink）

```jsonc
{
  "id": 7,
  "name": "深圳-主路由",
  "protocol": "openvpn | pptp | wireguard",   // 三选一
  "enabled": true,
  // —— 对端（路由器 VPN 服务端）——
  "remoteHost": "203.0.113.44",
  "remotePort": 51194,                        // ovpn: 服务端端口；pptp: 1723；wg: 对端 UDP 端口
  "lanSubnet": "192.168.225.0/24",            // 路由器内网段（只路由这个，见 §4）
  // —— 认证（加密存储，见 §12）——
  "auth": { "type": "password | cert | psk",
            "username": "…", "password": "…",
            "ca": "…", "cert": "…", "key": "…",          // openvpn 内联
            "privateKey": "…", "peerPublicKey": "…", "presharedKey": "…" },  // wg
  // —— 本端隧道地址（wg 客户端需要；ovpn/pptp 由对端推送）——
  "tunnelAddress": "192.168.225.6/24",         // 可空
  // —— 中转：服务器公网端口 → 路由器内网目标 ——
  "forwardedPorts": "8080->192.168.225.10:80, 8443->192.168.225.10:443",
  //    扩展语法：pubPort -> lanIP:lanPort（与 AmneziaWG 服务端的裸端口语法区分，见 §8）
  "status": "up | down | dialing"              // 运行时状态（不存库，由 manager 上报）
}
```

### 3.2 数据流

```
公网请求 ──▶ 服务器:forwardedPorts 监听 (host 网络模式容器内 Go 监听器)
                │
                ▼
        ┌───────────────┐
        │ 隧道 (按协议)  │
        │ ovpn: tunX     │
        │ pptp: pppX     │
        │ wg:   gVisor   │  ◀── 用户态，无主机接口
        │       netstack │
        └───────────────┘
                │
                ▼
        路由器内网 IP:端口 (如 192.168.225.10:80)
```

- WG：监听器在宿主网络命名空间 bind 公网端口（host 模式），`gonet.DialContextTCP`
  在**该连接独占的 gVisor stack** 内拨号 → 经 WG 隧道 → 路由器。
- OpenVPN/PPTP：监听器同样 bind 公网端口，Go 直接 `net.Dial` 路由器内网地址；
  容器路由表里只有该隧道的 scoped 路由（`192.168.225.0/24 via tun0`），包自然走隧道；
  多连接内网段重叠时用 `SO_BINDTODEVICE` 把 socket 钉到对应 `tunX`/`pppX`（见 §8.3）。

### 3.3 进程/线程模型（单面板容器，见 §11）

```
3x-ui 面板容器 (network_mode: host, NET_ADMIN, /dev/net/tun, /dev/ppp)
├── 面板主进程 (Go)
│   ├── vpnclient.Manager          // 新：按 RouterLink id 管理连接生命周期
│   │   ├── WG:   amneziawgnet client-role Device (in-process, 每连接一个 gVisor stack)
│   │   ├── OVPN: openvpn 子进程 ×N (per-连接 config + --management 本地 socket)
│   │   └── PPTP: pppd 子进程 ×N (pty "pptp <host> --nolaunchpppd")
│   ├── PortForwardSet(扩展版)      // per-连接的公网端口监听器
│   └── vpnclient_job (每 10s)     // 收敛：重连、路由护栏复检、状态上报
```

子进程托管参照现有模式：`internal/xray/process.go`、`internal/mtproto/process.go`
（面板已有成熟的子进程启停/看护写法）。

---
## 4. 路由安全（最高优先级）

**铁律：三个客户端都严禁改默认路由、严禁接受对端推送的网关/DNS。**
隧道只承载"路由器内网段"，服务器的公网出入是它自己的事。

### 4.1 各协议的具体做法

| 协议 | 做法 |
|---|---|
| OpenVPN | `--route-nopull`（已有 PROSCEND 实测先例）+ 显式 `--route <lanSubnet> vpn_gateway`；再加 `--pull-filter ignore "redirect-gateway"` 做双保险。DNS：`--pull-filter ignore "dhcp-option DNS"`，或干脆不装 `--up` 脚本碰 resolv.conf |
| PPTP/pppd | options 文件写死 `nodefaultroute`（绝不用 `defaultroute`）；`ip-up` 脚本**只**加 `lanSubnet` 的 scoped 路由（`ip route add <lan> dev $IFNAME`），`ip-down` 删掉。不装 `usepeerdns` |
| WireGuard（用户态） | 路由只活在 gVisor sandbox 里（`netstack.go` 的默认路由是 stack 内部的），宿主机零感知。`AllowedIPs` 只填 `lanSubnet`，**绝不用 `0.0.0.0/0`**；非 AllowedIPs 的包被 amneziawg-go 的 cryptokey 路由直接丢弃在用户态 |
| WireGuard（内核备选） | 不用 `wg-quick`（它会按 AllowedIPs 写路由，配错 `0.0.0.0/0` 就接管默认路由）；用裸 `wg set` + 手工 `ip route add <lan> dev wgX`，脚本化、可审计 |

### 4.2 路由护栏（Route Guard）

连接建立**前后**各做一次断言，失败就告警并撕掉连接：

1. 拨号前：`snapshot = ip route show default`（存内存）。
2. 隧道 up 后（ovpn: management `state` → CONNECTED；pptp: ip-up 触发；wg: 首次握手完成）：
   对比当前默认路由 vs snapshot，不一致 → `logger.Error` + 杀连接 + 面板红字告警。
3. `vpnclient_job` 每次 tick（10s）复检一次默认路由指纹，漂移即告警。

ovpn 的 `--route-nopull` + pppd 的 `nodefaultroute` 是第一道防线，护栏是第二道。
两者是"纵深"关系，不是二选一。

---

## 5. OpenVPN 客户端方案

### 5.1 形态：openvpn 可执行文件作被管子进程

- 面板按连接生成 config 文件（`0600`，路径见 §11），内联 `ca/cert/key`
  （`<ca>…</ca>` 块，避免满地散文件），认证走 `auth-user-pass <file>`（`0600`）。
- 关键 flags（面板生成，**用户不可改**，防手滑）：
  ```
  client
  dev tun
  proto udp                    # 或 tcp，按路由器服务端来
  remote <remoteHost> <remotePort>
  route-nopull
  pull-filter ignore "redirect-gateway"
  pull-filter ignore "dhcp-option DNS"
  route <lanSubnet> vpn_gateway  # 由面板按 lanSubnet 生成，可多条
  persist-tun
  persist-key
  keepalive 10 60
  remap
  connect-retry 5 30
  management 127.0.0.1 <port>   # per-连接分配本地端口，或 unix socket
  ```
- 状态监控：`--management` 查 `state`（CONNECTED/RECONNECTING）、`status` 取字节计数做流量统计。
- 断线自愈：openvpn 自带重连（`connect-retry`）；进程崩溃由 `vpnclient.Manager` +
  `vpnclient_job` 按 backoff 重启（参照 `internal/mtproto/process.go` 的看护写法）。

### 5.2 Docker 需求

- `apk add openvpn`（Alpine 官方源有）。
- `/dev/net/tun` 设备映射 + `NET_ADMIN` capability（建 tun 所需）。
- host 网络模式下 tun 接口建在容器 netns = 宿主 netns，接口名用 `ovpn-<linkid>` 避免冲突；
  路由条目是 scoped 的（只含 lanSubnet），满足约束。

### 5.3 与 PROSCEND 实测的对应关系

已有实测：`route-nopull` + 临时路由拿到 `192.168.225.6`、隧道通。
本方案就是把那次手工操作**面板化、持久化、多连接化**：config 模板化、路由条目由
`lanSubnet` 生成、护栏代替人肉检查。

---

## 6. PPTP 客户端方案

### 6.1 形态：pptp-linux + pppd

- 连接命令（面板拼装，子进程托管）：
  ```
  pppd pty "pptp <remoteHost> --nolaunchpppd" \
       name <username> remotename <profile> \
       file /etc/x-ui/routerlinks/<id>/options.pptp
  ```
- `options.pptp`（面板生成，用户不可改）：
  ```
  nodefaultroute     # 铁律：不碰默认路由
  noipdefault
  usepeerdns  → 不写（不要对端 DNS）
  require-mppe-128   # 可按路由器能力降级为 require-mppe（面板选项）
  noauth             # 这是"不要求对端认证我方"，不是免密；我方认证走 chap-secrets
  ```
- 认证：`chap-secrets` 文件（`0600`），面板按连接生成条目
  `<username> <remotename> <password> *`，多连接可共用一个文件（pppd 支持多行）。
- 路由：`ip-up.d/` 脚本（面板安装，幂等）只做一件事：
  `ip route add <lanSubnet> dev $IFNAME`（`$IFNAME` 即 `pppX`，pppd 环境变量传入）；
  `ip-down.d/` 做反向清理。脚本里**不写任何**默认路由/DNS 逻辑。
- 状态/流量：`ip-up`/`ip-down` 回调上报 up/down；流量走 `/proc/net/ppp` 或
  `ip -s link show pppX` 计数（job 周期采集）。

### 6.2 Docker 需求

- `apk add ppp pptpclient`（Alpine 官方源有 `pptpclient`，即 pptp-linux）。
- `/dev/ppp` 设备映射 + `NET_ADMIN`。
- **GRE（IP 协议 47）**：host 网络模式下容器直接用宿主协议栈，`ip_gre.ko` 已在宿主机就绪；
  出站 GRE 即 `pptp` 进程发的协议 47 包，无需端口映射（这是 v1 服务端方案被迫 host 模式的
  原因之一，客户端模式下同样自然成立）。
- 接口名 `pppX` 由内核分配，面板通过 ip-up 回调的 `$IFNAME`/`$IPLOCAL` 关联回连接 id
  （用 `unit`/`linkname` 或环境变量透传 id，最稳的是 `pppd … linkname rl-<id>`，
  ip-up 脚本读 `$LINKNAME`）。

### 6.3 协议定位（诚实标注）

PPTP 的 MPPE/CHAPv2 在现代视角下是弱加密。**只用于兼容只会拨 PPTP 的老旧路由器**，
面板 UI 上对 PPTP 连接打"兼容模式"标识，不作为推荐协议。

---

## 7. WireGuard 客户端方案

### 7.1 结论：复用现有 `amneziawgnet` 用户态引擎，加"客户端角色"

WireGuard 握手是**对称**的：配好本端私钥 + 对端公钥 + 对端 endpoint，设备就会主动发起握手。
"客户端"不是另一种协议，只是另一种配置形状。已查清的事实：

| 检查项 | 结论 |
|---|---|
| `buildUAPIConfig`（`device.go:182`） | 目前下发 `private_key` / `listen_port` / per-peer `public_key`+`preshared_key`+`allowed_ip`；**缺 `endpoint=` 与 `persistent_keepalive_interval=`**——实现时给 `amneziawg.Peer` 加 `Endpoint`/`PersistentKeepalive` 字段并补两行 UAPI 下发（约 10 行改动） |
| amneziawg-go 的 UAPI 是否认 `endpoint=` | amneziawg-go 继承 wireguard-go 的 UAPI 解析（`device/uapi.go`），`endpoint`/`persistent_keepalive_interval` 是标准键——**实现阶段用单测锁定**（模块缓存不在服务器上，本次未逐行验证，诚实标注） |
| gVisor 内路由注入 | `netstack.go: createNetTUNWithStack` 已给 NIC 1 加 `0.0.0.0/0` 默认路由（**sandbox 内部**）；对端内网段靠 peer `AllowedIPs=[lanSubnet]` 做 cryptokey 路由——即"注入"就是 AllowedIPs 本身，无需额外代码 |
| 宿主机影响 | **数学上为零**：没有真实网卡、不写主机路由、不碰 iptables；非 AllowedIPs 包在用户态直接丢弃 |
| 本端隧道地址 | `Instance.Address` 填面板分配/用户填写的隧道 IP（如 `192.168.225.6/32`），`AddProtocolAddress` 进 stack 即可 |
| NAT 穿透 | 服务器有公网 IP，握手由服务器侧发起；`persistent_keepalive_interval=25` 保持路由器侧 NAT 会话（如路由器在 NAT 后） |

客户端角色与服务端角色的**差异清单**（实现时在 `amneziawgnet` 内新增，不动服务端路径）：

1. 不 attach `SocksRelay` / promiscuous forwarder（那是"把客户端流量送公网"的服务端语义；
   客户端模式的出方向只有端口转发 dial，见 §8）。
2. `Manager` 用**独立实例**（key = RouterLink id），与 AmneziaWG 服务端的
   `GetManager()`（key = inbound id）隔离。
3. `PortForwardSet` 的目标解析改用扩展语法（§8.2），不再从 AllowedIPs 猜 tunnel 地址。

### 7.2 备选：内核 wg 接口做客户端（不推荐）

`ip link add wg-rl<id> type wireguard` + `wg set … peer … endpoint … allowed-ips <lanSubnet>` +
手工 `ip route add <lan> dev wg-rl<id>`。宿主机影响也可控（不用 wg-quick 即可），
但要多管一套接口生命周期、与现有 `amneziawgnet` 代码零复用。**推荐用户态**：
同一套引擎、同一套转发代码、天然隔离、单测可覆盖。

---

## 8. 端口转发进隧道（公网端口 → 路由器内网）

### 8.1 forwardedPorts 语法扩展（客户端模式）

```
8080->192.168.225.10:80, 8443->192.168.225.10:443
```

- `pubPort -> lanIP:lanPort`，逗号分隔；TCP/UDP 各开一个监听（沿用现有双协议习惯）。
- 与 AmneziaWG **服务端**的裸端口语法（`80, 443` = 转发到 peer 隧道地址同端口）**并存**：
  解析时按是否含 `->` 区分，服务端路径零改动。
- `lanIP` 必须落在该连接的 `lanSubnet` 内（保存时校验，防手误把流量送错地方）。

### 8.2 WG（用户态）：直接复用 PortForwardSet

- 每连接一个 `PortForwardSet`（已是 per-Device 设计，`manager.go: ensureLocked`
  每次重建 Device 时连带重建，正好对应"连接启停清理"）。
- 目标解析函数换成扩展语法的解析结果：`map[pubPort]lanAddr`。
- 监听器 bind 在 host 网络命名空间的公网端口（host 模式容器 = 宿主端口），
  `gonet.DialContextTCP(gstack, lanIP:lanPort)` 在**该连接独占的 stack** 内拨号。
- **多连接内网段重叠天然无冲突**：每个连接有自己的 gVisor stack，
  A 连接的 `192.168.1.10` 和 B 连接的 `192.168.1.10` 活在两个 sandbox 里，
  目标解析也是 per-连接的。零额外工作。

### 8.3 OpenVPN/PPTP（内核 tun/ppp 接口）：推荐 (b) Go 用户态 forwarder

对比两种实现：

| | (a) 容器内 iptables DNAT + scoped FORWARD 链 | (b) Go 用户态 forwarder（推荐） |
|---|---|---|
| 原理 | `PREROUTING -p tcp --dport 8080 -j DNAT --to 192.168.225.10:80` + 放行 FORWARD | 监听公网端口 → `net.Dial` 路由器内网地址，`io.Copy` 双向 |
| 主机网络影响 | 要写 NAT/forward 规则（虽可 scoped+自清理，仍是动防火墙） | **零**：不写任何规则；出方向走容器路由表已有的 scoped 隧道路由 |
| per-连接启停清理 | 删规则（顺序、幂等、崩溃残留都是坑） | `listener.Close()` 一行，`Reconcile` 增量对账（现有代码已实现该模式） |
| 状态/流量 | 需 `conntrack -L` 反查，难归因到连接 | accept 循环里直接计数，天然 per-连接 |
| 性能 | 内核态，高 | 用户态拷贝，中转场景（管理口、摄像头、内网服务）足够 |
| 与现有代码复用 | 无 | 复用 `PortForwardSet` 的监听/对账/关闭模式（换掉 dial 目标即可） |

**内网段重叠解法（真实坑，推荐方案）**：socket 上设 `SO_BINDTODEVICE=tunX/pppX`
（Go: `net.ListenConfig.Control` + `unix.SetsockoptString(SOL_SOCKET, SO_BINDTODEVICE)`，
dial 端同样），把该连接的转发 socket **钉死**在它自己的隧道接口上。
Linux 对绑定设备的 socket 做设备作用域的路由查找，两个连接都是 `192.168.1.0/24`
也不会串（A 走 tun0、B 走 tun1，各自确定）。**无需 NETMAP、无需额外路由表、
无需 netns**——这是比 v1 设想更干净的答案。

### 8.4 目标校验

转发 dial 的目标 IP 必须在连接的 `lanSubnet` 内（`§8.1` 保存时已校验；
运行时再断言一次，防 DB 被外部改写）。

---
## 9. 面板集成点清单（修订版）

### 9.1 新实体 RouterLink（不复用 Inbound 表）

理由：Inbound 是"服务端入站"语义（端口/协议/Xray 关联），RouterLink 是"客户端拨号"
语义，两者字段几乎不重叠。硬塞进 Inbound 会污染现有校验与订阅逻辑。

- `internal/database/model/router_link.go`：`RouterLink` struct（字段见 §3.1；
  `auth` 存 JSON 加密串，见 §12.4）。GORM 新表 `router_links`， migration 参照
  `internal/database/db.go` 现有写法。
- `internal/web/service/routerlink.go`：CRUD + `validateRouterLink`
  （lanSubnet 合法性、forwardedPorts 扩展语法解析、目标 IP 落在 lanSubnet 内、
  认证字段按协议齐备性检查）。
- `internal/vpnclient/`（新包，子进程/引擎托管层）：
  - `manager.go`：`Manager`（key = RouterLink id）：`Ensure/Remove/Reconcile/Status`
  - `wireguard.go`：amneziawgnet 客户端角色装配（§7.1 的 3 点差异）
  - `openvpn.go`：config 生成 + `exec.Command("openvpn", …)` 托管 + management 查询
  - `pptp.go`：options/chap-secrets 生成 + `exec.Command("pppd", …)` 托管 +
    ip-up.d/ip-down.d 脚本安装
  - `portforward.go`：扩展语法的 PortForwardSet（WG 复用 amneziawgnet 版；
    ovpn/pptp 用 §8.3(b) 的 dial 版，共用对账模式）
  - `guard.go`：路由护栏（§4.2）
- `internal/web/job/vpnclient_job.go`：每 10s tick——对账期望状态（enabled 的连接必须 up）、
  崩溃重启（backoff）、路由护栏复检、流量/状态采集入库（或内存快照由 controller 读）。
- `internal/web/controller/routerlink.go`：`POST /panel/routerlink/add|del|update`、
  `GET /panel/routerlink/list`、`POST /panel/routerlink/dial|hangup`（手动拨号/挂断）、
  `GET /panel/routerlink/status/:id`（隧道状态、握手时间、流量）。
- 前端：新页面"路由器连接"（列表 + per-协议表单：`routerlink-ovpn.tsx` /
  `routerlink-pptp.tsx` / `routerlink-wg.tsx`），状态灯（up/down/dialing），
  一键"测试拨号"。

### 9.2 settings JSON 示例（存 RouterLink 行内，或拆字段——实现时定，这里给形状）

```jsonc
// OpenVPN
{ "protocol": "openvpn",
  "remoteHost": "203.0.113.44", "remotePort": 51194, "proto": "udp",
  "lanSubnet": "192.168.225.0/24",
  "auth": { "type": "password", "username": "vpnuser", "password": "…(加密)" },
  // 或 "type": "cert", "ca": "…", "cert": "…", "key": "…"
  "forwardedPorts": "8080->192.168.225.10:80" }

// PPTP
{ "protocol": "pptp",
  "remoteHost": "203.0.113.45",
  "lanSubnet": "192.168.1.0/24",
  "auth": { "type": "password", "username": "pptpuser", "password": "…(加密)" },
  "mppe": "require-mppe-128",
  "forwardedPorts": "3389->192.168.1.20:3389" }

// WireGuard
{ "protocol": "wireguard",
  "remoteHost": "203.0.113.46", "remotePort": 51820,
  "lanSubnet": "192.168.2.0/24",
  "tunnelAddress": "192.168.2.6/32",
  "auth": { "type": "psk", "privateKey": "…(加密)", "peerPublicKey": "…", "presharedKey": "…(加密, 可空)" },
  "persistentKeepalive": 25,
  "forwardedPorts": "8080->192.168.2.10:80" }
```

### 9.3 状态监控

| 协议 | up/down 判定 | 握手/在线 | 流量 |
|---|---|---|---|
| WG 用户态 | amneziawg-go Device peer 握手时间戳（UAPI dump `last_handshake_time`，>0 且 180s 内为在线） | 同左 | Device per-peer 收发计数（UAPI `rx_bytes`/`tx_bytes`） |
| OpenVPN | management `state` → CONNECTED | `state` 时间 | management `status` 的 `TCP/UDP read/write bytes` |
| PPTP | ip-up/ip-down 回调 + `pppX` 接口存在性 | ip-up 时间戳 | `ip -s link show pppX` 计数（job 周期采） |

### 9.4 forwardedPorts 冲突检测（复用并扩展）

现有 `checkForwardedPortsConflict`（`inbound_amneziawg.go:364`）查的是
"面板端口/各入站端口/各 SOCKS 中继端口"。RouterLink 的 forwardedPorts 监听的是
**同一批宿主端口**，必须纳入同一冲突域：保存 RouterLink 时复用该函数，
把"其他 RouterLink 的 forwardedPorts"加进冲突上下文。扩展语法的 `pubPort` 部分
参与冲突计算（`lanIP:lanPort` 部分不参与——那是隧道另一头）。

---

## 10. 防火墙（修订版：客户端模式的大简化）

**客户端模式全部是出站拨号，入站方向不需要为 VPN 协议开任何端口**——
这是相对 v1（服务端模式）最大的简化，明确写死：

| 方向 | v1 服务端模式需要 | v2 客户端模式需要 |
|---|---|---|
| 入站 UDP（WG 监听） | 是 | **否**（WG 只向外打洞/握手） |
| 入站 TCP 1723 + GRE 47（PPTP 服务端） | 是 | **否**（pptp 是向外拨 TCP 1723，GRE 回包走 conntrack/出站允许） |
| 入站 UDP（OpenVPN 服务端） | 是 | **否**（openvpn 客户端只向外连） |
| 入站 forwardedPorts | 是 | 是（这才是要从公网访问的端口，按用户需求在 OCI 安全列表/宿主防火墙放行） |

- 宿主机现有 iptables/nftables **一条不加**：出站默认 ACCEPT，conntrack 处理回包；
  用户态转发（§8.3(b)）不经过 FORWARD 链（是本机终结+本机发起的两段 socket，
  不是转发）。
- 唯一的新增网络 footprint（全部 scoped、可自清理）：
  - ovpn/pptp 的 `lanSubnet via tunX/pppX` 路由（连接拆除时由 openvpn/pppd 或
    ip-down 脚本自动删；护栏只做断言不写规则）。
  - 就这些。没有 SNAT、没有 DNAT、没有自定义链。
- forwardedPorts 监听端口的公网可达性：用户在 OCI 控制台安全列表放行对应 TCP/UDP 端口
  （面板保存时可提示"该端口需在安全组放行"）。

---

## 11. docker-compose 草案（修订版）

### 11.1 推荐：单面板容器（all-in-one）

```yaml
services:
  3xui-relay:
    build: .
    network_mode: host          # VPN 拨号 + forwardedPorts 公网监听都需要宿主网络视角
    cap_add:
      - NET_ADMIN               # 建 tun/ppp 接口、写 scoped 路由
    devices:
      - /dev/net/tun:/dev/net/tun
      - /dev/ppp:/dev/ppp
    volumes:
      - /etc/x-ui:/etc/x-ui
      - ./routerlinks:/etc/x-ui/routerlinks   # 生成的 ovpn config / pppd options /
                                              # chap-secrets / ip-up.d 脚本（0600）
    environment:
      - XUI_IN_DOCKER=true
    restart: unless-stopped
```

- 镜像：在现有 Dockerfile final 阶段加 `apk add openvpn pptpclient ppp`
  （Alpine 官方源均有）。
- 不挂 `docker.sock`（面板不直接操作 Docker，一切在容器内进程级完成）。
- WG 无独立服务（in-process 用户态引擎）。

### 11.2 备选：独立 vpn-client 边车容器（不推荐）

面板容器 + `vpnclient` 边车容器（同样 host 模式/NET_ADMIN/devices），两者经
volume 共享配置 + 面板调边车的 HTTP/management 接口。隔离性略好，但：
配置同步、状态回传、双容器启停顺序都是新增复杂度；单容器内 `Manager` 直接管
子进程/引擎，心跳和状态都在一个进程里。**推荐单容器**。

### 11.3 volume 规划

```
/etc/x-ui/
├── x-ui.db                      # 现有：RouterLink 表新增在这里，auth 字段加密存
└── routerlinks/
    ├── <id>/client.ovpn          # 生成的 openvpn config（0600）
    ├── <id>/auth.txt             # openvpn 用户名密码（0600）
    ├── <id>/options.pptp         # pppd options（0600）
    ├── chap-secrets               # pppd 认证（0600，可多连接共用）
    ├── ip-up.d/rl-route           # pptp scoped 路由脚本（面板安装，幂等）
    └── ip-down.d/rl-route         # 反向清理
```

---

## 12. 风险清单（修订版）

1. **GRE 出站可达性（PPTP）**：Oracle VCN 默认出站全放行，但 `pptp` 发的是 IP 协议 47，
   不是 TCP/UDP——**上线前必须实测**：从服务器 `pptp` 拨一次真实路由器，看 GRE 回包
   是否被中间链路（运营商/CGNAT）吞掉。若某条线路 GRE 被拦，该路由器改用 ovpn/wg。
2. **子进程自愈**：openvpn/pppd 崩溃 → `vpnclient_job` 按 backoff 重启；
   宿主机 Docker 重启容器 → `restart: unless-stopped` + 面板启动时 `Ensure` 全部
   enabled 连接（幂等）。
3. **多路由器内网段重叠**：见 §8.2（WG：per-连接 gVisor stack 天然隔离）与
   §8.3（ovpn/pptp：`SO_BINDTODEVICE` 把转发 socket 钉到 `tunX`/`pppX`）。
   保存时**允许**重复 lanSubnet（这是合法场景），面板在重叠时提示"已启用接口隔离转发"。
4. **凭证加密存储**：`auth`（密码/私钥/证书）加密后存 DB。复用现有
   `node_token_encryption` 的机制（`node_token_encryption_test.go` 已有加解密单测），
   不要自己发明轮子；`routerlinks/` 下的明文文件 `0600` 且只在容器内。
5. **MPPE 协商**：老旧路由器可能只支持 `require-mppe`（40/56位）甚至无 MPPE；
   面板给 PPTP 连接留 `mppe` 三档（`require-mppe-128` / `require-mppe` / `nomppe`），
   默认 128，拨号失败日志里看 `MPPE` 关键字再降档。
6. **OpenVPN 被推送的配置**：`route-nopull` + `pull-filter` 双保险后，对端再推
   `redirect-gateway` 也进不来；护栏（§4.2）是最后一道。
7. **pppd 的 `defaultroute` 误配**：options 文件由面板**生成**（用户不可编辑原始文本，
   只填表单），从源头杜绝手滑。
8. **forwardedPorts 端口冲突**：§9.4 已纳入统一冲突域；`MaxForwardedPorts=100`
   的上限沿用。
9. **amneziawg-go UAPI `endpoint=` 支持**：实现阶段写单测锁定与真实对端握手
   （见 §7.1 表格标注）。
10. **DB 迁移**：新表 `router_links`，`db.go` migration 幂等；AmneziaWG 服务端入站
    零改动（两套 Manager 隔离）。
11. **外部还原风险**：v1 文档备注过"外部流程会周期性还原 app.py"式的运维风险——
    本方案所有生成文件放 `routerlinks/`（面板自有目录），不与外部流程写同一文件；
    compose 文件与 Dockerfile 进 git。
12. **PPTP 弱加密定位**：UI 明确标注"兼容模式"，不推荐新路由器使用；审计日志记录
    每次 PPTP 拨号（用户自己看得见风险）。

---

## 13. 结论（一句话）

单面板容器（host 模式，`NET_ADMIN` + `/dev/net/tun` + `/dev/ppp`）内：
**WG 复用现有用户态 `amneziawgnet` 引擎加客户端角色（endpoint/AllowedIPs 限定，
宿主机零感知），OpenVPN/PPTP 由面板托管 `openvpn`/`pppd` 子进程（`route-nopull`/
`nodefaultroute` + 路由护栏，隧道只路由路由器内网段），三者统一经扩展语法的
`forwardedPorts`（`pubPort->lanIP:lanPort`）做"公网端口 → 隧道 → 路由器内网"的中转，
全程不写防火墙规则、不碰默认路由；多路由器内网段重叠用 per-连接 gVisor stack
（WG）与 `SO_BINDTODEVICE` 接口钉死（ovpn/pptp）解决。**
