# mg3x-ui

[中文说明](README.zh-CN.md)

**mg3x-ui** is a modified fork of [3x-ui](https://github.com/MHSanaei/3x-ui), built around one core
feature: **Router Relay**.

## What it does

Instead of running VPN servers, the panel acts as a **VPN client**: the server actively dials
out to VPN servers running on the user's own routers (PPTP / WireGuard / OpenVPN, all in
**client mode**). Once a tunnel is up, the server's public ports are forwarded **through the
tunnel into the router's LAN**.

```
Internet → server public port → VPN tunnel → router LAN device
```

Typical use: expose a device inside the router's LAN (NAS, camera, admin page) through the
server's public IP, without touching the router's firewall or asking the ISP for a public IP.

## Features

- **Router Links**: manage N router connections; the server dials each router as a VPN client.
  Supported protocols (client mode): **PPTP**, **WireGuard**, **OpenVPN**.
- **Per-connection isolation**:
  - PPTP: each link gets its own `ppp` interface (`ppp0`, `ppp1`, …).
  - WireGuard: each link gets an independent userspace gVisor network stack — no host
    interfaces, no host routes, no iptables changes.
  - Overlapping LAN subnets across links do not conflict.
- **Port forwarding** (`forwardedPorts`): forward server public ports into the router LAN,
  e.g. `8080 → 192.168.1.10:80`.
- **Egress**: optionally route an inbound's outbound traffic through a tunnel (bind inbounds
  to a link). Each link exposes a local SOCKS5 proxy for its tunnel.
- **Docker deployment**: single all-in-one container, host networking, `NET_ADMIN` +
  `/dev/net/tun` + `/dev/ppp`.

## Deployment

Requirements: Docker + Docker Compose, Linux host with `/dev/net/tun` and `/dev/ppp`
(kernel `wireguard`, `ppp_generic` modules).

```bash
git clone https://github.com/psjiqi0/mg3x-ui && cd mg3x-ui   # branch: relay-client-mode
docker compose -f docker-compose.relay.yml build
docker compose -f docker-compose.relay.yml up -d
```

- Panel: `http://<server-ip>:2053` (default; change the temporary password on first login).
- Data persistence:
  - `/etc/x-ui` → host `/etc/x-ui` (SQLite `x-ui.db`; router-link credentials stored encrypted).
  - `./routerlinks` → generated dial configs (`.ovpn`, pppd options, `chap-secrets`, …).

## Quick start: add a router link

Panel → **Router Links** → **Add**. Pick the protocol from the dropdown, then fill in:

**Common fields** (all protocols)

| Field | Description |
|---|---|
| Name | Display name, e.g. `home-pptp` |
| Remote host / port | Router's public address running the VPN server |
| Router LAN subnet | CIDR of the router's LAN, e.g. `192.168.1.0/24` |
| Port forwarding | `publicPort → lanIp:lanPort` rules (optional) |
| Egress | Route bound inbounds' traffic out through this tunnel (optional) |

**PPTP**: username, password, MPPE mode (`require-mppe-128` recommended).

**WireGuard**: private key, peer public key, preshared key (optional), tunnel address
(e.g. `10.10.10.2/32`), persistent keepalive. Map 1:1 from a standard `.conf`'s
`[Interface]` / `[Peer]` sections (`Address` → tunnel address, `Endpoint` → remote
host/port, `DNS` not needed).

**OpenVPN**: password mode (username/password) or certificate mode (ca/cert/key).

When editing a link, sensitive fields (passwords, keys) may be left blank to keep the
existing values.

## Constraints (by design)

- Tunnels **never touch the server's default route** and **never modify firewall rules**.
- OpenVPN uses `route-nopull`; PPTP uses `nodefaultroute`.
- WireGuard `AllowedIPs` defaults to the router LAN subnet only. Setting it to `0.0.0.0/0`
  routes all of the bound inbounds' traffic out through the router (the router must NAT);
  use only if you understand the implications.

## Design doc

See [RELAY_DESIGN.md](RELAY_DESIGN.md) (Chinese) for the full architecture rationale.

## Credits

Based on [MHSanaei/3x-ui](https://github.com/MHSanaei/3x-ui). All VPN-server features of the
original panel remain available; Router Relay is the added capability.
