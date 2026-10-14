import { z } from 'zod';

// ============================================================================
// RouterLink（路由器 VPN 客户端连接）表单 / 列表 schema。
// API 契约（D 组冻结）：POST /panel/routerlink/add|update|del、
// GET /panel/routerlink/list、POST /panel/routerlink/dial|hangup、
// GET /panel/routerlink/status/:id
// ============================================================================

export const RouterLinkProtocolSchema = z.enum(['openvpn', 'pptp', 'wireguard']);
export type RouterLinkProtocol = z.infer<typeof RouterLinkProtocolSchema>;

export const RouterLinkMppeSchema = z.enum(['require-mppe-128', 'require-mppe', 'nomppe']);
export type RouterLinkMppe = z.infer<typeof RouterLinkMppeSchema>;

export const RouterLinkStatusSchema = z.enum(['up', 'down', 'dialing', 'error']);
export type RouterLinkStatus = z.infer<typeof RouterLinkStatusSchema>;

export const PPTP_FIXED_PORT = 1723;

// ----------------------------------------------------------------------------
// IP / CIDR 校验（v4 精确、v6 精确；含子网包含判断）
// ----------------------------------------------------------------------------

function parseIPv4(ip: string): number | null {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(ip.trim());
  if (!m) return null;
  let n = 0;
  for (let i = 1; i <= 4; i += 1) {
    const octet = Number(m[i]);
    if (octet > 255) return null;
    n = n * 256 + octet;
  }
  return n >>> 0;
}

function parseIPv6(ip: string): bigint | null {
  const s = ip.trim().toLowerCase();
  if (!/^[0-9a-f:]+$/.test(s) || s.includes(':::')) return null;
  const halves = s.split('::');
  if (halves.length > 2) return null;
  const parseGroup = (part: string): number[] | null => {
    if (part === '') return [];
    const gs = part.split(':');
    const out: number[] = [];
    for (const g of gs) {
      if (g === '' || g.length > 4 || !/^[0-9a-f]{1,4}$/.test(g)) return null;
      out.push(parseInt(g, 16));
    }
    return out;
  };
  const head = parseGroup(halves[0]);
  const tail = halves.length === 2 ? parseGroup(halves[1]) : [];
  if (!head || !tail) return null;
  const missing = 8 - head.length - tail.length;
  if (halves.length === 1 ? missing !== 0 : missing < 0) return null;
  const groups = [...head, ...new Array(Math.max(0, missing)).fill(0), ...tail];
  if (groups.length !== 8) return null;
  let n = 0n;
  for (const g of groups) n = (n << 16n) | BigInt(g);
  return n;
}

export interface ParsedCidr {
  v6: boolean;
  network: number | bigint;
  bits: number;
}

export function parseCidr(cidr: string): ParsedCidr | null {
  const m = /^(.+)\/(\d{1,3})$/.exec(cidr.trim());
  if (!m) return null;
  const bits = Number(m[2]);
  const v4 = parseIPv4(m[1]);
  if (v4 !== null) {
    if (bits > 32) return null;
    const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
    return { v6: false, network: (v4 & mask) >>> 0, bits };
  }
  const v6 = parseIPv6(m[1]);
  if (v6 === null || bits > 128) return null;
  const shift = BigInt(128 - bits);
  const mask = bits === 0 ? 0n : ((1n << 128n) - 1n) ^ ((1n << shift) - 1n);
  return { v6: true, network: v6 & mask, bits };
}

export function isValidCidr(cidr: string): boolean {
  return parseCidr(cidr) !== null;
}

export function isValidIp(ip: string): boolean {
  return parseIPv4(ip) !== null || parseIPv6(ip) !== null;
}

/** 目标 IP 是否落在 lanSubnet 内（v4/v6 必须同族）。 */
export function cidrContains(cidr: string, ip: string): boolean {
  const c = parseCidr(cidr);
  if (!c) return false;
  if (c.v6) {
    const v = parseIPv6(ip);
    if (v === null) return false;
    const shift = BigInt(128 - c.bits);
    const mask = c.bits === 0 ? 0n : ((1n << 128n) - 1n) ^ ((1n << shift) - 1n);
    return (v & mask) === (c.network as bigint);
  }
  const v = parseIPv4(ip);
  if (v === null) return false;
  const mask = c.bits === 0 ? 0 : (0xffffffff << (32 - c.bits)) >>> 0;
  return (v & mask) >>> 0 === (c.network as number);
}

export const CidrSchema = z
  .string()
  .trim()
  .min(1, 'pages.routerLink.form.lanSubnetRequired')
  .refine((v) => isValidCidr(v), 'pages.routerLink.form.lanSubnetInvalid');

// ----------------------------------------------------------------------------
// forwardedPorts 扩展语法：`8080->192.168.225.10:80` 逗号分隔，
// 目标 IP 必须在 lanSubnet 内。
// ----------------------------------------------------------------------------

const FORWARD_RULE_RE = /^\s*(\d{1,5})\s*->\s*([0-9A-Za-z.:]+)\s*:\s*(\d{1,5})\s*$/;

export interface ForwardRule {
  pubPort: number;
  lanIp: string;
  lanPort: number;
  raw: string;
}

export function parseForwardedPorts(value: string): ForwardRule[] | null {
  const text = (value ?? '').trim();
  if (text === '') return [];
  const rules: ForwardRule[] = [];
  for (const raw of text.split(',')) {
    const m = FORWARD_RULE_RE.exec(raw);
    if (!m) return null;
    const pubPort = Number(m[1]);
    const lanPort = Number(m[3]);
    if (pubPort < 1 || pubPort > 65535 || lanPort < 1 || lanPort > 65535) return null;
    if (!isValidIp(m[2])) return null;
    rules.push({ pubPort, lanIp: m[2].trim(), lanPort, raw: raw.trim() });
  }
  return rules;
}

/**
 * 校验 forwardedPorts，返回 i18n message key 数组（空 = 通过）。
 * 允许空字符串（不做端口转发）。
 */
export function forwardedPortsIssues(value: string, lanSubnet: string): string[] {
  const rules = parseForwardedPorts(value ?? '');
  if (rules === null) return ['pages.routerLink.form.forwardedPortsInvalid'];
  const seen = new Set<number>();
  for (const r of rules) {
    if (seen.has(r.pubPort)) return ['pages.routerLink.form.forwardedPortsDupPubPort'];
    seen.add(r.pubPort);
    if (lanSubnet.trim() !== '' && isValidCidr(lanSubnet) && !cidrContains(lanSubnet, r.lanIp)) {
      return ['pages.routerLink.form.forwardedPortsLanIpOutside'];
    }
  }
  return [];
}

export const ForwardedPortsSchema = z
  .string()
  .default('')
  .refine(
    (v) => parseForwardedPorts(v ?? '') !== null,
    'pages.routerLink.form.forwardedPortsInvalid',
  );

// ----------------------------------------------------------------------------
// 认证（明文只在表单内存中出现；列表接口永不返回明文）
// ----------------------------------------------------------------------------

export const RouterLinkAuthTypeSchema = z.enum(['password', 'cert', 'psk']);
export type RouterLinkAuthType = z.infer<typeof RouterLinkAuthTypeSchema>;

export const RouterLinkAuthSchema = z.object({
  type: RouterLinkAuthTypeSchema.default('password'),
  username: z.string().default(''),
  password: z.string().default(''),
  ca: z.string().default(''),
  cert: z.string().default(''),
  key: z.string().default(''),
  privateKey: z.string().default(''),
  peerPublicKey: z.string().default(''),
  presharedKey: z.string().default(''),
});
export type RouterLinkAuthValues = z.infer<typeof RouterLinkAuthSchema>;

// ----------------------------------------------------------------------------
// 表单（按协议分支校验）
// ----------------------------------------------------------------------------

export const RouterLinkFormSchema = z
  .object({
    id: z.number().optional(),
    name: z.string().trim().min(1, 'pages.routerLink.form.nameRequired').max(128),
    protocol: RouterLinkProtocolSchema,
    enable: z.boolean().default(true),
    remoteHost: z.string().trim().default(''),
    remotePort: z.number().int().min(1).max(65535).default(1194),
    proto: z.enum(['udp', 'tcp']).default('udp'),
    lanSubnet: z.string().trim().default(''),
    tunnelAddress: z.string().trim().default(''),
    mppe: RouterLinkMppeSchema.default('require-mppe-128'),
    persistentKeepalive: z.number().int().min(0).max(65535).default(25),
    forwardedPorts: ForwardedPortsSchema,
    // egress：经此隧道出公网（D2 组实现中；后端未实现前下发字段会被忽略）
    egress: z.boolean().default(false),
    egressInboundTags: z.array(z.string()).default([]),
    // 只读：后端分配的独占 SOCKS5 端口，0 = 未分配
    egressSocksPort: z.number().default(0),
    auth: RouterLinkAuthSchema,
  })
  .superRefine((v, ctx) => {
    const issue = (path: (string | number)[], message: string) =>
      ctx.addIssue({ code: 'custom', path, message });

    // lanSubnet 必填 CIDR（所有协议）
    if (v.lanSubnet.trim() === '') {
      issue(['lanSubnet'], 'pages.routerLink.form.lanSubnetRequired');
    } else if (!isValidCidr(v.lanSubnet)) {
      issue(['lanSubnet'], 'pages.routerLink.form.lanSubnetInvalid');
    }

    // forwardedPorts：语法 + 目标 IP 落在 lanSubnet 内
    for (const key of forwardedPortsIssues(v.forwardedPorts ?? '', v.lanSubnet)) {
      issue(['forwardedPorts'], key);
    }

    // egress 打开时至少绑定一个入站 tag
    if (v.egress && (v.egressInboundTags ?? []).length === 0) {
      issue(['egressInboundTags'], 'pages.routerLink.form.egressInboundTagsHint');
    }

    if (v.protocol === 'openvpn') {
      if (v.remoteHost.trim() === '') issue(['remoteHost'], 'pages.routerLink.form.remoteRequired');
      if (v.auth.type === 'password') {
        if (v.auth.username.trim() === '')
          issue(['auth', 'username'], 'pages.routerLink.form.usernameRequired');
        // 新增时密码必填；编辑时留空表示不修改（payload 里会省略空密钥）。
        if (v.id == null && v.auth.password === '') {
          issue(['auth', 'password'], 'pages.routerLink.form.passwordRequired');
        }
      } else if (v.auth.type === 'cert') {
        if (v.id == null) {
          if (v.auth.ca.trim() === '') issue(['auth', 'ca'], 'pages.routerLink.form.caRequired');
          if (v.auth.cert.trim() === '')
            issue(['auth', 'cert'], 'pages.routerLink.form.certRequired');
          if (v.auth.key.trim() === '') issue(['auth', 'key'], 'pages.routerLink.form.keyRequired');
        }
      }
    }

    if (v.protocol === 'pptp') {
      if (v.remoteHost.trim() === '') issue(['remoteHost'], 'pages.routerLink.form.remoteRequired');
      if (v.id == null && v.auth.username.trim() === '')
        issue(['auth', 'username'], 'pages.routerLink.form.usernameRequired');
      if (v.id == null && v.auth.password === '') {
        issue(['auth', 'password'], 'pages.routerLink.form.passwordRequired');
      }
    }

    if (v.protocol === 'wireguard') {
      if (v.remoteHost.trim() === '') issue(['remoteHost'], 'pages.routerLink.form.remoteRequired');
      if (v.id == null && v.auth.privateKey.trim() === '') {
        issue(['auth', 'privateKey'], 'pages.routerLink.form.privateKeyRequired');
      }
      if (v.id == null && v.auth.peerPublicKey.trim() === '') {
        issue(['auth', 'peerPublicKey'], 'pages.routerLink.form.peerPublicKeyRequired');
      }
      if (v.tunnelAddress.trim() !== '') {
        // 允许 192.168.225.6/32 或单个 IP（后端同样接受裸 IP）
        const ta = v.tunnelAddress.trim();
        if (!isValidCidr(ta) && !isValidIp(ta)) {
          issue(['tunnelAddress'], 'pages.routerLink.form.tunnelAddressInvalid');
        }
      }
    }
  });

export type RouterLinkFormValues = z.infer<typeof RouterLinkFormSchema>;

// ----------------------------------------------------------------------------
// 下发 payload（冻结 API 契约）
// ----------------------------------------------------------------------------

export interface RouterLinkPayload {
  id?: number;
  name: string;
  protocol: RouterLinkProtocol;
  remoteHost: string;
  remotePort: number;
  proto: string;
  lanSubnet: string;
  tunnelAddress: string;
  mppe: string;
  persistentKeepalive: number;
  forwardedPorts: string;
  enable: boolean;
  egress: boolean;
  egressInboundTags: string[];
  // 后端 update 语义：auth 缺席(nil) = 保留已有密钥；出现即全量替换并校验。
  // 因此编辑/快捷开关不碰密钥时必须整个省略该 key，不能传 {}。
  auth?: Record<string, string>;
}

/**
 * 表单里是否填了可用的密钥（编辑时据此决定是否下发 auth）。
 * 注意后端是"全量替换"语义：只要下发就必须带齐该类型所需的全部密钥。
 */
export function authCarriesSecrets(v: RouterLinkFormValues): boolean {
  const a = v.auth;
  if (v.protocol === 'openvpn') {
    return a.type === 'cert'
      ? a.ca.trim() !== '' && a.cert.trim() !== '' && a.key.trim() !== ''
      : a.username.trim() !== '' && a.password !== '';
  }
  if (v.protocol === 'pptp') {
    return a.username.trim() !== '' && a.password !== '';
  }
  return a.privateKey.trim() !== '' && a.peerPublicKey.trim() !== '';
}

/**
 * 表单值 → POST /panel/routerlink/add|update 的 payload。
 * includeAuth=false 时整个省略 auth key（后端 update 视为保留已有密钥）。
 */
export function buildRouterLinkPayload(
  values: RouterLinkFormValues,
  opts: { includeAuth?: boolean } = {},
): RouterLinkPayload {
  const auth: Record<string, string> = {};
  const put = (k: string, v: string | undefined) => {
    if (v != null && v !== '') auth[k] = v;
  };
  if (values.protocol === 'openvpn') {
    if (values.auth.type === 'cert') {
      auth.type = 'cert';
      put('ca', values.auth.ca);
      put('cert', values.auth.cert);
      put('key', values.auth.key);
    } else {
      auth.type = 'password';
      put('username', values.auth.username);
      put('password', values.auth.password);
    }
  } else if (values.protocol === 'pptp') {
    auth.type = 'password';
    put('username', values.auth.username);
    put('password', values.auth.password);
  } else {
    auth.type = 'psk';
    put('privateKey', values.auth.privateKey);
    put('peerPublicKey', values.auth.peerPublicKey);
    put('presharedKey', values.auth.presharedKey);
  }

  const { includeAuth = true } = opts;
  return {
    ...(values.id != null ? { id: values.id } : {}),
    name: values.name.trim(),
    protocol: values.protocol,
    remoteHost: values.remoteHost.trim(),
    // PPTP 端口固定 1723（表单 disabled 展示，后端同样忽略传入值）
    remotePort: values.protocol === 'pptp' ? PPTP_FIXED_PORT : values.remotePort,
    proto: values.protocol === 'openvpn' ? values.proto : '',
    lanSubnet: values.lanSubnet.trim(),
    tunnelAddress: values.tunnelAddress.trim(),
    mppe: values.protocol === 'pptp' ? values.mppe : '',
    persistentKeepalive: values.protocol === 'wireguard' ? values.persistentKeepalive : 0,
    forwardedPorts: (values.forwardedPorts ?? '').trim(),
    enable: values.enable,
    egress: values.egress,
    egressInboundTags: values.egressInboundTags ?? [],
    ...(includeAuth ? { auth } : {}),
  };
}

// ----------------------------------------------------------------------------
// 列表 / 状态（GET /panel/routerlink/list、GET /panel/routerlink/status/:id）
// ----------------------------------------------------------------------------

export const RouterLinkRecordSchema = z.object({
  id: z.number(),
  name: z.string().default(''),
  protocol: RouterLinkProtocolSchema,
  remoteHost: z.string().default(''),
  remotePort: z.number().default(0),
  proto: z.string().default(''),
  lanSubnet: z.string().default(''),
  tunnelAddress: z.string().default(''),
  mppe: z.string().default(''),
  persistentKeepalive: z.number().default(0),
  forwardedPorts: z.string().default(''),
  enable: z.boolean().default(true),
  egress: z.boolean().default(false),
  egressInboundTags: z.array(z.string()).default([]),
  egressSocksPort: z.number().default(0),
  hasAuth: z
    .object({ password: z.boolean().default(false), cert: z.boolean().default(false) })
    .default({ password: false, cert: false }),
  status: RouterLinkStatusSchema.default('down'),
  // 后端 int64（Unix 秒时间戳）；字符串做兼容
  handshakeAt: z.union([z.number(), z.string()]).default(0),
  rxBytes: z.number().default(0),
  txBytes: z.number().default(0),
  message: z.string().default(''),
  iface: z.string().default('').optional(),
});
export type RouterLinkRecord = z.infer<typeof RouterLinkRecordSchema>;

export const RouterLinkListSchema = z.array(RouterLinkRecordSchema);

// GET /panel/routerlink/status/:id → {success, obj:{id,status,handshakeAt,rxBytes,txBytes,message,iface}}
// 注意：该接口不返回 protocol/name 等列表字段，用独立 schema。
export const RouterLinkStatusRecordSchema = z.object({
  id: z.number(),
  status: RouterLinkStatusSchema.default('down'),
  handshakeAt: z.union([z.number(), z.string()]).default(0),
  rxBytes: z.number().default(0),
  txBytes: z.number().default(0),
  message: z.string().default(''),
  iface: z.string().default('').optional(),
});
export type RouterLinkStatusRecord = z.infer<typeof RouterLinkStatusRecordSchema>;
