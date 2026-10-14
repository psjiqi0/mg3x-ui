import { HttpUtil, type Msg } from '@/utils';
import { withBasePath } from '@/api/http-init';
import { parseMsg } from '@/utils/zodValidate';
import {
  RouterLinkListSchema,
  RouterLinkStatusRecordSchema,
  type RouterLinkPayload,
  type RouterLinkRecord,
  type RouterLinkStatusRecord,
} from '@/schemas/api/router-link';

const BASE = withBasePath('/panel/routerlink');
const JSON_HEADERS = { headers: { 'Content-Type': 'application/json' } };

type MsgResult = { success?: boolean; msg?: string };

export async function fetchRouterLinks(): Promise<RouterLinkRecord[]> {
  const msg = await HttpUtil.get<unknown>(`${BASE}/list`, undefined, { silent: true });
  if (!msg?.success) throw new Error(msg?.msg || 'Failed to fetch router links');
  const parsed = parseMsg(msg, RouterLinkListSchema, 'routerlink/list');
  return Array.isArray(parsed.obj) ? parsed.obj : [];
}

export async function fetchRouterLinkStatus(id: number): Promise<RouterLinkStatusRecord> {
  const msg = await HttpUtil.get<unknown>(`${BASE}/status/${id}`, undefined, { silent: true });
  if (!msg?.success) throw new Error(msg?.msg || 'Failed to fetch router link status');
  const parsed = parseMsg(msg, RouterLinkStatusRecordSchema, 'routerlink/status');
  if (!parsed.obj || typeof parsed.obj !== 'object')
    throw new Error(msg?.msg || 'Bad status payload');
  return parsed.obj as RouterLinkStatusRecord;
}

export function addRouterLink(payload: RouterLinkPayload): Promise<Msg<MsgResult>> {
  return HttpUtil.post(`${BASE}/add`, payload, JSON_HEADERS);
}

export function updateRouterLink(payload: RouterLinkPayload): Promise<Msg<MsgResult>> {
  return HttpUtil.post(`${BASE}/update`, payload, JSON_HEADERS);
}

export function deleteRouterLink(id: number): Promise<Msg<MsgResult>> {
  return HttpUtil.post(`${BASE}/del`, { id }, JSON_HEADERS);
}

export function dialRouterLink(id: number): Promise<Msg<MsgResult>> {
  return HttpUtil.post(`${BASE}/dial`, { id }, JSON_HEADERS);
}

export function hangupRouterLink(id: number): Promise<Msg<MsgResult>> {
  return HttpUtil.post(`${BASE}/hangup`, { id }, JSON_HEADERS);
}
