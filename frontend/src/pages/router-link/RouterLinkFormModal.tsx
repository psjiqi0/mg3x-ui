import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Form, Modal, Select, message } from 'antd';
import { FormProvider, useForm, useWatch } from 'react-hook-form';
import type { Path } from 'react-hook-form';

import { useMediaQuery } from '@/hooks/useMediaQuery';
import { useInboundOptions } from '@/api/queries/useInboundOptions';
import {
  PPTP_FIXED_PORT,
  RouterLinkFormSchema,
  authCarriesSecrets,
  buildRouterLinkPayload,
  type RouterLinkFormValues,
  type RouterLinkProtocol,
  type RouterLinkRecord,
} from '@/schemas/api/router-link';
import { addRouterLink, updateRouterLink } from './routerLinkApi';
import RouterLinkOvpnForm from './RouterLinkOvpnForm';
import RouterLinkPptpForm from './RouterLinkPptpForm';
import RouterLinkWgForm from './RouterLinkWgForm';

interface Props {
  open: boolean;
  mode: 'add' | 'edit';
  record: RouterLinkRecord | null;
  onOpenChange: (open: boolean) => void;
  onSaved: () => void;
}

const PROTOCOL_DEFAULTS: Record<RouterLinkProtocol, Partial<RouterLinkFormValues>> = {
  openvpn: { remotePort: 1194, proto: 'udp', mppe: 'require-mppe-128' },
  pptp: { remotePort: PPTP_FIXED_PORT, proto: 'udp', mppe: 'require-mppe-128' },
  wireguard: { remotePort: 51820, proto: 'udp', persistentKeepalive: 25 },
};

function defaultsFor(record: RouterLinkRecord | null): RouterLinkFormValues {
  return {
    id: record?.id,
    name: record?.name ?? '',
    protocol: record?.protocol ?? 'openvpn',
    enable: record ? record.enable : true,
    remoteHost: record?.remoteHost ?? '',
    remotePort: record?.remotePort || PROTOCOL_DEFAULTS[record?.protocol ?? 'openvpn'].remotePort!,
    proto: (record?.proto as 'udp' | 'tcp' | undefined) || 'udp',
    lanSubnet: record?.lanSubnet ?? '',
    tunnelAddress: record?.tunnelAddress ?? '',
    mppe: (record?.mppe as RouterLinkFormValues['mppe'] | undefined) || 'require-mppe-128',
    persistentKeepalive: record?.persistentKeepalive || 25,
    forwardedPorts: record?.forwardedPorts ?? '',
    egress: record?.egress ?? false,
    egressInboundTags: record?.egressInboundTags ?? [],
    egressSocksPort: record?.egressSocksPort ?? 0,
    auth: {
      type: record?.protocol === 'wireguard' ? 'psk' : record?.hasAuth?.cert ? 'cert' : 'password',
      username: '',
      password: '',
      ca: '',
      cert: '',
      key: '',
      privateKey: '',
      peerPublicKey: '',
      presharedKey: '',
    },
  };
}

export default function RouterLinkFormModal({ open, mode, record, onOpenChange, onSaved }: Props) {
  const { t } = useTranslation();
  const { isMobile } = useMediaQuery();
  const F = 'pages.routerLink';
  const [messageApi, messageContextHolder] = message.useMessage();
  const [loading, setLoading] = useState(false);

  const methods = useForm<RouterLinkFormValues>({ defaultValues: defaultsFor(record) });
  const protocol = useWatch({ control: methods.control, name: 'protocol' });
  const [activeTab, setActiveTab] = useState<RouterLinkProtocol>(protocol ?? 'openvpn');
  const { data: inboundOptions = [] } = useInboundOptions();
  useEffect(() => { if (open) { setActiveTab(defaultsFor(record).protocol); } }, [open]);

  // Modal 首次打开帧就展示清空/回填后的字段（仿 HostFormModal 的同步 reset 写法）。
  const openRecord = open ? record : null;
  const [synced, setSynced] = useState(openRecord);
  if (openRecord !== synced) {
    setSynced(openRecord);
    if (open) {
      const _d = defaultsFor(record); methods.reset(_d); setActiveTab(_d.protocol);
      setLoading(false);
    }
  }

  const onProtocolChange = (next: string) => {
    const p = next as RouterLinkProtocol;
    methods.setValue('protocol', p); setActiveTab(p);
    const d = PROTOCOL_DEFAULTS[p];
    if (d.remotePort != null) methods.setValue('remotePort', d.remotePort);
    if (p === 'openvpn') methods.setValue('auth.type', 'password');
    if (p === 'pptp') {
      methods.setValue('auth.type', 'password');
      methods.setValue('mppe', 'require-mppe-128');
    }
    if (p === 'wireguard') {
      methods.setValue('auth.type', 'psk');
      methods.setValue('persistentKeepalive', 25);
    }
  };

  const onFinish = async (values: RouterLinkFormValues) => {
    const fixedValues = { ...values, protocol: activeTab };
    if (loading) return;
    const parsed = RouterLinkFormSchema.safeParse(fixedValues);
    if (!parsed.success) {
      const seen = new Set<string>();
      for (const issue of parsed.error.issues) {
        const path = issue.path.join('.');
        if (path && !seen.has(path)) {
          seen.add(path);
          methods.setError(path as Path<RouterLinkFormValues>, { message: issue.message });
        }
      }
      const first = parsed.error.issues[0];
      messageApi.error(t(first?.message ?? `${F}.toasts.saveFailed`));
      return;
    }
    setLoading(true);
    try {
      // 新增：auth 必填；编辑：只有填了成套密钥才下发，否则省略 auth=保留已有密钥
      const payload = buildRouterLinkPayload(parsed.data, {
        includeAuth: mode === 'add' || authCarriesSecrets(parsed.data),
      });
      const res = mode === 'edit' ? await updateRouterLink(payload) : await addRouterLink(payload);
      if (res?.success) {
        messageApi.success(t(mode === 'add' ? `${F}.toasts.add` : `${F}.toasts.update`));
        onSaved();
        onOpenChange(false);
      } else {
        messageApi.error(res?.msg || 'saveFailed');
      }
    } catch (err) {
      console.error(err);
      messageApi.error(String(err));
    } finally {
      setLoading(false);
    }
  };

  const protocolLabel = (p: RouterLinkProtocol) => t(`${F}.protocols.${p}`);

  return (
    <Modal
      open={open}
      title={t(mode === 'add' ? `${F}.form.addTitle` : `${F}.form.editTitle`)}
      onOk={methods.handleSubmit(onFinish)}
      onCancel={() => onOpenChange(false)}
      confirmLoading={loading}
      okText={t('save')}
      cancelText={t('cancel')}
      destroyOnHidden
      width={isMobile ? '95vw' : 720}
      styles={{ body: { maxHeight: '70vh', overflowY: 'auto', overflowX: 'hidden' } }}
    >
      {messageContextHolder}
      <FormProvider {...methods}>
        <Form
          colon={false}
          labelCol={{ sm: { span: 7 } }}
          wrapperCol={{ sm: { span: 15 } }}
          labelWrap
        >
          <Form.Item label={t(`${F}.form.protocol`)}>
            <Select
              value={activeTab}
              onChange={mode === 'add' ? onProtocolChange : undefined}
              disabled={mode !== 'add'}
              options={[
                { value: 'openvpn', label: protocolLabel('openvpn') },
                { value: 'pptp', label: protocolLabel('pptp') },
                { value: 'wireguard', label: protocolLabel('wireguard') },
              ]}
            />
          </Form.Item>
          {activeTab === 'openvpn' && (
            <RouterLinkOvpnForm methods={methods} mode={mode} inboundOptions={inboundOptions} />
          )}
          {activeTab === 'pptp' && (
            <RouterLinkPptpForm methods={methods} mode={mode} inboundOptions={inboundOptions} />
          )}
          {activeTab === 'wireguard' && (
            <RouterLinkWgForm methods={methods} mode={mode} inboundOptions={inboundOptions} />
          )}
        </Form>
      </FormProvider>
    </Modal>
  );
}
