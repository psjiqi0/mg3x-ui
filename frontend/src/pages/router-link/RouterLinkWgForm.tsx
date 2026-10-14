import { useTranslation } from 'react-i18next';
import { Input, InputNumber } from 'antd';
import type { UseFormReturn } from 'react-hook-form';

import { FormField } from '@/components/form/rhf';
import type { InboundOption } from '@/schemas/client';
import type { RouterLinkFormValues } from '@/schemas/api/router-link';
/* no form context needed here */
import RouterLinkCommonFields from './RouterLinkCommonFields';

interface Props {
  methods: UseFormReturn<RouterLinkFormValues>;
  mode: 'add' | 'edit';
  inboundOptions: InboundOption[];
}

/** WireGuard 客户端表单：私钥 / 对端公钥 / 预共享密钥（可选）。 */
export default function RouterLinkWgForm({ methods, mode, inboundOptions }: Props) {
  const { t } = useTranslation();
  const F = 'pages.routerLink.form';

  return (
    <>
      <RouterLinkCommonFields methods={methods} inboundOptions={inboundOptions} />
      <FormField name="remotePort" label={t(`${F}.remotePort`)} required>
        <InputNumber min={1} max={65535} style={{ width: '100%' }} />
      </FormField>
      <FormField
        name="tunnelAddress"
        label={t(`${F}.tunnelAddress`)}
      >
        <Input maxLength={64} placeholder={t(`${F}.tunnelAddressPlaceholder`)} spellCheck={false} />
      </FormField>
      <FormField
        name="persistentKeepalive"
        label={t(`${F}.persistentKeepalive`)}
        tooltip={t(`${F}.persistentKeepaliveHint`)}
      >
        <InputNumber min={0} max={65535} style={{ width: '100%' }} />
      </FormField>
      <FormField
        name="auth.privateKey"
        label={t(`${F}.privateKey`)}
        required={mode === 'add'}
        extra={mode === 'edit' ? t(`${F}.passwordUnchanged`) : undefined}
      >
        <Input.Password
          autoComplete="new-password"
          spellCheck={false}
          placeholder={mode === 'edit' ? t(`${F}.passwordUnchanged`) : undefined}
        />
      </FormField>
      <FormField
        name="auth.peerPublicKey"
        label={t(`${F}.peerPublicKey`)}
        required={mode === 'add'}
        rules={mode === 'add' ? { required: t(`${F}.peerPublicKeyRequired`) } : undefined}
        extra={mode === 'edit' ? t(`${F}.passwordUnchanged`) : undefined}
      >
        <Input
          spellCheck={false}
          autoComplete="off"
          placeholder={mode === 'edit' ? t(`${F}.passwordUnchanged`) : undefined}
        />
      </FormField>
      <FormField
        name="auth.presharedKey"
        label={t(`${F}.presharedKey`)}
        extra={mode === 'edit' ? t(`${F}.passwordUnchanged`) : undefined}
      >
        <Input.Password
          autoComplete="new-password"
          spellCheck={false}
          placeholder={mode === 'edit' ? t(`${F}.passwordUnchanged`) : undefined}
        />
      </FormField>
    </>
  );
}
