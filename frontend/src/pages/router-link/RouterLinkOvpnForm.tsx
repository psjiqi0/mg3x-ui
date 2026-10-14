import { useTranslation } from 'react-i18next';
import { Input, InputNumber, Radio } from 'antd';
import type { UseFormReturn } from 'react-hook-form';

import { FormField } from '@/components/form/rhf';
import type { InboundOption } from '@/schemas/client';
import type { RouterLinkFormValues } from '@/schemas/api/router-link';
import RouterLinkCommonFields from './RouterLinkCommonFields';

interface Props {
  methods: UseFormReturn<RouterLinkFormValues>;
  mode: 'add' | 'edit';
  inboundOptions: InboundOption[];
}

/** OpenVPN 客户端表单：密码 / 证书二选一。 */
export default function RouterLinkOvpnForm({ methods, mode, inboundOptions }: Props) {
  const { t } = useTranslation();
  const F = 'pages.routerLink.form';
  const authType = methods.watch('auth.type');

  return (
    <>
      <RouterLinkCommonFields methods={methods} inboundOptions={inboundOptions} />
      <FormField name="remotePort" label={t(`${F}.remotePort`)} required>
        <InputNumber min={1} max={65535} style={{ width: '100%' }} />
      </FormField>
      <FormField name="proto" label={t(`${F}.proto`)}>
        <Radio.Group
          options={[
            { value: 'udp', label: 'UDP' },
            { value: 'tcp', label: 'TCP' },
          ]}
        />
      </FormField>
      <FormField name="auth.type" label={t(`${F}.authType`)}>
        <Radio.Group
          options={[
            { value: 'password', label: t(`${F}.authTypePassword`) },
            { value: 'cert', label: t(`${F}.authTypeCert`) },
          ]}
        />
      </FormField>
      {authType === 'cert' ? (
        <>
          <FormField
            name="auth.ca"
            label={t(`${F}.ca`)}
            required={mode === 'add'}
            extra={mode === 'edit' ? t(`${F}.certUnchanged`) : undefined}
          >
            <Input.TextArea rows={4} spellCheck={false} placeholder={mode === 'edit' ? t(`${F}.certUnchanged`) : "-----BEGIN CERTIFICATE-----"} />
          </FormField>
          <FormField
            name="auth.cert"
            label={t(`${F}.cert`)}
            required={mode === 'add'}
            extra={mode === 'edit' ? t(`${F}.certUnchanged`) : undefined}
          >
            <Input.TextArea rows={4} spellCheck={false} placeholder={mode === 'edit' ? t(`${F}.certUnchanged`) : "-----BEGIN CERTIFICATE-----"} />
          </FormField>
          <FormField
            name="auth.key"
            label={t(`${F}.key`)}
            required={mode === 'add'}
            extra={mode === 'edit' ? t(`${F}.certUnchanged`) : undefined}
          >
            <Input.TextArea rows={4} spellCheck={false} placeholder={mode === 'edit' ? t(`${F}.certUnchanged`) : "-----BEGIN PRIVATE KEY-----"} />
          </FormField>
        </>
      ) : (
        <>
          <FormField
            name="auth.username"
            label={t(`${F}.username`)}
            required
            rules={{ required: t(`${F}.usernameRequired`) }}
          >
            <Input maxLength={128} autoComplete="off" />
          </FormField>
          <FormField
            name="auth.password"
            label={t(`${F}.password`)}
            required={mode === 'add'}
            extra={mode === 'edit' ? t(`${F}.passwordUnchanged`) : undefined}
          >
            <Input.Password autoComplete="new-password" placeholder={mode === 'edit' ? t(`${F}.passwordUnchanged`) : undefined} />
          </FormField>
        </>
      )}
    </>
  );
}
