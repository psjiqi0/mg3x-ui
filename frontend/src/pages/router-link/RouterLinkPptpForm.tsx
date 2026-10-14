import { useTranslation } from 'react-i18next';
import { Alert, Input, InputNumber, Radio, Tag } from 'antd';
import type { UseFormReturn } from 'react-hook-form';

import { FormField } from '@/components/form/rhf';
import type { InboundOption } from '@/schemas/client';
import type { RouterLinkFormValues } from '@/schemas/api/router-link';
import { PPTP_FIXED_PORT } from '@/schemas/api/router-link';
import RouterLinkCommonFields from './RouterLinkCommonFields';

interface Props {
  methods: UseFormReturn<RouterLinkFormValues>;
  mode: 'add' | 'edit';
  inboundOptions: InboundOption[];
}

/**
 * PPTP 客户端表单。设计要求：PPTP 只用于老旧路由器，整行打"兼容模式"徽标；
 * 端口固定 1723（disabled 展示）；MPPE 默认 require-mppe-128 且默认启用
 * stateful（兼容实测路由器，见 RELAY_DESIGN.md）。
 */
export default function RouterLinkPptpForm({ methods, mode, inboundOptions }: Props) {
  const { t } = useTranslation();
  const F = 'pages.routerLink.form';

  return (
    <>
      <Alert
        type="warning"
        showIcon
        style={{ marginBottom: 16 }}
        message={
          <span>
            <Tag color="orange" style={{ marginInlineEnd: 8 }}>
              {t(`${F}.compatBadge`)}
            </Tag>
            {t(`${F}.compatNote`)}
          </span>
        }
      />
      <RouterLinkCommonFields methods={methods} inboundOptions={inboundOptions} />
      <FormField
        name="remotePort"
        label={t(`${F}.remotePort`)}
        tooltip={t(`${F}.remotePortFixed`)}
      >
        <InputNumber min={1} max={65535} disabled style={{ width: '100%' }} placeholder={String(PPTP_FIXED_PORT)} />
      </FormField>
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
        <Input.Password
          autoComplete="new-password"
          placeholder={mode === 'edit' ? t(`${F}.passwordUnchanged`) : undefined}
        />
      </FormField>
      <FormField
        name="mppe"
        label={t(`${F}.mppe`)}
        extra={t(`${F}.mppeStatefulNote`)}
      >
        <Radio.Group
          options={[
            { value: 'require-mppe-128', label: t(`${F}.mppeOptions.require-mppe-128`) },
            { value: 'require-mppe', label: t(`${F}.mppeOptions.require-mppe`) },
            { value: 'nomppe', label: t(`${F}.mppeOptions.nomppe`) },
          ]}
        />
      </FormField>
    </>
  );
}
