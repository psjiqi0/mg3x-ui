import { useMemo } from 'react';
import { useTranslation } from 'react-i18next';
import { Form as AntdForm, Input, Select, Switch } from 'antd';
import type { UseFormReturn } from 'react-hook-form';

import { FormField, rhfZodValidate } from '@/components/form/rhf';
import type { InboundOption } from '@/schemas/client';
import {
  CidrSchema,
  forwardedPortsIssues,
  type RouterLinkFormValues,
} from '@/schemas/api/router-link';

interface Props {
  methods: UseFormReturn<RouterLinkFormValues>;
  inboundOptions: InboundOption[];
}

/**
 * 三协议共用：名称 / 启用 / 对端地址 / 内网段 / 端口转发 / egress 出口（走 FormProvider 上下文）。
 */
export default function RouterLinkCommonFields({ methods, inboundOptions }: Props) {
  const { t } = useTranslation();
  const F = 'pages.routerLink.form';
  const egress = methods.watch('egress');
  const socksPort = methods.watch('egressSocksPort');

  const inboundTagOptions = useMemo(
    () =>
      (inboundOptions || [])
        .filter((ib) => ib.tag && ib.tag.trim() !== '')
        .map((ib) => ({
          value: ib.tag as string,
          label: ib.remark ? `${ib.remark} (${ib.tag})` : (ib.tag as string),
        })),
    [inboundOptions],
  );

  return (
    <>
      <FormField
        name="name"
        label={t(`${F}.name`)}
        required
        rules={{ required: t(`${F}.nameRequired`), maxLength: { value: 128, message: t(`${F}.nameRequired`) } }}
      >
        <Input maxLength={128} placeholder={t(`${F}.namePlaceholder`)} />
      </FormField>
      <FormField
        name="enable"
        label={t(`${F}.enable`)}
        tooltip={t(`${F}.enableHint`)}
        valueProp="checked"
      >
        <Switch />
      </FormField>
      <FormField
        name="remoteHost"
        label={t(`${F}.remoteHost`)}
        required
        rules={{ required: t(`${F}.remoteRequired`) }}
      >
        <Input maxLength={256} placeholder={t(`${F}.remoteHostPlaceholder`)} />
      </FormField>
      <FormField
        name="lanSubnet"
        label={t(`${F}.lanSubnet`)}
        tooltip={t(`${F}.lanSubnetHint`)}
        required
        rules={{ validate: rhfZodValidate(CidrSchema) }}
      >
        <Input maxLength={64} placeholder={t(`${F}.lanSubnetPlaceholder`)} />
      </FormField>
      <FormField
        name="forwardedPorts"
        label={t(`${F}.forwardedPorts`)}
        tooltip={t(`${F}.forwardedPortsHint`)}
        rules={{
          validate: (v, fv) => {
            const lan = String((fv as RouterLinkFormValues | undefined)?.lanSubnet ?? '');
            const issues = forwardedPortsIssues(String(v ?? ''), lan);
            return issues.length === 0 ? true : t(issues[0]);
          },
        }}
      >
        <Input.TextArea
          rows={2}
          placeholder={t(`${F}.forwardedPortsPlaceholder`)}
          spellCheck={false}
        />
      </FormField>
      <FormField name="egress" label={t(`${F}.egress`)} tooltip={t(`${F}.egressHint`)} valueProp="checked">
        <Switch />
      </FormField>
      {egress && (
        <>
          <FormField
            name="egressInboundTags"
            label={t(`${F}.egressInboundTags`)}
            tooltip={t(`${F}.egressInboundTagsHint`)}
            required
          >
            <Select
              mode="multiple"
              options={inboundTagOptions}
              showSearch={{ optionFilterProp: 'label' }}
              placeholder={t(`${F}.egressInboundTagsPlaceholder`)}
            />
          </FormField>
          <AntdForm.Item label={t(`${F}.egressSocksPort`)}>
            <Input
              value={socksPort > 0 ? String(socksPort) : t(`${F}.egressSocksPortUnassigned`)}
              disabled
            />
          </AntdForm.Item>
        </>
      )}
    </>
  );
}
