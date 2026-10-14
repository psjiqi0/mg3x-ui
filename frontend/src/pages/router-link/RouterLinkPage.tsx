import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import {
  Button,
  Card,
  Col,
  ConfigProvider,
  Descriptions,
  Layout,
  Modal,
  Result,
  Row,
  Spin,
  Statistic,
  message,
} from 'antd';
import {
  CheckCircleOutlined,
  CloseCircleOutlined,
  LoadingOutlined,
  ThunderboltOutlined,
} from '@ant-design/icons';

import { useTheme } from '@/hooks/useTheme';
import { useMediaQuery } from '@/hooks/useMediaQuery';
import AppSidebar from '@/layouts/AppSidebar';
import { setMessageInstance } from '@/utils/messageBus';
import {
  buildRouterLinkPayload,
  RouterLinkFormSchema,
  type RouterLinkRecord,
  type RouterLinkStatusRecord,
} from '@/schemas/api/router-link';
import './routerLinkI18n';
import {
  deleteRouterLink,
  dialRouterLink,
  fetchRouterLinks,
  fetchRouterLinkStatus,
  hangupRouterLink,
  updateRouterLink,
} from './routerLinkApi';
import RouterLinkList, { formatHandshakeAt, humanBytes } from './RouterLinkList';
import RouterLinkFormModal from './RouterLinkFormModal';

const LIST_KEY = ['router-links', 'list'] as const;

function useRouterLinksQuery() {
  const query = useQuery({
    queryKey: LIST_KEY,
    queryFn: fetchRouterLinks,
    // 状态灯是运行时状态：后台 10s 对账一次，这里跟着 10s 刷新
    refetchInterval: 10_000,
  });
  const records = useMemo(() => query.data ?? [], [query.data]);
  return {
    records,
    loading: query.isFetching,
    fetched: query.data !== undefined || query.isError,
    fetchError: query.error ? (query.error as Error).message : '',
    refetch: query.refetch,
  };
}

interface TestDialState {
  record: RouterLinkRecord;
  seconds: number;
  phase: 'sending' | 'polling' | 'ok' | 'failed' | 'timeout';
  status?: RouterLinkStatusRecord;
  error?: string;
}

const TEST_DIAL_MAX_SECONDS = 30;

export default function RouterLinkPage() {
  const { t } = useTranslation();
  const { isDark, isUltra, antdThemeConfig } = useTheme();
  const { isMobile } = useMediaQuery();
  const F = 'pages.routerLink';
  const [modal, modalContextHolder] = Modal.useModal();
  const [messageApi, messageContextHolder] = message.useMessage();
  useEffect(() => {
    setMessageInstance(messageApi);
  }, [messageApi]);

  const queryClient = useQueryClient();
  const { records, loading, fetched, fetchError, refetch } = useRouterLinksQuery();
  const invalidate = useCallback(
    () => queryClient.invalidateQueries({ queryKey: LIST_KEY }),
    [queryClient],
  );

  const [formOpen, setFormOpen] = useState(false);
  const [formMode, setFormMode] = useState<'add' | 'edit'>('add');
  const [formRecord, setFormRecord] = useState<RouterLinkRecord | null>(null);
  const [testDial, setTestDial] = useState<TestDialState | null>(null);
  const testDialTimer = useRef<ReturnType<typeof setInterval> | null>(null);

  const stopTestDialTimer = useCallback(() => {
    if (testDialTimer.current) {
      clearInterval(testDialTimer.current);
      testDialTimer.current = null;
    }
  }, []);

  useEffect(() => stopTestDialTimer, [stopTestDialTimer]);

  const onAdd = useCallback(() => {
    setFormMode('add');
    setFormRecord(null);
    setFormOpen(true);
  }, []);

  const onEdit = useCallback((record: RouterLinkRecord) => {
    setFormMode('edit');
    setFormRecord({ ...record });
    setFormOpen(true);
  }, []);

  const onDelete = useCallback(
    (record: RouterLinkRecord) => {
      modal.confirm({
        title: t(`${F}.deleteConfirmTitle`, { name: record.name }),
        okText: t('delete'),
        okType: 'danger',
        cancelText: t('cancel'),
        onOk: async () => {
          const res = await deleteRouterLink(record.id);
          if (res?.success) {
            messageApi.success(t(`${F}.toasts.delete`));
            invalidate();
          } else if (res?.msg) {
            messageApi.error(res.msg);
          }
        },
      });
    },
    [modal, t, messageApi, invalidate],
  );

  const onDial = useCallback(
    async (record: RouterLinkRecord) => {
      const res = await dialRouterLink(record.id);
      if (res?.success) {
        messageApi.success(t(`${F}.toasts.dialSent`));
        invalidate();
      } else if (res?.msg) {
        messageApi.error(res.msg);
      }
    },
    [messageApi, t, invalidate],
  );

  const onHangup = useCallback(
    async (record: RouterLinkRecord) => {
      const res = await hangupRouterLink(record.id);
      if (res?.success) {
        messageApi.success(t(`${F}.toasts.hangupSent`));
        invalidate();
      } else if (res?.msg) {
        messageApi.error(res.msg);
      }
    },
    [messageApi, t, invalidate],
  );

  // 启用开关：走 update 且整个省略 auth（= 保留已有密钥，见 schema 注释）。
  const onToggleEnable = useCallback(
    async (record: RouterLinkRecord, next: boolean) => {
      const parsed = RouterLinkFormSchema.safeParse({
        id: record.id,
        name: record.name,
        protocol: record.protocol,
        enable: next,
        remoteHost: record.remoteHost,
        remotePort: record.remotePort,
        proto: record.proto || 'udp',
        lanSubnet: record.lanSubnet,
        tunnelAddress: record.tunnelAddress,
        mppe: record.mppe || 'require-mppe-128',
        persistentKeepalive: record.persistentKeepalive,
        forwardedPorts: record.forwardedPorts,
        egress: record.egress,
        egressInboundTags: record.egressInboundTags ?? [],
        egressSocksPort: record.egressSocksPort ?? 0,
        auth: { type: record.protocol === 'wireguard' ? 'psk' : 'password' },
      });
      if (!parsed.success) {
        messageApi.error(t(`${F}.toasts.saveFailed`));
        return;
      }
      const payload = buildRouterLinkPayload(parsed.data, { includeAuth: false });
      const res = await updateRouterLink(payload);
      if (res?.success) invalidate();
      else if (res?.msg) messageApi.error(res.msg);
    },
    [messageApi, t, invalidate],
  );

  // 出口开关：走 update（D2 的 POST /panel/routerlink/egress 尚未实现；实现后可切过去），
  // auth 整个省略 = 保留已有密钥。
  const onToggleEgress = useCallback(
    async (record: RouterLinkRecord, next: boolean) => {
      const parsed = RouterLinkFormSchema.safeParse({
        id: record.id,
        name: record.name,
        protocol: record.protocol,
        enable: record.enable,
        remoteHost: record.remoteHost,
        remotePort: record.remotePort,
        proto: record.proto || 'udp',
        lanSubnet: record.lanSubnet,
        tunnelAddress: record.tunnelAddress,
        mppe: record.mppe || 'require-mppe-128',
        persistentKeepalive: record.persistentKeepalive,
        forwardedPorts: record.forwardedPorts,
        egress: next,
        egressInboundTags: record.egressInboundTags ?? [],
        egressSocksPort: record.egressSocksPort ?? 0,
        auth: { type: record.protocol === 'wireguard' ? 'psk' : 'password' },
      });
      if (!parsed.success) {
        messageApi.error(t(`${F}.toasts.saveFailed`));
        return;
      }
      const payload = buildRouterLinkPayload(parsed.data, { includeAuth: false });
      const res = await updateRouterLink(payload);
      if (res?.success) {
        invalidate();
      } else if (res?.msg) {
        messageApi.error(res.msg);
      }
    },
    [messageApi, t, invalidate],
  );

  // 测试拨号：调 dial 后每 2s 轮询 status/:id，最多 30s
  const onTestDial = useCallback(
    (record: RouterLinkRecord) => {
      stopTestDialTimer();
      setTestDial({ record, seconds: 0, phase: 'sending' });
      let seconds = 0;
      const finish = (patch: Partial<TestDialState>) => {
        stopTestDialTimer();
        setTestDial((prev) => (prev ? { ...prev, ...patch } : prev));
        invalidate();
      };
      const poll = async () => {
        seconds += 2;
        setTestDial((prev) => (prev ? { ...prev, seconds, phase: 'polling' } : prev));
        try {
          const st = await fetchRouterLinkStatus(record.id);
          setTestDial((prev) => (prev ? { ...prev, status: st } : prev));
          if (st.status === 'up') {
            messageApi.success(t(`${F}.toasts.dialOk`));
            finish({ phase: 'ok', status: st });
            return;
          }
          if (st.status === 'error') {
            messageApi.error(t(`${F}.toasts.dialFailed`));
            finish({ phase: 'failed', status: st });
            return;
          }
        } catch (err) {
          finish({ phase: 'failed', error: (err as Error).message });
          return;
        }
        if (seconds >= TEST_DIAL_MAX_SECONDS) {
          messageApi.warning(t(`${F}.toasts.dialTimeout`));
          finish({ phase: 'timeout' });
        }
      };
      (async () => {
        try {
          const res = await dialRouterLink(record.id);
          if (!res?.success) {
            messageApi.error(res?.msg || t(`${F}.toasts.dialFailed`));
            finish({ phase: 'failed', error: res?.msg });
            return;
          }
          messageApi.success(t(`${F}.toasts.dialSent`));
        } catch (err) {
          finish({ phase: 'failed', error: (err as Error).message });
          return;
        }
        testDialTimer.current = setInterval(poll, 2000);
      })();
    },
    [messageApi, t, invalidate, stopTestDialTimer],
  );

  const summary = useMemo(() => {
    const total = records.length;
    const up = records.filter((r) => r.status === 'up').length;
    const error = records.filter((r) => r.status === 'error').length;
    return { total, up, down: total - up - error, error };
  }, [records]);

  const pageClass = useMemo(() => {
    const classes = ['router-link-page'];
    if (isDark) classes.push('is-dark');
    if (isUltra) classes.push('is-ultra');
    return classes.join(' ');
  }, [isDark, isUltra]);

  const testDialStatusIcon = (phase: TestDialState['phase']) => {
    if (phase === 'ok') return <CheckCircleOutlined style={{ color: 'var(--ant-color-success)', fontSize: 40 }} />;
    if (phase === 'failed' || phase === 'timeout')
      return <CloseCircleOutlined style={{ color: 'var(--ant-color-error)', fontSize: 40 }} />;
    return <LoadingOutlined style={{ fontSize: 40 }} />;
  };

  return (
    <ConfigProvider theme={antdThemeConfig}>
      {messageContextHolder}
      {modalContextHolder}
      <Layout className={pageClass}>
        <AppSidebar />
        <Layout className="content-shell">
          <Layout.Content id="content-layout" className="content-area">
            <Spin spinning={!fetched} delay={200} size="large">
              {!fetched ? (
                <div className="loading-spacer" />
              ) : fetchError ? (
                <Result
                  status="error"
                  title={t('somethingWentWrong')}
                  subTitle={fetchError}
                  extra={
                    <Button type="primary" loading={loading} onClick={() => refetch()}>
                      {t('refresh')}
                    </Button>
                  }
                />
              ) : (
                <Row gutter={[isMobile ? 8 : 16, isMobile ? 8 : 12]}>
                  <Col span={24}>
                    <Card size="small" hoverable className="summary-card">
                      <Row gutter={[16, 12]}>
                        <Col xs={6} sm={6} md={6}>
                          <Statistic
                            title={t(`${F}.summary.total`)}
                            value={String(summary.total)}
                            prefix={<ThunderboltOutlined />}
                          />
                        </Col>
                        <Col xs={6} sm={6} md={6}>
                          <Statistic
                            title={t(`${F}.summary.up`)}
                            value={String(summary.up)}
                            prefix={<CheckCircleOutlined style={{ color: 'var(--ant-color-success)' }} />}
                          />
                        </Col>
                        <Col xs={6} sm={6} md={6}>
                          <Statistic
                            title={t(`${F}.summary.down`)}
                            value={String(summary.down)}
                            prefix={<CheckCircleOutlined style={{ color: 'var(--ant-color-text-quaternary)' }} />}
                          />
                        </Col>
                        <Col xs={6} sm={6} md={6}>
                          <Statistic
                            title={t(`${F}.summary.error`)}
                            value={String(summary.error)}
                            prefix={<CloseCircleOutlined style={{ color: 'var(--ant-color-error)' }} />}
                          />
                        </Col>
                      </Row>
                    </Card>
                  </Col>
                  <Col span={24}>
                    <RouterLinkList
                      records={records}
                      loading={loading}
                      isMobile={isMobile}
                      onAdd={onAdd}
                      onEdit={onEdit}
                      onDelete={onDelete}
                      onDial={onDial}
                      onHangup={onHangup}
                      onTestDial={onTestDial}
                      onToggleEnable={onToggleEnable}
                      onToggleEgress={onToggleEgress}
                    />
                  </Col>
                </Row>
              )}
            </Spin>
          </Layout.Content>
        </Layout>

        <RouterLinkFormModal
          open={formOpen}
          mode={formMode}
          record={formRecord}
          onOpenChange={setFormOpen}
          onSaved={invalidate}
        />

        <Modal
          open={testDial !== null}
          title={testDial ? t(`${F}.testDialTitle`, { name: testDial.record.name }) : ''}
          footer={[
            <Button
              key="close"
              type="primary"
              onClick={() => {
                stopTestDialTimer();
                setTestDial(null);
              }}
            >
              {testDial && (testDial.phase === 'polling' || testDial.phase === 'sending')
                ? t('cancel')
                : t('close')}
            </Button>,
          ]}
          onCancel={() => {
            stopTestDialTimer();
            setTestDial(null);
          }}
          destroyOnHidden
        >
          {testDial && (
            <div style={{ textAlign: 'center', padding: '12px 0' }}>
              {testDialStatusIcon(testDial.phase)}
              <div style={{ marginTop: 12, fontSize: 15 }}>
                {(testDial.phase === 'sending' || testDial.phase === 'polling') &&
                  t(`${F}.testDialPolling`, { n: testDial.seconds })}
                {testDial.phase === 'ok' && t(`${F}.toasts.dialOk`)}
                {testDial.phase === 'failed' && t(`${F}.toasts.dialFailed`)}
                {testDial.phase === 'timeout' && t(`${F}.toasts.dialTimeout`)}
              </div>
              <div style={{ marginTop: 8, color: 'var(--ant-color-text-secondary)', fontSize: 12 }}>
                {t(`${F}.testDialHint`)}
              </div>
              {testDial.status && (
                <Descriptions
                  size="small"
                  column={1}
                  bordered
                  style={{ marginTop: 16, textAlign: 'left' }}
                >
                  <Descriptions.Item label={t(`${F}.columns.status`)}>
                    {t(`${F}.status.${testDial.status.status}`)}
                  </Descriptions.Item>
                  {testDial.status.iface ? (
                    <Descriptions.Item label={t(`${F}.testDialIface`)}>
                      {testDial.status.iface}
                    </Descriptions.Item>
                  ) : null}
                  <Descriptions.Item label={t(`${F}.columns.handshakeAt`)}>
                    {formatHandshakeAt(testDial.status.handshakeAt)}
                  </Descriptions.Item>
                  <Descriptions.Item label={t(`${F}.columns.traffic`)}>
                    ↓{humanBytes(testDial.status.rxBytes)} ↑{humanBytes(testDial.status.txBytes)}
                  </Descriptions.Item>
                  {testDial.status.message ? (
                    <Descriptions.Item label={t(`${F}.testDialMessage`)}>
                      {testDial.status.message}
                    </Descriptions.Item>
                  ) : null}
                </Descriptions>
              )}
              {testDial.error && !testDial.status && (
                <div style={{ marginTop: 12, color: 'var(--ant-color-error)' }}>{testDial.error}</div>
              )}
            </div>
          )}
        </Modal>
      </Layout>
    </ConfigProvider>
  );
}
