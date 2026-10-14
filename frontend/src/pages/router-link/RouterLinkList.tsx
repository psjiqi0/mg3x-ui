import { useMemo } from 'react';
import { useTranslation } from 'react-i18next';
import { Button, Card, Space, Switch, Table, Tag, Tooltip } from 'antd';
import type { ColumnsType } from 'antd/es/table';
import {
  DeleteOutlined,
  DisconnectOutlined,
  EditOutlined,
  ExperimentOutlined,
  PlusOutlined,
  ThunderboltOutlined,
} from '@ant-design/icons';

import type { RouterLinkRecord, RouterLinkStatus } from '@/schemas/api/router-link';

interface Props {
  records: RouterLinkRecord[];
  loading?: boolean;
  isMobile?: boolean;
  onAdd: () => void;
  onEdit: (record: RouterLinkRecord) => void;
  onDelete: (record: RouterLinkRecord) => void;
  onDial: (record: RouterLinkRecord) => void;
  onHangup: (record: RouterLinkRecord) => void;
  onTestDial: (record: RouterLinkRecord) => void;
  onToggleEnable: (record: RouterLinkRecord, next: boolean) => void;
  onToggleEgress: (record: RouterLinkRecord, next: boolean) => void;
}

const STATUS_COLOR: Record<RouterLinkStatus, string> = {
  up: '#52c41a',
  down: '#bfbfbf',
  dialing: '#faad14',
  error: '#ff4d4f',
};

const PROTOCOL_COLOR: Record<string, string> = {
  openvpn: 'blue',
  pptp: 'orange',
  wireguard: 'green',
};

export function humanBytes(n: number): string {
  if (!Number.isFinite(n) || n <= 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let v = n;
  let u = 0;
  while (v >= 1024 && u < units.length - 1) {
    v /= 1024;
    u += 1;
  }
  return `${v >= 100 ? Math.round(v) : v.toFixed(1)} ${units[u]}`;
}

export function formatHandshakeAt(raw: number | string | undefined | null): string {
  if (raw == null || raw === '' || raw === 0) return '—';
  let ms: number;
  if (typeof raw === 'number') {
    ms = raw > 1e12 ? raw : raw * 1000; // 后端 int64 为 Unix 秒；毫秒也兼容
  } else {
    const asNum = Number(raw);
    if (raw.trim() !== '' && Number.isFinite(asNum)) {
      ms = asNum > 1e12 ? asNum : asNum * 1000;
    } else {
      const d = new Date(raw);
      if (Number.isNaN(d.getTime())) return raw;
      return d.toLocaleString();
    }
  }
  const d = new Date(ms);
  if (Number.isNaN(d.getTime())) return String(raw);
  return d.toLocaleString();
}

export default function RouterLinkList(props: Props) {
  const { t } = useTranslation();
  const F = 'pages.routerLink';
  const {
    records,
    loading,
    isMobile,
    onAdd,
    onEdit,
    onDelete,
    onDial,
    onHangup,
    onTestDial,
    onToggleEnable,
    onToggleEgress,
  } = props;

  const sorted = useMemo(() => [...records].sort((a, b) => a.id - b.id), [records]);

  const columns: ColumnsType<RouterLinkRecord> = [
    {
      title: t(`${F}.columns.actions`),
      key: 'actions',
      width: 210,
      fixed: 'left',
      render: (_, r) => (
        <Space size={2}>
          <Tooltip title={t(`${F}.testDial`)}>
            <Button
              size="small"
              type="text"
              icon={<ExperimentOutlined />}
              aria-label={t(`${F}.testDial`)}
              onClick={() => onTestDial(r)}
            />
          </Tooltip>
          <Tooltip title={t(`${F}.dial`)}>
            <Button
              size="small"
              type="text"
              icon={<ThunderboltOutlined />}
              aria-label={t(`${F}.dial`)}
              onClick={() => onDial(r)}
            />
          </Tooltip>
          <Tooltip title={t(`${F}.hangup`)}>
            <Button
              size="small"
              type="text"
              icon={<DisconnectOutlined />}
              aria-label={t(`${F}.hangup`)}
              onClick={() => onHangup(r)}
            />
          </Tooltip>
          <Tooltip title={t('edit')}>
            <Button
              size="small"
              type="text"
              icon={<EditOutlined />}
              aria-label={t('edit')}
              onClick={() => onEdit(r)}
            />
          </Tooltip>
          <Tooltip title={t('delete')}>
            <Button
              size="small"
              type="text"
              danger
              icon={<DeleteOutlined />}
              aria-label={t('delete')}
              onClick={() => onDelete(r)}
            />
          </Tooltip>
        </Space>
      ),
    },
    {
      title: t(`${F}.columns.enable`),
      key: 'enable',
      width: 80,
      render: (_, r) => (
        <Switch size="small" checked={r.enable} onChange={(next) => onToggleEnable(r, next)} />
      ),
    },
    {
      title: t(`${F}.columns.egress`),
      key: 'egress',
      width: 120,
      render: (_, r) => (
        <Space size={4}>
          <Switch
            size="small"
            checked={r.egress}
            onChange={(next) => onToggleEgress(r, next)}
          />
          {r.egress ? (
            <Tag color="green">{t(`${F}.form.egressOn`)}</Tag>
          ) : (
            <Tag>{t(`${F}.form.egressOff`)}</Tag>
          )}
          {r.egressSocksPort > 0 && (
            <Tooltip title={t(`${F}.form.egressSocksPort`)}>
              <Tag style={{ fontFamily: 'monospace' }}>:{r.egressSocksPort}</Tag>
            </Tooltip>
          )}
        </Space>
      ),
    },
    {
      title: t(`${F}.columns.name`),
      dataIndex: 'name',
      key: 'name',
      render: (name: string, r) => (
        <Space size={4} wrap>
          <span style={{ fontWeight: 600 }}>{name}</span>
          <Tag color={PROTOCOL_COLOR[r.protocol] ?? 'default'}>{r.protocol}</Tag>
          {r.protocol === 'pptp' && <Tag color="orange">{t(`${F}.form.compatBadge`)}</Tag>}
        </Space>
      ),
    },
    {
      title: t(`${F}.columns.remote`),
      key: 'remote',
      render: (_, r) => (
        <span>
          {r.remoteHost || '—'}
          {r.remotePort ? `:${r.remotePort}` : ''}
          {r.protocol === 'openvpn' && r.proto ? (
            <Tag style={{ marginInlineStart: 6 }}>{r.proto.toUpperCase()}</Tag>
          ) : null}
        </span>
      ),
    },
    {
      title: t(`${F}.columns.lanSubnet`),
      dataIndex: 'lanSubnet',
      key: 'lanSubnet',
      render: (v: string) => (v ? <Tag>{v}</Tag> : '—'),
    },
    {
      title: t(`${F}.columns.forwardedPorts`),
      dataIndex: 'forwardedPorts',
      key: 'forwardedPorts',
      render: (v: string) => {
        if (!v) return <span style={{ color: 'var(--ant-color-text-quaternary)' }}>—</span>;
        const short = v.length > 42 ? `${v.slice(0, 42)}…` : v;
        return (
          <Tooltip title={<span style={{ wordBreak: 'break-all' }}>{v}</span>}>
            <span style={{ fontFamily: 'monospace', fontSize: 12 }}>{short}</span>
          </Tooltip>
        );
      },
    },
    {
      title: t(`${F}.columns.status`),
      key: 'status',
      render: (_, r) => (
        <Space size={4}>
          <span
            style={{
              display: 'inline-block',
              width: 10,
              height: 10,
              borderRadius: '50%',
              background: STATUS_COLOR[r.status] ?? STATUS_COLOR.down,
              boxShadow: r.status === 'dialing' ? `0 0 6px ${STATUS_COLOR.dialing}` : undefined,
              animation: r.status === 'dialing' ? 'rl-blink 1s infinite' : undefined,
            }}
          />
          <span>{t(`${F}.status.${r.status}`)}</span>
          {r.message ? (
            <Tooltip title={r.message}>
              <span style={{ color: 'var(--ant-color-text-quaternary)', cursor: 'help' }}>ⓘ</span>
            </Tooltip>
          ) : null}
        </Space>
      ),
    },
    {
      title: t(`${F}.columns.handshakeAt`),
      dataIndex: 'handshakeAt',
      key: 'handshakeAt',
      render: (v: number | string) => (
        <span style={{ whiteSpace: 'nowrap' }}>{formatHandshakeAt(v)}</span>
      ),
    },
    {
      title: t(`${F}.columns.traffic`),
      key: 'traffic',
      render: (_, r) => (
        <span style={{ whiteSpace: 'nowrap' }}>
          ↓{humanBytes(r.rxBytes)} ↑{humanBytes(r.txBytes)}
        </span>
      ),
    },
    {
      title: t(`${F}.columns.auth`),
      key: 'auth',
      render: (_, r) => (
        <Space size={4}>
          {r.hasAuth?.password ? (
            <Tag color="green">{t(`${F}.auth.passwordSet`)}</Tag>
          ) : (
            <Tag>{t(`${F}.auth.passwordUnset`)}</Tag>
          )}
          {r.hasAuth?.cert ? <Tag color="cyan">{t(`${F}.auth.certSet`)}</Tag> : null}
        </Space>
      ),
    },
  ];

  const toolbar = (
    <div className="card-toolbar">
      <Button type="primary" icon={<PlusOutlined />} onClick={onAdd}>
        {!isMobile && t(`${F}.add`)}
      </Button>
    </div>
  );

  return (
    <Card size="small" hoverable title={toolbar} className="router-link-card">
      <style>{`@keyframes rl-blink { 0%,100% { opacity: 1; } 50% { opacity: 0.35; } }`}</style>
      <Table<RouterLinkRecord>
        rowKey="id"
        size="small"
        loading={loading}
        columns={columns}
        dataSource={sorted}
        pagination={false}
        scroll={{ x: 'max-content' }}
        locale={{
          emptyText: (
            <div className="card-empty">
              <ThunderboltOutlined style={{ fontSize: 32, marginBottom: 8 }} />
              <div>{t('noData')}</div>
            </div>
          ),
        }}
      />
    </Card>
  );
}
