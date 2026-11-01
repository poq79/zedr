import { useCallback, useEffect, useMemo, useState } from 'react';
import { useNavigate, useParams, useSearchParams } from 'react-router-dom';
import { ArrowLeft, RefreshCw, Search } from 'lucide-react';
import { api } from '../lib/api';
import type { AgentCommand, Alert, Host, HostInventorySection, User } from '../lib/types';
import { relTime, fmtTime, SEV_LABEL } from '../lib/format';
import { Badge, Button, Card, CardTitle, Input, SkeletonRows, Tabs } from '../components/ui/basics';
import { useToast, useConfirm } from '../components/ui/overlays';
import { useError } from '../lib/hooks';
import { cn } from '../lib/utils';
import { LiveFilesTab } from './HostLiveFiles';

/* 主机详情（整页，/hosts/:id）。
   资产清单 7 节各有明确 schema（服务/任务/自启动动辄数百行），
   所以按节做专属渲染：搜索 + 状态过滤 + 分页，而不是甩一段 JSON。 */

type Row = Record<string, unknown>;

const CMD_LABEL: Record<string, string> = {
  rescan: '重新扫描', sync_rules: '同步规则', collect: '采集清单',
  terminate: '终止进程', quarantine_file: '隔离文件', quarantine_restore: '恢复隔离',
};
const CMD_STATUS_TONE: Record<string, string> = {
  pending: 'medium', delivered: 'info', done: 'resolved', failed: 'critical',
};

const num = (v: unknown) => (typeof v === 'number' ? v : Number(v) || 0);
const str = (v: unknown) => (v == null ? '' : String(v));

export function HostDetailPage({ user }: { user: User }) {
  const { id = '' } = useParams();
  const navigate = useNavigate();
  const err = useError();
  const toast = useToast();
  const confirm = useConfirm();
  const [host, setHost] = useState<Host | null>(null);
  const [recent, setRecent] = useState<Alert[] | null>(null);
  const [sections, setSections] = useState<HostInventorySection[] | null>(null);
  const [cmds, setCmds] = useState<AgentCommand[] | null>(null);
  const [cmdBusy, setCmdBusy] = useState('');
  const [qPath, setQPath] = useState('');
  const [qPid, setQPid] = useState('');
  const [changes, setChanges] = useState<Alert[] | null>(null);
  const [changeSection, setChangeSection] = useState('');
  const [searchParams, setSearchParams] = useSearchParams();
  const tab = searchParams.get('tab') || 'overview';
  const setTab = (k: string) => setSearchParams(k === 'overview' ? {} : { tab: k }, { replace: true });

  const load = useCallback(async () => {
    try {
      // GET /hosts/{id} 返回 {agent, alerts, alert_total}——附带最近告警供上下文联动
      const d = await api.get<{ agent: Host; alerts: Alert[] }>(`/api/v1/hosts/${encodeURIComponent(id)}`);
      setHost(d.agent);
      setRecent(d.alerts || []);
      setSections((await api.get<{ sections: HostInventorySection[] }>(`/api/v1/hosts/${encodeURIComponent(id)}/inventory`)).sections || []);
      const all = (await api.get<{ items: AgentCommand[] }>('/api/v1/commands')).items || [];
      setCmds(all.filter((c) => c.agent_id === id));
      setChanges((await api.get<{ items: Alert[] }>(`/api/v1/hosts/${encodeURIComponent(id)}/changes?limit=100`)).items || []);
    } catch (e) { err.capture(e); }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [id]);

  /* 变更节过滤：服务端 ?section= 白名单过滤，切 chip 重新拉取 */
  useEffect(() => {
    if (!id || changeSection === '') return;
    api.get<{ items: Alert[] }>(`/api/v1/hosts/${encodeURIComponent(id)}/changes?limit=100&section=${encodeURIComponent(changeSection)}`)
      .then((r) => setChanges(r.items || []))
      .catch(() => setChanges([]));
  }, [changeSection, id]);

  useEffect(() => { setHost(null); setRecent(null); setSections(null); setCmds(null); setChanges(null); load(); }, [load]);
  if (err.rendered) return err.rendered;

  const sec = (name: string) => sections?.find((s) => s.name === name);
  const rowsOf = (name: string): Row[] => {
    const s = sec(name);
    return s ? parseAny(s) : [];
  };

  const send = async (type: string, payload = '', dangerNote?: { title: string; message: string; danger?: boolean; okText?: string }) => {
    if (dangerNote) {
      const ok = await confirm(dangerNote);
      if (!ok) return;
    }
    setCmdBusy(type + payload);
    try {
      await api.post(`/api/v1/hosts/${encodeURIComponent(id)}/commands`, { type, payload });
      toast(`指令 ${CMD_LABEL[type] || type} 已下发，等待终端执行`);
      const all = (await api.get<{ items: AgentCommand[] }>('/api/v1/commands')).items || [];
      setCmds(all.filter((c) => c.agent_id === id));
    } catch (ex) { toast((ex as Error).message, 'err'); }
    finally { setCmdBusy(''); }
  };

  return (
    <div>
      {/* 页头：返回 + 主机标识 + 动作 */}
      <div className="mb-4 flex flex-wrap items-center gap-3">
        <button onClick={() => navigate('/hosts')} aria-label="返回主机列表"
          className="grid h-8 w-8 cursor-pointer place-items-center rounded-md border border-border-soft bg-card text-muted-foreground transition-colors hover:bg-accent hover:text-foreground">
          <ArrowLeft size={15} />
        </button>
        <div className="min-w-0">
          <div className="flex items-center gap-2.5">
            <h1 className="m-0 text-[18px] font-semibold tracking-tight">{host?.hostname ?? '…'}</h1>
            {host && <Badge tone={host.status}>{host.status === 'online' ? '在线' : '离线'}</Badge>}
            {(host?.clock_skew_ms || 0) > 10000 && <Badge tone="medium" title="终端与服务端时钟偏移超过 10 秒">时钟偏移 {Math.round(host!.clock_skew_ms! / 1000)}s</Badge>}
          </div>
          <div className="mt-0.5 font-mono text-[11.5px] text-faint">{id}{host ? ` · ${host.os_version} · ${host.arch} · 探针 v${host.version}` : ''}</div>
        </div>
        <div className="flex-1" />
        <Button size="sm" onClick={() => send('rescan')} disabled={!!cmdBusy}>
          <RefreshCw size={13} className={cn(cmdBusy === 'rescan' && 'anim-spin')} /> 重新扫描
        </Button>
        <Button size="sm" onClick={() => send('sync_rules')} disabled={!!cmdBusy}>同步规则</Button>
        <Button size="sm" onClick={() => send('collect')} disabled={!!cmdBusy}>采集清单</Button>
      </div>

      {!host || !sections ? (
        <Card className="px-2 pb-2"><SkeletonRows rows={6} /></Card>
      ) : (
        <div>
          <Tabs
            className="mb-3.5" value={tab} onChange={setTab}
            tabs={[
              { key: 'overview', label: '概览' },
              { key: 'services', label: '服务', count: rowsOf('services').length },
              { key: 'tasks', label: '计划任务', count: rowsOf('tasks').length },
              { key: 'startup', label: '自启动', count: rowsOf('startup').length },
              { key: 'network', label: '网络', count: rowsOf('adapters').length + rowsOf('listeners').length },
              { key: 'live', label: '实时文件' },
              { key: 'changes', label: '变更', count: changes?.length },
              { key: 'ops', label: '处置与历史', count: cmds?.length },
            ]}
          />
          <div key={tab} className="anim-page flex flex-col gap-3.5">
            {tab === 'overview' && (
              <>
                <div className="grid gap-3.5 lg:grid-cols-2">
                  <SystemCard s={sec('system')} host={host} />
                  <AgentCard s={sec('agent')} />
                </div>
          {/* 最近告警：/hosts/{id} 随附 20 条，点行进告警详情（/alerts?open=id） */}
          <Card className="px-2 py-3.5">
            <div className="mb-1 flex items-center gap-2.5 px-3.5">
              <CardTitle>最近告警</CardTitle>
              <span className="font-mono text-[11px] text-ghost">{recent?.length ?? 0}</span>
              <div className="flex-1" />
              <span className="text-[11px] text-ghost">点击行进入告警详情</span>
            </div>
            {!recent ? <SkeletonRows rows={3} /> : !recent.length ? (
              <div className="px-4 py-6 text-center text-[12.5px] text-faint">这台主机近期没有告警——环境安静</div>
            ) : (
              <table className="w-full text-[12.5px]">
                <tbody>
                  {recent.map((a) => (
                    <tr key={a.id} onClick={() => navigate(`/alerts?open=${encodeURIComponent(a.id)}`)}
                      className="cursor-pointer border-b border-border-soft transition-colors last:border-b-0 hover:bg-secondary">
                      <td className="w-[72px] px-3.5 py-2"><Badge tone={a.severity}>{SEV_LABEL[a.severity]}</Badge></td>
                      <td className="px-3.5 py-2"><span className="block max-w-[420px] truncate font-medium">{a.title}</span></td>
                      <td className="px-3.5 py-2 font-mono text-[11.5px] text-faint">{a.process_name}</td>
                      <td className="w-[64px] px-3.5 py-2 font-mono font-semibold tabular-nums">{a.score}</td>
                      <td className="w-[90px] px-3.5 py-2 text-xs text-faint">{relTime(a.created_at)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </Card>

              </>
            )}
            {tab === 'services' && (
          <BigTable title="服务" rows={rowsOf('services')} searchKeys={['name', 'display_name', 'path_name', 'account']}
            stateKey="state" stateLabel="运行状态"
            columns={[
              { key: 'name', label: '服务名', mono: true },
              { key: 'display_name', label: '显示名' },
              { key: 'state', label: '状态', badge: true, tone: (v) => (str(v) === 'running' ? 'resolved' : str(v) === 'stopped' ? 'neutral' : 'info') },
              { key: 'start_mode', label: '启动类型', mono: true },
              { key: 'path_name', label: '二进制路径', mono: true, truncate: true },
              { key: 'account', label: '账号', mono: true },
            ]} />

            )}
            {tab === 'tasks' && (
          <BigTable title="计划任务" rows={rowsOf('tasks')} searchKeys={['path', 'name']}
            stateKey="state" stateLabel="状态"
            columns={[
              { key: 'name', label: '任务名', mono: true },
              { key: 'path', label: '路径', mono: true, truncate: true },
              { key: 'state', label: '状态', badge: true, tone: (v) => (str(v) === 'ready' ? 'resolved' : 'neutral') },
            ]} />

            )}
            {tab === 'startup' && (
          <BigTable title="自启动项" rows={rowsOf('startup')} searchKeys={['kind', 'location', 'value']}
            stateKey="kind" stateLabel="类型" kindLabel
            columns={[
              { key: 'kind', label: '类型', badge: true, tone: () => 'info', labelMap: KIND_LABEL },
              { key: 'location', label: '位置', mono: true, truncate: true },
              { key: 'value', label: '命令 / 值', mono: true, truncate: true },
            ]} />

            )}
            {tab === 'network' && (
              <>
              <SectionCard title="网络适配器" count={sec('adapters') && parseAny(sec('adapters')!).length} >
                {sec('adapters') && <AdaptersTable rows={parseAny(sec('adapters')!)} />}
              </SectionCard>

              <SectionCard title="监听端口" extra={sec('listeners') && <ListenersSummary s={sec('listeners')!} />}>
                {sec('listeners') && <ListenersTable s={sec('listeners')!} />}
              </SectionCard>

              </>
            )}
            {tab === 'live' && <LiveFilesTab agentId={id} user={user} />}
            {tab === 'changes' && (
              <Card className="p-4">
                <div className="mb-2.5 flex flex-wrap items-center gap-2.5">
                  <CardTitle>资产变更历史</CardTitle>
                  <span className="font-mono text-[11px] text-ghost">{changes?.length ?? 0}</span>
                  <div className="flex-1" />
                  <div className="flex flex-wrap gap-1">
                    {[{ k: '', l: '全部' }, { k: 'system', l: '系统' }, { k: 'adapters', l: '适配器' }, { k: 'listeners', l: '端口' }, { k: 'services', l: '服务' }, { k: 'tasks', l: '任务' }, { k: 'startup', l: '启动项' }, { k: 'agent', l: '探针' }].map((c) => (
                      <button key={c.k} onClick={() => { setChangeSection(c.k); if (c.k === '') load(); }}
                        className={cn('cursor-pointer rounded-[5px] border px-2 py-1 text-[11.5px] transition-colors',
                          changeSection === c.k ? 'border-border-strong bg-secondary font-medium text-foreground' : 'border-border-soft text-muted-foreground hover:text-foreground')}>
                        {c.l}
                      </button>
                    ))}
                  </div>
                </div>
                {!changes ? <SkeletonRows rows={3} /> : !changes.length ? (
                  <div className="px-4 py-6 text-center text-[12.5px] text-faint">该范围内没有资产变更记录</div>
                ) : (
                  <table className="w-full text-[12.5px]">
                    <tbody>
                      {changes.map((c) => (
                        <tr key={c.id} onClick={() => navigate(`/alerts?open=${encodeURIComponent(c.id)}`)}
                          className="cursor-pointer border-b border-border-soft transition-colors last:border-b-0 hover:bg-secondary">
                          <td className="w-[72px] px-3 py-2"><Badge tone={c.severity}>{SEV_LABEL[c.severity]}</Badge></td>
                          <td className="px-3 py-2"><span className="block max-w-[520px] truncate font-medium" title={c.title}>{c.title}</span></td>
                          <td className="px-3 py-2 font-mono text-[11.5px] text-faint">{c.process_name}</td>
                          <td className="w-[90px] px-3 py-2 text-xs text-faint">{relTime(c.created_at)}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
                <p className="mt-2 text-xs text-faint">变更事件由探针 30s 差量上报触发（监听端口/服务/任务/启动项等），并进入告警管线。</p>
              </Card>
            )}
            {tab === 'ops' && (
              <>
              {/* 处置指令 */}
              <Card className="p-4">
                <CardTitle className="mb-2.5">处置指令</CardTitle>
                <div className="flex flex-col gap-2 rounded-md border border-border-soft bg-destructive-soft/40 p-3.5">
                  <div className="flex flex-wrap items-center gap-2">
                    <Input value={qPath} onChange={(e) => setQPath(e.target.value)} placeholder="文件完整路径，例 C:\Users\...\sample.exe" className="min-w-[280px] flex-1 font-mono text-[12px]" spellCheck={false} />
                    <Button variant="danger" size="sm" disabled={!qPath.trim() || !!cmdBusy}
                      onClick={() => send('quarantine_file', qPath.trim(), {
                        title: '隔离该文件？', danger: true, okText: '隔离',
                        message: `将把 ${qPath.trim()} 移入终端侧隔离区并阻断执行。\n路径以终端实际文件为准；终端侧还有第二道确认开关。`,
                      })}>隔离文件</Button>
                    <Button size="sm" disabled={!qPath.trim() || !!cmdBusy}
                      onClick={() => send('quarantine_restore', qPath.trim(), {
                        title: '恢复该文件？', okText: '恢复',
                        message: `将把 ${qPath.trim()} 从隔离区还原到原路径。`,
                      })}>恢复隔离</Button>
                  </div>
                  <div className="flex flex-wrap items-center gap-2">
                    <Input value={qPid} onChange={(e) => setQPid(e.target.value)} placeholder="目标进程 PID" className="w-[200px] font-mono text-[12px]" inputMode="numeric" />
                    <Button variant="danger" size="sm" disabled={!qPid.trim() || !!cmdBusy}
                      onClick={() => send('terminate', qPid.trim(), {
                        title: `终止进程 PID ${qPid.trim()}？`, danger: true, okText: '终止',
                        message: `将向终端下发进程终止指令（PID ${qPid.trim()}）。\n请确认 PID 属于恶意进程——误杀系统进程可能导致蓝屏或服务中断。`,
                      })}>终止进程</Button>
                    <span className="text-[11px] text-ghost">处置类指令需服务端与终端双侧开关开启；下发前先在告警详情核对证据</span>
                  </div>
                </div>
              </Card>

              {/* 指令历史 */}
              <Card className="px-2 py-3.5">
                <div className="mb-1 flex items-center gap-2.5 px-3.5">
                  <CardTitle>指令历史</CardTitle>
                  <div className="flex-1" />
                  <span className="text-[11px] text-ghost">{(cmds || []).length} 条</span>
                </div>
                {!cmds ? <SkeletonRows rows={2} /> : !cmds.length ? (
                  <div className="px-4 py-6 text-center text-[12.5px] text-faint">还没有指令记录</div>
                ) : (
                  <table className="w-full text-[13px]">
                    <thead><tr className="border-b border-border-soft text-left text-[11px] tracking-[.06em] text-faint uppercase">
                      {['指令', '状态', '载荷', '结果', '下发时间', '操作人'].map((h) => <th key={h} className="px-3.5 py-2.5 font-semibold">{h}</th>)}
                    </tr></thead>
                    <tbody>
                      {cmds.map((c) => (
                        <tr key={c.id} className="border-b border-border-soft transition-colors last:border-b-0 hover:bg-secondary">
                          <td className="px-3.5 py-2.5 font-medium">{CMD_LABEL[c.type] || c.type}</td>
                          <td className="px-3.5 py-2.5"><Badge tone={CMD_STATUS_TONE[c.status] || 'neutral'}>{c.status}</Badge></td>
                          <td className="max-w-[240px] px-3.5 py-2.5"><span className="block truncate font-mono text-[11.5px] text-muted-foreground" title={c.payload}>{c.payload || '-'}</span></td>
                          <td className="max-w-[220px] px-3.5 py-2.5"><span className="block truncate font-mono text-[11.5px] text-faint" title={c.result}>{c.result || '-'}</span></td>
                          <td className="px-3.5 py-2.5 text-xs text-faint" title={fmtTime(c.created_at)}>{relTime(c.created_at)}</td>
                          <td className="px-3.5 py-2.5 font-mono text-xs">{c.created_by || '-'}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
              </Card>
              </>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

/* ================= 节渲染器 ================= */

function SectionCard({ title, count, extra, children }: { title: string; count?: number | null; extra?: React.ReactNode; children: React.ReactNode }) {
  return (
    <Card className="p-4">
      <div className="mb-2.5 flex items-center gap-2.5">
        <CardTitle>{title}</CardTitle>
        {count != null && <span className="font-mono text-[11px] text-ghost">{count}</span>}
        <div className="flex-1" />
        {extra}
      </div>
      {children}
    </Card>
  );
}

/** payload 解析：数组 / {items:[]} / 平铺对象，统一为"行数组或平铺" */
function parseAny(s: HostInventorySection): Row[] {
  try {
    const p = JSON.parse(s.payload) as unknown;
    if (Array.isArray(p)) return p as Row[];
    if (p && typeof p === 'object') {
      const o = p as Row;
      if (Array.isArray(o.items)) return o.items as Row[];
      for (const k of ['tcp', 'udp']) {
        if (Array.isArray(o[k])) return (o[k] as Row[]).map((r) => ({ proto: k.toUpperCase(), ...r }));
      }
    }
  } catch { /* 落到空 */ }
  return [];
}

const GB = 1024;

function SystemCard({ s, host }: { s?: HostInventorySection; host: Host }) {
  let sys: Record<string, unknown> | null = null;
  if (s) { try { sys = JSON.parse(s.payload) as Record<string, unknown>; } catch { /* 原样 */ } }
  const memTotal = sys ? num(sys.mem_total_mb) : 0;
  const memFree = sys ? num(sys.mem_free_mb) : 0;
  const disks = sys && Array.isArray(sys.disks) ? (sys.disks as Row[]) : [];
  return (
    <Card className="p-4">
      <div className="mb-2.5 flex items-center gap-2.5">
        <CardTitle>系统概要</CardTitle>
        <div className="flex-1" />
        <span className="font-mono text-[10.5px] text-ghost" title={s?.hash}>#{(s?.hash || '').slice(0, 8)}</span>
      </div>
      {!sys ? <div className="py-4 text-center text-[12.5px] text-faint">暂无数据</div> : (
        <>
          <div className="mb-3 text-[12.5px]"><b>{str(sys.cpu_name) || '-'}</b><span className="ml-2 font-mono text-faint">{num(sys.cpu_cores)} 核</span></div>
          <div className="mb-3">
            <div className="mb-1 flex justify-between text-[11.5px] text-faint">
              <span>内存</span>
              <span className="font-mono tabular-nums">{(memFree / GB).toFixed(1)} / {(memTotal / GB).toFixed(0)} GB 可用</span>
            </div>
            <div className="h-1.5 overflow-hidden rounded-[3px] bg-border-soft">
              <i className="block h-full rounded-[3px] bg-foreground" style={{ width: `${Math.min(100, ((memTotal - memFree) / Math.max(1, memTotal)) * 100)}%` }} />
            </div>
          </div>
          <div className="mb-3 flex flex-col gap-1.5">
            {disks.map((d) => {
              const total = num(d.total_mb), free = num(d.free_mb);
              return (
                <div key={str(d.drive)}>
                  <div className="mb-1 flex justify-between text-[11.5px] text-faint">
                    <span className="font-mono">{str(d.drive)}</span>
                    <span className="font-mono tabular-nums">{(free / GB).toFixed(0)} / {(total / GB).toFixed(0)} GB 可用</span>
                  </div>
                  <div className="h-1.5 overflow-hidden rounded-[3px] bg-border-soft">
                    <i className={cn('block h-full rounded-[3px]', (total - free) / Math.max(1, total) > 0.9 ? 'bg-crit' : 'bg-foreground')}
                      style={{ width: `${Math.min(100, ((total - free) / Math.max(1, total)) * 100)}%` }} />
                  </div>
                </div>
              );
            })}
          </div>
          <dl className="grid grid-cols-[110px_1fr] gap-x-3 gap-y-1.5 text-[12px]">
            <dt className="text-faint">开机时间</dt><dd className="m-0 font-mono">{str(sys.boot_time) ? fmtTime(str(sys.boot_time)) : '-'}</dd>
            <dt className="text-faint">已运行</dt><dd className="m-0 font-mono tabular-nums">{Math.round(num(sys.uptime_sec) / 3600)} 小时</dd>
            <dt className="text-faint">运行账号</dt><dd className="m-0 font-mono">{host.username || '-'}</dd>
            <dt className="text-faint">最后心跳</dt><dd className="m-0">{fmtTime(host.last_seen_at)}</dd>
          </dl>
        </>
      )}
    </Card>
  );
}

function AgentCard({ s }: { s?: HostInventorySection }) {
  let a: Record<string, unknown> | null = null;
  if (s) { try { a = JSON.parse(s.payload) as Record<string, unknown>; } catch { /* 原样 */ } }
  const dropped = a ? num(a.queue_dropped) : 0;
  return (
    <Card className="p-4">
      <div className="mb-2.5 flex items-center gap-2.5">
        <CardTitle>探针状态</CardTitle>
        <div className="flex-1" />
        <span className="font-mono text-[10.5px] text-ghost" title={s?.hash}>#{(s?.hash || '').slice(0, 8)}</span>
      </div>
      {!a ? <div className="py-4 text-center text-[12.5px] text-faint">暂无数据</div> : (
        <dl className="grid grid-cols-[110px_1fr] gap-x-3 gap-y-1.5 text-[12px]">
          <dt className="text-faint">版本</dt><dd className="m-0 font-mono">v{str(a.version) || '-'}</dd>
          <dt className="text-faint">采集器</dt><dd className="m-0 font-mono">{str(a.collector) || '-'}</dd>
          <dt className="text-faint">扫描间隔</dt><dd className="m-0 font-mono tabular-nums">{num(a.scan_interval_sec)}s</dd>
          <dt className="text-faint">规则 / IOC</dt><dd className="m-0 font-mono tabular-nums">{num(a.rule_count)} / {num(a.ioc_count)}</dd>
          <dt className="text-faint">上报队列</dt>
          <dd className="m-0">{dropped > 0 ? <Badge tone="critical" title="队列溢出被丢弃的上报数——查终端日志">丢弃 {dropped}</Badge> : <Badge tone="resolved">无丢弃</Badge>}</dd>
          <dt className="text-faint">进程运行</dt><dd className="m-0 font-mono tabular-nums">{Math.round(num(a.uptime_sec) / 3600)} 小时</dd>
        </dl>
      )}
    </Card>
  );
}

function AdaptersTable({ rows }: { rows: Row[] }) {
  if (!rows.length) return <div className="py-4 text-center text-[12.5px] text-faint">暂无数据</div>;
  return (
    <table className="w-full text-[12.5px]">
      <thead><tr className="border-b border-border-soft text-left text-[11px] tracking-[.06em] text-faint uppercase">
        {['适配器', '状态', 'IP 地址', '网关', 'MAC'].map((h) => <th key={h} className="px-3 py-2 font-semibold">{h}</th>)}
      </tr></thead>
      <tbody>
        {rows.map((r, i) => (
          <tr key={i} className="border-b border-border-soft last:border-b-0">
            <td className="px-3 py-2 font-medium">{str(r.name)}</td>
            <td className="px-3 py-2">{str(r.oper_state) === 'up' ? <Badge tone="resolved">up</Badge> : <Badge tone="neutral">{str(r.oper_state) || '-'}</Badge>}</td>
            <td className="px-3 py-2"><span className="font-mono text-[11.5px]">{(Array.isArray(r.ips) ? r.ips : []).join('  ') || '-'}</span></td>
            <td className="px-3 py-2 font-mono text-[11.5px] text-faint">{str(r.gateway) || '-'}</td>
            <td className="px-3 py-2 font-mono text-[11.5px] text-faint">{str(r.mac) || '-'}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function ListenersSummary({ s }: { s: HostInventorySection }) {
  let counts = { tcp: 0, udp: 0 };
  try {
    const p = JSON.parse(s.payload) as { tcp?: unknown[]; udp?: unknown[] };
    counts = { tcp: (p.tcp || []).length, udp: (p.udp || []).length };
  } catch { /* 忽略 */ }
  return (
    <span className="font-mono text-[11px] text-ghost">TCP {counts.tcp} · UDP {counts.udp}</span>
  );
}

function ListenersTable({ s }: { s: HostInventorySection }) {
  const rows = parseAny(s);
  const [q, setQ] = useState('');
  const filtered: Row[] = useMemo(() => rows
    .map((r): Row => ({ ...r, port: num(r.port), pid: num(r.pid) }))
    .sort((x, y) => num(x.port) - num(y.port))
    .filter((r) => !q || String(r.port).includes(q) || String(r.pid).includes(q)), [rows, q]);
  const page = filtered.slice(0, 60);
  if (!rows.length) return <div className="py-4 text-center text-[12.5px] text-faint">暂无数据</div>;
  return (
    <>
      <div className="mb-2 flex items-center gap-2">
        <div className="relative">
          <Search size={13} className="pointer-events-none absolute top-1/2 left-2.5 -translate-y-1/2 text-ghost" />
          <Input value={q} onChange={(e) => setQ(e.target.value)} placeholder="过滤端口 / PID" className="h-7 w-[200px] pl-7 font-mono text-[12px]" />
        </div>
        <span className="text-[11px] text-faint">显示前 60 条（共 {rows.length}）</span>
      </div>
      <table className="w-full text-[12.5px]">
        <thead><tr className="border-b border-border-soft text-left text-[11px] tracking-[.06em] text-faint uppercase">
          {['协议', '端口', 'PID'].map((h) => <th key={h} className="px-3 py-2 font-semibold">{h}</th>)}
        </tr></thead>
        <tbody>
          {page.map((r, i) => (
            <tr key={i} className="border-b border-border-soft last:border-b-0">
              <td className="px-3 py-1.5"><Badge tone={str(r.proto) === 'TCP' ? 'info' : 'neutral'}>{str(r.proto)}</Badge></td>
              <td className="px-3 py-1.5 font-mono tabular-nums">{str(r.port)}</td>
              <td className="px-3 py-1.5 font-mono tabular-nums text-faint">{str(r.pid) || '-'}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </>
  );
}

const KIND_LABEL: Record<string, string> = {
  registry_run: '注册表 Run', startup_folder: '启动文件夹', service: '服务', scheduled_task: '计划任务',
};

interface Col { key: string; label: string; mono?: boolean; truncate?: boolean; badge?: boolean; tone?: (v: unknown) => string; labelMap?: Record<string, string> }

/** 大行数表：搜索 + 状态过滤 + 分页（服务 247 / 任务 187 / 自启动 422 行实测） */
function BigTable({ title, rows, columns, searchKeys, stateKey, stateLabel, kindLabel }: {
  title: string; rows: Row[]; columns: Col[]; searchKeys: string[]; stateKey: string; stateLabel: string; kindLabel?: boolean;
}) {
  const [q, setQ] = useState('');
  const [state, setState] = useState('');
  const [page, setPage] = useState(1);
  const PAGE = 50;

  const states = useMemo(() => Array.from(new Set(rows.map((r) => str(r[stateKey])).filter(Boolean))).sort(), [rows, stateKey]);
  const filtered = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return rows.filter((r) => {
      if (state && str(r[stateKey]) !== state) return false;
      if (!needle) return true;
      return searchKeys.some((k) => str(r[k]).toLowerCase().includes(needle));
    });
  }, [rows, q, state, searchKeys, stateKey]);

  const pages = Math.max(1, Math.ceil(filtered.length / PAGE));
  const cur = Math.min(page, pages);
  const view = filtered.slice((cur - 1) * PAGE, cur * PAGE);

  if (!rows.length) return null;

  return (
    <Card className="p-4">
      <div className="mb-2.5 flex flex-wrap items-center gap-2.5">
        <CardTitle>{title}</CardTitle>
        <span className="font-mono text-[11px] text-ghost">{rows.length}</span>
        <div className="flex-1" />
        <div className="relative">
          <Search size={13} className="pointer-events-none absolute top-1/2 left-2.5 -translate-y-1/2 text-ghost" />
          <Input value={q} onChange={(e) => { setQ(e.target.value); setPage(1); }} placeholder={`搜索 ${title}`} className="h-7 w-[220px] pl-7 text-[12px]" />
        </div>
        <select value={state} onChange={(e) => { setState(e.target.value); setPage(1); }}
          className="h-7 cursor-pointer rounded-md border border-input bg-card px-2 text-[12px] text-foreground outline-none focus:border-primary">
          <option value="">全部{stateLabel}</option>
          {states.map((s) => <option key={s} value={s}>{kindLabel ? (KIND_LABEL[s] || s) : s}</option>)}
        </select>
      </div>
      <div className="overflow-x-auto">
        <table className="w-full text-[12.5px]">
          <thead><tr className="border-b border-border-soft text-left text-[11px] tracking-[.06em] text-faint uppercase">
            {columns.map((c) => <th key={c.key} className="px-3 py-2 font-semibold">{c.label}</th>)}
          </tr></thead>
          <tbody>
            {view.map((r, i) => (
              <tr key={i} className="border-b border-border-soft transition-colors last:border-b-0 hover:bg-secondary">
                {columns.map((c) => (
                  <td key={c.key} className="px-3 py-1.5">
                    {c.badge
                      ? <Badge tone={c.tone ? c.tone(r[c.key]) : 'neutral'}>{c.labelMap ? (c.labelMap[str(r[c.key])] || str(r[c.key])) : (str(r[c.key]) || '-')}</Badge>
                      : <span className={cn('block', c.mono && 'font-mono text-[11.5px]', c.truncate && 'max-w-[320px] truncate text-faint')} title={str(r[c.key])}>{str(r[c.key]) || '-'}</span>}
                  </td>
                ))}
              </tr>
            ))}
            {!view.length && <tr><td colSpan={columns.length} className="px-3 py-6 text-center text-[12.5px] text-faint">没有匹配的行</td></tr>}
          </tbody>
        </table>
      </div>
      {pages > 1 && (
        <div className="mt-2 flex items-center gap-3 px-3">
          <Button size="sm" variant="ghost" disabled={cur <= 1} onClick={() => setPage(cur - 1)}>上一页</Button>
          <span className="font-mono text-[11px] text-faint">{cur} / {pages}</span>
          <Button size="sm" variant="ghost" disabled={cur >= pages} onClick={() => setPage(cur + 1)}>下一页</Button>
          <span className="text-[11px] text-faint">共 {filtered.length} 行（筛选后）</span>
        </div>
      )}
    </Card>
  );
}
