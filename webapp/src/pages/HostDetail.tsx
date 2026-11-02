import { Fragment, useCallback, useEffect, useMemo, useState } from 'react';
import { useNavigate, useParams, useSearchParams } from 'react-router-dom';
import { ArrowLeft, ChevronRight, RefreshCw, ScanSearch, Search, ShieldCheck } from 'lucide-react';
import { api, ApiError, live, liveErrorKind } from '../lib/api';
import type { AgentCommand, Alert, Host, HostInventorySection, LiveHash, LiveNetConn, LiveProcRow, User } from '../lib/types';
import { relTime, fmtTime, SEV_LABEL } from '../lib/format';
import { Badge, Button, Card, CardTitle, Input, SkeletonRows, Tabs } from '../components/ui/basics';
import { useToast, useConfirm } from '../components/ui/overlays';
import { useError } from '../lib/hooks';
import { cn } from '../lib/utils';
import { LiveFilesTab } from './HostLiveFiles';
import { LiveProcsTab, LiveProbeInfo } from './HostLiveProcs';
import { HostReconTab } from './HostReconTab';
import { HostBaselineTab } from './HostBaselineTab';
import { HostAccountsTab } from './HostAccountsTab';

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

/* ================= 服务 / 任务 / 网络深化（LIVE-TUNNEL §13.1） ================= */

/* 从服务路径或任务动作字符串里提取第一个绝对可执行路径。
   任务动作可能是 `"C:\x\a.exe" --arg` 或 `C:\x\a.bat /c ...`；非贪婪
   匹配到第一个扩展名即停，后面的参数不会混进哈希请求。 */
const EXE_RE = /[A-Za-z]:\\[^"]+?\.(?:exe|dll|com|bat|cmd|ps1)/i;

function extractExePath(raw: string): string {
  const s = (raw || '').trim();
  if (!s) return '';
  const quoted = s.match(/^"([^"]+?\.(?:exe|dll|com|bat|cmd|ps1))"/i);
  if (quoted) return quoted[1].trim();
  const m = s.match(EXE_RE);
  return m ? m[0].trim() : '';
}

const normPath = (p: string) => (p || '').trim().replace(/^"|"$/g, '').replace(/\//g, '\\').toLowerCase();

/* 用户可写（或低权限可写）位置 = 服务/任务的提权面。只做前缀/片段匹配，
   不做文件系统 ACL 查询——后者需要现场枚举父目录，成本远高于本轮收益。 */
const WRITABLE_RULES: { re: RegExp; label: string }[] = [
  { re: /^[a-z]:\\users\\/i, label: 'C:\\Users 用户目录' },
  { re: /\\windows\\temp\\/i, label: 'Windows\\Temp 临时目录' },
  { re: /\\temp\\/i, label: 'Temp 临时目录' },
  { re: /^[a-z]:\\programdata\\/i, label: 'ProgramData 公共目录' },
  { re: /\\(?:\$recycle\.bin|recycler)\\/i, label: '回收站目录' },
  { re: /\\appdata\\/i, label: 'AppData 用户配置目录' },
  { re: /\\downloads\\/i, label: '下载目录' },
  { re: /\\desktop\\/i, label: '桌面目录' },
];

function writableRiskLabel(path: string): string | null {
  const p = (path || '').trim().replace(/"/g, '');
  if (!/^[a-z]:\\/i.test(p)) return null;
  return WRITABLE_RULES.find((r) => r.re.test(p))?.label || null;
}

const isLoopbackAddr = (addr: string) => {
  const a = (addr || '').trim().replace(/^\[|\]$/g, '').toLowerCase();
  return a === '::1' || a === '127.0.0.1' || a.startsWith('127.');
};

/* 公网 IPv4：排除回环/私网/链路本地/组播/保留段；IPv6 只排除 ::/::1/
   fe80 链路本地与 fc00::/7 唯一本地地址，其余按公网处理（保守警示）。 */
function isPublicBind(addr: string): boolean {
  const a = (addr || '').trim().replace(/^\[|\]$/g, '');
  if (!a) return false;
  if (a.includes(':')) {
    const low = a.toLowerCase();
    if (low === '::' || low === '::1') return false;
    if (low.startsWith('fe80:') || low.startsWith('fc') || low.startsWith('fd')) return false;
    return true;
  }
  const parts = a.split('.').map((x) => Number(x));
  if (parts.length !== 4 || parts.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return false;
  const [b1, b2] = parts;
  if (b1 === 0 || b1 === 10 || b1 === 127 || b1 >= 224) return false;
  if (b1 === 172 && b2 >= 16 && b2 <= 31) return false;
  if (b1 === 192 && b2 === 168) return false;
  if (b1 === 169 && b2 === 254) return false;
  if (b1 === 100 && b2 >= 64 && b2 <= 127) return false; // CGNAT
  return true;
}

type ProcClass = 'system' | 'third' | 'unknown';

const SYSTEM_PROC = new Set([
  'system', 'smss.exe', 'csrss.exe', 'wininit.exe', 'winlogon.exe', 'services.exe',
  'lsass.exe', 'svchost.exe', 'spoolsv.exe', 'dwm.exe', 'fontdrvhost.exe',
  'audiodg.exe', 'msmpeng.exe', 'nissrv.exe', 'securityhealthservice.exe', 'wudfhost.exe',
]);

const PROC_CLASS_META: Record<ProcClass, { label: string; tone: string }> = {
  system: { label: '系统服务', tone: 'neutral' },
  third: { label: '第三方', tone: 'medium' },
  unknown: { label: '未知', tone: 'neutral' },
};

function classifyProc(name: string, path: string): ProcClass {
  const n = (name || '').trim().toLowerCase();
  const p = (path || '').trim().toLowerCase();
  if (p && /^[a-z]:\\windows\\(?:system32|syswow64|winsxs)\\/.test(p)) return 'system';
  if (n && SYSTEM_PROC.has(n)) return 'system';
  if (n === '(已退出)') return 'unknown';
  if (p || n) return 'third';
  return 'unknown';
}

interface BindExposure { label: string; tone: string; hint: string }

function exposureOf(addr: string, cls: ProcClass): BindExposure {
  if (!addr) {
    return { label: '绑定未知', tone: 'neutral', hint: '资产清单不含绑定地址，实时连接表也未匹配到该端口' };
  }
  const bare = addr.trim().replace(/^\[|\]$/g, '');
  if (isPublicBind(bare)) {
    return { label: '对外监听（公网）', tone: 'critical', hint: `绑定 ${addr}：可从公网直接访问，暴露面最高` };
  }
  if (bare === '0.0.0.0' || bare === '::') {
    return {
      label: '对外监听', tone: cls === 'system' ? 'neutral' : 'medium',
      hint: `绑定 ${addr}（全部网卡）${cls === 'system' ? '；系统服务，按中性呈现' : '；非系统进程监听全部网卡'}`,
    };
  }
  if (isLoopbackAddr(bare)) {
    return { label: '仅本机', tone: 'neutral', hint: `绑定 ${addr}，仅回环可达` };
  }
  return {
    label: '对外监听', tone: cls === 'system' ? 'neutral' : 'medium',
    hint: `绑定 ${addr}（非回环地址）`,
  };
}

/* 监听行的绑定地址：同一端口可能有 0.0.0.0 与 127.0.0.1 两条，优先展示
   暴露面最大的那条；没有实时连接表时返回空串，由 UI 显示"绑定未知"。 */
function pickBindAddr(conns: LiveNetConn[]): string {
  const addrs = conns.map((c) => (c.local_ip || '').trim()).filter(Boolean);
  return addrs.find((a) => isPublicBind(a))
    || addrs.find((a) => a === '0.0.0.0' || a === '::')
    || addrs.find((a) => !isLoopbackAddr(a))
    || addrs[0]
    || '';
}

/* 计划任务动作/触发/作者可能以对象或数组出现（后端后续版本扩展），
   统一压成可读文本；取不到就是空串，UI 明确写"清单未包含"。 */
function textOfValue(v: unknown): string {
  if (typeof v === 'string') return v.trim();
  if (typeof v === 'number') return String(v);
  if (Array.isArray(v)) return v.map(textOfValue).filter(Boolean).join('；');
  if (v && typeof v === 'object') {
    const o = v as Row;
    const cmd = textOfValue(o.command);
    const args = textOfValue(o.arguments);
    if (cmd) return [cmd, args].filter(Boolean).join(' ');
    for (const k of ['path', 'exec', 'value', 'name', 'kind', 'type', 'description']) {
      const t = textOfValue(o[k]);
      if (t) return t;
    }
  }
  return '';
}

function pickText(row: Row, keys: string[]): string {
  for (const k of keys) {
    const t = textOfValue(row[k]);
    if (t) return t;
  }
  return '';
}

const START_MODE_LABEL: Record<string, string> = {
  auto: '自动', manual: '手动', disabled: '禁用', boot: '启动', system: '系统',
  'delayed-auto': '延迟自动', delayed: '延迟自动', unknown: '未知',
};

const AUTH_STATE_META: Record<string, { label: string; tone: string }> = {
  valid: { label: '已签名', tone: 'resolved' },
  unsigned: { label: '未签名', tone: 'high' },
  distrusted: { label: '签名不受信', tone: 'critical' },
  bad_digest: { label: '签名内容不符', tone: 'critical' },
  expired: { label: '证书已过期', tone: 'medium' },
  untrusted: { label: '证书链不受信', tone: 'medium' },
  error: { label: '签名状态未知', tone: 'neutral' },
};

function hashErrNote(e: unknown): string {
  switch (liveErrorKind(e)) {
    case 'tunnel': return '探针隧道未连接';
    case 'busy': return '探针忙，稍后重试';
    case 'off': return '实时查询未启用或权限不足';
    case 'unsupported': return '该探针版本不支持按需哈希';
    default:
      if (e instanceof ApiError && e.status === 404) return '文件不存在或不可访问';
      return e instanceof Error ? e.message : String(e);
  }
}

/* 签名校验结果前端缓存（LIVE-TUNNEL §14.3）：同路径 30s 内重复点击不重复
   请求——哈希与 Authenticode 校验在探针侧现场计算，成本不可忽略。
   键为小写路径（服务/任务展开行来自同一台主机，路径即事实源）；
   请求失败不写缓存，避免把瞬时错误（隧道忙/离线）钉住 30 秒。 */
const HASH_CACHE_TTL_MS = 30_000;
const hashCache = new Map<string, { at: number; data: LiveHash }>();

/* 按需签名校验：一个按钮 + 一行结果，各展开行各自持有可见状态；
   实际哈希结果按小写路径走模块级 30s 缓存（见上），避免重复点击重复哈希。
   fs/hash 是 analyst+ 且不需要 FILEREAD 权限，见 LIVE-TUNNEL §13 契约说明。 */
function HashCheck({ agentId, path, canLive }: { agentId: string; path: string; canLive: boolean }) {
  const [busy, setBusy] = useState(false);
  const [res, setRes] = useState<LiveHash | null>(null);
  const [err, setErr] = useState('');
  const [cached, setCached] = useState(false);

  const run = async () => {
    if (!path) return;
    // key 必须含 agentId：30 秒内切换主机且路径相同时，纯路径键会串用
    // 另一台主机的哈希结果（同名系统文件路径极为常见）
    const key = agentId + ":" + path.trim().toLowerCase();
    const hit = hashCache.get(key);
    if (hit && Date.now() - hit.at < HASH_CACHE_TTL_MS) {
      setRes(hit.data);
      setErr('');
      setCached(true);
      return;
    }
    setBusy(true); setErr('');
    try {
      const data = await live.hash(agentId, path);
      hashCache.set(key, { at: Date.now(), data });
      setRes(data);
      setCached(false);
    } catch (e) {
      setRes(null);
      setErr(hashErrNote(e));
      setCached(false);
    } finally {
      setBusy(false);
    }
  };

  const meta = res ? (AUTH_STATE_META[str(res.authenticode?.state).toLowerCase()] || {
    label: str(res.authenticode?.state) || '签名状态未知', tone: 'neutral',
  }) : null;

  return (
    <div className="flex flex-wrap items-center gap-2">
      <Button size="sm" variant="ghost" disabled={!canLive || !path || busy} onClick={() => void run()}
        title={!path ? '没有可校验的绝对可执行路径' : !canLive ? '需要分析师及以上角色' : '现场计算 SHA256 并校验 Authenticode 签名'}>
        {busy ? <RefreshCw size={13} className="anim-spin" /> : <ShieldCheck size={13} />}
        {busy ? '校验中…' : '校验签名'}
      </Button>
      {!path && <span className="text-[11px] text-ghost">缺少可校验的可执行路径</span>}
      {path && !canLive && <span className="text-[11px] text-ghost">需要分析师及以上角色</span>}
      {err && <span className="text-[11px] break-all text-warn">{err}</span>}
      {res && meta && (
        <span className="flex flex-wrap items-center gap-2">
          <Badge tone={meta.tone}>{meta.label}</Badge>
          {cached && (
            <span className="text-[11px] text-ghost" title="30 秒内重复查询，未重新哈希">缓存</span>
          )}
          <span className="font-mono text-[11px] text-muted-foreground" title={res.sha256}>
            SHA256 {res.sha256.slice(0, 16)}…
          </span>
          {res.authenticode?.subject && (
            <span className="max-w-[360px] truncate text-[11px] text-faint" title={res.authenticode.subject}>
              {res.authenticode.subject}
            </span>
          )}
        </span>
      )}
    </div>
  );
}

/* 实时进程表关联：服务路径 → 进程路径精确匹配（同路径多实例时列出前几个）。 */
function useLiveProcs(agentId: string, enabled: boolean) {
  const [items, setItems] = useState<LiveProcRow[] | null>(null);
  const [tried, setTried] = useState(false);
  useEffect(() => {
    if (!enabled) return;
    let alive = true;
    setTried(false);
    live.processes(agentId)
      .then((r) => { if (alive) { setItems(r.items || []); setTried(true); } })
      .catch(() => { if (alive) { setItems(null); setTried(true); } });
    return () => { alive = false; };
  }, [agentId, enabled]);
  return { items, tried };
}

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
  /* 实时进程→实时文件 跨 Tab 联动：待打开的文件绝对路径（消费后置空） */
  const [liveFileTarget, setLiveFileTarget] = useState<string | null>(null);
  const [searchParams, setSearchParams] = useSearchParams();
  const tab = searchParams.get('tab') || 'overview';
  const setTab = (k: string) => setSearchParams(k === 'overview' ? {} : { tab: k }, { replace: true });
  /* live/hash、live/processes、live/netstat 均要求 analyst+（viewer 只读到 403），
     所以关联类请求在前端也按角色闸门，避免无意义的失败请求。 */
  const canLive = user.role !== 'viewer';
  /* 服务展开需要 PID 关联：只在主机已加载且服务 Tab 打开时拉一次实时进程表，
     失败静默降级 */
  const liveProcs = useLiveProcs(id, canLive && !!host && tab === 'services');

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
              { key: 'liveprocs', label: '实时进程' },
              { key: 'live', label: '实时文件' },
              { key: 'recon', label: '资产侦查' },
              { key: 'baseline', label: '安全基线' },
              { key: 'accounts', label: '账户与会话' },
              { key: 'changes', label: '变更', count: changes?.length },
              { key: 'ops', label: '处置与历史', count: cmds?.length },
            ]}
          />
          <div key={tab} className="anim-page flex flex-col gap-3.5">
            {tab === 'overview' && (
              <>
                <div className="grid gap-3.5 lg:grid-cols-2">
                  <SystemCard s={sec('system')} host={host} />
                  <AgentCard s={sec('agent')} agentId={id} />
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
            rowKey={(r) => `svc:${str(r.name)}`}
            renderExpanded={(r) => (
              <ServiceRowDetail row={r} agentId={id} canLive={canLive}
                procs={liveProcs.items} procsTried={liveProcs.tried}
                onOpenProcs={() => setTab('liveprocs')} />
            )}
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
            rowKey={(r) => `task:${str(r.path)}:${str(r.name)}`}
            renderExpanded={(r) => <TaskRowDetail row={r} agentId={id} canLive={canLive} />}
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
                {sec('listeners') && (
                  <ListenersTable s={sec('listeners')!} agentId={id} canLive={canLive}
                    onOpenRecon={() => setTab('recon')} />
                )}
              </SectionCard>

              </>
            )}
            {tab === 'liveprocs' && (
              <LiveProcsTab agentId={id} user={user}
                onAnalyzeFile={(p) => { setLiveFileTarget(p); setTab('live'); }} />
            )}
            {tab === 'live' && (
              <LiveFilesTab agentId={id} user={user}
                openPath={liveFileTarget} onOpenPathDone={() => setLiveFileTarget(null)} />
            )}
            {tab === 'recon' && <HostReconTab agentId={id} />}
            {tab === 'baseline' && <HostBaselineTab agentId={id} />}
            {tab === 'accounts' && <HostAccountsTab agentId={id} />}
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

function AgentCard({ s, agentId }: { s?: HostInventorySection; agentId?: string }) {
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
      {/* 实时 CPU/内存/进程数（30s 轮询；失败静默降级不显示，见 HostLiveProcs.tsx） */}
      {agentId && <LiveProbeInfo agentId={agentId} />}
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

interface ListenerView {
  key: string;
  proto: string;
  port: number;
  pid: number;
  proc: string;
  path: string;
  addr: string;
  user: string;
  cls: ProcClass;
  exposure: BindExposure;
  conns: LiveNetConn[];
}

function ListenersTable({ s, agentId, canLive, onOpenRecon }: {
  s: HostInventorySection; agentId: string; canLive: boolean; onOpenRecon?: () => void;
}) {
  const rows = useMemo(() => parseAny(s), [s]);
  const [q, setQ] = useState('');
  const [conns, setConns] = useState<LiveNetConn[] | null>(null);
  const [connTried, setConnTried] = useState(false);
  const [openKey, setOpenKey] = useState('');

  /* 资产清单的 listeners 节只有 port/pid/process，没有 bind 地址；
     绑定地址与进程路径只能从实时连接表按 (协议, 端口, PID) join。
     失败静默降级为"绑定未知"，不阻塞端口表本身。 */
  useEffect(() => {
    if (!canLive) { setConns(null); setConnTried(true); return; }
    let alive = true;
    setConns(null); setConnTried(false);
    live.netstat(agentId)
      .then((r) => { if (alive) { setConns(r.items || []); setConnTried(true); } })
      .catch(() => { if (alive) { setConns(null); setConnTried(true); } });
    return () => { alive = false; };
  }, [agentId, canLive]);

  const connMap = useMemo(() => {
    const m = new Map<string, LiveNetConn[]>();
    for (const c of conns || []) {
      const proto = (c.proto || '').toUpperCase();
      if (!proto) continue;
      if (proto === 'TCP' && (c.state || '').toUpperCase() !== 'LISTEN') continue;
      const k = `${proto}:${c.local_port}:${c.pid}`;
      const arr = m.get(k);
      if (arr) arr.push(c); else m.set(k, [c]);
    }
    return m;
  }, [conns]);

  const enriched = useMemo<ListenerView[]>(() => rows.map((r, i) => {
    const proto = (str(r.proto) || 'TCP').toUpperCase();
    const port = num(r.port);
    const pid = num(r.pid);
    const matched = connMap.get(`${proto}:${port}:${pid}`) || [];
    const primary = matched.find((c) => c.proc_name || c.proc_path) || matched[0];
    const proc = str(r.process) || str(r.proc_name) || primary?.proc_name || '';
    const path = str(r.proc_path) || primary?.proc_path || '';
    const addr = str(r.addr) || str(r.local_ip) || str(r.bind) || pickBindAddr(matched);
    const cls = classifyProc(proc, path);
    return {
      key: `${proto}:${port}:${pid}:${i}`,
      proto, port, pid, proc, path, addr,
      user: primary?.proc_user || '',
      cls, exposure: exposureOf(addr, cls), conns: matched,
    };
  }), [rows, connMap]);

  const filtered = useMemo(() => [...enriched]
    .sort((a, b) => a.port - b.port || a.pid - b.pid)
    .filter((r) => {
      if (!q) return true;
      const needle = q.toLowerCase();
      return [r.port, r.pid, r.proc, r.path, r.addr].some((v) => String(v).toLowerCase().includes(needle));
    }), [enriched, q]);
  const page = filtered.slice(0, 60);

  if (!rows.length) return <div className="py-4 text-center text-[12.5px] text-faint">暂无数据</div>;

  return (
    <>
      <div className="mb-2 flex flex-wrap items-center gap-2">
        <div className="relative">
          <Search size={13} className="pointer-events-none absolute top-1/2 left-2.5 -translate-y-1/2 text-ghost" />
          <Input value={q} onChange={(e) => setQ(e.target.value)} placeholder="过滤端口 / PID / 进程"
            className="h-7 w-[220px] pl-7 font-mono text-[12px]" />
        </div>
        <span className="text-[11px] text-faint">显示前 60 条（共 {rows.length}）</span>
        <div className="flex-1" />
        {!canLive ? (
          <span className="text-[11px] text-ghost">当前角色无法读取实时连接表</span>
        ) : !connTried ? (
          <span className="text-[11px] text-ghost">正在匹配实时连接表…</span>
        ) : conns === null ? (
          <span className="text-[11px] text-ghost">实时连接表不可用，仅展示资产清单端口</span>
        ) : null}
      </div>
      <div className="overflow-x-auto">
        <table className="w-full text-[12.5px]">
          <thead><tr className="border-b border-border-soft text-left text-[11px] tracking-[.06em] text-faint uppercase">
            <th className="w-7 px-2 py-2" aria-label="展开" />
            {['协议', '端口', 'PID', '进程', '归类', '绑定地址', '暴露'].map((h) => (
              <th key={h} className="px-3 py-2 font-semibold">{h}</th>
            ))}
          </tr></thead>
          <tbody>
            {page.map((r) => {
              const meta = PROC_CLASS_META[r.cls];
              const open = openKey === r.key;
              return (
                <Fragment key={r.key}>
                  <tr
                    tabIndex={0}
                    aria-expanded={open}
                    onClick={() => setOpenKey(open ? '' : r.key)}
                    onKeyDown={(e) => {
                      if (e.key === 'Enter' || e.key === ' ') {
                        e.preventDefault();
                        setOpenKey(open ? '' : r.key);
                      }
                    }}
                    className="cursor-pointer border-b border-border-soft transition-colors last:border-b-0 hover:bg-secondary focus-visible:bg-secondary focus-visible:outline-none"
                  >
                    <td className="px-2 py-1.5">
                      <ChevronRight size={13} className={cn('text-ghost transition-transform duration-150', open && 'rotate-90')} />
                    </td>
                    <td className="px-3 py-1.5"><Badge tone={r.proto === 'TCP' ? 'info' : 'neutral'}>{r.proto || '-'}</Badge></td>
                    <td className="px-3 py-1.5 font-mono tabular-nums">{r.port || '-'}</td>
                    <td className="px-3 py-1.5 font-mono tabular-nums text-faint">{r.pid || '-'}</td>
                    <td className="px-3 py-1.5">
                      <span className="block max-w-[180px] truncate font-mono text-[11.5px]" title={r.proc || r.path || undefined}>
                        {r.proc || '—'}
                      </span>
                    </td>
                    <td className="px-3 py-1.5"><Badge tone={meta.tone}>{meta.label}</Badge></td>
                    <td className="px-3 py-1.5">
                      <span className={cn('font-mono text-[11.5px]', !r.addr && 'text-ghost')}>{r.addr || '—'}</span>
                    </td>
                    <td className="px-3 py-1.5">
                      <Badge tone={r.exposure.tone} title={r.exposure.hint}>{r.exposure.label}</Badge>
                    </td>
                  </tr>
                  {open && (
                    <tr className="border-b border-border-soft bg-secondary/20 last:border-b-0">
                      <td colSpan={8} className="px-4 py-3">
                        <div className="flex flex-col gap-2.5">
                          <dl className="grid grid-cols-[84px_1fr] gap-x-3 gap-y-1.5 text-[12px]">
                            <dt className="text-faint">进程路径</dt>
                            <dd className="m-0 min-w-0 break-all font-mono text-[11.5px]">
                              {r.path || <span className="font-sans text-faint">未获取（实时连接表不可用或进程已退出）</span>}
                            </dd>
                            <dt className="text-faint">运行账号</dt>
                            <dd className="m-0 font-mono text-[11.5px]">{r.user || '—'}</dd>
                            <dt className="text-faint">绑定判定</dt>
                            <dd className="m-0 text-muted-foreground">{r.exposure.hint}</dd>
                            {r.conns.length > 1 && (
                              <>
                                <dt className="text-faint">全部绑定</dt>
                                <dd className="m-0 font-mono text-[11.5px] text-muted-foreground">
                                  {r.conns.map((c) => c.local_ip).filter(Boolean).join('、')}
                                </dd>
                              </>
                            )}
                          </dl>
                          <div className="flex flex-wrap items-center gap-2 border-t border-border-soft pt-2">
                            <HashCheck agentId={agentId} path={r.path} canLive={canLive} />
                            {onOpenRecon && (
                              <Button size="sm" variant="ghost" onClick={onOpenRecon} title="切到资产侦查 Tab 查看该端口的业务归属">
                                <ScanSearch size={13} /> 在资产侦查中查看
                              </Button>
                            )}
                          </div>
                        </div>
                      </td>
                    </tr>
                  )}
                </Fragment>
              );
            })}
            {!page.length && (
              <tr><td colSpan={8} className="px-3 py-6 text-center text-[12.5px] text-faint">没有匹配的监听端口</td></tr>
            )}
          </tbody>
        </table>
      </div>
    </>
  );
}

/* ---------------- 服务 / 计划任务行展开 ---------------- */

function ServiceRowDetail({ row, agentId, canLive, procs, procsTried, onOpenProcs }: {
  row: Row; agentId: string; canLive: boolean; procs: LiveProcRow[] | null;
  procsTried: boolean; onOpenProcs: () => void;
}) {
  const pathName = str(row.path_name);
  const exePath = extractExePath(pathName) || pathName.trim();
  const risk = writableRiskLabel(exePath);
  const startMode = str(row.start_mode);
  const startLabel = START_MODE_LABEL[startMode.toLowerCase()] || startMode || '—';

  /* 同路径多实例（svchost 等）全部列出；只做精确路径匹配，不用服务名猜 */
  const matched = useMemo(() => {
    if (!procs || !exePath) return [];
    const target = normPath(exePath);
    return procs.filter((p) => normPath(p.path) === target);
  }, [procs, exePath]);

  return (
    <div className="flex flex-col gap-2.5">
      <dl className="grid grid-cols-[84px_1fr] gap-x-3 gap-y-1.5 text-[12px]">
        <dt className="text-faint">二进制路径</dt>
        <dd className="m-0 min-w-0 break-all font-mono text-[11.5px]">{pathName || '—'}</dd>
        <dt className="text-faint">运行账户</dt>
        <dd className="m-0 font-mono text-[11.5px]">{str(row.account) || '—'}</dd>
        <dt className="text-faint">启动类型</dt>
        <dd className="m-0">
          {startLabel}
          {startMode && startLabel !== startMode && <span className="ml-1.5 font-mono text-[11px] text-faint">({startMode})</span>}
        </dd>
        <dt className="text-faint">运行中进程</dt>
        <dd className="m-0">
          {!canLive ? (
            <span className="text-faint">需要分析师及以上角色才能关联实时进程</span>
          ) : !procsTried ? (
            <span className="text-faint">关联实时进程表中…</span>
          ) : !procs ? (
            <span className="text-faint">实时进程表不可用（隧道未连接或未启用）</span>
          ) : matched.length > 0 ? (
            <button type="button" onClick={onOpenProcs}
              title={matched.length > 1
                ? '同路径有多个进程（如 svchost 共享宿主），无法仅凭路径归属到具体服务；切到实时进程 Tab 可按 PID 搜索'
                : '切到实时进程 Tab（可在该页按 PID 搜索）'}
              className="cursor-pointer font-mono text-[11.5px] text-primary hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring">
              {matched.length === 1 ? 'PID ' : '同路径进程 PID '}
              {matched.slice(0, 3).map((p) => p.pid).join('、')}
              {matched.length > 3 ? ` 等 ${matched.length} 个` : ''} · 查看实时进程
              {matched.length > 1 && <span className="text-faint">（共享宿主，无法归属到具体服务）</span>}
            </button>
          ) : (
            <span className="text-faint">未在实时进程表找到匹配路径</span>
          )}
        </dd>
        {risk && (
          <>
            <dt className="text-faint">路径风险</dt>
            <dd className="m-0">
              <Badge tone="critical" title="服务从低权限可写位置加载可执行文件，攻击者可替换文件取得服务权限">
                可写目录中的可执行（提权面）
              </Badge>
              <span className="ml-2 text-[11px] text-faint">命中 {risk}</span>
            </dd>
          </>
        )}
      </dl>
      <div className="flex flex-wrap items-center gap-2 border-t border-border-soft pt-2">
        <HashCheck agentId={agentId} path={exePath} canLive={canLive} />
      </div>
    </div>
  );
}

function TaskRowDetail({ row, agentId, canLive }: { row: Row; agentId: string; canLive: boolean }) {
  /* 当前资产清单的 tasks 节只有 path/name/state；动作/触发/作者是后续探针
     版本可能追加的字段，取不到就明确写"未包含"，不伪造。 */
  const action = pickText(row, ['action', 'command', 'cmdline', 'exec', 'action_text', 'actions', 'arguments']);
  const trigger = pickText(row, ['trigger', 'trigger_kind', 'triggers', 'schedule', 'trigger_text']);
  const author = pickText(row, ['author', 'registration_author', 'run_as', 'account', 'user']);
  const exePath = extractExePath(action);
  const risk = writableRiskLabel(exePath);

  return (
    <div className="flex flex-col gap-2.5">
      <dl className="grid grid-cols-[84px_1fr] gap-x-3 gap-y-1.5 text-[12px]">
        <dt className="text-faint">任务路径</dt>
        <dd className="m-0 min-w-0 break-all font-mono text-[11.5px]">{str(row.path) || '—'}</dd>
        <dt className="text-faint">动作命令行</dt>
        <dd className="m-0 min-w-0">
          {action ? (
            <pre className="m-0 rounded-md border border-border-soft bg-[var(--code-bg)] p-2.5 font-mono text-[11.5px] leading-[1.7] break-all whitespace-pre-wrap text-[var(--code-fg)]">{action}</pre>
          ) : (
            <span className="text-faint">当前资产清单未包含动作详情（仅有任务名/路径/状态）</span>
          )}
        </dd>
        {exePath && (
          <>
            <dt className="text-faint">可执行路径</dt>
            <dd className="m-0 min-w-0 break-all font-mono text-[11.5px]">{exePath}</dd>
          </>
        )}
        {risk && (
          <>
            <dt className="text-faint">路径风险</dt>
            <dd className="m-0">
              <Badge tone="critical" title="计划任务从低权限可写位置执行可执行文件，攻击者可替换文件取得任务权限">
                可写目录中的可执行（提权面）
              </Badge>
              <span className="ml-2 text-[11px] text-faint">命中 {risk}</span>
            </dd>
          </>
        )}
        <dt className="text-faint">触发方式</dt>
        <dd className="m-0">{trigger || '—'}</dd>
        <dt className="text-faint">作者</dt>
        <dd className="m-0">{author || '—'}</dd>
      </dl>
      <div className="flex flex-wrap items-center gap-2 border-t border-border-soft pt-2">
        <HashCheck agentId={agentId} path={exePath} canLive={canLive} />
        {!action && <span className="text-[11px] text-ghost">动作路径缺失时签名校验不可用</span>}
      </div>
    </div>
  );
}

const KIND_LABEL: Record<string, string> = {
  registry_run: '注册表 Run', startup_folder: '启动文件夹', service: '服务', scheduled_task: '计划任务',
};

interface Col { key: string; label: string; mono?: boolean; truncate?: boolean; badge?: boolean; tone?: (v: unknown) => string; labelMap?: Record<string, string> }

/** 大行数表：搜索 + 状态过滤 + 分页（服务 247 / 任务 187 / 自启动 422 行实测）。
    renderExpanded 存在时每行可点击/回车展开：首列加箭头，展开内容作为
    下一行整宽插入（不弹抽屉，保持既有排查动线）。 */
function BigTable({ title, rows, columns, searchKeys, stateKey, stateLabel, kindLabel, rowKey, renderExpanded }: {
  title: string; rows: Row[]; columns: Col[]; searchKeys: string[]; stateKey: string; stateLabel: string; kindLabel?: boolean;
  rowKey?: (r: Row) => string;
  renderExpanded?: (r: Row) => React.ReactNode;
}) {
  const [q, setQ] = useState('');
  const [state, setState] = useState('');
  const [page, setPage] = useState(1);
  const [openRows, setOpenRows] = useState<Record<string, boolean>>({});
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

  const toggle = (id: string) => setOpenRows((v) => ({ ...v, [id]: !v[id] }));

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
            {renderExpanded && <th className="w-7 px-2 py-2" aria-label="展开" />}
            {columns.map((c) => <th key={c.key} className="px-3 py-2 font-semibold">{c.label}</th>)}
          </tr></thead>
          <tbody>
            {view.map((r, i) => {
              const rid = rowKey ? rowKey(r) : `${cur}:${i}`;
              const open = !!renderExpanded && !!openRows[rid];
              return (
                <Fragment key={`${rid}:${i}`}>
                  <tr
                    tabIndex={renderExpanded ? 0 : undefined}
                    aria-expanded={renderExpanded ? open : undefined}
                    onClick={renderExpanded ? () => toggle(rid) : undefined}
                    onKeyDown={renderExpanded ? (e) => {
                      if (e.key === 'Enter' || e.key === ' ') {
                        e.preventDefault();
                        toggle(rid);
                      }
                    } : undefined}
                    className={cn(
                      'border-b border-border-soft transition-colors',
                      renderExpanded ? 'cursor-pointer hover:bg-secondary focus-visible:bg-secondary focus-visible:outline-none' : 'last:border-b-0 hover:bg-secondary',
                    )}
                  >
                    {renderExpanded && (
                      <td className="px-2 py-1.5">
                        <ChevronRight size={13} className={cn('text-ghost transition-transform duration-150', open && 'rotate-90')} />
                      </td>
                    )}
                    {columns.map((c) => (
                      <td key={c.key} className="px-3 py-1.5">
                        {c.badge
                          ? <Badge tone={c.tone ? c.tone(r[c.key]) : 'neutral'}>{c.labelMap ? (c.labelMap[str(r[c.key])] || str(r[c.key])) : (str(r[c.key]) || '-')}</Badge>
                          : <span className={cn('block', c.mono && 'font-mono text-[11.5px]', c.truncate && 'max-w-[320px] truncate text-faint')} title={str(r[c.key])}>{str(r[c.key]) || '-'}</span>}
                      </td>
                    ))}
                  </tr>
                  {open && (
                    <tr className="border-b border-border-soft bg-secondary/20">
                      <td colSpan={columns.length + 1} className="px-4 py-3">{renderExpanded!(r)}</td>
                    </tr>
                  )}
                </Fragment>
              );
            })}
            {!view.length && <tr><td colSpan={columns.length + (renderExpanded ? 1 : 0)} className="px-3 py-6 text-center text-[12.5px] text-faint">没有匹配的行</td></tr>}
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
