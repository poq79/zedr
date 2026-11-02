import { useCallback, useEffect, useMemo, useState } from 'react';
import {
  ChevronRight, CircleAlert, Copy, Cpu, Fingerprint, Globe, Layers, List, ListTree, MemoryStick,
  RefreshCw, ScanSearch, ShieldBan, Unplug, Users,
} from 'lucide-react';
import { api, ApiError, live, liveErrorKind } from '../lib/api';
import type {
  LiveHandle, LiveHandleList, LiveInfo, LiveMemScan, LiveNetConn, LiveProcInfo, LiveProcRow,
  LiveThreads, User,
} from '../lib/types';
import { fmtBytes, fmtTime } from '../lib/format';
import { Badge, Button, Card, CardTitle, EmptyState, Input, Select, SkeletonRows } from '../components/ui/basics';
import { Drawer, useConfirm, useToast } from '../components/ui/overlays';
import { cn } from '../lib/utils';
import type { LiveFixtureApi } from '../lib/liveFixture';

/* 主机详情「实时进程」Tab（docs/LIVE-TUNNEL.md §11.4，F2；§15.5 进程树与
   句柄/线程/内存三面板，F8）。
   上半：实时连接表（netstat 富化行：内外网分类彩点 + exited 高亮）；
   下半：实时进程表 / 进程树（同一份 processes 快照两种视图）。
   进程抽屉 = 交叉动线中枢：连接/模块/可执行速览（procinfo 按需加载）
   + 句柄/线程/内存取证（handles/threads/memscan 各自按需加载、互不阻塞），
   「分析此文件」联动实时文件 Tab 的文件抽屉；「终止进程」走既有指令
   铁律（agent_commands + 双层开关），不在隧道内做任何写操作。
   数据获取：processes + netstat 两请求并行；手动刷新，不做自动轮询。 */

/* 隧道错误的中文短句（与 HostLiveFiles 同一套口径；文件所有权分属两个
   页面文件，为避免跨页耦合各留一份——文案必须保持一致，W3 联调注意） */
function liveErrNote(e: unknown): string | null {
  switch (liveErrorKind(e)) {
    case 'tunnel': return '探针隧道未连接';
    case 'busy': return '探针忙，稍后重试';
    case 'off': return '实时查询未启用';
    case 'unsupported': return '该探针版本不支持此能力';
    default: return null;
  }
}

/* §15 四个端点的降级口径：老探针 mux 没挂 handler 时 501，老服务端代理
   预算表没收录路径时 404——两者对操作员含义相同（升级即可）。不改
   liveErrorKind 的全局分类：404 在 fs/stat 语义里是"文件不存在"，
   全局归为"不支持"会误导。 */
function panelErrNote(e: unknown): string {
  if (e instanceof ApiError && (e.status === 404 || e.status === 501)) return '该探针版本不支持此能力';
  return liveErrNote(e) || (e as Error).message;
}

/* 复制到剪贴板（与 HostLiveFiles 同款降级；两页各有所有权，故意各留一份） */
async function copyText(text: string): Promise<boolean> {
  try { await navigator.clipboard.writeText(text); return true; } catch { /* 降级 execCommand */ }
  try {
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.style.position = 'fixed'; ta.style.opacity = '0';
    document.body.appendChild(ta); ta.focus(); ta.select();
    const ok = document.execCommand('copy');
    ta.remove();
    return ok;
  } catch { return false; }
}

/* 开发期假数据开关：仅 DEV 构建且 localStorage 显式打开时可用（与
   HostLiveFiles 同款做法——动态 import 保证生产构建剔除本模块） */
async function devFixture(): Promise<LiveFixtureApi | null> {
  if (!import.meta.env.DEV) return null;
  try { if (localStorage.getItem('hg_live_fixture') !== '1') return null; } catch { return null; }
  const m = await import('../lib/liveFixture');
  return m.fixture;
}

/* Authenticode / signed_state（winapi/signature.go 口径）→ 中文标签 + 徽标 tone */
const AUTH_STATE: Record<string, [string, string]> = {
  valid: ['已签名 · 有效', 'resolved'],
  unsigned: ['未签名', 'neutral'],
  distrusted: ['签名不受信', 'critical'],
  bad_digest: ['签名内容不符', 'critical'],
  expired: ['证书已过期', 'medium'],
  untrusted: ['证书链不受信', 'medium'],
};

/* remote_class → 状态点（SOC 色彩契约：只有公网占用警示色，其余中性/弱化） */
const REMOTE_DOT: Record<string, [string, string]> = {
  public: ['bg-warn', '公网地址'],
  private: ['bg-muted-foreground', '内网地址'],
  loopback: ['bg-border-strong', '回环地址'],
  multicast: ['bg-ghost', '组播地址'],
  reserved: ['bg-ghost', '保留地址'],
};

function RemoteDot({ rc }: { rc?: string }) {
  if (!rc) return <span className="text-faint">—</span>;
  const [dot, label] = REMOTE_DOT[rc] || ['bg-ghost', rc];
  return <span aria-label={label} title={label} className={cn('inline-block h-2 w-2 shrink-0 rounded-full', dot)} />;
}

const addr = (ip?: string, port?: number) => (ip && ip !== '0.0.0.0' && ip !== '::' ? `${ip}:${port ?? 0}` : '—');

/* 该行是否命中过滤词：进程名/远端 IP/端口/状态/本地 IP/账号，纯前端即时过滤 */
function connHit(c: LiveNetConn, needle: string): boolean {
  return [c.proc_name, c.remote_ip, c.remote_port, c.state, c.local_ip, c.pid, c.proc_user]
    .some((v) => v != null && String(v).toLowerCase().includes(needle));
}

export function LiveProcsTab({ agentId, user, onAnalyzeFile }: {
  agentId: string; user: User; onAnalyzeFile?: (path: string) => void;
}) {
  const canBrowse = user.role !== 'viewer'; // /live/processes /netstat = analyst+（LIVE-TUNNEL §4）

  const [procs, setProcs] = useState<LiveProcRow[] | null>(null);
  const [conns, setConns] = useState<LiveNetConn[] | null>(null);
  const [loading, setLoading] = useState(false);
  const [tunnelDown, setTunnelDown] = useState(false);
  const [loadErr, setLoadErr] = useState('');
  const [freshAt, setFreshAt] = useState('');
  const [qConn, setQConn] = useState('');
  const [qProc, setQProc] = useState('');
  const [sel, setSel] = useState<LiveProcRow | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const fx = await devFixture();
      // processes + netstat 并行：两份快照同一次刷新，抽屉里按 PID 关联才成立
      const [pr, ne] = fx
        ? await Promise.all([fx.processes(), fx.netstat()])
        : await Promise.all([live.processes(agentId), live.netstat(agentId)]);
      setProcs(pr.items || []); setConns(ne.items || []);
      setTunnelDown(false); setLoadErr('');
      setFreshAt(new Date().toLocaleTimeString('zh-CN', { hour12: false }));
    } catch (e) {
      setProcs(null); setConns(null);
      const note = liveErrNote(e);
      if (liveErrorKind(e) === 'tunnel') setTunnelDown(true);
      else setLoadErr(note || (e as Error).message);
    } finally {
      setLoading(false);
    }
  }, [agentId]);

  useEffect(() => {
    setProcs(null); setConns(null); setTunnelDown(false); setLoadErr('');
    setQConn(''); setQProc(''); setSel(null);
    if (canBrowse) void load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [agentId]);

  const needleConn = qConn.trim().toLowerCase();
  const viewConns = useMemo(
    () => (conns || []).filter((c) => !needleConn || connHit(c, needleConn)),
    [conns, needleConn],
  );
  const needleProc = qProc.trim().toLowerCase();
  const viewProcs = useMemo(
    () => (procs || []).filter((p) => !needleProc
      || [p.name, p.path, p.pid, p.user].some((v) => v != null && String(v).toLowerCase().includes(needleProc))),
    [procs, needleProc],
  );
  const exitedCount = (conns || []).filter((c) => c.exited).length;

  return (
    <>
      {/* 503 tunnel_not_connected：顶部状态条（含重试），与实时文件 Tab 同款 */}
      {canBrowse && tunnelDown && (
        <div className="flex flex-wrap items-center gap-2.5 rounded-md border border-warn/30 bg-warn-soft px-3.5 py-2.5 text-[12.5px]">
          <Unplug size={15} className="shrink-0 text-warn" />
          <span className="min-w-0 flex-1">
            <b>探针隧道未连接</b>——探针离线、版本过旧或未开启隧道拨号（HG_AGENT_TUNNEL_ENABLED）。指令通道不受影响，隧道恢复后即可继续查询。
          </span>
          <Button size="sm" onClick={() => void load()}>重试</Button>
        </div>
      )}

      {/* ===== 上半：实时连接表 ===== */}
      <Card className="p-4">
        <div className="mb-2.5 flex flex-wrap items-center gap-2.5">
          <CardTitle>实时连接</CardTitle>
          <span className="font-mono text-[11px] text-ghost">{conns?.length ?? 0}</span>
          {exitedCount > 0 && (
            <Badge tone="medium" title="连接仍存在但进程已退出——排查高价值信号">进程已退出 {exitedCount}</Badge>
          )}
          <span className="hidden items-center gap-3 text-[11px] text-faint lg:flex" aria-hidden>
            <span className="flex items-center gap-1.5"><RemoteDot rc="public" />公网</span>
            <span className="flex items-center gap-1.5"><RemoteDot rc="private" />内网</span>
            <span className="flex items-center gap-1.5"><RemoteDot rc="loopback" />回环</span>
          </span>
          <div className="flex-1" />
          <Input value={qConn} onChange={(e) => setQConn(e.target.value)}
            placeholder="过滤进程名 / 远端 IP / 端口 / 状态" spellCheck={false} aria-label="连接过滤框"
            className="h-7 w-[230px] text-[12px]" />
          <Button size="icon" aria-label="刷新" title="刷新（进程与连接一并刷新）" disabled={loading}
            onClick={() => void load()}>
            <RefreshCw size={13} className={cn(loading && 'anim-spin')} />
          </Button>
          {freshAt && <span className="text-[11px] text-ghost">更新于 {freshAt}</span>}
        </div>
        {!canBrowse ? (
          <EmptyState tone="info" icon={<Users size={20} />} title="实时进程与连接需要分析师及以上角色"
            sub="实时查询属于现场调查能力，只读角色不开放。如需使用，请联系管理员调整账号角色。" />
        ) : loading ? (
          <SkeletonRows rows={6} />
        ) : tunnelDown || loadErr ? (
          <EmptyState tone="warn" icon={<CircleAlert size={20} />} title={tunnelDown ? '无法读取实时连接' : '实时查询失败'}
            sub={loadErr || '此处不留缓存数据——所见即终端现场，隧道恢复后重试即可。'}
            action={<Button size="sm" onClick={() => void load()}>重试</Button>} />
        ) : !viewConns.length ? (
          <div className="px-4 py-8 text-center text-[12.5px] text-faint">
            {conns?.length ? '没有匹配的连接' : '快照中没有连接记录'}
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-[12.5px]">
              <thead>
                <tr className="border-b border-border-soft text-left text-[11px] tracking-[.06em] text-faint uppercase">
                  <th className="w-[26px] px-3 py-2"><span className="sr-only">分类</span></th>
                  <th className="w-[56px] px-3 py-2 font-semibold">协议</th>
                  <th className="w-[160px] px-3 py-2 font-semibold">本地</th>
                  <th className="w-[170px] px-3 py-2 font-semibold">远端</th>
                  <th className="w-[110px] px-3 py-2 font-semibold">状态</th>
                  <th className="px-3 py-2 font-semibold">进程名</th>
                  <th className="w-[64px] px-3 py-2 font-semibold">PID</th>
                  <th className="w-[150px] px-3 py-2 font-semibold">账号</th>
                  <th className="w-[150px] px-3 py-2 font-semibold">启动时间</th>
                </tr>
              </thead>
              <tbody>
                {viewConns.map((c, i) => (
                  <tr key={i}
                    title={c.exited ? '该连接仍存在，但归属进程已退出' : c.proc_path || undefined}
                    className={cn('border-b border-border-soft transition-colors last:border-b-0',
                      c.exited ? 'bg-warn-soft/60 hover:bg-warn-soft' : 'hover:bg-secondary')}>
                    <td className="px-3 py-1.5"><RemoteDot rc={c.remote_class} /></td>
                    <td className="px-3 py-1.5 font-mono text-[11.5px] text-muted-foreground">{c.proto || '-'}</td>
                    <td className="px-3 py-1.5 font-mono text-[11.5px] tabular-nums">{addr(c.local_ip, c.local_port)}</td>
                    <td className="px-3 py-1.5 font-mono text-[11.5px] tabular-nums">{addr(c.remote_ip, c.remote_port)}</td>
                    <td className="px-3 py-1.5 font-mono text-[11.5px] text-muted-foreground">{c.state || '—'}</td>
                    <td className="px-3 py-1.5">
                      <span className="flex items-center gap-1.5" title={c.proc_path || undefined}>
                        <span className={cn('block truncate', c.exited ? 'text-warn' : 'font-medium')}>{c.proc_name || '-'}</span>
                        {c.exited && <Badge tone="medium">已退出</Badge>}
                      </span>
                    </td>
                    <td className="px-3 py-1.5 font-mono text-[11.5px] tabular-nums text-muted-foreground">{c.pid || '—'}</td>
                    <td className="max-w-[150px] px-3 py-1.5"><span className="block truncate font-mono text-[11.5px] text-faint" title={c.proc_user}>{c.proc_user || '—'}</span></td>
                    <td className="px-3 py-1.5 font-mono text-[11.5px] text-faint">{c.proc_started_at ? fmtTime(c.proc_started_at) : '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      {/* ===== 下半：实时进程表 ===== */}
      <Card className="p-4">
        <div className="mb-2.5 flex flex-wrap items-center gap-2.5">
          <CardTitle>实时进程</CardTitle>
          <span className="font-mono text-[11px] text-ghost">{procs?.length ?? 0}</span>
          <div className="flex-1" />
          <Input value={qProc} onChange={(e) => setQProc(e.target.value)}
            placeholder="过滤名称 / 路径 / PID / 账号" spellCheck={false} aria-label="进程过滤框"
            className="h-7 w-[230px] text-[12px]" />
        </div>
        {!canBrowse || loading || tunnelDown || loadErr ? (
          <div className="px-4 py-6 text-center text-[12.5px] text-faint">
            {canBrowse ? '等待实时数据——先解决上方状态' : '无权限'}
          </div>
        ) : !viewProcs.length ? (
          <div className="px-4 py-8 text-center text-[12.5px] text-faint">
            {procs?.length ? '没有匹配的进程' : '快照中没有进程记录'}
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-[12.5px]">
              <thead>
                <tr className="border-b border-border-soft text-left text-[11px] tracking-[.06em] text-faint uppercase">
                  <th className="w-[70px] px-3 py-2 font-semibold">PID</th>
                  <th className="w-[150px] px-3 py-2 font-semibold">名称</th>
                  <th className="px-3 py-2 font-semibold">路径</th>
                  <th className="w-[150px] px-3 py-2 font-semibold">账号</th>
                  <th className="w-[70px] px-3 py-2 text-right font-semibold">连接</th>
                  <th className="w-[70px] px-3 py-2 text-right font-semibold">模块</th>
                  <th className="w-[150px] px-3 py-2 font-semibold">首次发现</th>
                </tr>
              </thead>
              <tbody>
                {viewProcs.map((p) => (
                  <tr key={p.pid} tabIndex={0}
                    onClick={() => setSel(p)}
                    onKeyDown={(ev) => { if (ev.key === 'Enter') setSel(p); }}
                    title="点击打开进程详情"
                    className="cursor-pointer border-b border-border-soft transition-colors last:border-b-0 hover:bg-secondary focus-visible:bg-secondary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-ring">
                    <td className="px-3 py-1.5 font-mono text-[11.5px] font-semibold tabular-nums">{p.pid}</td>
                    <td className="px-3 py-1.5 font-medium"><span className="block truncate" title={p.name}>{p.name || '-'}</span></td>
                    <td className="max-w-[320px] px-3 py-1.5"><span className="block truncate font-mono text-[11.5px] text-muted-foreground" title={p.path}>{p.path || '—'}</span></td>
                    <td className="max-w-[150px] px-3 py-1.5"><span className="block truncate font-mono text-[11.5px] text-faint" title={p.user}>{p.user || '—'}</span></td>
                    <td className="px-3 py-1.5 text-right font-mono text-[11.5px] tabular-nums text-muted-foreground">{p.conn_count || 0}</td>
                    <td className="px-3 py-1.5 text-right font-mono text-[11.5px] tabular-nums text-muted-foreground">{p.modules || 0}</td>
                    <td className="px-3 py-1.5 font-mono text-[11.5px] text-faint" title="探针首次发现该进程的时间">{fmtTime(p.first_seen)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        {canBrowse && (
          <p className="mt-2.5 px-3.5 text-xs text-faint">
            数据为点击刷新时刻的快照，不做自动轮询；点击进程行查看命令行、连接、模块与可执行文件速览。
          </p>
        )}
      </Card>

      <ProcDrawer agentId={agentId} sel={sel} conns={conns || []}
        onAnalyzeFile={onAnalyzeFile} onClose={() => setSel(null)} />
    </>
  );
}

/* ================= 进程抽屉（交叉动线中枢） ================= */

function ProcDrawer({ agentId, sel, conns, onAnalyzeFile, onClose }: {
  agentId: string; sel: LiveProcRow | null; conns: LiveNetConn[];
  onAnalyzeFile?: (path: string) => void; onClose: () => void;
}) {
  const toast = useToast();
  const confirm = useConfirm();
  const [info, setInfo] = useState<LiveProcInfo | null>(null);
  const [infoBusy, setInfoBusy] = useState(false);
  const [infoErr, setInfoErr] = useState('');
  const [termBusy, setTermBusy] = useState(false);

  const pidConns = useMemo(() => conns.filter((c) => c.pid === sel?.pid), [conns, sel]);

  /* 模块/可执行速览按需加载：枚举模块有成本，不随抽屉打开自动拉取 */
  const loadInfo = useCallback(async () => {
    if (!sel) return;
    setInfoBusy(true); setInfoErr('');
    try {
      const fx = await devFixture();
      setInfo(fx ? await fx.procinfo(sel.pid) : await live.procinfo(agentId, sel.pid));
    } catch (ex) {
      setInfo(null);
      const note = liveErrNote(ex);
      setInfoErr(note || (ex as Error).message);
      if (note) toast(note, 'warn');
    } finally { setInfoBusy(false); }
  }, [agentId, sel, toast]);

  useEffect(() => {
    if (!sel) { setInfo(null); setInfoErr(''); setTermBusy(false); }
  }, [sel]);

  const doTerminate = async () => {
    if (!sel) return;
    const ok = await confirm({
      title: `终止进程 ${sel.name}（PID ${sel.pid}）？`, danger: true, okText: '终止',
      message: `将向终端下发进程终止指令（PID ${sel.pid}）。\n路径：${sel.path || '（未知）'}\n请确认目标属于恶意进程——误杀系统进程可能导致蓝屏或服务中断。`,
    });
    if (!ok) return;
    setTermBusy(true);
    try {
      // 处置走指令铁律（LIVE-TUNNEL §2）：查询走隧道，处置走 agent_commands
      await api.post(`/api/v1/hosts/${encodeURIComponent(agentId)}/commands`, { type: 'terminate', payload: String(sel.pid) });
      toast('指令 终止进程 已下发，等待终端执行');
    } catch (ex) {
      toast((ex as Error).message, 'err'); // 失败透出后端原文（如双层开关未开）
    } finally { setTermBusy(false); }
  };

  const execPath = info?.path || sel?.path || '';
  const signedState = info?.exec_info?.signed_state || '';
  const [authLabel, authTone] = AUTH_STATE[signedState] || [signedState || '-', 'neutral'];

  return (
    <Drawer open={sel != null} onClose={onClose} width={720}
      title={sel ? `${sel.name}（PID ${sel.pid}）` : ''}
      sub={sel ? <span className="block truncate font-mono text-[11.5px]" title={sel.path}>{sel.path || '路径未知'}</span> : undefined}
      foot={sel && (
        <>
          <Button variant="danger" disabled={termBusy} onClick={() => void doTerminate()}>
            <ShieldBan size={13} /> 终止进程
          </Button>
          <span className="text-[11px] text-ghost">处置走指令通道并记入审计，需服务端与终端双层开关开启</span>
        </>
      )}
    >
      {sel && (
        <div className="space-y-5">
          <RowSection title="基本信息">
            <dl className="grid grid-cols-[110px_1fr] gap-x-3 gap-y-2 text-[12.5px]">
              <dt className="text-faint">PID / PPID</dt>
              <dd className="m-0 font-mono tabular-nums">{sel.pid} / {sel.ppid || '—'}</dd>
              <dt className="text-faint">账号</dt>
              <dd className="m-0 font-mono text-[11.5px]">{sel.user || '—'}</dd>
              <dt className="text-faint">提权</dt>
              <dd className="m-0">
                {info?.elevated != null
                  ? (info.elevated ? <Badge tone="medium">已提权</Badge> : <Badge tone="neutral">未提权</Badge>)
                  : <span className="text-xs text-faint">加载模块后可见</span>}
              </dd>
              <dt className="text-faint">首次发现</dt>
              <dd className="m-0 font-mono text-[11.5px]">{fmtTime(sel.first_seen)}</dd>
              {info?.session_id != null && (
                <>
                  <dt className="text-faint">会话 ID</dt>
                  <dd className="m-0 font-mono tabular-nums">{info.session_id}</dd>
                </>
              )}
              {info?.cpu_percent != null && (
                <>
                  <dt className="text-faint">CPU / 内存</dt>
                  <dd className="m-0 font-mono tabular-nums">{info.cpu_percent}% · {fmtBytes((info.mem_mb || 0) * 1024 * 1024)}</dd>
                </>
              )}
              <dt className="text-faint">命令行</dt>
              <dd className="m-0">
                {sel.cmdline
                  ? <pre className="m-0 rounded-md border border-border-soft bg-[var(--code-bg)] p-2.5 font-mono text-[11.5px] leading-[1.7] break-all whitespace-pre-wrap text-[var(--code-fg)]">{sel.cmdline}</pre>
                  : <span className="text-faint">—</span>}
              </dd>
            </dl>
          </RowSection>

          <RowSection title={`实时连接（快照）${pidConns.length ? ` · ${pidConns.length}` : ''}`}>
            {pidConns.length ? (
              <table className="w-full text-[12px]">
                <thead>
                  <tr className="border-b border-border-soft text-left text-[11px] tracking-[.06em] text-faint uppercase">
                    <th className="w-[26px] px-2 py-1.5"><span className="sr-only">分类</span></th>
                    <th className="w-[50px] px-2 py-1.5 font-semibold">协议</th>
                    <th className="px-2 py-1.5 font-semibold">本地</th>
                    <th className="px-2 py-1.5 font-semibold">远端</th>
                    <th className="w-[100px] px-2 py-1.5 font-semibold">状态</th>
                  </tr>
                </thead>
                <tbody>
                  {pidConns.map((c, i) => (
                    <tr key={i} className={cn('border-b border-border-soft last:border-b-0', c.exited && 'bg-warn-soft/60')}>
                      <td className="px-2 py-1.5"><RemoteDot rc={c.remote_class} /></td>
                      <td className="px-2 py-1.5 font-mono text-[11.5px] text-muted-foreground">{c.proto}</td>
                      <td className="px-2 py-1.5 font-mono text-[11.5px] tabular-nums">{addr(c.local_ip, c.local_port)}</td>
                      <td className="px-2 py-1.5 font-mono text-[11.5px] tabular-nums">{addr(c.remote_ip, c.remote_port)}</td>
                      <td className="px-2 py-1.5 font-mono text-[11.5px] text-muted-foreground">{c.state || '—'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            ) : (
              <p className="text-xs text-faint">本次快照中该进程没有网络连接。</p>
            )}
          </RowSection>

          <RowSection title="模块与可执行文件" extra={
            <Button size="sm" variant="ghost" disabled={infoBusy} onClick={() => void loadInfo()}>
              <Fingerprint size={13} /> {infoBusy ? '加载中…' : info ? '重新加载' : '加载模块'}
            </Button>
          }>
            {infoBusy && <SkeletonRows rows={3} />}
            {!infoBusy && infoErr && (
              <div className="text-[12.5px] text-destructive">{infoErr}</div>
            )}
            {!infoBusy && !infoErr && !info && (
              <p className="text-xs leading-[1.8] text-faint">
                枚举模块与校验签名有成本，按需加载：模块列表、未签名模块计数、可执行文件签名状态与下载来源标记。
              </p>
            )}
            {!infoBusy && info && !info.exists && (
              <div className="mb-3 flex items-center gap-2 rounded-md border border-warn/30 bg-warn-soft px-3 py-2 text-[12.5px] text-warn">
                <CircleAlert size={14} className="shrink-0" />
                <span>进程已退出（快照时点不存在）——以下信息可能不完整。</span>
              </div>
            )}
            {!infoBusy && info && (
              <div className="space-y-3">
                {info.unsigned_module_count != null && (
                  <div className="flex flex-wrap items-center gap-2 text-[12.5px]">
                    <Badge tone={info.unsigned_module_count > 0 ? 'medium' : 'resolved'}>
                      未签名模块 {info.unsigned_module_count}
                    </Badge>
                    <span className="font-mono text-[11px] text-ghost">共 {info.modules?.length ?? 0} 个模块</span>
                    {info.truncated && <Badge tone="medium" title="预算内未枚举完">模块列表已截断</Badge>}
                  </div>
                )}
                {info.modules?.length ? (
                  <div className="max-h-[220px] overflow-y-auto rounded-md border border-border-soft">
                    <table className="w-full text-[12px]">
                      <tbody>
                        {info.modules.map((m, i) => (
                          <tr key={`${m.name}-${i}`} className="border-b border-border-soft last:border-b-0">
                            <td className="w-[160px] px-3 py-1.5 font-medium"><span className="block truncate" title={m.name}>{m.name}</span></td>
                            <td className="px-3 py-1.5"><span className="block truncate font-mono text-[11.5px] text-muted-foreground" title={m.path}>{m.path || '—'}</span></td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                ) : (
                  <p className="text-xs text-faint">未返回模块列表。</p>
                )}
                {info.exec_info && (
                  <div className="rounded-md border border-border-soft bg-secondary/40 p-3 text-[12px]">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="shrink-0 text-faint">可执行</span>
                      <code className="min-w-0 flex-1 break-all font-mono text-[11.5px]" title={execPath}>
                        {info.exec_info.exists ? (execPath || '—') : '（文件已不存在）'}
                      </code>
                    </div>
                    <div className="mt-2 flex flex-wrap items-center gap-2">
                      <Badge tone={authTone}>{authLabel}</Badge>
                      {info.exec_info.ads_zone_id === 3 && (
                        <Badge tone="medium" title="可执行文件携带 Zone.Identifier（Zone 3 = Internet）">
                          <Globe size={11} /> 来自 Internet
                        </Badge>
                      )}
                      <div className="flex-1" />
                      {execPath && onAnalyzeFile && (
                        <Button size="sm" onClick={() => onAnalyzeFile(execPath)}>
                          <ScanSearch size={13} /> 分析此文件
                        </Button>
                      )}
                    </div>
                  </div>
                )}
              </div>
            )}
          </RowSection>
        </div>
      )}
    </Drawer>
  );
}

/* 抽屉小节（标题 + 发丝线，与 HostLiveFiles 的 Section 同款；此处独立成
   命名避免两页共用组件——文件所有权分属不同页面文件） */
function RowSection({ title, extra, children }: { title: string; extra?: React.ReactNode; children: React.ReactNode }) {
  return (
    <section>
      <h3 className="mb-2.5 flex items-center gap-2 text-xs font-semibold tracking-[.05em] text-muted-foreground uppercase">
        <span>{title}</span>
        <span aria-hidden className="h-px flex-1 bg-border-soft" />
        {extra}
      </h3>
      {children}
    </section>
  );
}

/* ================= 探针实时状态行（挂主机详情「探针状态」卡内） =================
   30s 轮询 live/info；仅当所在页可见时挂载（HostDetail 按 tab 卸载子树，
   挂在概览 Tab 内即天然满足），后台标签页跳过请求；失败静默降级不显示。 */
export function LiveProbeInfo({ agentId }: { agentId: string }) {
  const [info, setInfo] = useState<LiveInfo | null>(null);
  const [at, setAt] = useState('');

  useEffect(() => {
    let alive = true;
    const tick = async () => {
      if (document.hidden) return; // 后台标签页不打扰探针
      try {
        const fx = await devFixture();
        const d = fx ? await fx.info() : await live.info(agentId);
        if (!alive) return;
        setInfo(d);
        setAt(new Date().toLocaleTimeString('zh-CN', { hour12: false }));
      } catch {
        if (alive) { setInfo(null); setAt(''); } // 静默降级：隧道/权限/版本任一不满足就不显示
      }
    };
    void tick();
    const iv = setInterval(tick, 30000);
    return () => { alive = false; clearInterval(iv); };
  }, [agentId]);

  if (!info) return null;
  const mem = (info.mem_mb ?? 0) > 0 ? fmtBytes((info.mem_mb || 0) * 1024 * 1024) : null;
  return (
    <div className="mt-3 flex flex-wrap items-center gap-x-4 gap-y-1 border-t border-border-soft pt-2.5 text-[11.5px] text-faint">
      <span className="flex items-center gap-1.5">
        <span aria-hidden className="h-1.5 w-1.5 rounded-full bg-ok" />
        实时（隧道）
      </span>
      <span>CPU <b className="font-mono font-semibold tabular-nums text-muted-foreground">{info.cpu_percent != null ? `${info.cpu_percent}%` : '-'}</b></span>
      <span>内存 <b className="font-mono font-semibold tabular-nums text-muted-foreground">{mem ?? '-'}</b></span>
      <span>进程 <b className="font-mono font-semibold tabular-nums text-muted-foreground">{info.proc_count != null ? info.proc_count : '-'}</b></span>
      {info.version && <span className="font-mono">v{info.version}</span>}
      {at && <span className="text-ghost">更新于 {at}</span>}
    </div>
  );
}
