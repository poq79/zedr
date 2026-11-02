import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  ChevronRight, CircleAlert, Copy, Cpu, Fingerprint, Globe, Layers, List, ListTree, MemoryStick,
  RefreshCw, ScanSearch, ShieldBan, Unplug, Users,
} from 'lucide-react';
import { api, ApiError, live, liveErrorKind } from '../lib/api';
import type {
  LiveHandleList, LiveInfo, LiveMemScan, LiveNetConn, LiveProcInfo, LiveProcRow,
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
   全局归为"不支持"会误导。
   memScan 开关专给 /memscan：探针在目标进程已退出时返回 404
   （procforensics.go ErrMemScanProcessGone → NotFound），此时说"版本
   不支持"会严重误导——短命恶意进程恰恰是高频场景；403 也透出后端
   原文（含 HG_AGENT_MEMSCAN_ENABLED 开关名），比笼统的"未启用"可操作。 */
function panelErrNote(e: unknown, memScan = false): string {
  if (e instanceof ApiError) {
    if (memScan && e.status === 403) return e.message;
    if (e.status === 404 || e.status === 501) {
      if (memScan && e.status === 404) return '目标进程可能已退出，或该探针版本不支持此能力';
      return '该探针版本不支持此能力';
    }
  }
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

/* ================= 进程树（LIVE-TUNNEL §15.5） ================= */

interface ProcNode {
  key: string;
  /** 虚拟节点（父进程已退出）的 pid = 缺失的 ppid，没有 row */
  pid: number;
  row?: LiveProcRow;
  children: ProcNode[];
}

/* 由 processes 快照构建森林。快照是瞬时采样，必须对三种脏数据稳定：
   1) 父 PID 不在快照里（父进程已退出/未被采到）→ 每个缺失 ppid 只建一个
      虚线虚拟节点，兄弟进程归到同一节点下；不伪造父进程名称/账号/路径；
   2) ppid 指向自己或祖先成环（异常快照）→ 该进程挂根，避免渲染无限递归；
   3) pid 重复（两次采样竞态）→ 只认第一条进树，其余作为根行展示，不丢进程。
   排序按 PID 升序（虚拟节点落在其 PID 的位置），刷新后结构稳定。 */
function buildProcTree(rows: LiveProcRow[]): ProcNode[] {
  const nodeOf = new Map<number, ProcNode>();
  const nodes: ProcNode[] = [];
  for (const r of rows) {
    if (nodeOf.has(r.pid)) {
      nodes.push({ key: `dup:${r.pid}:${nodes.length}`, pid: r.pid, row: r, children: [] });
      continue;
    }
    const n: ProcNode = { key: `p:${r.pid}`, pid: r.pid, row: r, children: [] };
    nodeOf.set(r.pid, n);
    nodes.push(n);
  }

  /* 祖先链环路检测：最多跟 64 层，超长链按异常快照处理（挂根） */
  const cyclic = (r: LiveProcRow): boolean => {
    const seen = new Set<number>([r.pid]);
    let pid = r.ppid || 0;
    for (let i = 0; i < 64; i++) {
      if (!pid) return false;
      if (seen.has(pid)) return true;
      seen.add(pid);
      const p = nodeOf.get(pid)?.row;
      if (!p) return false;
      pid = p.ppid || 0;
    }
    return true;
  };

  const roots: ProcNode[] = [];
  const orphans: { node: ProcNode; ppid: number }[] = [];
  for (const n of nodes) {
    const r = n.row!;
    const ppid = r.ppid || 0;
    const parent = ppid ? nodeOf.get(ppid) : undefined;
    if (n.key.startsWith('dup:') || !ppid || ppid === r.pid || parent === n || cyclic(r)) {
      roots.push(n);
      continue;
    }
    if (parent) parent.children.push(n);
    else orphans.push({ node: n, ppid });
  }
  /* 虚拟父节点第二遍创建：保证与行出现顺序无关，同一 ppid 只出现一次 */
  const virtuals = new Map<number, ProcNode>();
  for (const o of orphans) {
    let v = virtuals.get(o.ppid);
    if (!v) {
      v = { key: `x:${o.ppid}`, pid: o.ppid, children: [] };
      virtuals.set(o.ppid, v);
      roots.push(v);
    }
    v.children.push(o.node);
  }

  const sortRec = (arr: ProcNode[]) => {
    arr.sort((a, b) => a.pid - b.pid || a.key.localeCompare(b.key));
    for (const n of arr) sortRec(n.children);
  };
  sortRec(roots);
  return roots;
}

/* 树节点（递归）。默认展开深度 2：根层展开、其子节点可见，更深层折叠。
   onClick 开抽屉（与列表行一致）；虚拟节点只负责展开/收起，不开抽屉。 */
function ProcTreeBranch({ node, depth, openKeys, onToggle, onOpen }: {
  node: ProcNode; depth: number; openKeys: Record<string, boolean>;
  onToggle: (key: string, open: boolean) => void; onOpen: (r: LiveProcRow) => void;
}) {
  const row = node.row;
  const kids = node.children;
  const open = openKeys[node.key] ?? depth === 0;
  const activate = () => {
    if (row) onOpen(row);
    else if (kids.length) onToggle(node.key, open);
  };
  return (
    <div role="treeitem" aria-expanded={kids.length ? open : undefined} aria-level={depth + 1}>
      <div
        tabIndex={0}
        onClick={activate}
        onKeyDown={(ev) => {
          if (ev.key === 'Enter' || ev.key === ' ') { ev.preventDefault(); activate(); }
        }}
        title={row
          ? `${row.path || '路径未知'} · 点击打开进程详情`
          : '快照中没有该 PID 的进程记录（父进程已退出）——展开查看其子进程'}
        className={cn(
          'flex cursor-pointer items-center gap-2 border-b px-2 py-1.5 text-[12.5px] transition-colors',
          'hover:bg-secondary focus-visible:bg-secondary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-ring',
          'last:border-b-0',
          row ? 'border-border-soft' : 'border-dashed border-border-soft bg-secondary/25 text-faint',
        )}
      >
        <button
          type="button"
          aria-label={kids.length ? (open ? '收起子进程' : '展开子进程') : undefined}
          aria-hidden={!kids.length}
          tabIndex={kids.length ? 0 : -1}
          onClick={(ev) => { ev.stopPropagation(); if (kids.length) onToggle(node.key, open); }}
          className={cn('grid h-5 w-5 shrink-0 place-items-center rounded',
            kids.length ? 'cursor-pointer text-ghost hover:text-foreground' : 'invisible')}
        >
          <ChevronRight size={12} className={cn('transition-transform duration-150', open && 'rotate-90')} />
        </button>
        <span className={cn('min-w-0 flex-1 truncate', row ? 'font-medium' : 'italic')}>
          {row ? (row.name || '-') : `父进程已退出（PID ${node.pid}）`}
        </span>
        <span className="w-[78px] shrink-0 font-mono text-[11.5px] tabular-nums text-muted-foreground">
          {row ? row.pid : '—'}
        </span>
        <span className="w-[140px] shrink-0 truncate font-mono text-[11.5px] text-faint" title={row?.user}>
          {row ? (row.user || '—') : '—'}
        </span>
        <span className="w-[72px] shrink-0 text-right font-mono text-[11.5px] tabular-nums text-muted-foreground">
          {row ? (row.conn_count || 0) : `${kids.length} 子进程`}
        </span>
      </div>
      {kids.length > 0 && open && (
        <div role="group" className="ml-[13px] border-l border-border-soft pl-2">
          {kids.map((k) => (
            <ProcTreeBranch key={k.key} node={k} depth={depth + 1}
              openKeys={openKeys} onToggle={onToggle} onOpen={onOpen} />
          ))}
        </div>
      )}
    </div>
  );
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
  /* 进程视图：默认列表；树是同一份快照的另一种呈现（§15.5） */
  const [view, setView] = useState<'list' | 'tree'>('list');
  const [openKeys, setOpenKeys] = useState<Record<string, boolean>>({});

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
    setView('list'); setOpenKeys({});
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

  /* 树与过滤互斥：搜索下自动用列表（子树剪裁会让"父进程已退出"的层级
     断裂，且过滤后的树更难读）。保留用户的树/列表偏好，清空搜索即回到树。 */
  const treeMode = view === 'tree' && !needleProc;
  const tree = useMemo(() => buildProcTree(procs || []), [procs]);
  const treeCounts = useMemo(() => {
    let virtuals = 0;
    const walk = (arr: ProcNode[]) => {
      for (const n of arr) { if (!n.row) virtuals++; walk(n.children); }
    };
    walk(tree);
    return { virtuals };
  }, [tree]);
  const toggleTree = useCallback((key: string, open: boolean) => {
    setOpenKeys((m) => ({ ...m, [key]: !open }));
  }, []);

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
          {canBrowse && !!procs?.length && (
            <div role="group" aria-label="进程视图切换"
              className="flex items-center gap-0.5 rounded-md border border-border-soft bg-card p-0.5">
              <button type="button" aria-pressed={view === 'list'} onClick={() => setView('list')}
                className={cn('flex cursor-pointer items-center gap-1 rounded-[5px] px-2 py-1 text-[11.5px] transition-colors',
                  view === 'list' ? 'bg-secondary font-medium text-foreground' : 'text-muted-foreground hover:text-foreground')}>
                <List size={12} /> 列表
              </button>
              <button type="button" aria-pressed={view === 'tree'} onClick={() => setView('tree')}
                title="按 pid/ppid 构建进程树"
                className={cn('flex cursor-pointer items-center gap-1 rounded-[5px] px-2 py-1 text-[11.5px] transition-colors',
                  view === 'tree' ? 'bg-secondary font-medium text-foreground' : 'text-muted-foreground hover:text-foreground')}>
                <ListTree size={12} /> 树
              </button>
            </div>
          )}
          {treeMode && (
            <span className="text-[11px] text-faint">
              顶层节点 {tree.length} · 父已退出 {treeCounts.virtuals} 组
            </span>
          )}
          <div className="flex-1" />
          <Input value={qProc} onChange={(e) => setQProc(e.target.value)}
            placeholder="过滤名称 / 路径 / PID / 账号" spellCheck={false} aria-label="进程过滤框"
            className="h-7 w-[230px] text-[12px]" />
        </div>
        {view === 'tree' && needleProc && (
          <p className="mb-2.5 rounded-md border border-border-soft bg-secondary/40 px-3 py-1.5 text-[11.5px] text-faint">
            搜索过滤下自动使用列表视图（树视图不做子树剪裁，避免过滤后层级断裂）；清空搜索回到树。
          </p>
        )}
        {!canBrowse || loading || tunnelDown || loadErr ? (
          <div className="px-4 py-6 text-center text-[12.5px] text-faint">
            {canBrowse ? '等待实时数据——先解决上方状态' : '无权限'}
          </div>
        ) : !procs?.length ? (
          <div className="px-4 py-8 text-center text-[12.5px] text-faint">快照中没有进程记录</div>
        ) : treeMode ? (
          <div className="overflow-hidden rounded-md border border-border-soft">
            <div className="flex items-center gap-2 border-b border-border-soft bg-secondary/30 px-2 py-2 text-[11px] tracking-[.06em] text-faint uppercase">
              <span className="h-5 w-5 shrink-0" aria-hidden />
              <span className="min-w-0 flex-1 font-semibold">名称</span>
              <span className="w-[78px] shrink-0 font-semibold">PID</span>
              <span className="w-[140px] shrink-0 font-semibold">账号</span>
              <span className="w-[72px] shrink-0 text-right font-semibold">连接</span>
            </div>
            <div role="tree" aria-label="进程树">
              {tree.map((n) => (
                <ProcTreeBranch key={n.key} node={n} depth={0}
                  openKeys={openKeys} onToggle={toggleTree} onOpen={setSel} />
              ))}
            </div>
          </div>
        ) : !viewProcs.length ? (
          <div className="px-4 py-8 text-center text-[12.5px] text-faint">没有匹配的进程</div>
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
            {treeMode && ' 树按快照 pid/ppid 构建，父进程已退出的子进程归入虚线虚拟节点。'}
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

  /* §15 三面板各自独立状态：互不阻塞（一个端点忙/失败不影响另外两个）。
     全部按需加载——句柄表/线程/内存遍历在探针侧都有真实成本。 */
  const [hData, setHData] = useState<LiveHandleList | null>(null);
  const [hBusy, setHBusy] = useState(false);
  const [hErr, setHErr] = useState('');
  const [hType, setHType] = useState('');
  const [hQ, setHQ] = useState('');
  /* 类型直方图只在"未过滤"请求后更新：过滤请求的 types 可能是子集，
     拿它覆盖会让筛选器选项越点越少 */
  const [hTypes, setHTypes] = useState<Record<string, number>>({});

  const [tData, setTData] = useState<LiveThreads | null>(null);
  const [tBusy, setTBusy] = useState(false);
  const [tErr, setTErr] = useState('');

  const [mData, setMData] = useState<LiveMemScan | null>(null);
  const [mBusy, setMBusy] = useState(false);
  const [mErr, setMErr] = useState('');
  const [regionsOpen, setRegionsOpen] = useState(false);

  /* 每个面板独立的请求序号：切换目标进程或重复点击时，旧响应落地必须丢弃，
     否则会把上一个 PID 的句柄/线程/内存结果渲染到当前进程名下。 */
  const hSeq = useRef(0);
  const tSeq = useRef(0);
  const mSeq = useRef(0);

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

  /* 切换/关闭目标进程时清空三面板：不同 PID 的句柄/线程/内存结果没有
     可复用性（句柄值与地址只在该进程上下文里成立），串用会直接误判。
     同时递增序号，作废旧进程尚在途中的响应。 */
  useEffect(() => {
    hSeq.current++; tSeq.current++; mSeq.current++;
    setHData(null); setHErr(''); setHType(''); setHQ(''); setHTypes({}); setHBusy(false);
    setTData(null); setTErr(''); setTBusy(false);
    setMData(null); setMErr(''); setRegionsOpen(false); setMBusy(false);
  }, [sel?.pid]);

  /* 句柄：类型过滤走服务端参数（limit 截断时客户端过滤会漏），
     名称搜索纯前端（对象名已在本页内存里）。 */
  const loadHandles = useCallback(async (type: string) => {
    if (!sel) return;
    const seq = ++hSeq.current;
    setHBusy(true); setHErr(''); setHType(type);
    try {
      const d = await live.handles(agentId, sel.pid, { type: type || undefined });
      if (seq !== hSeq.current) return;
      setHData(d);
      if (!type) setHTypes(d.types || {});
    } catch (ex) {
      if (seq !== hSeq.current) return;
      setHData(null);
      setHErr(panelErrNote(ex)); // 三面板各自内联报错，不叠加 Toast
    } finally {
      if (seq === hSeq.current) setHBusy(false);
    }
  }, [agentId, sel]);

  const loadThreads = useCallback(async () => {
    if (!sel) return;
    const seq = ++tSeq.current;
    setTBusy(true); setTErr('');
    try {
      const d = await live.threads(agentId, sel.pid);
      if (seq === tSeq.current) setTData(d);
    } catch (ex) {
      if (seq !== tSeq.current) return;
      setTData(null);
      setTErr(panelErrNote(ex));
    } finally {
      if (seq === tSeq.current) setTBusy(false);
    }
  }, [agentId, sel]);

  const loadMem = useCallback(async () => {
    if (!sel) return;
    const seq = ++mSeq.current;
    setMBusy(true); setMErr('');
    try {
      const d = await live.memscan(agentId, sel.pid);
      if (seq === mSeq.current) setMData(d);
    } catch (ex) {
      if (seq !== mSeq.current) return;
      setMData(null);
      setMErr(panelErrNote(ex, true)); // 404 = 进程已退出（见 panelErrNote 注释）
    } finally {
      if (seq === mSeq.current) setMBusy(false);
    }
  }, [agentId, sel]);

  const hHist = useMemo(
    () => Object.entries(hTypes).sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0])),
    [hTypes],
  );
  const hTypeOptions = useMemo(() => {
    const keys = Object.keys(hTypes);
    if (hType && !keys.includes(hType)) keys.push(hType); // 过滤中类型不在直方图里也保留选项
    return keys.sort((a, b) => (hTypes[b] || 0) - (hTypes[a] || 0) || a.localeCompare(b));
  }, [hTypes, hType]);
  const hItems = useMemo(() => {
    const needle = hQ.trim().toLowerCase();
    const items = hData?.items || [];
    return needle ? items.filter((h) => (h.name || '').toLowerCase().includes(needle)) : items;
  }, [hData, hQ]);

  const mRegions = mData?.regions || [];
  const mSusp = mData?.suspicious || [];
  const mCounts = mData?.counts || { regions: mRegions.length, private_exec: 0, suspicious: mSusp.length };

  const copy = async (text: string) => {
    const ok = await copyText(text);
    toast(ok ? '已复制到剪贴板' : '复制失败，请手动选择', ok ? 'ok' : 'warn');
  };

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

          <RowSection title="句柄" extra={
            <Button size="sm" variant="ghost" disabled={hBusy} onClick={() => void loadHandles(hType)}>
              <Layers size={13} /> {hBusy ? '枚举中…' : hData ? '重新加载' : '加载句柄'}
            </Button>
          }>
            {hBusy && <SkeletonRows rows={3} />}
            {!hBusy && hErr && (
              <div className="flex flex-wrap items-center gap-2 text-[12.5px] text-destructive">
                <CircleAlert size={13} className="shrink-0" /> <span>{hErr}</span>
                {hType && (
                  <Button size="sm" variant="ghost" onClick={() => void loadHandles('')}>清除类型过滤</Button>
                )}
              </div>
            )}
            {!hBusy && !hErr && !hData && (
              <p className="text-xs leading-[1.8] text-faint">
                枚举该进程的句柄表：类型直方图、类型过滤与对象名（仅对安全类型解析，单请求 ≤2 秒预算）。
              </p>
            )}
            {!hBusy && hData && (
              <div className="space-y-2.5">
                {hHist.length > 0 && (
                  <div className="flex flex-wrap items-center gap-1.5">
                    {hHist.slice(0, 10).map(([t, n]) => (
                      <Badge key={t} tone={t.toLowerCase() === 'file' ? 'info' : 'neutral'} title={`${t} 类型 ${n} 个句柄`}>
                        {t} <span className="font-mono tabular-nums">{n}</span>
                      </Badge>
                    ))}
                    {hHist.length > 10 && <span className="text-[11px] text-faint">另有 {hHist.length - 10} 类</span>}
                  </div>
                )}
                <div className="flex flex-wrap items-center gap-2">
                  <Select value={hType} aria-label="句柄类型筛选" disabled={hBusy}
                    onChange={(e) => void loadHandles(e.target.value)} className="h-7 text-[12px]">
                    <option value="">全部类型</option>
                    {hTypeOptions.map((t) => <option key={t} value={t}>{t}（{hTypes[t] ?? 0}）</option>)}
                  </Select>
                  <Input value={hQ} onChange={(e) => setHQ(e.target.value)} placeholder="搜索句柄名称"
                    spellCheck={false} aria-label="句柄名称搜索" className="h-7 w-[190px] text-[12px]" />
                  <span className="font-mono text-[11px] text-ghost">
                    共 {hData.total ?? 0} · 显示 {(hData.items || []).length}
                  </span>
                  {hData.truncated && <Badge tone="medium" title="预算或条数上限用尽，结果不完整">已截断</Badge>}
                </div>
                {hData.note && <p className="text-[11px] leading-[1.7] text-faint">{hData.note}</p>}
                {!(hData.items || []).length ? (
                  <p className="text-xs text-faint">未返回句柄——进程可能已退出，或探针无权打开该进程。</p>
                ) : !hItems.length ? (
                  <p className="text-xs text-faint">没有匹配的句柄名称。</p>
                ) : (
                  <div className="max-h-[260px] overflow-y-auto rounded-md border border-border-soft">
                    <table className="w-full text-[12px]">
                      <thead>
                        <tr className="text-left text-[11px] tracking-[.06em] text-faint uppercase">
                          <th className="w-[110px] px-3 py-2 font-semibold">句柄值</th>
                          <th className="w-[110px] px-3 py-2 font-semibold">类型</th>
                          <th className="px-3 py-2 font-semibold">名称</th>
                        </tr>
                      </thead>
                      <tbody>
                        {hItems.map((h, i) => {
                          const name = h.name || '';
                          const isFile = (h.type || '').toLowerCase() === 'file';
                          /* 只有形如 C:\... 的盘符路径才能交给实时文件 Tab；
                             \Device\HarddiskVolumeN\... 需要 QueryDosDevice 映射，
                             浏览器侧拿不到——诚实降级为复制按钮。 */
                          const drivePath = isFile && /^[A-Za-z]:\\/.test(name);
                          return (
                            <tr key={`${h.value}-${i}`} className="border-b border-border-soft last:border-b-0">
                              <td className="px-3 py-1.5 font-mono text-[11.5px] tabular-nums text-muted-foreground"
                                title={`十进制 ${h.value}`}>0x{(h.value || 0).toString(16)}</td>
                              <td className="px-3 py-1.5 font-mono text-[11.5px]">{h.type || '—'}</td>
                              <td className="px-3 py-1.5">
                                {!name ? <span className="text-faint">—</span> : (
                                  <span className="flex min-w-0 items-center gap-1">
                                    <span className="min-w-0 flex-1 truncate font-mono text-[11.5px] text-muted-foreground" title={name}>{name}</span>
                                    {drivePath && onAnalyzeFile && (
                                      <Button size="sm" variant="ghost" className="h-6 px-1.5" aria-label="在实时文件 Tab 中打开"
                                        title="在实时文件 Tab 打开该路径的文件抽屉" onClick={() => onAnalyzeFile(name)}>
                                        <ScanSearch size={12} />
                                      </Button>
                                    )}
                                    {isFile && (
                                      <Button size="sm" variant="ghost" className="h-6 px-1.5" aria-label="复制句柄名称"
                                        title={drivePath ? '复制路径' : '复制设备路径（浏览器无法映射 \\Device 路径，需在终端侧换算盘符）'}
                                        onClick={() => void copy(name)}>
                                        <Copy size={12} />
                                      </Button>
                                    )}
                                  </span>
                                )}
                              </td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                  </div>
                )}
                <p className="text-[11px] leading-[1.7] text-faint">
                  对象名只对 File/Directory/Key/Section/Mutant/Semaphore/SymbolicLink 等安全类型解析；
                  <code className="font-mono">\Device\HarddiskVolumeN\…</code> 设备路径无法在浏览器侧换算盘符，可复制后在终端核对。
                </p>
              </div>
            )}
          </RowSection>

          <RowSection title="线程" extra={
            <Button size="sm" variant="ghost" disabled={tBusy} onClick={() => void loadThreads()}>
              <Cpu size={13} /> {tBusy ? '枚举中…' : tData ? '重新加载' : '加载线程'}
            </Button>
          }>
            {tBusy && <SkeletonRows rows={3} />}
            {!tBusy && tErr && (
              <div className="flex items-center gap-2 text-[12.5px] text-destructive">
                <CircleAlert size={13} className="shrink-0" /> <span>{tErr}</span>
              </div>
            )}
            {!tBusy && !tErr && !tData && (
              <p className="text-xs leading-[1.8] text-faint">
                枚举线程起始地址并与进程模块区间比对；起始于匿名可执行内存的线程会标红（注入线索）。
              </p>
            )}
            {!tBusy && tData && (
              <div className="space-y-2.5">
                {tData.note && <p className="text-[11px] leading-[1.7] text-faint">{tData.note}</p>}
                {!(tData.items || []).length ? (
                  <p className="text-xs text-faint">未返回线程——受保护进程可能无法打开，覆盖度见上方说明。</p>
                ) : (
                  <div className="max-h-[240px] overflow-y-auto rounded-md border border-border-soft">
                    <table className="w-full text-[12px]">
                      <thead>
                        <tr className="text-left text-[11px] tracking-[.06em] text-faint uppercase">
                          <th className="w-[90px] px-3 py-2 font-semibold">TID</th>
                          <th className="w-[130px] px-3 py-2 font-semibold">起始地址</th>
                          <th className="px-3 py-2 font-semibold">模块</th>
                          <th className="px-3 py-2 font-semibold">线索</th>
                        </tr>
                      </thead>
                      <tbody>
                        {(tData.items || []).map((t) => (
                          <tr key={t.tid}
                            className={cn('border-b border-border-soft last:border-b-0',
                              t.in_anonymous_exec && 'bg-destructive-soft/40')}>
                            <td className="px-3 py-1.5 font-mono text-[11.5px] tabular-nums">{t.tid}</td>
                            <td className="px-3 py-1.5 font-mono text-[11.5px] text-muted-foreground">
                              0x{(t.start_address || 0).toString(16)}
                            </td>
                            <td className="px-3 py-1.5">
                              {t.module
                                ? <span className="block truncate font-mono text-[11.5px] text-muted-foreground" title={t.module}>{t.module}</span>
                                : <span className="text-[11.5px] text-faint" title="起始地址不在本进程任何模块区间内（可能是 JIT / 反射加载 / 注入代码）">未归属模块</span>}
                            </td>
                            <td className="px-3 py-1.5">
                              {t.in_anonymous_exec
                                ? <Badge tone="critical">线程起始于匿名可执行内存（注入线索）</Badge>
                                : <span className="text-faint">—</span>}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
                <p className="text-[11px] leading-[1.7] text-faint">
                  起始地址来自 NtQueryInformationThread；受保护进程打不开时条目会缺失，覆盖率以 note 为准。
                </p>
              </div>
            )}
          </RowSection>

          <RowSection title="内存" extra={
            <Button size="sm" variant="ghost" disabled={mBusy} onClick={() => void loadMem()}>
              <MemoryStick size={13} /> {mBusy ? '扫描中…' : mData ? '重新扫描' : '加载内存'}
            </Button>
          }>
            {mBusy && <SkeletonRows rows={3} />}
            {!mBusy && mErr && (
              <div className="flex items-center gap-2 text-[12.5px] text-destructive">
                <CircleAlert size={13} className="shrink-0" /> <span>{mErr}</span>
              </div>
            )}
            {!mBusy && !mErr && !mData && (
              <p className="text-xs leading-[1.8] text-faint">
                遍历虚拟内存区域，只回传地址/大小/保护位与可疑标记——探针绝不读取或回传内存内容；目标 PID 0/4 由探针拒绝。
              </p>
            )}
            {!mBusy && mData && (
              <div className="space-y-2.5">
                <div className="flex flex-wrap items-center gap-1.5">
                  <Badge tone="neutral" title="提交区域总数；regions 列表最多返回 200 条">区域 {mCounts.regions}</Badge>
                  <Badge tone="neutral" title="MEM_PRIVATE 且带执行位——JIT/运行时也会产生，仅作画像">
                    私有可执行 {mCounts.private_exec}
                  </Badge>
                  <Badge tone={mCounts.suspicious > 0 ? 'critical' : 'resolved'} title="私有 + 可执行 + 无映射文件 + ≥4KB">
                    可疑 {mCounts.suspicious}
                  </Badge>
                  {mData.truncated && <Badge tone="medium" title="区域列表达到 200 条上限">区域列表已截断</Badge>}
                </div>
                {mData.note && <p className="text-[11px] leading-[1.7] text-faint">{mData.note}</p>}
                {!mSusp.length ? (
                  <p className="text-xs text-faint">未发现"私有 + 可执行 + 无文件映射"的可疑内存区域。</p>
                ) : (
                  <div className="rounded-md border border-border-soft">
                    <table className="w-full text-[12px]">
                      <thead>
                        <tr className="border-b border-border-soft text-left text-[11px] tracking-[.06em] text-faint uppercase">
                          <th className="px-3 py-2 font-semibold">地址范围</th>
                          <th className="w-[90px] px-3 py-2 font-semibold">大小</th>
                          <th className="w-[120px] px-3 py-2 font-semibold">保护位</th>
                          <th className="w-[60px] px-3 py-2 font-semibold">头</th>
                        </tr>
                      </thead>
                      <tbody>
                        {mSusp.map((s, i) => (
                          <tr key={`${s.base}-${i}`} className="border-b border-border-soft last:border-b-0">
                            <td className="px-3 py-1.5 font-mono text-[11.5px] tabular-nums">
                              0x{(s.base || 0).toString(16)}–0x{((s.base || 0) + (s.size || 0)).toString(16)}
                            </td>
                            <td className="px-3 py-1.5 font-mono text-[11.5px] tabular-nums text-muted-foreground">{fmtBytes(s.size)}</td>
                            <td className="px-3 py-1.5 font-mono text-[11.5px] text-muted-foreground">{s.protect || '—'}</td>
                            <td className="px-3 py-1.5">
                              {s.pe_header === true
                                ? <Badge tone="critical" title="区域起始处可读到 MZ 头——可能是反射加载的 PE">MZ</Badge>
                                : s.pe_header === false
                                  ? <span className="text-faint">—</span>
                                  : <span className="text-ghost" title="ReadProcessMemory 失败，无法判断">?</span>}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
                {!!mRegions.length && (
                  <>
                    <Button size="sm" variant="ghost" aria-expanded={regionsOpen} onClick={() => setRegionsOpen((v) => !v)}>
                      <ChevronRight size={12} className={cn('transition-transform duration-150', regionsOpen && 'rotate-90')} />
                      {regionsOpen ? '收起内存区域明细' : `展开内存区域明细（${mRegions.length}）`}
                    </Button>
                    {regionsOpen && (
                      <div className="max-h-[240px] overflow-y-auto rounded-md border border-border-soft">
                        <table className="w-full text-[12px]">
                          <thead>
                            <tr className="text-left text-[11px] tracking-[.06em] text-faint uppercase">
                              <th className="w-[130px] px-3 py-2 font-semibold">起始</th>
                              <th className="w-[80px] px-3 py-2 font-semibold">大小</th>
                              <th className="w-[110px] px-3 py-2 font-semibold">保护位</th>
                              <th className="w-[100px] px-3 py-2 font-semibold">类型</th>
                              <th className="px-3 py-2 font-semibold">映射文件</th>
                            </tr>
                          </thead>
                          <tbody>
                            {mRegions.map((r, i) => (
                              <tr key={`${r.base}-${i}`} className="border-b border-border-soft last:border-b-0">
                                <td className="px-3 py-1.5 font-mono text-[11.5px] tabular-nums">0x{(r.base || 0).toString(16)}</td>
                                <td className="px-3 py-1.5 font-mono text-[11.5px] tabular-nums text-muted-foreground">{fmtBytes(r.size)}</td>
                                <td className="px-3 py-1.5 font-mono text-[11.5px] text-muted-foreground">{r.protect || '—'}</td>
                                <td className="px-3 py-1.5 font-mono text-[11.5px] text-muted-foreground">{r.type || '—'}</td>
                                <td className="px-3 py-1.5">
                                  {r.mapped_file
                                    ? <span className="block truncate font-mono text-[11.5px] text-muted-foreground" title={r.mapped_file}>{r.mapped_file}</span>
                                    : <span className="text-[11.5px] text-faint" title="无文件映射（匿名内存）">匿名</span>}
                                </td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    )}
                  </>
                )}
                <p className="text-[11px] leading-[1.7] text-faint">
                  保护位为该区域的基础保护值；仅出摘要，探针不读取内容。MZ 标记只判前两个字节，不代表文件可信。
                </p>
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
