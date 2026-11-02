import { Fragment, useCallback, useEffect, useMemo, useState } from 'react';
import { ChevronRight, CircleAlert, ListChecks, RefreshCw, Search, ShieldCheck, Unplug } from 'lucide-react';
import { ApiError, live, liveErrorKind } from '../lib/api';
import type { LiveHash, LivePersistence, PersistenceItem, PersistenceSource } from '../lib/types';
import { fmtTime } from '../lib/format';
import { Badge, Button, Card, CardTitle, EmptyState, Input, Skeleton, SkeletonRows } from '../components/ui/basics';
import { cn } from '../lib/utils';

/* 主机详情「持久化总览」Tab（docs/LIVE-TUNNEL.md §16.1，第七轮 F9）。
   探针侧把既有枚举（服务 / 计划任务 XML / 启动项 7 类）聚合成一张表，
   本页只做三件事：按来源分组可折叠、全局搜索、逐项按需签名校验。
   设计取舍：签名现场计算有成本，绝不随页面加载批量触发——默认只有
   "校验签名"按钮，结果按 (agentId, 路径) 走模块级 30s 缓存。 */

const SOURCE_ORDER: PersistenceSource[] = ['service', 'task', 'startup'];

const SOURCE_META: Record<PersistenceSource, { label: string; hint: string }> = {
  service: { label: '服务', hint: 'start=auto / delayed-auto 的自动启动服务' },
  task: { label: '计划任务', hint: '已注册任务（enabled=false 也列出便于审视）' },
  startup: { label: '启动项', hint: '注册表 Run/RunOnce/Winlogon/IFEO、启动目录、服务项、任务项' },
};

/* ---- 与 HostDetail.tsx 同口径的路径判定 ----
   HostDetail 里的 extractExePath / WRITABLE_RULES / writableRiskLabel 是文件内
   私有函数（未导出），且本轮文件所有权不含它的导出改造，因此在此复制同等实现。
   两处判定口径必须同步：改其中一处时另一处也要改（服务 Tab 与持久化 Tab
   对同一路径给出不一致的风险结论会直接误导值班判断）。 */

const EXE_RE = /[A-Za-z]:\\[^"]+?\.(?:exe|dll|com|bat|cmd|ps1|vbs|js|msi|scr)/i;

/** 从命令文本里提取第一个绝对可执行路径；取不到返回空串（不猜相对路径） */
function extractExePath(raw: string): string {
  const s = (raw || '').trim();
  if (!s) return '';
  const quoted = s.match(/^"([^"]+?\.(?:exe|dll|com|bat|cmd|ps1|vbs|js|msi|scr))"/i);
  if (quoted) return quoted[1].trim();
  const m = s.match(EXE_RE);
  return m ? m[0].trim() : '';
}

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

/* Authenticode state → 中文标签 + 徽标 tone（与 HostDetail/HostLiveFiles 一致） */
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

/* 签名结果前端缓存（与 HostDetail.HashCheck 同口径）：键必须含 agentId——
   30 秒内切换主机且路径相同时，纯路径键会串用另一台主机的哈希结果。 */
const HASH_CACHE_TTL_MS = 30_000;
const hashCache = new Map<string, { at: number; data: LiveHash }>();

/** 行内签名校验：一个按钮 + 结果徽标 + SHA256 前 16 位；exe_path 为空时禁用 */
function SigCheck({ agentId, path, canLive }: { agentId: string; path: string; canLive: boolean }) {
  const [busy, setBusy] = useState(false);
  const [res, setRes] = useState<LiveHash | null>(null);
  const [err, setErr] = useState('');
  const [cached, setCached] = useState(false);

  const run = async (ev: React.MouseEvent) => {
    ev.stopPropagation(); // 行点击是展开命令，按钮不能连带触发展开
    if (!path) return;
    const key = `${agentId}:${path.trim().toLowerCase()}`;
    const hit = hashCache.get(key);
    if (hit && Date.now() - hit.at < HASH_CACHE_TTL_MS) {
      setRes(hit.data); setErr(''); setCached(true);
      return;
    }
    setBusy(true); setErr('');
    try {
      const data = await live.hash(agentId, path);
      hashCache.set(key, { at: Date.now(), data });
      setRes(data); setCached(false);
    } catch (e) {
      setRes(null); setErr(hashErrNote(e)); setCached(false);
    } finally {
      setBusy(false);
    }
  };

  const meta = res ? (AUTH_STATE_META[String(res.authenticode?.state || '').toLowerCase()] || {
    label: String(res.authenticode?.state || '') || '签名状态未知', tone: 'neutral',
  }) : null;

  return (
    <div className="flex flex-wrap items-center gap-1.5">
      <Button size="sm" variant="ghost" disabled={!canLive || !path || busy} onClick={(e) => void run(e)}
        title={!path ? '该项命令里没有可校验的绝对可执行路径' : !canLive ? '需要分析师及以上角色' : '现场计算 SHA256 并校验 Authenticode 签名'}>
        {busy ? <RefreshCw size={13} className="anim-spin" /> : <ShieldCheck size={13} />}
        {busy ? '校验中…' : '校验签名'}
      </Button>
      {err && <span className="text-[11px] text-warn">{err}</span>}
      {res && meta && (
        <>
          <Badge tone={meta.tone}>{meta.label}</Badge>
          {cached && <span className="text-[10.5px] text-ghost" title="30 秒内重复查询，未重新哈希">缓存</span>}
          <span className="font-mono text-[11px] text-muted-foreground" title={res.sha256}>
            {res.sha256.slice(0, 16)}…
          </span>
        </>
      )}
    </div>
  );
}

/* ---------------- 错误态 ---------------- */

interface PersistenceErr { kind: 'tunnel' | 'busy' | 'off' | 'unsupported' | 'other'; note: string }

/* 404/501 统一收敛为"该探针版本不支持"（老服务端预算表未收录即 404） */
function persistenceErr(e: unknown): PersistenceErr {
  if (e instanceof ApiError && e.status === 404) {
    return { kind: 'unsupported', note: '该探针或服务端版本不支持持久化总览' };
  }
  switch (liveErrorKind(e)) {
    case 'tunnel': return { kind: 'tunnel', note: '探针隧道未连接' };
    case 'busy': return { kind: 'busy', note: '探针忙，稍后重试' };
    case 'off': return { kind: 'off', note: '实时查询未启用或权限不足' };
    case 'unsupported': return { kind: 'unsupported', note: '该探针或服务端版本不支持持久化总览' };
    default: return { kind: 'other', note: e instanceof Error ? e.message : String(e) };
  }
}

function PersistenceErrorState({ e, onRetry }: { e: PersistenceErr; onRetry: () => void }) {
  let info: { tone: 'info' | 'warn'; icon: React.ReactNode; title: string; sub: string };
  switch (e.kind) {
    case 'tunnel':
      info = {
        tone: 'warn', icon: <Unplug size={20} />, title: '无法读取持久化总览',
        sub: '探针隧道未连接——探针离线、版本过旧或未开启隧道拨号；恢复后重试即可，此处不展示缓存数据。',
      };
      break;
    case 'busy':
      info = {
        tone: 'warn', icon: <CircleAlert size={20} />, title: '探针忙，稍后重试',
        sub: '持久化聚合需要现场枚举服务、计划任务与启动项（约 10 秒预算），请等待当前任务结束后重试。',
      };
      break;
    case 'off':
      info = {
        tone: 'info', icon: <CircleAlert size={20} />, title: '实时查询未启用或权限不足',
        sub: '持久化总览需要服务端开启实时隧道并授予分析师及以上角色。',
      };
      break;
    case 'unsupported':
      info = {
        tone: 'warn', icon: <CircleAlert size={20} />, title: '该探针版本不支持持久化总览',
        sub: '请升级终端探针（与服务端）到包含持久化聚合能力的版本后重试。',
      };
      break;
    default:
      info = {
        tone: 'warn', icon: <CircleAlert size={20} />, title: '持久化枚举失败',
        sub: e.note || '未知错误，请稍后重试。',
      };
  }
  return (
    <Card>
      <EmptyState tone={info.tone} icon={info.icon} title={info.title} sub={info.sub}
        action={<Button size="sm" onClick={onRetry}>重试</Button>} />
    </Card>
  );
}

function PersistenceSkeleton() {
  return (
    <>
      <Card className="p-4">
        <div className="flex flex-wrap items-center gap-2.5">
          <Skeleton className="h-3 w-24" />
          <div className="flex-1" />
          <Skeleton className="h-7 w-20 rounded-[7px]" />
        </div>
        <div className="mt-3 grid grid-cols-1 gap-px overflow-hidden rounded-md border border-border-soft bg-border-soft sm:grid-cols-3">
          {[0, 1, 2].map((i) => (
            <div key={i} className="bg-card px-3.5 py-3">
              <Skeleton className="h-6 w-10" />
              <Skeleton className="mt-2 h-3 w-14" />
            </div>
          ))}
        </div>
      </Card>
      <Card><SkeletonRows rows={8} /></Card>
    </>
  );
}

/* ---------------- 主组件 ---------------- */

const normSource = (s: string): PersistenceSource | 'other' =>
  (SOURCE_ORDER as string[]).includes(s) ? (s as PersistenceSource) : 'other';

export function HostPersistenceTab({ agentId, canLive }: { agentId: string; canLive: boolean }) {
  const [res, setRes] = useState<LivePersistence | null>(null);
  const [loading, setLoading] = useState(false);
  const [loadErr, setLoadErr] = useState<PersistenceErr | null>(null);
  const [freshAt, setFreshAt] = useState('');
  const [q, setQ] = useState('');
  const [collapsed, setCollapsed] = useState<Record<string, boolean>>({});
  const [openRows, setOpenRows] = useState<Record<string, boolean>>({});
  /* 每组默认只渲染前 60 行：上限 2000 条，一次铺开会把浏览器拖垮 */
  const [visible, setVisible] = useState(60);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const d = await live.persistence(agentId);
      setRes(d);
      setLoadErr(null);
      setOpenRows({});
      // generated_at 是探针时刻；缺省时退回本地时刻（与基线/账户页同口径）
      setFreshAt(d.generated_at ? fmtTime(d.generated_at) : new Date().toLocaleTimeString('zh-CN', { hour12: false }));
    } catch (e) {
      // 失败清空：持久化是现场快照，旧数据比没有数据更危险
      setRes(null);
      setLoadErr(persistenceErr(e));
    } finally {
      setLoading(false);
    }
  }, [agentId]);

  useEffect(() => {
    setRes(null); setLoadErr(null); setFreshAt(''); setQ(''); setCollapsed({}); setVisible(60);
    void load();
  }, [load]);

  useEffect(() => { setVisible(60); }, [q]);

  const items = useMemo(() => res?.items || [], [res]);

  /* 计数优先用探针回传的 counts；缺省时按条目现算，避免徽标恒 0 误导 */
  const counts = useMemo(() => {
    const c: Record<PersistenceSource, number> = { service: 0, task: 0, startup: 0 };
    for (const it of items) {
      const s = normSource(it.source);
      if (s !== 'other') c[s]++;
    }
    if (res?.counts) {
      c.service = res.counts.service ?? c.service;
      c.task = res.counts.task ?? c.task;
      c.startup = res.counts.startup ?? c.startup;
    }
    return c;
  }, [items, res]);

  const grouped = useMemo(() => {
    const m: Record<string, PersistenceItem[]> = { service: [], task: [], startup: [], other: [] };
    for (const it of items) m[normSource(it.source)].push(it);
    // 启用项置顶、同级按名称排序：值班先看"当前生效"的面
    for (const k of Object.keys(m)) {
      m[k].sort((a, b) => {
        const ea = a.enabled !== false ? 0 : 1;
        const eb = b.enabled !== false ? 0 : 1;
        if (ea !== eb) return ea - eb;
        return (a.name || '').localeCompare(b.name || '', 'zh-CN');
      });
    }
    return m;
  }, [items]);

  const filtered = useMemo(() => {
    const needle = q.trim().toLowerCase();
    const out: Record<string, PersistenceItem[]> = {};
    for (const [k, rows] of Object.entries(grouped)) {
      out[k] = needle
        ? rows.filter((it) => [it.name, it.command, it.exe_path, it.user, it.location]
          .some((v) => String(v || '').toLowerCase().includes(needle)))
        : rows;
    }
    return out;
  }, [grouped, q]);

  const total = items.length;
  const shownTotal = Object.values(filtered).reduce((n, rows) => n + rows.length, 0);

  const toggleGroup = (k: string) => setCollapsed((v) => ({ ...v, [k]: !v[k] }));
  const toggleRow = (k: string) => setOpenRows((v) => ({ ...v, [k]: !v[k] }));

  return (
    <>
      {!res ? (
        loadErr ? <PersistenceErrorState e={loadErr} onRetry={() => void load()} /> : <PersistenceSkeleton />
      ) : (
        <>
          <Card className="p-4">
            <div className="flex flex-wrap items-center gap-2.5">
              <CardTitle>持久化总览</CardTitle>
              <span className="font-mono text-[11px] tabular-nums text-ghost">{total} 项</span>
              {res.truncated && (
                <Badge tone="medium" title="探针侧达到 2000 条上限或预算用尽，结果不完整">结果已截断</Badge>
              )}
              <div className="flex-1" />
              {freshAt && <span className="text-[11px] text-ghost">更新于 {freshAt}</span>}
              <div className="relative">
                <Search size={13} className="pointer-events-none absolute top-1/2 left-2.5 -translate-y-1/2 text-ghost" />
                <Input value={q} onChange={(e) => setQ(e.target.value)}
                  placeholder="搜索名称 / 命令 / 路径 / 账户 / 位置"
                  className="h-7 w-[260px] pl-7 text-[12px]" spellCheck={false} aria-label="搜索持久化项" />
              </div>
              <Button size="sm" disabled={loading} onClick={() => void load()} title="重新枚举服务、计划任务与启动项">
                <RefreshCw size={13} className={cn(loading && 'anim-spin')} />
                {loading ? '刷新中…' : '刷新'}
              </Button>
            </div>

            <div className="mt-3 grid grid-cols-1 gap-px overflow-hidden rounded-md border border-border-soft bg-border-soft sm:grid-cols-3">
              {SOURCE_ORDER.map((s) => (
                <div key={s} className="bg-card px-3.5 py-3" title={SOURCE_META[s].hint}>
                  <div className={cn('font-mono text-[26px] leading-none font-semibold tabular-nums',
                    counts[s] ? 'text-foreground' : 'text-ghost')}>
                    {counts[s]}
                  </div>
                  <div className="mt-1.5 text-[11px] text-faint">{SOURCE_META[s].label}</div>
                </div>
              ))}
            </div>

            <p className="mt-2.5 text-[11px] leading-relaxed text-ghost">
              聚合自本机只读枚举（不执行任何命令）；签名需逐项触发校验，可写路径风险按路径片段判定，不是 ACL 实测。
              任务 enabled=false 也会列出——禁用不等于已删除。
            </p>
          </Card>

          {!total ? (
            <Card>
              <EmptyState tone="info" icon={<ListChecks size={20} />} title="没有枚举到持久化项"
                sub="探针返回了空结果：可能是枚举失败或该主机确实没有自动启动项。可点刷新重试，并核对探针版本与权限。" />
            </Card>
          ) : !shownTotal ? (
            <Card>
              <EmptyState tone="info" icon={<Search size={20} />} title="没有匹配的持久化项"
                sub={`没有名称、命令、路径、账户或位置包含“${q.trim()}”的条目。`} />
            </Card>
          ) : (
            <Card>
              <div className="flex flex-wrap items-center gap-2.5 px-4 py-3">
                <CardTitle>按来源</CardTitle>
                <span className="font-mono text-[11px] tabular-nums text-ghost">
                  {q ? `${shownTotal} / ${total}` : total}
                </span>
                <div className="flex-1" />
                <span className="text-[11px] text-ghost">点击行展开完整命令 · 每组先显示 {visible} 条</span>
              </div>

              {(Object.keys(filtered) as string[]).map((key) => {
                if (!filtered[key].length) return null;
                const meta = key === 'other' ? { label: '其他来源', hint: '探针返回了未约定的 source 值' } : SOURCE_META[key as PersistenceSource];
                const rows = filtered[key];
                const disabled = rows.filter((it) => it.enabled === false).length;
                const open = !collapsed[key];
                const page = rows.slice(0, visible);
                return (
                  <section key={key} aria-label={`${meta.label} ${rows.length} 项`}>
                    <button type="button" onClick={() => toggleGroup(key)} aria-expanded={open}
                      className="flex w-full cursor-pointer flex-wrap items-center gap-2 border-y border-border-soft bg-secondary/30 px-4 py-2 text-left transition-colors hover:bg-secondary/60">
                      <ChevronRight size={13} className={cn('shrink-0 text-ghost transition-transform duration-150', open && 'rotate-90')} />
                      <span className="text-[12.5px] font-medium">{meta.label}</span>
                      <span className="font-mono text-[11px] tabular-nums text-ghost">{rows.length}</span>
                      <span className="text-[11px] text-faint">{meta.hint}</span>
                      <div className="flex-1" />
                      {disabled > 0 && <span className="text-[11px] text-faint">未启用 {disabled}</span>}
                    </button>

                    {open && (
                      <div className="overflow-x-auto">
                        <table className="w-full text-[12.5px]">
                          <thead>
                            <tr className="border-b border-border-soft text-left text-[11px] tracking-[.06em] text-faint uppercase">
                              <th className="px-3 py-2 font-semibold">名称</th>
                              <th className="px-3 py-2 font-semibold">命令</th>
                              <th className="w-[150px] px-3 py-2 font-semibold">账户</th>
                              <th className="w-[220px] px-3 py-2 font-semibold">来源位置</th>
                              <th className="w-[88px] px-3 py-2 font-semibold">状态</th>
                              <th className="w-[260px] px-3 py-2 font-semibold">签名 / 风险</th>
                            </tr>
                          </thead>
                          <tbody>
                            {page.map((it, i) => {
                              const rowKey = `${key}:${it.name}:${it.location}:${i}`;
                              const expanded = !!openRows[rowKey];
                              const exe = (it.exe_path || '').trim() || extractExePath(it.command);
                              const risk = writableRiskLabel(exe);
                              return (
                                <Fragment key={rowKey}>
                                  <tr
                                    tabIndex={0}
                                    aria-expanded={expanded}
                                    onClick={() => toggleRow(rowKey)}
                                    onKeyDown={(e) => {
                                      if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); toggleRow(rowKey); }
                                    }}
                                    className="cursor-pointer border-b border-border-soft transition-colors last:border-b-0 hover:bg-secondary focus-visible:bg-secondary focus-visible:outline-none">
                                    <td className="px-3 py-1.5">
                                      <span className="flex items-center gap-2">
                                        <ChevronRight size={13} className={cn('shrink-0 text-ghost transition-transform duration-150', expanded && 'rotate-90')} />
                                        <span className="block max-w-[240px] truncate font-mono text-[11.5px] font-medium" title={it.name}>
                                          {it.name || '（未命名）'}
                                        </span>
                                        {risk && (
                                          <Badge tone="critical" title={`命令路径命中可写位置：${risk}（攻击者可替换文件取得同等权限）`}>
                                            可写路径
                                          </Badge>
                                        )}
                                      </span>
                                    </td>
                                    <td className="px-3 py-1.5">
                                      <span className="block max-w-[380px] truncate font-mono text-[11.5px] text-muted-foreground" title={it.command}>
                                        {it.command || '—'}
                                      </span>
                                    </td>
                                    <td className="px-3 py-1.5">
                                      <span className="block truncate font-mono text-[11.5px]" title={it.user}>{it.user || '—'}</span>
                                    </td>
                                    <td className="px-3 py-1.5">
                                      <span className="block truncate font-mono text-[11.5px] text-faint" title={it.location}>{it.location || '—'}</span>
                                    </td>
                                    <td className="px-3 py-1.5">
                                      {it.enabled === false
                                        ? <Badge tone="low" title="已禁用：不再触发，但仍建议确认是否应删除">未启用</Badge>
                                        : <Badge tone="neutral">启用</Badge>}
                                    </td>
                                    <td className="px-3 py-1.5">
                                      <SigCheck agentId={agentId} path={exe} canLive={canLive} />
                                    </td>
                                  </tr>
                                  {expanded && (
                                    <tr className="border-b border-border-soft bg-secondary/20 last:border-b-0">
                                      <td colSpan={6} className="px-4 py-3">
                                        <dl className="grid grid-cols-[84px_1fr] gap-x-3 gap-y-1.5 text-[12px]">
                                          <dt className="text-faint">完整命令</dt>
                                          <dd className="m-0 min-w-0">
                                            {it.command ? (
                                              <pre className="m-0 rounded-md border border-border-soft bg-[var(--code-bg)] p-2.5 font-mono text-[11.5px] leading-[1.7] break-all whitespace-pre-wrap text-[var(--code-fg)]">{it.command}</pre>
                                            ) : <span className="text-faint">命令为空</span>}
                                          </dd>
                                          <dt className="text-faint">来源位置</dt>
                                          <dd className="m-0 min-w-0 break-all font-mono text-[11.5px]">{it.location || '—'}</dd>
                                          <dt className="text-faint">可执行路径</dt>
                                          <dd className="m-0 min-w-0 break-all font-mono text-[11.5px]">{exe || <span className="text-faint">命令中没有绝对可执行路径</span>}</dd>
                                          {risk && (
                                            <>
                                              <dt className="text-faint">路径风险</dt>
                                              <dd className="m-0">
                                                <Badge tone="critical">可写目录中的可执行（提权面）</Badge>
                                                <span className="ml-2 text-[11px] text-faint">命中 {risk}</span>
                                              </dd>
                                            </>
                                          )}
                                        </dl>
                                      </td>
                                    </tr>
                                  )}
                                </Fragment>
                              );
                            })}
                          </tbody>
                        </table>
                        {rows.length > page.length && (
                          <div className="flex flex-wrap items-center gap-3 px-4 py-2.5">
                            <Button size="sm" variant="ghost" onClick={() => setVisible((v) => v + 60)}>
                              显示更多（{page.length} / {rows.length}）
                            </Button>
                            <span className="text-[11px] text-ghost">用搜索框可以更快定位具体条目</span>
                          </div>
                        )}
                      </div>
                    )}
                  </section>
                );
              })}
            </Card>
          )}

          <p className="px-1 text-[11px] text-ghost">
            数据为点击时刻的探针枚举快照，不做自动轮询；签名按需现场计算（30 秒内同路径复用结果）。
          </p>
        </>
      )}
    </>
  );
}
