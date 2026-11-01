import { useCallback, useEffect, useState, type ReactNode } from 'react';
import {
  ChevronUp, CircleAlert, Copy, EyeOff, FileQuestion, Fingerprint, Folder, FolderSearch,
  RefreshCw, ShieldBan, ShieldCheck, Unplug,
} from 'lucide-react';
import { api, live, ApiError, liveErrorKind } from '../lib/api';
import type { LiveFsEntry, LiveFsList, LiveHash, User } from '../lib/types';
import { fmtBytes, fmtTime } from '../lib/format';
import { Badge, Button, Card, EmptyState, Input, Skeleton, SkeletonRows } from '../components/ui/basics';
import { Drawer, useConfirm, useToast } from '../components/ui/overlays';
import { cn } from '../lib/utils';
import type { LiveFixtureApi } from '../lib/liveFixture';

/* 主机详情「实时文件」Tab（docs/LIVE-TUNNEL.md §5.3，W1-F）。
   通过服务端代理只读浏览探针终端文件系统：目录列表游标分页、文本预览、
   现场哈希；处置（加白/隔离）走既有 REST/指令通道，隧道本身只读。
   错误契约：503 tunnel_not_connected → 状态条；429/403/501 → Toast。 */

const INITIAL_PATH = 'C:\\';
const PREVIEW_LIMIT = 64 * 1024;

/* ---- 路径工具（Win32：条目只含 name，全路径由前端拼接） ---- */

function joinPath(dir: string, name: string): string {
  return dir.endsWith('\\') ? dir + name : `${dir}\\${name}`;
}

function parentPath(p: string): string {
  const t = p.replace(/\\+$/, '');
  if (/^[A-Za-z]:$/.test(t)) return `${t}\\`; // 盘符根的上级仍是自己
  const cut = t.lastIndexOf('\\');
  if (cut <= 2) return `${t.slice(0, 2)}\\`;
  return t.slice(0, cut);
}

function crumbs(p: string): { label: string; path: string }[] {
  const out = [{ label: p.slice(0, 2), path: `${p.slice(0, 2)}\\` }];
  let acc = p.slice(0, 2) + '\\';
  for (const seg of p.slice(3).split('\\').filter(Boolean)) {
    acc += seg;
    out.push({ label: seg, path: acc });
    acc += '\\';
  }
  return out;
}

/* 隧道错误的中文短句（状态条/Toast/内联共用一套口径） */
function liveErrNote(e: unknown): string | null {
  switch (liveErrorKind(e)) {
    case 'tunnel': return '探针隧道未连接';
    case 'busy': return '探针忙，稍后重试';
    case 'off': return '实时查询未启用';
    case 'unsupported': return '该探针版本不支持此能力';
    default: return null;
  }
}

/* 开发期假数据开关：仅 DEV 构建且 localStorage 显式打开时可用（W3 联调前
   预览交互）。生产构建 DEV=false 为编译期常量，死分支连同本模块整体剔除。 */
async function devFixture(): Promise<LiveFixtureApi | null> {
  if (!import.meta.env.DEV) return null;
  try { if (localStorage.getItem('hg_live_fixture') !== '1') return null; } catch { return null; }
  const m = await import('../lib/liveFixture');
  return m.fixture;
}

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

export function LiveFilesTab({ agentId, user }: { agentId: string; user: User }) {
  const toast = useToast();
  const canBrowse = user.role !== 'viewer'; // /live/fs = analyst+（LIVE-TUNNEL §4）

  const [path, setPath] = useState(INITIAL_PATH); // 已请求路径（成功后取服务端回显）
  const [input, setInput] = useState(INITIAL_PATH);
  const [list, setList] = useState<LiveFsList | null>(null);
  const [loading, setLoading] = useState(false);
  const [more, setMore] = useState(false); // 游标追加分页
  const [tunnelDown, setTunnelDown] = useState(false);
  const [loadErr, setLoadErr] = useState(''); // 通用错误（非隧道契约态）也内联呈现，不与"空目录"混淆
  const [freshAt, setFreshAt] = useState('');
  const [openFile, setOpenFile] = useState<{ entry: LiveFsEntry; dir: string } | null>(null);

  const canonical = list?.path || path;
  const atRoot = /^[A-Za-z]:\\?$/.test(canonical);

  const load = useCallback(async (dir: string, cursor?: string) => {
    cursor ? setMore(true) : setLoading(true);
    try {
      const fx = await devFixture();
      const d = fx ? await fx.fs(dir, cursor) : await live.fs(agentId, dir, cursor);
      setTunnelDown(false); setLoadErr('');
      setList((prev) =>
        cursor && prev && prev.path === d.path
          ? { ...d, entries: [...prev.entries, ...d.entries] } // 追加，替换游标
          : d);
      setPath(d.path || dir);
      setInput(d.path || dir);
      setFreshAt(new Date().toLocaleTimeString('zh-CN', { hour12: false }));
    } catch (e) {
      if (!cursor) setList(null);
      const note = liveErrNote(e);
      if (liveErrorKind(e) === 'tunnel') setTunnelDown(true);
      else if (note) { setLoadErr(note); toast(note, 'warn'); }
      else {
        const msg = e instanceof ApiError ? e.message : (e as Error).message;
        setLoadErr(msg);
        toast(msg, 'err');
      }
    } finally {
      setLoading(false); setMore(false);
    }
  }, [agentId, toast]);

  useEffect(() => {
    setList(null); setPath(INITIAL_PATH); setInput(INITIAL_PATH); setTunnelDown(false); setLoadErr(''); setOpenFile(null);
    if (canBrowse) void load(INITIAL_PATH);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [agentId]);

  /* 路径框跳转：容错正斜杠与结尾反斜杠；缺盘符直接提醒（探针侧会 400） */
  const submit = () => {
    let p = input.trim().replace(/\//g, '\\');
    if (!/^[A-Za-z]:/.test(p)) { toast('请输入以盘符开头的完整路径，例 C:\\Windows', 'warn'); return; }
    if (p.length > 3) p = p.replace(/\\+$/, '');
    void load(p);
  };

  const enterRow = (en: LiveFsEntry) => {
    if (en.is_dir) void load(joinPath(canonical, en.name));
    else setOpenFile({ entry: en, dir: canonical }); // 冻结点击时的目录，防浏览中途漂移
  };

  return (
    <>
      <Card className="p-4">
        {/* 工具行：上级 / 面包屑 / 路径输入 / 刷新 / 新鲜度 */}
        {canBrowse && (
          <div className="mb-3 flex flex-wrap items-center gap-2">
            <Button size="icon" aria-label="上一级目录" title="上一级" disabled={atRoot || loading}
              onClick={() => void load(parentPath(canonical))}>
              <ChevronUp size={15} strokeWidth={1.8} />
            </Button>
            <nav aria-label="路径导航"
              className="flex min-w-0 flex-1 flex-wrap items-center gap-x-0.5 gap-y-1 rounded-md border border-border-soft bg-secondary/40 px-2 py-1">
              {crumbs(canonical).map((c, i, arr) => (
                <span key={c.path} className="flex min-w-0 items-center">
                  {i > 0 && <span className="px-0.5 font-mono text-[11px] text-ghost" aria-hidden>\</span>}
                  <button onClick={() => void load(c.path)} title={c.path}
                    className={cn('cursor-pointer rounded px-1 py-0.5 font-mono text-[12px] transition-colors hover:bg-accent hover:text-foreground',
                      i === arr.length - 1 ? 'font-medium text-foreground' : 'text-muted-foreground')}>
                    {c.label}
                  </button>
                </span>
              ))}
            </nav>
            <Input value={input} onChange={(ev) => setInput(ev.target.value)}
              onKeyDown={(ev) => { if (ev.key === 'Enter') submit(); }}
              placeholder="输入完整路径，回车跳转" spellCheck={false} aria-label="路径输入框"
              className="h-8 w-[230px] font-mono text-[12px]" />
            <Button size="icon" aria-label="刷新" title="刷新" disabled={loading}
              onClick={() => void load(canonical)}>
              <RefreshCw size={13} className={cn(loading && 'anim-spin')} />
            </Button>
            {freshAt && <span className="text-[11px] text-ghost">更新于 {freshAt}</span>}
          </div>
        )}

        {/* 503 tunnel_not_connected：顶部状态条（含重试），列表区给空态 */}
        {canBrowse && tunnelDown && (
          <div className="mb-3 flex flex-wrap items-center gap-2.5 rounded-md border border-warn/30 bg-warn-soft px-3.5 py-2.5 text-[12.5px]">
            <Unplug size={15} className="shrink-0 text-warn" />
            <span className="min-w-0 flex-1">
              <b>探针隧道未连接</b>——探针离线、版本过旧或未开启隧道拨号（HG_AGENT_TUNNEL_ENABLED）。指令通道不受影响，隧道恢复后即可继续浏览。
            </span>
            <Button size="sm" onClick={() => void load(canonical)}>重试</Button>
          </div>
        )}

        {!canBrowse ? (
          <EmptyState tone="info" icon={<FolderSearch size={20} />} title="实时文件浏览需要分析师及以上角色"
            sub="实时查询属于现场调查能力，只读角色不开放。如需使用，请联系管理员调整账号角色。" />
        ) : loading ? (
          <SkeletonRows rows={8} />
        ) : tunnelDown ? (
          <EmptyState tone="warn" icon={<Unplug size={20} />} title="无法读取目录"
            sub="此处不留缓存数据——所见即终端现场，隧道恢复后重试即可。" />
        ) : loadErr ? (
          <EmptyState tone="warn" icon={<CircleAlert size={20} />} title="实时查询失败" sub={loadErr}
            action={<Button size="sm" onClick={() => void load(canonical)}>重试</Button>} />
        ) : !list || !list.entries.length ? (
          <div className="px-4 py-8 text-center text-[12.5px] text-faint">此目录为空</div>
        ) : (
          <>
            <div className="overflow-x-auto">
              <table className="w-full text-[12.5px]">
                <thead>
                  <tr className="border-b border-border-soft text-left text-[11px] tracking-[.06em] text-faint uppercase">
                    <th className="px-3 py-2 font-semibold">名称</th>
                    <th className="w-[100px] px-3 py-2 text-right font-semibold">大小</th>
                    <th className="w-[170px] px-3 py-2 font-semibold">修改时间</th>
                    <th className="w-[190px] px-3 py-2 font-semibold">属性</th>
                  </tr>
                </thead>
                <tbody>
                  {list.entries.map((en) => (
                    <tr key={en.name} tabIndex={0}
                      onClick={() => enterRow(en)}
                      onKeyDown={(ev) => { if (ev.key === 'Enter') enterRow(en); }}
                      className="cursor-pointer border-b border-border-soft transition-colors last:border-b-0 hover:bg-secondary focus-visible:bg-secondary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-ring">
                      <td className="px-3 py-1.5">
                        {en.is_dir ? (
                          <span className="flex items-center gap-2 font-medium" title={en.name}>
                            <Folder size={14} strokeWidth={1.8} className="shrink-0 text-muted-foreground" />
                            <span className="truncate">{en.name}</span>
                          </span>
                        ) : (
                          <span className="block truncate pl-[22px] text-muted-foreground" title={en.name}>{en.name}</span>
                        )}
                      </td>
                      <td className="px-3 py-1.5 text-right font-mono text-[11.5px] tabular-nums text-muted-foreground">
                        {en.is_dir ? '—' : fmtBytes(en.size)}
                      </td>
                      <td className="px-3 py-1.5 font-mono text-[11.5px] text-faint">
                        {en.mtime_unix ? fmtTime(new Date(en.mtime_unix * 1000).toISOString()) : '-'}
                      </td>
                      <td className="px-3 py-1.5">{attrBadges(en)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            {list.next_cursor && (
              <div className="mt-2.5 flex items-center gap-3 px-3">
                <Button size="sm" variant="ghost" disabled={more || loading}
                  onClick={() => void load(canonical, list.next_cursor)}>
                  {more ? '加载中…' : '下一页'}
                </Button>
                <span className="font-mono text-[11px] text-faint">已载入 {list.entries.length} 项 · 目录优先，按名称排序</span>
              </div>
            )}
          </>
        )}

        {canBrowse && (
          <p className="mt-2.5 px-3.5 text-xs text-faint">
            通过服务端代理向探针发起只读实时查询，不落库不缓存；点击目录进入，点击文件查看详情与文本预览。
          </p>
        )}
      </Card>

      {/* canWrite 与 canBrowse 同一谓词：/live/fs 与指令通道都是 analyst+ */}
      <FileDrawer agentId={agentId} sel={openFile} canWrite={canBrowse} onClose={() => setOpenFile(null)} />
    </>
  );
}

/* ================= 文件抽屉 ================= */

type PrevState =
  | { state: 'loading' }
  | { state: 'text'; text: string; truncated: boolean }
  | { state: 'binary' }
  | { state: 'off' }
  | { state: 'error'; note: string };

/* Authenticode state（winapi/signature.go）→ 中文标签 + 徽标 tone */
const AUTH_STATE: Record<string, [string, string]> = {
  valid: ['已签名 · 有效', 'resolved'],
  unsigned: ['未签名', 'neutral'],
  distrusted: ['签名不受信', 'critical'],
  bad_digest: ['签名内容不符', 'critical'],
  expired: ['证书已过期', 'medium'],
  untrusted: ['证书链不受信', 'medium'],
};

function attrBadges(en: LiveFsEntry): ReactNode {
  const out: ReactNode[] = [];
  if (en.hidden) out.push(<Badge key="h" tone="neutral">隐藏</Badge>);
  if (en.system) out.push(<Badge key="s" tone="neutral">系统</Badge>);
  if (en.readonly) out.push(<Badge key="r" tone="neutral">只读</Badge>);
  return out.length ? out : <span className="text-faint">—</span>;
}

function FileDrawer({ agentId, sel, canWrite, onClose }: {
  agentId: string; sel: { entry: LiveFsEntry; dir: string } | null; canWrite: boolean; onClose: () => void;
}) {
  const toast = useToast();
  const confirm = useConfirm();
  const fullPath = sel ? joinPath(sel.dir, sel.entry.name) : '';
  const [preview, setPreview] = useState<PrevState>({ state: 'loading' });
  const [previewTick, setPreviewTick] = useState(0);
  const [hash, setHash] = useState<LiveHash | null>(null);
  const [hashBusy, setHashBusy] = useState(false);
  const [hashErr, setHashErr] = useState('');
  const [busy, setBusy] = useState<'' | 'allow' | 'quar'>('');

  /* 文本预览：fs/read 字节流直通，Content-Type 以 text/ 开头才渲染 */
  useEffect(() => {
    if (!sel) return;
    let alive = true;
    setPreview({ state: 'loading' });
    (async () => {
      try {
        const fx = await devFixture();
        const r = fx ? await fx.read(fullPath) : await live.read(agentId, fullPath, PREVIEW_LIMIT);
        if (!alive) return;
        if (r.contentType.startsWith('text/')) {
          setPreview({ state: 'text', text: await r.blob.text(), truncated: r.truncated || r.size > PREVIEW_LIMIT });
        } else {
          setPreview({ state: 'binary' });
        }
      } catch (ex) {
        if (!alive) return;
        const note = liveErrNote(ex);
        if (liveErrorKind(ex) === 'off') setPreview({ state: 'off' });
        else {
          setPreview({ state: 'error', note: note || (ex as Error).message });
          if (note) toast(note, 'warn'); // 429/501 等：按契约 Toast，面板同时给内联说明
        }
      }
    })();
    return () => { alive = false; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [sel, previewTick]);

  const runHash = async () => {
    if (!sel) return;
    setHashBusy(true); setHashErr('');
    try {
      const fx = await devFixture();
      setHash(fx ? await fx.hash(fullPath) : await live.hash(agentId, fullPath));
    } catch (ex) {
      const note = liveErrNote(ex);
      setHashErr(note || (ex as Error).message);
      if (note) toast(note, 'warn');
    } finally { setHashBusy(false); }
  };

  /* 抽屉重开时清理上一次的哈希/预览（不同文件不共用结果） */
  useEffect(() => {
    if (!sel) { setHash(null); setHashErr(''); setPreview({ state: 'loading' }); setPreviewTick((t) => t + 1); }
  }, [sel]);

  const doAllow = async () => {
    if (!hash) return;
    const ok = await confirm({
      title: '将文件哈希加入白名单？',
      message: <>SHA256：<code className="break-all">{hash.sha256}</code><br />
        来源：实时文件浏览（{fullPath}）。加白后该文件在本机与服务端都不再告警，请确认这是可信文件。</>,
      danger: true, okText: '仍要加白',
    });
    if (!ok) return;
    setBusy('allow');
    try {
      await api.post('/api/v1/allowlist', { type: 'hash', value: hash.sha256, note: `live: ${fullPath}` });
      toast('已加入白名单');
    } catch (ex) { toast((ex as Error).message, 'err'); }
    finally { setBusy(''); }
  };

  /* 处置走指令表（LIVE-TUNNEL §2 铁律：查询走隧道，处置走 agent_commands）；
     服务端/终端双层开关未开时由后端拒绝，错误原文经 Toast 透出 */
  const doQuarantine = async () => {
    const ok = await confirm({
      title: '隔离该文件？', danger: true, okText: '隔离',
      message: `将向终端下发隔离指令，把 ${fullPath} 移入终端侧隔离区并阻断执行。\n路径以终端实际文件为准；终端侧还有第二道确认开关。`,
    });
    if (!ok) return;
    setBusy('quar');
    try {
      await api.post(`/api/v1/hosts/${encodeURIComponent(agentId)}/commands`, { type: 'quarantine_file', payload: fullPath });
      toast('指令 隔离文件 已下发，等待终端执行');
    } catch (ex) { toast((ex as Error).message, 'err'); }
    finally { setBusy(''); }
  };

  const copy = async (t: string) => {
    const ok = await copyText(t);
    toast(ok ? '已复制到剪贴板' : '复制失败，请手动选择', ok ? 'ok' : 'warn');
  };

  const auth = hash?.authenticode;
  const [authLabel, authTone] = AUTH_STATE[auth?.state || ''] || [auth?.state || '-', 'neutral'];

  return (
    <Drawer open={sel != null} onClose={onClose} width={680}
      title={sel ? sel.entry.name : ''}
      sub={sel ? <span className="block truncate font-mono text-[11.5px]" title={fullPath}>{fullPath}</span> : undefined}
      foot={sel && (canWrite ? (
        <>
          <Button variant="ghost" disabled={!hash || busy !== ''} title={hash ? undefined : '先计算哈希，再按结果加白'}
            onClick={() => void doAllow()}>
            <ShieldCheck size={13} /> 加入白名单
          </Button>
          <Button variant="danger" disabled={busy !== ''} onClick={() => void doQuarantine()}>
            <ShieldBan size={13} /> 隔离文件
          </Button>
          <div className="flex-1" />
          <span className="text-[11px] text-ghost">加白与隔离均记入审计；隔离需服务端与终端双层开关开启</span>
        </>
      ) : (
        <>
          <span className="text-[11px] text-ghost">只读角色无权执行加白与隔离操作</span>
          <div className="flex-1" />
          <Button variant="ghost" onClick={onClose}>关闭</Button>
        </>
      ))}
    >
      {sel && (
        <div className="space-y-5">
          <Section title="元数据">
            <dl className="grid grid-cols-[110px_1fr] gap-x-3 gap-y-2 text-[12.5px]">
              <dt className="text-faint">大小</dt>
              <dd className="m-0 font-mono tabular-nums">{fmtBytes(sel.entry.size)}（{sel.entry.size} 字节）</dd>
              <dt className="text-faint">修改时间</dt>
              <dd className="m-0 font-mono">{sel.entry.mtime_unix ? fmtTime(new Date(sel.entry.mtime_unix * 1000).toISOString()) : '-'}</dd>
              <dt className="text-faint">属性</dt>
              <dd className="m-0 flex flex-wrap gap-1">{attrBadges(sel.entry)}</dd>
            </dl>
          </Section>

          <Section title="文本预览" extra={<span className="font-mono text-[10.5px] text-ghost">≤ 64 KB</span>}>
            {preview.state === 'loading' && (
              <div className="space-y-2">{[88, 72, 94, 60].map((w, i) => <Skeleton key={i} style={{ width: `${w}%`, height: 12 }} />)}</div>
            )}
            {preview.state === 'text' && (
              <>
                <pre className="m-0 max-h-[300px] overflow-auto rounded-md border border-border-soft bg-[var(--code-bg)] p-3 font-mono text-[11.5px] leading-[1.7] whitespace-pre-wrap break-all text-[var(--code-fg)]">
                  {preview.text || '（空文件）'}
                </pre>
                {preview.truncated && (
                  <p className="mt-1.5 text-[11px] text-faint">内容已截断，仅预览前 64 KB；完整内容请以现场取证为准。</p>
                )}
              </>
            )}
            {preview.state === 'binary' && (
              <EmptyState tone="info" icon={<FileQuestion size={20} />} title="不支持预览（非文本文件）"
                sub="内容预览只对文本文件开放。如需研判，可先计算哈希再联动情报与白名单。" />
            )}
            {preview.state === 'off' && (
              <EmptyState tone="info" icon={<EyeOff size={20} />} title="文件内容预览未启用"
                sub="该端点信息暴露面最大，服务端默认关闭（HG_SERVER_LIVEQUERY_FILEREAD）。需要时由管理员现场开启；目录浏览与哈希计算不受影响。" />
            )}
            {preview.state === 'error' && (
              <EmptyState tone="warn" icon={<CircleAlert size={20} />} title="预览读取失败" sub={preview.note}
                action={<Button size="sm" onClick={() => setPreviewTick((t) => t + 1)}>重试</Button>} />
            )}
          </Section>

          <Section title="文件哈希" extra={
            <Button size="sm" variant="ghost" onClick={() => void runHash()} disabled={hashBusy}>
              <Fingerprint size={13} /> {hashBusy ? '计算中…' : hash ? '重新计算' : '计算哈希'}
            </Button>
          }>
            {hashBusy && <Skeleton style={{ width: '72%', height: 12 }} />}
            {!hashBusy && hashErr && <div className="text-[12.5px] text-destructive">{hashErr}</div>}
            {!hashBusy && !hashErr && !hash && (
              <p className="text-xs leading-[1.8] text-faint">由探针现场流式计算 SHA256 并做 Authenticode 校验；结果可直接用于加白与情报联动。</p>
            )}
            {!hashBusy && hash && (
              <div className="rounded-md border border-border-soft bg-secondary/40 p-3 text-[12px]">
                <div className="flex items-start gap-2">
                  <span className="w-[72px] shrink-0 pt-0.5 text-faint">SHA256</span>
                  <code className="min-w-0 flex-1 break-all font-mono text-[11.5px]">{hash.sha256}</code>
                  <Button size="sm" variant="ghost" aria-label="复制哈希" title="复制" onClick={() => void copy(hash.sha256)}>
                    <Copy size={13} />
                  </Button>
                </div>
                <dl className="mt-2 grid grid-cols-[72px_1fr] gap-x-2 gap-y-1.5">
                  <dt className="text-faint">签名</dt>
                  <dd className="m-0 flex flex-wrap items-center gap-1.5">
                    <Badge tone={authTone}>{authLabel}</Badge>
                    {auth?.subject && <span className="text-muted-foreground">{auth.subject}</span>}
                    {auth?.issuer && <span className="text-faint">颁发：{auth.issuer}</span>}
                  </dd>
                  <dt className="text-faint">大小</dt>
                  <dd className="m-0 font-mono tabular-nums">{fmtBytes(hash.size)}（{hash.size} 字节）</dd>
                </dl>
              </div>
            )}
          </Section>
        </div>
      )}
    </Drawer>
  );
}

function Section({ title, extra, children }: { title: string; extra?: ReactNode; children: ReactNode }) {
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
