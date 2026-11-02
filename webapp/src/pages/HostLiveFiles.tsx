import { useCallback, useEffect, useRef, useState, type ReactNode } from 'react';
import {
  ChevronUp, CircleAlert, Copy, EyeOff, FileQuestion, Fingerprint, Folder, FolderSearch,
  Globe, Hand, RefreshCw, ScanSearch, Search, ShieldBan, ShieldCheck, TriangleAlert, Unplug,
} from 'lucide-react';
import { api, live, ApiError, liveErrorKind } from '../lib/api';
import type {
  LiveAds, LiveAnalyze, LiveFsEntry, LiveFsList, LiveHandleOwners, LiveHash, LiveSearchEntry,
  LiveSearchResult, LiveStrings, User,
} from '../lib/types';
import { fmtBytes, fmtTime } from '../lib/format';
import { Badge, Button, Card, EmptyState, Input, Skeleton, SkeletonRows } from '../components/ui/basics';
import { Drawer, useConfirm, useToast } from '../components/ui/overlays';
import { cn } from '../lib/utils';
import type { LiveFixtureApi } from '../lib/liveFixture';

/* 主机详情「实时文件」Tab（docs/LIVE-TUNNEL.md §5.3 v1 + §11.4 v2，W1-F/F2）。
   通过服务端代理只读浏览探针终端文件系统：目录列表游标分页、文本预览、
   现场哈希；v2 增量：目录限深搜索（fs/search，quick 速览徽标）、三哈希
   与一键复制、按需深度分析（PE 节区熵/导入分类/版本资源/字符串线索）、
   MotW 下载来源（ADS）。处置（加白/隔离）走既有 REST/指令通道，隧道本身
   只读。错误契约：503 tunnel_not_connected → 状态条；429/403/501 → Toast。 */

const INITIAL_PATH = 'C:\\';
const PREVIEW_LIMIT = 64 * 1024;
const SEARCH_DEPTH = 2; // fs/search 默认深度（契约 ≤4）
const SEARCH_LIMIT = 100; // 结果条数（契约 ≤200）

/* ---- 落地风险面（docs/LIVE-TUNNEL.md §16.3，F9）----
   纯前端组合：对临时/下载/公共/启动目录并行跑 fs/search，合并去重后按
   修改时间排序。fs/search 一次只接受单一 pattern，所以每个目录 × 每个
   扩展名各发一次请求（5 目录 × 8 类 = 40 次），并发压到 3——探针侧每条
   查询自带 30s 预算，串行会拖到几分钟，全并发又会把隧道打满。 */
const LANDING_PATTERNS = ['*.exe', '*.dll', '*.ps1', '*.bat', '*.cmd', '*.vbs', '*.js', '*.msi'];
const LANDING_DEPTH = 2;
const LANDING_LIMIT = 100;
const LANDING_CONCURRENCY = 3;

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

function baseName(p: string): string {
  const i = p.lastIndexOf('\\');
  return i >= 0 ? p.slice(i + 1) : p;
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

/* fs/search 的 dir 是**相对搜索根**的目录（根层为 "."，见探针 search.go
   buildHit）。老版本/假数据可能直接给绝对目录，这里两种都认——把相对
   路径当绝对路径拼会得到 "sub\a.exe" 这种打不开的伪路径。 */
function searchFullPath(root: string, en: LiveSearchEntry): string {
  const d = (en.dir || '').trim();
  if (/^[A-Za-z]:[\\/]/.test(d)) return joinPath(d, en.name);
  if (!d || d === '.') return joinPath(root, en.name);
  return joinPath(joinPath(root, d), en.name);
}

/* ---- 落地风险面：目录解析 ----
   探针 fs/search 只接受绝对路径（validateFSPath 不做环境变量展开），因此
   契约里的 %TEMP% / %USERPROFILE% / %APPDATA% 必须由前端解析成真实目录：
   1. 用主机注册的运行账户去 C:\Users 列表里对 profile 目录；
   2. 对不上（服务化探针通常报 NT AUTHORITY\SYSTEM）就取 mtime 最新的
      profile——单机场景一般就是最近在用的交互账户；
   3. C:\Users 都读不到时 Temp 退到 C:\Windows\Temp，两个用户级目录记入
      skipped 并在结果底部如实说明（不做静默丢弃）。
   多用户机器只覆盖一个 profile 是本轮已知取舍：逐个用户扫描会让请求数
   随账户数线性膨胀，超出本轮 UX 预算。 */
interface LandingDir { label: string; path: string }

async function resolveLandingDirs(agentId: string): Promise<{ dirs: LandingDir[]; skipped: string[] }> {
  let profile = '';
  try {
    const host = await api.get<{ agent: { username?: string } }>(
      `/api/v1/hosts/${encodeURIComponent(agentId)}`,
    ).then((d) => d.agent).catch(() => null);
    const user = (host?.username || '').split('\\').pop()?.trim().toLowerCase() || '';
    const fx = await devFixture();
    const users = fx ? await fx.fs('C:\\Users') : await live.fs(agentId, 'C:\\Users');
    const profiles = (users.entries || []).filter((en) => en.is_dir && !en.reparse
      && !/^(public|default|default user|all users)$/i.test(en.name));
    const exact = user ? profiles.find((p) => p.name.toLowerCase() === user) : undefined;
    const latest = [...profiles].sort((a, b) => (b.mtime_unix || 0) - (a.mtime_unix || 0))[0];
    profile = (exact || latest)?.name || '';
  } catch { /* 解析失败走降级目录，不影响扫描本身 */ }

  const skipped: string[] = [];
  const dirs: LandingDir[] = [];
  if (profile) {
    const base = `C:\\Users\\${profile}`;
    dirs.push({ label: '%TEMP%', path: `${base}\\AppData\\Local\\Temp` });
    dirs.push({ label: '%USERPROFILE%\\Downloads', path: `${base}\\Downloads` });
  } else {
    dirs.push({ label: 'C:\\Windows\\Temp（%TEMP% 无法解析）', path: 'C:\\Windows\\Temp' });
    skipped.push('%USERPROFILE%\\Downloads', '%APPDATA%\\...\\Startup');
  }
  dirs.push({ label: 'C:\\Users\\Public', path: 'C:\\Users\\Public' });
  if (profile) {
    dirs.push({
      label: '%APPDATA%\\...\\Startup',
      path: `C:\\Users\\${profile}\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup`,
    });
  }
  dirs.push({
    label: 'C:\\ProgramData\\...\\StartUp',
    path: 'C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp',
  });
  return { dirs, skipped };
}

interface LandingHit {
  key: string; // 小写全路径，去重键
  path: string; // 完整文件路径（抽屉/标题用）
  dir: string; // 完整父目录（复用 openFile 的 {entry, dir}）
  entry: LiveSearchEntry;
}

interface LandingScan {
  running: boolean;
  dirCount: number;
  done: number;
  total: number;
  hits: LandingHit[];
  failures: { label: string; reason: string }[];
  skipped: string[];
  /** 因探针 30s 预算被截断的查询次数（不是条目数） */
  truncated: number;
  startedAt: number;
  elapsedMs?: number;
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

/* v2 端点（analyze/ads/fs/search）的降级口径：老服务端预算表没有这些路径
   时代理 404、老探针 mux 没挂 handler 时 501——两者对操作员含义相同 */
function featNote(e: unknown): string {
  if (e instanceof ApiError && (e.status === 404 || e.status === 501)) return '该探针或服务端版本不支持此能力';
  return liveErrNote(e) || (e as Error).message;
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

export function LiveFilesTab({ agentId, user, openPath, onOpenPathDone }: {
  agentId: string; user: User;
  /** 跨 Tab 联动：实时进程抽屉「分析此文件」以绝对路径打开本 Tab 的文件抽屉 */
  openPath?: string | null;
  onOpenPathDone?: () => void;
}) {
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

  /* v2：目录搜索状态（与目录浏览互斥呈现） */
  const [pattern, setPattern] = useState('');
  const [patternUsed, setPatternUsed] = useState('');
  const [searchRes, setSearchRes] = useState<LiveSearchResult | null>(null);
  const [searching, setSearching] = useState(false);
  const [searchErr, setSearchErr] = useState('');

  /* §16.3 落地风险面扫描状态（与目录浏览/搜索结果三态互斥） */
  const [scan, setScan] = useState<LandingScan | null>(null);
  /* 请求序号：换主机 / 重新扫描 / 离开页面都会作废在途任务，防止旧结果落地 */
  const scanSeq = useRef(0);

  const canonical = list?.path || path;
  const atRoot = /^[A-Za-z]:\\?$/.test(canonical);

  const load = useCallback(async (dir: string, cursor?: string) => {
    // 任何目录导航都退出落地扫描视图：扫描结果属于发起时的上下文，
    // 留在屏幕上会和新的目录内容混在一起
    scanSeq.current++;
    setScan(null);
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
    clearSearchState();
    scanSeq.current++; // 换主机：作废上一台主机在途的落地扫描
    setScan(null);
    if (canBrowse) void load(INITIAL_PATH);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [agentId]);

  /* 卸载时作废在途扫描（并发 worker 会在下一个 await 后自行退出） */
  useEffect(() => () => { scanSeq.current++; }, []);

  const clearSearchState = () => {
    setSearchRes(null); setPattern(''); setPatternUsed(''); setSearchErr('');
  };

  const clearScan = () => {
    scanSeq.current++;
    setScan(null);
  };

  /* 跨 Tab 联动：拿到目标路径后先 fs/stat 取元数据（条目字段才完整），
     再以 {entry, dir} 形态复用文件抽屉；失败 Toast 透出原因 */
  useEffect(() => {
    if (!openPath) return;
    let alive = true;
    (async () => {
      try {
        const fx = await devFixture();
        const st = fx ? await fx.stat(openPath) : await live.stat(agentId, openPath);
        if (!alive) return;
        const full = st.path || openPath;
        setOpenFile({
          entry: {
            name: baseName(full), size: st.size, is_dir: st.is_dir, hidden: st.hidden,
            system: st.system, readonly: st.readonly, reparse: st.reparse, mtime_unix: st.mtime_unix,
          },
          dir: parentPath(full),
        });
      } catch (ex) {
        if (alive) toast(liveErrNote(ex) || (ex as Error).message, 'warn');
      } finally {
        if (alive) onOpenPathDone?.();
      }
    })();
    return () => { alive = false; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [openPath, agentId]);

  /* 路径框跳转：容错正斜杠与结尾反斜杠；缺盘符直接提醒（探针侧会 400） */
  const submit = () => {
    let p = input.trim().replace(/\//g, '\\');
    if (!/^[A-Za-z]:/.test(p)) { toast('请输入以盘符开头的完整路径，例 C:\\Windows', 'warn'); return; }
    if (p.length > 3) p = p.replace(/\\+$/, '');
    clearSearchState();
    void load(p);
  };

  /* 目录限深搜索：根 = 当前浏览目录（冻结进结果，浏览导航后结果仍在） */
  const runSearch = async (root?: string) => {
    const p = pattern.trim();
    if (!p) return;
    const at = root || canonical;
    clearScan(); // 搜索与落地扫描互斥，避免两套结果叠在同一区域
    setSearching(true); setSearchErr('');
    try {
      const fx = await devFixture();
      const r = fx ? await fx.search(at, p, SEARCH_DEPTH, SEARCH_LIMIT)
        : await live.search(agentId, at, p, SEARCH_DEPTH, SEARCH_LIMIT);
      setSearchRes(r); setPatternUsed(p);
    } catch (ex) {
      setSearchRes(null);
      setSearchErr(featNote(ex));
    } finally { setSearching(false); }
  };

  /* §16.3 落地风险面：先解析目录，再把 (目录 × 扩展名) 摊平成请求队列，
     3 个 worker 共享游标。单条失败只记该目录一次（底部按"目录"汇总），
     不让同一目录的 8 个 pattern 各刷一条失败。 */
  const runLandingScan = async () => {
    const seq = ++scanSeq.current;
    clearSearchState();
    setScan({
      running: true, dirCount: 0, done: 0, total: 0, hits: [], failures: [], skipped: [],
      truncated: 0, startedAt: Date.now(),
    });

    const { dirs, skipped } = await resolveLandingDirs(agentId);
    if (seq !== scanSeq.current) return;
    const tasks = dirs.flatMap((d) => LANDING_PATTERNS.map((p) => ({ dir: d, pattern: p })));
    const total = tasks.length;
    setScan((s) => (s ? { ...s, dirCount: dirs.length, total, skipped } : s));

    const hits = new Map<string, LandingHit>();
    const failures = new Map<string, string>();
    let truncated = 0;
    let done = 0;
    let cursor = 0;

    const commit = (running: boolean) => {
      if (seq !== scanSeq.current) return;
      setScan((s) => (s ? {
        ...s,
        running,
        done,
        total,
        truncated,
        hits: [...hits.values()].sort((a, b) => (b.entry.mtime_unix || 0) - (a.entry.mtime_unix || 0)),
        failures: [...failures.entries()].map(([label, reason]) => ({ label, reason })),
        elapsedMs: running ? s.elapsedMs : Date.now() - s.startedAt,
      } : s));
    };

    const worker = async () => {
      while (seq === scanSeq.current) {
        const idx = cursor++;
        if (idx >= tasks.length) return;
        const t = tasks[idx];
        try {
          const fx = await devFixture();
          const r = fx ? await fx.search(t.dir.path, t.pattern, LANDING_DEPTH, LANDING_LIMIT)
            : await live.search(agentId, t.dir.path, t.pattern, LANDING_DEPTH, LANDING_LIMIT);
          if (seq !== scanSeq.current) return;
          if (r.truncated) truncated++;
          for (const en of r.entries || []) {
            if (en.is_dir) continue;
            const full = searchFullPath(r.path || t.dir.path, en);
            const key = full.toLowerCase();
            if (!hits.has(key)) hits.set(key, { key, path: full, dir: parentPath(full), entry: en });
          }
        } catch (e) {
          if (seq !== scanSeq.current) return;
          if (!failures.has(t.dir.label)) failures.set(t.dir.label, featNote(e));
        } finally {
          if (seq === scanSeq.current) { done++; commit(true); }
        }
      }
    };

    await Promise.all(Array.from({ length: Math.min(LANDING_CONCURRENCY, tasks.length) }, () => worker()));
    commit(false);
  };

  const enterRow = (en: LiveFsEntry & { dir?: string }) => {
    if (searchRes) {
      // 搜索结果：dir 是相对搜索根（根层 "."），先换成完整路径再打开
      const full = searchFullPath(searchRes.path, en);
      if (en.is_dir) { clearSearchState(); void load(full); return; }
      setOpenFile({ entry: en, dir: parentPath(full) });
      return;
    }
    if (en.is_dir) { clearSearchState(); void load(joinPath(canonical, en.name)); }
    else setOpenFile({ entry: en, dir: canonical }); // 冻结点击时的目录，防浏览中途漂移
  };

  /* 刷新语义随模式切换：落地扫描 → 重跑扫描；搜索结果 → 重跑同参搜索；
     目录浏览 → 重列目录 */
  const refresh = () => {
    if (scan?.running) return; // 扫描进行中不重启，避免白白作废在途的 40 次查询
    if (scan) void runLandingScan();
    else if (searchRes) void runSearch(searchRes.path);
    else void load(canonical);
  };

  return (
    <>
      <Card className="p-4">
        {/* 工具行：上级 / 面包屑 / 路径输入 / 刷新 / 新鲜度 */}
        {canBrowse && (
          <div className="mb-2 flex flex-wrap items-center gap-2">
            <Button size="icon" aria-label="上一级目录" title="上一级" disabled={atRoot || loading}
              onClick={() => { clearSearchState(); void load(parentPath(canonical)); }}>
              <ChevronUp size={15} strokeWidth={1.8} />
            </Button>
            <nav aria-label="路径导航"
              className="flex min-w-0 flex-1 flex-wrap items-center gap-x-0.5 gap-y-1 rounded-md border border-border-soft bg-secondary/40 px-2 py-1">
              {crumbs(canonical).map((c, i, arr) => (
                <span key={c.path} className="flex min-w-0 items-center">
                  {i > 0 && <span className="px-0.5 font-mono text-[11px] text-ghost" aria-hidden>\</span>}
                  <button onClick={() => { clearSearchState(); void load(c.path); }} title={c.path}
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
            <Button size="icon" aria-label="刷新" title="刷新" disabled={loading || searching || !!scan?.running}
              onClick={() => void refresh()}>
              <RefreshCw size={13} className={cn((loading || searching) && 'anim-spin')} />
            </Button>
            {freshAt && <span className="text-[11px] text-ghost">更新于 {freshAt}</span>}
          </div>
        )}

        {/* v2 搜索行：文件名通配 → fs/search；清空恢复目录浏览 */}
        {canBrowse && (
          <div className="mb-3 flex flex-wrap items-center gap-2">
            <div className="relative min-w-[240px] flex-1">
              <Search size={13} className="pointer-events-none absolute top-1/2 left-2.5 -translate-y-1/2 text-ghost" />
              <Input value={pattern} onChange={(ev) => setPattern(ev.target.value)}
                onKeyDown={(ev) => { if (ev.key === 'Enter') { ev.preventDefault(); void runSearch(); } }}
                placeholder={`在 ${canonical} 下搜索文件名（支持 * ? 通配），回车执行`} spellCheck={false}
                aria-label="文件名搜索框" className="h-8 w-full pl-7 font-mono text-[12px]" />
            </div>
            <Button size="sm" disabled={!pattern.trim() || searching} onClick={() => void runSearch()}>
              {searching ? '搜索中…' : '搜索'}
            </Button>
            <Button size="sm" variant="ghost" disabled={searching || !!scan?.running}
              onClick={() => void runLandingScan()}
              title="并行扫描临时/下载/公共/启动目录中的可执行与脚本文件（约 40 次查询，可能超过 25 秒）">
              <ScanSearch size={13} />
              {scan?.running
                ? (scan.total ? `已完成 ${scan.done}/${scan.total} 次请求` : '解析扫描目录…')
                : '扫描落地风险面'}
            </Button>
            {searchRes && (
              <Button size="sm" variant="ghost" onClick={clearSearchState}>返回目录浏览</Button>
            )}
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
        ) : scan ? (
          /* ===== 落地风险面模式（§16.3） ===== */
          <>
            <div className="mb-2.5 flex flex-wrap items-center gap-2 rounded-md border border-border-soft bg-secondary/40 px-3 py-2 text-[12.5px]">
              <ScanSearch size={13} className="shrink-0 text-ghost" />
              <span>
                {scan.running ? '正在扫描落地风险面' : '落地风险面扫描完成'}
                {scan.dirCount > 0 && (
                  <span className="text-faint">（{scan.dirCount} 个目录 × {LANDING_PATTERNS.length} 类扩展名）</span>
                )}
              </span>
              <span className="font-mono text-[11px] text-ghost">{scan.hits.length} 个文件</span>
              {scan.running && (
                <span className="font-mono text-[11px] text-ghost">
                  {scan.total ? `已完成 ${scan.done}/${scan.total} 次请求` : '正在解析扫描目录…'}
                </span>
              )}
              {!scan.running && scan.elapsedMs != null && (
                <span className="font-mono text-[11px] text-ghost">耗时 {(scan.elapsedMs / 1000).toFixed(1)}s</span>
              )}
              {scan.truncated > 0 && (
                <Badge tone="medium" title="探针侧 30 秒预算用尽，返回已收集的部分">
                  {scan.truncated} 次查询被截断
                </Badge>
              )}
              <div className="flex-1" />
              <Button size="sm" variant="ghost" onClick={clearScan}>返回目录浏览</Button>
              <Button size="sm" variant="ghost" disabled={scan.running} onClick={() => void runLandingScan()}>
                <RefreshCw size={13} /> 重新扫描
              </Button>
            </div>

            {scan.running && !scan.hits.length ? (
              <SkeletonRows rows={6} />
            ) : !scan.hits.length ? (
              <EmptyState tone="info" icon={<ScanSearch size={20} />} title="没有在落地目录发现可执行/脚本文件"
                sub={`已扫描临时、下载、公共与启动目录（深度 ≤${LANDING_DEPTH}）。此处只覆盖这些落地区域，不代表主机上没有其它可执行文件。`} />
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-[12.5px]">
                  <thead>
                    <tr className="border-b border-border-soft text-left text-[11px] tracking-[.06em] text-faint uppercase">
                      <th className="px-3 py-2 font-semibold">路径</th>
                      <th className="w-[100px] px-3 py-2 text-right font-semibold">大小</th>
                      <th className="w-[170px] px-3 py-2 font-semibold">修改时间</th>
                      <th className="w-[200px] px-3 py-2 font-semibold">属性</th>
                    </tr>
                  </thead>
                  <tbody>
                    {scan.hits.map((h) => (
                      <tr key={h.key} tabIndex={0} title={h.path}
                        onClick={() => setOpenFile({ entry: h.entry, dir: h.dir })}
                        onKeyDown={(ev) => { if (ev.key === 'Enter') setOpenFile({ entry: h.entry, dir: h.dir }); }}
                        className="cursor-pointer border-b border-border-soft transition-colors last:border-b-0 hover:bg-secondary focus-visible:bg-secondary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-ring">
                        <td className="px-3 py-1.5">
                          <span className="block max-w-[560px] truncate font-mono text-[11.5px] text-muted-foreground" title={h.path}>
                            {h.path}
                          </span>
                        </td>
                        <td className="px-3 py-1.5 text-right font-mono text-[11.5px] tabular-nums text-muted-foreground">
                          {fmtBytes(h.entry.size)}
                        </td>
                        <td className="px-3 py-1.5 font-mono text-[11.5px] text-faint">
                          {h.entry.mtime_unix ? fmtTime(new Date(h.entry.mtime_unix * 1000).toISOString()) : '-'}
                        </td>
                        <td className="px-3 py-1.5">{attrBadges(h.entry)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}

            {(scan.failures.length > 0 || scan.skipped.length > 0) && (
              <div className="mt-2.5 flex items-start gap-2 rounded-md border border-border-soft bg-secondary/40 px-3 py-2 text-[11.5px] leading-relaxed text-faint">
                <CircleAlert size={13} className="mt-0.5 shrink-0" />
                <span className="min-w-0">
                  {scan.failures.length > 0 && (
                    <>
                      {scan.failures.length} 个目录扫描失败（权限/超时）：
                      {scan.failures.map((f) => `${f.label}（${f.reason}）`).join('；')}
                    </>
                  )}
                  {scan.failures.length > 0 && scan.skipped.length > 0 && '；'}
                  {scan.skipped.length > 0 && (
                    <>{scan.skipped.length} 个用户级目录因无法解析用户配置而跳过：{scan.skipped.join('、')}</>
                  )}
                </span>
              </div>
            )}

            <p className="mt-2.5 px-3.5 text-xs text-faint">
              按修改时间倒序；同一文件被多个扩展名或目录命中只保留一条。每条查询最多返回 {LANDING_LIMIT} 个命中，目录内文件很多时结果可能不完整。扫描由探针现场限深遍历（不落库），点击行打开文件抽屉查看哈希与深度分析。
            </p>
          </>
        ) : searchRes || searchErr || searching ? (
          /* ===== 搜索结果模式 ===== */
          searchErr ? (
            <EmptyState tone="warn" icon={<CircleAlert size={20} />} title="搜索失败" sub={searchErr}
              action={<Button size="sm" onClick={() => void runSearch(searchRes ? searchRes.path : canonical)}>重试</Button>} />
          ) : searching ? (
            <SkeletonRows rows={6} />
          ) : searchRes && (
            <>
              <div className="mb-2.5 flex flex-wrap items-center gap-2 rounded-md border border-border-soft bg-secondary/40 px-3 py-2 text-[12.5px]">
                <Search size={13} className="shrink-0 text-ghost" />
                <span>“<b className="font-mono">{patternUsed}</b>” 于 <code className="font-mono text-[11.5px]">{searchRes.path}</code>（深度 ≤{SEARCH_DEPTH}）</span>
                <span className="font-mono text-[11px] text-ghost">{searchRes.entries.length} 项</span>
                {searchRes.truncated && (
                  <Badge tone="medium" title="探针侧预算用尽，返回已收集的部分">结果因超时截断</Badge>
                )}
              </div>
              {!searchRes.entries.length ? (
                <EmptyState tone="info" icon={<Search size={20} />} title="没有命中"
                  sub={`在 ${searchRes.path} 以下 ${SEARCH_DEPTH} 层内没有匹配 “${patternUsed}” 的文件名。可放大通配范围（如 *.dll）或先进入更深的目录再搜。`} />
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full text-[12.5px]">
                    <thead>
                      <tr className="border-b border-border-soft text-left text-[11px] tracking-[.06em] text-faint uppercase">
                        <th className="px-3 py-2 font-semibold">名称</th>
                        <th className="w-[100px] px-3 py-2 text-right font-semibold">大小</th>
                        <th className="w-[170px] px-3 py-2 font-semibold">修改时间</th>
                        <th className="w-[220px] px-3 py-2 font-semibold">属性</th>
                      </tr>
                    </thead>
                    <tbody>
                      {searchRes.entries.map((en, i) => {
                        const full = searchFullPath(searchRes.path, en);
                        return (
                          <tr key={`${en.dir || ''}-${en.name}-${i}`} tabIndex={0}
                            title={full}
                            onClick={() => enterRow(en)}
                            onKeyDown={(ev) => { if (ev.key === 'Enter') enterRow(en); }}
                            className="cursor-pointer border-b border-border-soft transition-colors last:border-b-0 hover:bg-secondary focus-visible:bg-secondary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-ring">
                            <td className="px-3 py-1.5">
                              {en.is_dir ? (
                                <span className="flex items-center gap-2 font-medium" title={full}>
                                  <Folder size={14} strokeWidth={1.8} className="shrink-0 text-muted-foreground" />
                                  <span className="truncate">{en.name}</span>
                                </span>
                              ) : (
                                <span className="block truncate pl-[22px] text-muted-foreground" title={full}>{en.name}</span>
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
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              )}
              <p className="mt-2.5 px-3.5 text-xs text-faint">
                搜索由探针现场限深遍历（不落库）；quick 徽标来自文件头与流枚举速览，结论以文件抽屉的深度分析为准。
              </p>
            </>
          )
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
            通过服务端代理向探针发起只读实时查询，不落库不缓存；点击目录进入，点击文件查看详情、哈希与深度分析。
          </p>
        )}
      </Card>

      {/* canWrite 与 canBrowse 同一谓词：/live/fs 与指令通道都是 analyst+ */}
      <FileDrawer agentId={agentId} sel={openFile} canWrite={canBrowse} onClose={() => setOpenFile(null)} />
    </>
  );
}

/* ================= 文件抽屉（v2：三哈希 + 深度分析 + MotW） ================= */

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

/* MotW ZoneId → 展示（zone_name 服务端/探针已给，这里只定徽标语义） */
function zoneBadge(z: NonNullable<LiveAds['zone']>): ReactNode {
  if (z.zone_id === 3) return <Badge tone="medium"><Globe size={11} /> Internet</Badge>;
  if (z.zone_id === 4) return <Badge tone="critical">{z.zone_name || '受限'}</Badge>;
  return <Badge tone="neutral">{z.zone_name || `区域 ${z.zone_id}`}</Badge>;
}

/* 属性徽标：常规条目用条目自身标志位；搜索结果追加 quick 速览（PE/ADS）。
   常规列表不做逐文件 ADS 探测——200 次/页成本不可接受（v2 决策）。 */
function attrBadges(en: LiveFsEntry & { quick?: LiveSearchEntry['quick'] }): ReactNode {
  const hidden = en.hidden || !!en.quick?.hidden;
  const system = en.system || !!en.quick?.system;
  const out: ReactNode[] = [];
  if (en.quick?.pe) out.push(<Badge key="pe" tone="info" title="PE 可执行文件（MZ 头）">PE</Badge>);
  if (en.quick?.ads) out.push(<Badge key="ads" tone="medium" title="含 NTFS 备用数据流（如 Zone.Identifier）">ADS</Badge>);
  if (hidden) out.push(<Badge key="h" tone="neutral">隐藏</Badge>);
  if (system) out.push(<Badge key="s" tone="neutral">系统</Badge>);
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

  /* v2：深度分析（按需）与 MotW（打开即查，10s 预算的轻量端点） */
  const [ana, setAna] = useState<LiveAnalyze | null>(null);
  const [anaBusy, setAnaBusy] = useState(false);
  const [anaErr, setAnaErr] = useState('');
  const [adsData, setAdsData] = useState<LiveAds | null>(null);
  const [adsErr, setAdsErr] = useState('');

  /* §15.2「谁打开了它」：全系统 File 句柄扫描，按需执行（默认不发请求） */
  const [owners, setOwners] = useState<LiveHandleOwners | null>(null);
  const [ownersBusy, setOwnersBusy] = useState(false);
  const [ownersErr, setOwnersErr] = useState('');
  /* 请求序号：扫描耗时可达数秒，抽屉换文件后旧响应落地必须丢弃 */
  const ownersSeq = useRef(0);

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

  /* MotW：打开抽屉即查（轻量流枚举）；结果静默降级为区块内说明 */
  useEffect(() => {
    if (!sel || sel.entry.is_dir) return;
    let alive = true;
    setAdsData(null); setAdsErr('');
    (async () => {
      try {
        const fx = await devFixture();
        const d = fx ? await fx.ads(fullPath) : await live.ads(agentId, fullPath);
        if (alive) setAdsData(d);
      } catch (ex) {
        if (alive) setAdsErr(featNote(ex));
      }
    })();
    return () => { alive = false; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [sel]);

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

  /* 深度分析按需执行：PE 解析 + 全文件三哈希 + 字符串采样有真实成本（≤64MB） */
  const runAnalyze = async () => {
    if (!sel) return;
    setAnaBusy(true); setAnaErr('');
    try {
      const fx = await devFixture();
      setAna(fx ? await fx.analyze(fullPath) : await live.analyze(agentId, fullPath));
    } catch (ex) {
      setAna(null);
      setAnaErr(featNote(ex));
    } finally { setAnaBusy(false); }
  };

  /* 「谁打开了它」按需执行：探针要扫全系统 File 句柄并逐个解析对象名，
     成本明显高于 stat/hash，不随抽屉打开自动拉取。结果是部分覆盖，
     覆盖度以响应的 scanned/resolved/note 为准，不把"没命中"说成"没人占用"。 */
  const runOwners = async () => {
    if (!sel) return;
    const seq = ++ownersSeq.current;
    setOwnersBusy(true); setOwnersErr(''); setOwners(null);
    try {
      const d = await live.handleowners(agentId, fullPath);
      if (seq === ownersSeq.current) setOwners(d);
    } catch (ex) {
      if (seq === ownersSeq.current) setOwnersErr(featNote(ex));
    } finally {
      if (seq === ownersSeq.current) setOwnersBusy(false);
    }
  };

  /* 抽屉重开/换文件时清理上一次的哈希/预览/分析/占用者（不同文件不共用结果）。
     换文件也要作废在途的占用扫描——不然旧路径的 owners 会挂在新文件抽屉里。 */
  useEffect(() => {
    ownersSeq.current++;
    setOwners(null); setOwnersErr(''); setOwnersBusy(false);
  }, [fullPath]);

  useEffect(() => {
    if (!sel) {
      setHash(null); setHashErr(''); setPreview({ state: 'loading' }); setPreviewTick((t) => t + 1);
      setAna(null); setAnaErr(''); setAdsData(null); setAdsErr('');
    }
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

  /* 哈希区数据源：默认 fs/hash 只有 SHA256；深度分析后补齐三哈希
     （MD5/SHA1 为旧情报源兼容，非替代 SHA256） */
  const hashRows: [string, string][] = ana
    ? [['MD5', ana.md5], ['SHA1', ana.sha1], ['SHA256', ana.sha256]]
    : hash ? [['SHA256', hash.sha256]] : [];
  const copyAll = hashRows.map(([k, v]) => `${k}: ${v}`).join('\n');

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
                sub="内容预览只对文本文件开放。如需研判，可计算哈希或执行深度分析，再联动情报与白名单。" />
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

          <Section title="哈希与签名" extra={
            <span className="flex items-center gap-1.5">
              {hashRows.length >= 2 && (
                <Button size="sm" variant="ghost" onClick={() => void copy(copyAll)} title="复制当前已知的全部哈希">
                  <Copy size={13} /> 复制全部
                </Button>
              )}
              <Button size="sm" variant="ghost" onClick={() => void runHash()} disabled={hashBusy}>
                <Fingerprint size={13} /> {hashBusy ? '计算中…' : hash ? '重新计算' : '计算哈希'}
              </Button>
            </span>
          }>
            {hashBusy && <Skeleton style={{ width: '72%', height: 12 }} />}
            {!hashBusy && hashErr && <div className="text-[12.5px] text-destructive">{hashErr}</div>}
            {!hashBusy && !hashErr && !hashRows.length && (
              <p className="text-xs leading-[1.8] text-faint">由探针现场流式计算 SHA256 并做 Authenticode 校验；执行深度分析后补齐 MD5/SHA1（旧情报源兼容）。</p>
            )}
            {!hashBusy && !!hashRows.length && (
              <div className="rounded-md border border-border-soft bg-secondary/40 p-3 text-[12px]">
                {hashRows.map(([label, v]) => (
                  <div key={label} className="flex items-start gap-2 [&+&]:mt-1.5">
                    <span className="w-[58px] shrink-0 pt-0.5 text-faint">{label}</span>
                    <code className="min-w-0 flex-1 break-all font-mono text-[11.5px]">{v}</code>
                    <Button size="sm" variant="ghost" aria-label={`复制 ${label}`} title={`复制 ${label}`}
                      onClick={() => void copy(v)}>
                      <Copy size={13} />
                    </Button>
                  </div>
                ))}
                {ana?.pe?.imphash && (
                  <div className="mt-1.5 flex items-start gap-2 border-t border-border-soft pt-1.5">
                    <span className="w-[58px] shrink-0 pt-0.5 text-faint" title="VT 口径 imphash">imphash</span>
                    <code className="min-w-0 flex-1 break-all font-mono text-[11.5px]">{ana.pe.imphash}</code>
                    <Button size="sm" variant="ghost" aria-label="复制 imphash" title="复制 imphash"
                      onClick={() => void copy(ana.pe!.imphash!)}>
                      <Copy size={13} />
                    </Button>
                  </div>
                )}
                <dl className="mt-2 grid grid-cols-[72px_1fr] gap-x-2 gap-y-1.5">
                  <dt className="text-faint">签名</dt>
                  <dd className="m-0 flex flex-wrap items-center gap-1.5">
                    <Badge tone={authTone}>{authLabel}</Badge>
                    {auth?.subject && <span className="text-muted-foreground">{auth.subject}</span>}
                    {auth?.issuer && <span className="text-faint">颁发：{auth.issuer}</span>}
                  </dd>
                </dl>
              </div>
            )}
          </Section>

          {/* 占用进程只展示不跳转：HostDetail 目前只向本 Tab 暴露 openPath 回调，
              没有"切到实时进程 Tab 并打开指定 PID 抽屉"的通道（本会话文件所有权
              不含 HostDetail，不能新增回调）。列表给足 PID，操作员可到「实时进程」
              Tab 按 PID 搜索打开对应抽屉；后端契约与跳转能力已就绪，只差宿主回调。 */}
          {!sel.entry.is_dir && (
            <Section title="谁打开了它" extra={
              <Button size="sm" variant="ghost" disabled={ownersBusy} onClick={() => void runOwners()}>
                <Hand size={13} /> {ownersBusy ? '扫描中…' : owners ? '重新扫描' : '谁打开了它'}
              </Button>
            }>
              {ownersBusy && <SkeletonRows rows={2} />}
              {!ownersBusy && ownersErr && <div className="text-[12.5px] text-destructive">{ownersErr}</div>}
              {!ownersBusy && !ownersErr && !owners && (
                <p className="text-xs leading-[1.8] text-faint">
                  枚举全系统 File 类型句柄并解析对象名，找出正持有该文件的进程。扫描有真实成本（探针侧约 5 秒预算），按需执行；结果是部分覆盖。
                </p>
              )}
              {!ownersBusy && owners && (
                <div className="space-y-2">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="font-mono text-[11px] text-ghost">
                      已扫描 {owners.scanned ?? 0} 个文件句柄 · 解析成功 {owners.resolved ?? 0}
                    </span>
                    {owners.truncated && <Badge tone="medium">扫描预算耗尽，列表可能不完整</Badge>}
                  </div>
                  {(owners.owners || []).length ? (
                    <div className="rounded-md border border-border-soft">
                      <table className="w-full text-[12px]">
                        <thead>
                          <tr className="border-b border-border-soft text-left text-[11px] tracking-[.06em] text-faint uppercase">
                            <th className="px-3 py-2 font-semibold">进程名</th>
                            <th className="w-[80px] px-3 py-2 font-semibold">PID</th>
                            <th className="px-3 py-2 font-semibold">镜像路径</th>
                          </tr>
                        </thead>
                        <tbody>
                          {(owners.owners || []).map((o, i) => (
                            <tr key={`${o.pid}-${i}`} className="border-b border-border-soft last:border-b-0">
                              <td className="max-w-[180px] px-3 py-1.5 font-medium">
                                <span className="block truncate" title={o.name}>{o.name || '—'}</span>
                              </td>
                              <td className="px-3 py-1.5 font-mono text-[11.5px] tabular-nums">{o.pid}</td>
                              <td className="px-3 py-1.5">
                                <span className="block truncate font-mono text-[11.5px] text-muted-foreground" title={o.path}>{o.path || '—'}</span>
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  ) : (
                    <div className="rounded-md border border-border-soft bg-secondary/40 px-3 py-2.5 text-[12.5px] text-faint">
                      当前无进程持有该文件句柄
                    </div>
                  )}
                  {owners.note && <p className="text-[11px] leading-[1.7] text-faint">{owners.note}</p>}
                  <p className="text-[11px] leading-[1.7] text-faint">
                    {owners.truncated
                      ? '扫描预算耗尽，列表可能不完整——可稍后重试或到「实时进程」Tab 按 PID 逐一核对。'
                      : (owners.owners || []).length
                        ? '可在「实时进程」Tab 按 PID 搜索并打开进程抽屉查看命令行与模块。'
                        : '未命中也可能来自覆盖度限制：非 File 类型句柄、无权打开的进程都不在结果里。'}
                  </p>
                </div>
              )}
            </Section>
          )}

          <Section title="深度分析" extra={
            <Button size="sm" variant="ghost" onClick={() => void runAnalyze()} disabled={anaBusy || sel.entry.is_dir}>
              <ScanSearch size={13} /> {anaBusy ? '分析中…' : ana ? '重新分析' : '深度分析'}
            </Button>
          }>
            {anaBusy && <SkeletonRows rows={4} />}
            {!anaBusy && anaErr && (
              <div className="text-[12.5px] text-destructive">{anaErr}</div>
            )}
            {!anaBusy && !anaErr && !ana && (
              <p className="text-xs leading-[1.8] text-faint">
                单遍流式计算三哈希，并对 PE 文件解析节区熵、导入表分类、版本资源与字符串线索（文件 ≤64MB）。解析有真实成本，按需执行。
              </p>
            )}
            {!anaBusy && ana && <AnalyzeReport ana={ana} fileName={sel.entry.name} />}
          </Section>

          {!sel.entry.is_dir && (
            <Section title="下载来源（MotW）">
              {adsErr ? (
                <p className="text-[12.5px] text-faint">{adsErr}</p>
              ) : !adsData ? (
                <Skeleton style={{ width: '48%', height: 12 }} />
              ) : adsData.zone ? (
                <div className="rounded-md border border-border-soft bg-secondary/40 p-3 text-[12px]">
                  <dl className="grid grid-cols-[110px_1fr] gap-x-3 gap-y-1.5">
                    <dt className="text-faint">分区</dt>
                    <dd className="m-0 flex flex-wrap items-center gap-1.5">{zoneBadge(adsData.zone)}</dd>
                    {adsData.zone.referrer_url && (
                      <>
                        <dt className="text-faint">来源页面</dt>
                        <dd className="m-0 break-all font-mono text-[11.5px]">{adsData.zone.referrer_url}</dd>
                      </>
                    )}
                    {adsData.zone.host_url && (
                      <>
                        <dt className="text-faint">下载地址</dt>
                        <dd className="m-0 break-all font-mono text-[11.5px]">{adsData.zone.host_url}</dd>
                      </>
                    )}
                    {adsData.zone.download_time && (
                      <>
                        <dt className="text-faint">下载时间</dt>
                        <dd className="m-0 font-mono">{fmtTime(adsData.zone.download_time)}</dd>
                      </>
                    )}
                  </dl>
                  {!!adsData.streams.length && (
                    <p className="mt-2 border-t border-border-soft pt-1.5 font-mono text-[11px] text-ghost">
                      备用数据流：{adsData.streams.map((s) => `${s.name}（${fmtBytes(s.size)}）`).join(' · ')}
                    </p>
                  )}
                </div>
              ) : (
                <p className="text-xs text-faint">无托管标记——文件未携带 Zone.Identifier（非浏览器下载或标记已被清除，不代表文件安全）。</p>
              )}
            </Section>
          )}
        </div>
      )}
    </Drawer>
  );
}

/* ================= 深度分析报告卡 ================= */

type ImpCatKey = keyof NonNullable<NonNullable<LiveAnalyze['pe']>['imports']>['categories'];

/* 第三位 = 是否值得警示 tone（注入/钩子/反调试是强信号；网络/执行/文件只是画像） */
const IMP_CATS: [ImpCatKey, string, boolean][] = [
  ['process_injection', '进程注入', true],
  ['keyboard_hook', '键盘钩子', true],
  ['anti_debug', '反调试', true],
  ['network', '网络', false],
  ['persistence', '持久化', false],
  ['exec', '执行', false],
  ['fs', '文件', false],
];

/* 熵条：上限 8.0，>7.2 走 crit 色阶（加壳/加密节信号） */
function EntropyBar({ v }: { v: number }) {
  const hot = v > 7.2;
  return (
    <span className="flex items-center gap-2">
      <span className="h-1.5 w-20 overflow-hidden rounded-[3px] bg-border-soft">
        <i className={cn('block h-full rounded-[3px]', hot ? 'bg-crit' : 'bg-foreground')}
          style={{ width: `${Math.min(100, (v / 8) * 100)}%` }} />
      </span>
      <span className={cn('font-mono text-[11px] tabular-nums', hot ? 'text-crit' : 'text-muted-foreground')}>{v.toFixed(2)}</span>
    </span>
  );
}

function AnalyzeReport({ ana, fileName }: { ana: LiveAnalyze; fileName: string }) {
  const pe = ana.pe;
  const vr = ana.version_resource;
  const strs = ana.strings;
  return (
    <div className="space-y-3">
      {/* 伪装警示（version_resource.mismatch）——放最上，先看结论 */}
      {vr?.mismatch && (
        <div className="flex items-start gap-2 rounded-md border border-warn/30 bg-warn-soft px-3 py-2 text-[12.5px] text-warn">
          <TriangleAlert size={14} className="mt-px shrink-0" />
          <span>声明原始文件名与实际不符（OriginalFilename：{vr.original_filename || '未知'}，实际：{fileName}）——常见于改名伪装，建议结合签名状态与下载来源进一步研判。</span>
        </div>
      )}
      {!!ana.packer_hints?.length && (
        <div className="flex items-start gap-2 rounded-md border border-warn/30 bg-warn-soft px-3 py-2 text-[12.5px] text-warn">
          <TriangleAlert size={14} className="mt-px shrink-0" />
          <span>疑似加壳 / 高熵节：{ana.packer_hints.join('；')}</span>
        </div>
      )}

      {/* PE 属性 + 节区表 */}
      {pe ? (
        <div className="rounded-md border border-border-soft bg-secondary/40 p-3 text-[12px]">
          <dl className="grid grid-cols-[110px_1fr] gap-x-3 gap-y-1.5">
            <dt className="text-faint">架构 / 子系统</dt>
            <dd className="m-0 font-mono">{pe.machine || '-'} · {pe.subsystem || '-'}{pe.is_dll ? ' · DLL' : ''}</dd>
            <dt className="text-faint">编译时间</dt>
            <dd className="m-0 font-mono">{pe.compile_ts_unix ? fmtTime(new Date(pe.compile_ts_unix * 1000).toISOString()) : '-'}</dd>
            <dt className="text-faint">入口点</dt>
            <dd className="m-0 font-mono">0x{pe.entry_point.toString(16)}</dd>
            <dt className="text-faint">最高节熵</dt>
            <dd className="m-0"><EntropyBar v={pe.max_section_entropy ?? 0} /></dd>
          </dl>
          {!!pe.sections?.length && (
            <table className="mt-2.5 w-full border-t border-border-soft text-[11.5px]">
              <thead>
                <tr className="text-left text-[10.5px] tracking-[.06em] text-faint uppercase">
                  <th className="py-1.5 pr-3 font-semibold">节区</th>
                  <th className="py-1.5 pr-3 text-right font-semibold">大小</th>
                  <th className="py-1.5 font-semibold">熵</th>
                </tr>
              </thead>
              <tbody>
                {pe.sections.map((s, i) => (
                  <tr key={`${s.name}-${i}`} className="border-t border-border-soft/60">
                    <td className="py-1 pr-3 font-mono">{s.name || `#${i}`}</td>
                    <td className="py-1 pr-3 text-right font-mono tabular-nums">{fmtBytes(s.size)}</td>
                    <td className="py-1"><EntropyBar v={s.entropy} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
          {pe.imports && (
            <div className="mt-2.5 border-t border-border-soft pt-2">
              <div className="flex flex-wrap items-center gap-1.5">
                <span className="text-faint">导入 {pe.imports.total} 个 · 分类：</span>
                {IMP_CATS.filter(([k]) => (pe.imports!.categories[k] || 0) > 0).map(([k, label, hot]) => (
                  <Badge key={k} tone={hot ? 'medium' : 'neutral'}>
                    {label} {pe.imports!.categories[k]}
                  </Badge>
                ))}
                {IMP_CATS.every(([k]) => !(pe.imports!.categories[k] || 0)) && (
                  <span className="text-faint">未识别到显著类别</span>
                )}
              </div>
              {!!pe.imports.notable?.length && (
                <ul className="m-0 mt-1.5 max-h-[120px] list-none overflow-y-auto p-0 font-mono text-[11.5px] text-muted-foreground">
                  {pe.imports.notable.slice(0, 10).map((f, i) => (
                    <li key={i} className="truncate py-px" title={f}>{f}</li>
                  ))}
                  {pe.imports.notable.length > 10 && (
                    <li className="py-px text-faint">…共 {pe.imports.notable.length} 条显著导入</li>
                  )}
                </ul>
              )}
            </div>
          )}
        </div>
      ) : (
        <p className="text-xs text-faint">非 PE 文件（无 MZ 头）——不解析结构，哈希与字符串线索照常可用。</p>
      )}

      {/* 版本资源 */}
      {vr && (vr.company || vr.product || vr.description || vr.original_filename) && (
        <div className="rounded-md border border-border-soft bg-secondary/40 p-3 text-[12px]">
          <dl className="grid grid-cols-[110px_1fr] gap-x-3 gap-y-1.5">
            <dt className="text-faint">公司 / 产品</dt>
            <dd className="m-0">{vr.company || '-'} · {vr.product || '-'}</dd>
            <dt className="text-faint">描述</dt>
            <dd className="m-0">{vr.description || '-'}</dd>
            <dt className="text-faint">原始文件名</dt>
            <dd className="m-0 font-mono text-[11.5px]">{vr.original_filename || '-'}<span className="ml-2 text-faint">（实际：{fileName}）</span></dd>
          </dl>
        </div>
      )}

      {/* 字符串线索：采样前 64KB + 尾 64KB，每类探针侧 ≤10 */}
      {strs && <StringsBlock s={strs} />}
    </div>
  );
}

function StringsBlock({ s }: { s: LiveStrings }) {
  const groups: [string, string[] | undefined][] = [
    ['URL', s.urls], ['IP', s.ips], ['注册表路径', s.registry_paths],
    ['文件路径', s.file_paths], ['互斥量', s.mutex],
  ];
  const present = groups.filter(([, items]) => !!items?.length);
  if (!present.length) return <p className="text-xs text-faint">未提取到字符串线索。</p>;
  return (
    <div className="rounded-md border border-border-soft bg-secondary/40 p-3 text-[12px]">
      <div className="grid gap-x-6 gap-y-2.5 sm:grid-cols-2">
        {present.map(([label, items]) => (
          <div key={label} className="min-w-0">
            <div className="mb-1 flex items-center gap-1.5 text-[11px] tracking-[.05em] text-faint uppercase">
              {label}
              <span className="font-mono">{items!.length}</span>
            </div>
            <ul className="m-0 max-h-[104px] list-none overflow-y-auto p-0 font-mono text-[11.5px] text-muted-foreground">
              {items!.map((it, i) => (
                <li key={i} className="truncate py-px" title={it}>{it}</li>
              ))}
            </ul>
          </div>
        ))}
      </div>
      <p className="mt-2 border-t border-border-soft pt-1.5 text-[11px] text-faint">采样自文件头尾各 64 KB，仅作线索，不代表实际行为。</p>
    </div>
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
