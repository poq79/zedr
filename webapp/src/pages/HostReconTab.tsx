import { Fragment, useCallback, useEffect, useMemo, useState, type ReactNode } from 'react';
import {
  Bot, ChevronRight, CircleAlert, Container, Database, Globe, Monitor, RefreshCw,
  ScanSearch, Terminal, TriangleAlert, Unplug,
} from 'lucide-react';
import { ApiError, live, liveErrorKind } from '../lib/api';
import type {
  ReconAssetItem, ReconCategory, ReconExposureLevel, ReconFindingLike, ReconListen,
  ReconProcess, ReconResult,
} from '../lib/types';
import { fmtTime } from '../lib/format';
import { Badge, Button, Card, CardTitle, EmptyState, Skeleton, SkeletonRows } from '../components/ui/basics';
import { cn } from '../lib/utils';
import type { ReconFixtureApi } from '../lib/reconFixture';

/* 主机详情「资产侦查」Tab（docs/LIVE-TUNNEL.md §12，F4）。
   回答"这台机器上到底跑着什么资产、暴露成什么样"：六类分组卡（可折叠）+
   顶部暴露面总览（五档计数点击过滤）+ 资产行（kind/监听/进程/账号/暴露级别，
   展开后按类目渲染 details 与 findings）+ 底部问题汇总（类目级与资产级去重）。
   数据为点击侦查时刻的快照，手动刷新不做自动轮询；单次预算 30s、主动探测
   仅回环——超时截断与被动模式都必须在界面上诚实标注，不能假装完整。 */

/* 六类固定口径：标题以契约为准（后端 title 若缺省/英文，仍回退到这里的
   中文标题）；图标只承担类目识别，不做装饰。 */
const CATEGORY_META: Record<string, { title: string; Icon: typeof Globe }> = {
  web: { title: 'Web 服务', Icon: Globe },
  ai: { title: 'AI Agent Harness', Icon: Bot },
  db: { title: '数据库与中间件', Icon: Database },
  remote: { title: '远程管理面', Icon: Monitor },
  dev: { title: '开发与自动化', Icon: Terminal },
  virt: { title: '容器与虚拟化', Icon: Container },
};

const CATEGORY_KEYS = Object.keys(CATEGORY_META);

/* exposure 五档：Badge tone 走既有 SOC 语义色（v1.0 Carbon 不再有蓝色档，
   low/info 用中性色阶表达"无需紧张"，符合设计宪法"满屏红是事故"） */
const LEVELS: { key: ReconExposureLevel; label: string; tone: string }[] = [
  { key: 'critical', label: '严重', tone: 'critical' },
  { key: 'high', label: '高危', tone: 'high' },
  { key: 'medium', label: '中危', tone: 'medium' },
  { key: 'low', label: '低危', tone: 'low' },
  { key: 'info', label: '提示', tone: 'info' },
];
const LEVEL_META: Record<string, { label: string; tone: string }> =
  Object.fromEntries(LEVELS.map((l) => [l.key, { label: l.label, tone: l.tone }]));

type LevelFilter = '' | 'highplus' | ReconExposureLevel;

const levelOf = (it: ReconAssetItem): string => {
  const lv = String(it.exposure?.level || '').toLowerCase();
  return LEVEL_META[lv] ? lv : 'unknown';
};

const keepByFilter = (it: ReconAssetItem, filter: LevelFilter): boolean => {
  if (!filter) return true;
  const lv = levelOf(it);
  if (filter === 'highplus') return lv === 'critical' || lv === 'high';
  return lv === filter;
};

/* ---------------- 通用小工具（详情渲染只做键值对/列表，杜绝裸 JSON） ---------------- */

const hasKey = (d: Record<string, unknown>, k: string) => Object.prototype.hasOwnProperty.call(d, k);
const asText = (v: unknown): string => (typeof v === 'string' ? v : typeof v === 'number' ? String(v) : '');

function asBool(v: unknown): boolean | null {
  if (typeof v === 'boolean') return v;
  if (v === 1 || v === '1' || v === 'true') return true;
  if (v === 0 || v === '0' || v === 'false') return false;
  return null;
}

function objArray(v: unknown): Record<string, unknown>[] {
  if (!Array.isArray(v)) return [];
  return v.filter((x): x is Record<string, unknown> => x != null && typeof x === 'object' && !Array.isArray(x));
}

function omit(d: Record<string, unknown>, keys: string[]): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(d)) if (!keys.includes(k)) out[k] = v;
  return out;
}

function fmtListen(l: ReconListen): string {
  const addr = (l.addr || '').trim();
  const host = addr.includes(':') && !addr.startsWith('[') ? `[${addr}]` : addr;
  const port = l.port == null ? '' : String(l.port);
  if (!host) return port;
  return port ? `${host}:${port}` : host;
}

const DETAIL_LABEL: Record<string, string> = {
  webroot: '站点根目录',
  config_path: '配置文件',
  server_header: 'Server 头',
  title: '页面标题',
  aspx_present: 'ASPX 标记',
  version: '版本',
  auth_state: '认证状态',
  models: '模型',
  dashboard_url: '控制台地址',
  nla_enabled: 'NLA',
  shares: '共享',
  product: '产品',
  backend_pid: '后端 PID',
  sites: '站点',
  name: '名称',
  path: '路径',
  remark: '备注',
  physicalPath: '物理路径',
  physical_path: '物理路径',
  bindings: '绑定',
  pid: 'PID',
  cmdline: '命令行',
  user: '账号',
  started_at: '启动时间',
  token_in_cmdline: 'Token 位置',
  distros: '发行版',
  api_version: 'API 版本',
};

function DetailValue({ v }: { v: unknown }) {
  if (v == null) return <span className="text-faint">—</span>;
  if (typeof v === 'boolean') return <Badge tone="neutral">{v ? '是' : '否'}</Badge>;
  if (typeof v === 'number') return <span className="font-mono tabular-nums">{v}</span>;
  if (typeof v === 'string') {
    const text = v.trim();
    if (!text) return <span className="text-faint">—</span>;
    const mono = /^https?:\/\//i.test(text) || /[\\/]/.test(text);
    return <span className={cn('break-all', mono && 'font-mono text-[11.5px]')}>{text}</span>;
  }
  if (Array.isArray(v)) {
    if (!v.length) return <span className="text-faint">—</span>;
    if (v.every((x) => x == null || typeof x !== 'object')) {
      return <span className="font-mono text-[11.5px] break-all">{v.map((x) => String(x)).join('、')}</span>;
    }
    return (
      <span className="block space-y-1.5">
        {v.map((x, i) => (
          <span key={i} className="block rounded-md border border-border-soft px-2 py-1.5">
            <DetailValue v={x} />
          </span>
        ))}
      </span>
    );
  }
  if (typeof v === 'object') {
    const entries = Object.entries(v as Record<string, unknown>);
    if (!entries.length) return <span className="text-faint">—</span>;
    return (
      <span className="block space-y-1">
        {entries.map(([k, val]) => (
          <span key={k} className="flex gap-2">
            <span className="w-[96px] shrink-0 text-faint">
              {DETAIL_LABEL[k] || <span className="font-mono text-[11px]">{k}</span>}
            </span>
            <span className="min-w-0 flex-1"><DetailValue v={val} /></span>
          </span>
        ))}
      </span>
    );
  }
  return <span className="text-faint">—</span>;
}

function DetailList({ d, exclude = [] }: { d: Record<string, unknown>; exclude?: string[] }) {
  const rows = Object.entries(d).filter(([k]) => !exclude.includes(k));
  if (!rows.length) return null;
  return (
    <dl className="grid grid-cols-[110px_1fr] gap-x-3 gap-y-1.5 text-[12px]">
      {rows.map(([k, v]) => (
        <Fragment key={k}>
          <dt className="text-faint">{DETAIL_LABEL[k] || <span className="font-mono text-[11px]">{k}</span>}</dt>
          <dd className="m-0 min-w-0">
            {/* auth_state 在所有类目统一成中文徽标：dev 类的 Jupyter 等也不会漏出原始枚举值 */}
            {k === 'auth_state' ? <AuthBadge state={asText(v)} /> : <DetailValue v={v} />}
          </dd>
        </Fragment>
      ))}
    </dl>
  );
}

function SubSection({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section>
      <h4 className="mb-2 flex items-center gap-2 text-[11px] font-semibold uppercase tracking-[.05em] text-muted-foreground">
        <span>{title}</span>
        <span aria-hidden className="h-px flex-1 bg-border-soft" />
      </h4>
      {children}
    </section>
  );
}

/* ---------------- 认证状态（AI/DB 共用；open 是高风险信号，必须红警示） ---------------- */

function authMeta(state: string): { label: string; tone: string; anonymous: boolean } {
  const s = state.toLowerCase().replace(/\s+/g, '_');
  if (['open', 'no_auth', 'none', 'anonymous', 'unauthenticated', 'without_auth'].includes(s)) {
    return { label: '匿名可访问', tone: 'critical', anonymous: true };
  }
  if (['auth_required', 'required', 'authenticated', 'secured', 'password', 'token_required'].includes(s)) {
    return { label: '需要认证', tone: 'resolved', anonymous: false };
  }
  if (!s || s === 'unknown') return { label: '认证状态未知', tone: 'neutral', anonymous: false };
  return { label: state, tone: 'neutral', anonymous: false };
}

function AuthBadge({ state }: { state: string }) {
  const m = authMeta(state);
  return <Badge tone={m.tone} title={m.anonymous ? '能力端点未要求任何认证' : undefined}>{m.label}</Badge>;
}

/* ---------------- 按类目定制的 details ---------------- */

function AiDetails({ d }: { d: Record<string, unknown> }) {
  const hasAuth = hasKey(d, 'auth_state');
  const auth = asText(d.auth_state);
  const am = authMeta(auth);
  const hasModels = hasKey(d, 'models');
  const models = Array.isArray(d.models) ? d.models.map((m) => asText(m)).filter(Boolean) : [];
  const dash = asText(d.dashboard_url);
  const extra = omit(d, ['auth_state', 'models', 'dashboard_url']);
  return (
    <div className="space-y-2.5">
      {hasAuth && (
        <div className="flex flex-wrap items-center gap-2 text-[12px]">
          <span className="text-faint">认证状态</span>
          <AuthBadge state={auth} />
          {am.anonymous && (
            <span className="flex items-center gap-1.5 text-[11.5px] text-crit">
              <TriangleAlert size={12} className="shrink-0" />
              能力端点匿名可访问，本机/内网进程可直接调用
            </span>
          )}
        </div>
      )}
      {hasModels && (
        <div className="flex flex-wrap items-center gap-1.5 text-[12px]">
          <span className="mr-1 text-faint">已加载模型</span>
          {models.length
            ? models.map((m, i) => <Badge key={`${m}-${i}`} tone="neutral" className="font-mono">{m}</Badge>)
            : <span className="text-faint">未读取到模型列表</span>}
        </div>
      )}
      {dash && (
        <div className="flex flex-wrap items-center gap-2 text-[12px]">
          <span className="text-faint">控制台地址</span>
          <span className="break-all font-mono text-[11.5px]">{dash}</span>
        </div>
      )}
      {Object.keys(extra).length > 0 && <DetailList d={extra} />}
    </div>
  );
}

function WebDetails({ d }: { d: Record<string, unknown> }) {
  const hasSites = hasKey(d, 'sites');
  const sites = objArray(d.sites);
  const webroot = asText(d.webroot);
  const aspx = asBool(d.aspx_present);
  const extra = omit(d, ['sites', 'webroot', 'aspx_present']);
  return (
    <div className="space-y-3">
      {sites.length > 0 && (
        <div className="overflow-x-auto rounded-md border border-border-soft">
          <table className="w-full text-[12px]">
            <thead>
              <tr className="border-b border-border-soft text-left text-[11px] tracking-[.06em] text-faint uppercase">
                <th className="w-[160px] px-2.5 py-1.5 font-semibold">站点</th>
                <th className="w-[180px] px-2.5 py-1.5 font-semibold">绑定</th>
                <th className="px-2.5 py-1.5 font-semibold">物理路径</th>
              </tr>
            </thead>
            <tbody>
              {sites.map((s, i) => {
                const bindings = Array.isArray(s.bindings)
                  ? s.bindings.map((b) => asText(b)).filter(Boolean).join('、')
                  : asText(s.bindings);
                const physical = asText(s.physicalPath) || asText(s.physical_path);
                return (
                  <tr key={`${asText(s.name)}-${i}`} className="border-b border-border-soft last:border-b-0">
                    <td className="px-2.5 py-1.5 font-medium">{asText(s.name) || '—'}</td>
                    <td className="px-2.5 py-1.5 font-mono text-[11.5px] break-all">{bindings || '—'}</td>
                    <td className="px-2.5 py-1.5 font-mono text-[11.5px] break-all text-muted-foreground">{physical || '—'}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
      {hasSites && !sites.length && <p className="text-xs text-faint">未读取到站点配置。</p>}
      <div className="flex flex-wrap items-center gap-x-4 gap-y-1.5 text-[12px]">
        {webroot && (
          <span className="flex min-w-0 items-center gap-2">
            <span className="shrink-0 text-faint">站点根目录</span>
            <span className="break-all font-mono text-[11.5px]">{webroot}</span>
          </span>
        )}
        {aspx != null && (
          <span className="flex items-center gap-2">
            <span className="text-faint">ASPX 标记</span>
            <Badge tone={aspx ? 'medium' : 'neutral'} title="webroot 顶层抽查 aspx/asax/ashx/web.config/bin 的结果">
              {aspx ? '存在' : '未发现'}
            </Badge>
          </span>
        )}
      </div>
      {Object.keys(extra).length > 0 && <DetailList d={extra} />}
    </div>
  );
}

function DatabaseDetails({ d }: { d: Record<string, unknown> }) {
  const hasVersion = hasKey(d, 'version');
  const version = asText(d.version);
  const hasAuth = hasKey(d, 'auth_state');
  const auth = asText(d.auth_state);
  const extra = omit(d, ['version', 'auth_state']);
  return (
    <div className="space-y-2.5">
      {(hasVersion || hasAuth) && (
        <div className="flex flex-wrap items-center gap-x-4 gap-y-1.5 text-[12px]">
          {hasVersion && (
            <span className="flex items-center gap-2">
              <span className="text-faint">版本</span>
              <span className="font-mono text-[11.5px]">{version || '未知'}</span>
            </span>
          )}
          {hasAuth && (
            <span className="flex items-center gap-2">
              <span className="text-faint">认证状态</span>
              <AuthBadge state={auth} />
            </span>
          )}
        </div>
      )}
      {Object.keys(extra).length > 0 && <DetailList d={extra} />}
    </div>
  );
}

function RemoteDetails({ d }: { d: Record<string, unknown> }) {
  const nla = asBool(d.nla_enabled);
  const hasShares = hasKey(d, 'shares');
  const shares = objArray(d.shares);
  const product = asText(d.product);
  const extra = omit(d, ['nla_enabled', 'shares', 'product']);
  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-x-4 gap-y-1.5 text-[12px]">
        {product && (
          <span className="flex items-center gap-2">
            <span className="text-faint">产品</span>
            <span>{product}</span>
          </span>
        )}
        {nla != null && (
          <span className="flex flex-wrap items-center gap-2">
            <span className="text-faint">NLA</span>
            <Badge tone={nla ? 'resolved' : 'high'}>{nla ? '已启用' : '未启用'}</Badge>
            {!nla && <span className="text-[11px] text-warn">未启用网络级认证，RDP 预认证面暴露</span>}
          </span>
        )}
      </div>
      {shares.length > 0 && (
        <div className="overflow-x-auto rounded-md border border-border-soft">
          <table className="w-full text-[12px]">
            <thead>
              <tr className="border-b border-border-soft text-left text-[11px] tracking-[.06em] text-faint uppercase">
                <th className="w-[150px] px-2.5 py-1.5 font-semibold">共享名</th>
                <th className="px-2.5 py-1.5 font-semibold">路径</th>
                <th className="w-[180px] px-2.5 py-1.5 font-semibold">备注</th>
              </tr>
            </thead>
            <tbody>
              {shares.map((s, i) => (
                <tr key={`${asText(s.name)}-${i}`} className="border-b border-border-soft last:border-b-0">
                  <td className="px-2.5 py-1.5 font-medium">{asText(s.name) || '—'}</td>
                  <td className="px-2.5 py-1.5 font-mono text-[11.5px] break-all text-muted-foreground">{asText(s.path) || '—'}</td>
                  <td className="px-2.5 py-1.5 text-faint">{asText(s.remark) || asText(s.note) || '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {hasShares && !shares.length && <p className="text-xs text-faint">未读取到共享列表。</p>}
      {Object.keys(extra).length > 0 && <DetailList d={extra} />}
    </div>
  );
}

function AssetDetails({ item }: { item: ReconAssetItem }) {
  const d = item.details || {};
  switch ((item.category || '').toLowerCase()) {
    case 'ai': return <AiDetails d={d} />;
    case 'web': return <WebDetails d={d} />;
    case 'db': return <DatabaseDetails d={d} />;
    case 'remote': return <RemoteDetails d={d} />;
    default: return <DetailList d={d} />;
  }
}

function ProcessBlock({ p }: { p: ReconProcess }) {
  const rows: [string, ReactNode][] = [];
  if (p.pid != null) rows.push(['PID', <span className="font-mono tabular-nums">{p.pid}</span>]);
  if (p.name) rows.push(['进程', <span className="font-mono text-[11.5px]">{p.name}</span>]);
  if (p.user) rows.push(['账号', <span className="font-mono text-[11.5px]">{p.user}</span>]);
  if (p.path) rows.push(['路径', <span className="break-all font-mono text-[11.5px]">{p.path}</span>]);
  if (p.started_at) rows.push(['启动时间', <span className="font-mono text-[11.5px]">{fmtTime(p.started_at)}</span>]);
  if (!rows.length && !p.cmdline) return null;
  return (
    <SubSection title="进程归属">
      {rows.length > 0 && (
        <dl className="grid grid-cols-[110px_1fr] gap-x-3 gap-y-1.5 text-[12px]">
          {rows.map(([k, v]) => (
            <Fragment key={k}>
              <dt className="text-faint">{k}</dt>
              <dd className="m-0 min-w-0">{v}</dd>
            </Fragment>
          ))}
        </dl>
      )}
      {p.cmdline && (
        <div className={cn(rows.length > 0 && 'mt-2')}>
          <div className="mb-1 text-[11.5px] text-faint">命令行</div>
          <pre className="m-0 rounded-md border border-border-soft bg-[var(--code-bg)] p-2.5 font-mono text-[11.5px] leading-[1.7] break-all whitespace-pre-wrap text-[var(--code-fg)]">{p.cmdline}</pre>
        </div>
      )}
    </SubSection>
  );
}

/* ---------------- Finding 归一化（对象/字符串两种形态都要能渲染） ---------------- */

interface NormalizedFinding {
  key: string;
  label: string;
  tone: string;
  text: string;
  advice: string;
  source: string;
}

const SEV_LABEL: Record<string, string> = { critical: '严重', high: '高危', medium: '中危', low: '低危', info: '提示' };

function sevMeta(sev: string): { label: string; tone: string; key: string } {
  const s = sev.toLowerCase();
  return SEV_LABEL[s]
    ? { label: SEV_LABEL[s], tone: s, key: s }
    : { label: '未分级', tone: 'neutral', key: '' };
}

function firstText(...vals: unknown[]): string {
  for (const v of vals) if (typeof v === 'string' && v.trim()) return v.trim();
  return '';
}

function normalizeFinding(f: ReconFindingLike, source: string): NormalizedFinding | null {
  let text = '';
  let sev = '';
  let advice = '';
  if (typeof f === 'string') {
    text = f.trim();
  } else if (f && typeof f === 'object') {
    const o = f as Record<string, unknown>;
    text = firstText(o.title, o.message, o.description, o.detail, o.summary, o.text, o.note, o.issue);
    sev = firstText(o.severity, o.level, o.risk);
    advice = firstText(o.advice, o.recommendation, o.suggestion, o.solution, o.fix, o.remediation, o.action);
    // Finding 的最终字段名仍可能变化：兜底取第一个叙述性字符串，永不回退成裸 JSON
    if (!text) {
      for (const [k, v] of Object.entries(o)) {
        if ([
          'severity', 'level', 'risk', 'id', 'asset_id', 'category',
          'advice', 'recommendation', 'suggestion', 'solution', 'fix', 'remediation', 'action',
        ].includes(k)) continue;
        if (typeof v === 'string' && v.trim()) { text = v.trim(); break; }
      }
    }
  }
  if (!text) return null;
  const sm = sevMeta(sev);
  return { key: `${sm.key}|${text}`, label: sm.label, tone: sm.tone, text, advice, source };
}

function collectFindings(categories: ReconCategory[]): NormalizedFinding[] {
  const out: NormalizedFinding[] = [];
  const seen = new Set<string>();
  const push = (n: NormalizedFinding | null) => {
    if (!n || seen.has(n.key)) return;
    seen.add(n.key);
    out.push(n);
  };
  for (const c of categories) {
    const cTitle = CATEGORY_META[c.key || '']?.title || c.title || c.key || '资产';
    for (const f of Array.isArray(c.findings) ? c.findings : []) push(normalizeFinding(f, cTitle));
    for (const it of Array.isArray(c.items) ? c.items : []) {
      const src = `${cTitle} · ${it.title || (it.kind || '').toUpperCase() || '资产'}`;
      for (const f of Array.isArray(it.findings) ? it.findings : []) push(normalizeFinding(f, src));
    }
  }
  return out;
}

function FindingRow({ f, showSource = false }: { f: NormalizedFinding; showSource?: boolean }) {
  return (
    <div className="flex items-start gap-2 rounded-md border border-warn/30 bg-warn-soft px-2.5 py-2 text-[12px]">
      <TriangleAlert size={13} className={cn('mt-0.5 shrink-0', (f.tone === 'critical' || f.tone === 'high') ? 'text-crit' : 'text-warn')} />
      <span className="min-w-0 flex-1">
        <span className="flex flex-wrap items-center gap-1.5">
          <Badge tone={f.tone}>{f.label}</Badge>
          <span className="min-w-0 break-words">{f.text}</span>
        </span>
        {f.advice && <span className="mt-1 block text-[11.5px] leading-relaxed text-faint">建议：{f.advice}</span>}
        {showSource && f.source && <span className="mt-0.5 block text-[10.5px] text-ghost">来源：{f.source}</span>}
      </span>
    </div>
  );
}

/* ---------------- 顶部暴露面总览 ---------------- */

function FilterChip({ active, onClick, children }: { active: boolean; onClick: () => void; children: ReactNode }) {
  return (
    <button type="button" onClick={onClick} aria-pressed={active}
      className={cn('cursor-pointer rounded-[5px] border px-2 py-1 text-[11.5px] transition-colors',
        'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring',
        active ? 'border-border-strong bg-secondary font-medium text-foreground' : 'border-border-soft text-muted-foreground hover:text-foreground')}>
      {children}
    </button>
  );
}

function ReconOverview({
  res, counts, total, freshAt, loading, filter, setFilter, onRefresh,
}: {
  res: ReconResult;
  counts: Record<ReconExposureLevel, number>;
  total: number;
  freshAt: string;
  loading: boolean;
  filter: LevelFilter;
  setFilter: (f: LevelFilter) => void;
  onRefresh: () => void;
}) {
  const categories = res.categories || [];
  return (
    <Card className="p-4">
      <div className="flex flex-wrap items-center gap-2.5">
        <CardTitle>暴露面总览</CardTitle>
        <span className="font-mono text-[11px] tabular-nums text-ghost">{total} 项资产</span>
        {typeof res.duration_ms === 'number' && (
          <span className="font-mono text-[11px] tabular-nums text-ghost" title="探针侧侦查耗时">耗时 {res.duration_ms} ms</span>
        )}
        <div className="flex-1" />
        {freshAt && <span className="text-[11px] text-ghost">更新于 {freshAt}</span>}
        <Button size="sm" disabled={loading} onClick={onRefresh} title="重新执行本机资产侦查">
          <RefreshCw size={13} className={cn(loading && 'anim-spin')} />
          {loading ? '侦查中…' : '重新侦查'}
        </Button>
      </div>

      <div className="mt-2.5 flex flex-wrap items-center gap-1.5">
        {LEVELS.map((lv) => {
          const n = counts[lv.key] || 0;
          const active = filter === lv.key;
          return (
            <button key={lv.key} type="button" aria-pressed={active}
              onClick={() => setFilter(active ? '' : lv.key)}
              title={`只显示暴露级别为「${lv.label}」的资产`}
              className={cn('cursor-pointer rounded-full transition-shadow',
                'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring',
                active && 'ring-2 ring-ring ring-offset-1 ring-offset-card')}>
              {/* 计数为 0 时用中性色，避免满屏红制造虚假紧迫感 */}
              <Badge tone={n ? lv.tone : 'neutral'} className="tabular-nums">
                {lv.label} <span className="font-mono">{n}</span>
              </Badge>
            </button>
          );
        })}
        <span aria-hidden className="mx-1 h-4 w-px bg-border-soft" />
        <FilterChip active={filter === ''} onClick={() => setFilter('')}>全部</FilterChip>
        <FilterChip active={filter === 'highplus'} onClick={() => setFilter('highplus')}>仅严重+高危</FilterChip>
        <div className="flex-1" />
        {res.probed === false && (
          <span className="text-[11px] text-faint" title="探针侧 HG_AGENT_RECON_PROBE=false 或本次以 probe=0 调用">
            被动模式（未做主动探测）
          </span>
        )}
      </div>

      {categories.length > 0 && (
        <div className="mt-2 flex flex-wrap items-center gap-x-3.5 gap-y-1 text-[11px] text-faint">
          {categories.map((c, i) => {
            const title = CATEGORY_META[c.key || '']?.title || c.title || c.key || '未分类';
            const n = Array.isArray(c.items) ? c.items.length : 0;
            return (
              <span key={c.key || `cat-${i}`}>
                {title} <b className="font-mono font-semibold tabular-nums text-muted-foreground">{n}</b>
              </span>
            );
          })}
        </div>
      )}
    </Card>
  );
}

/* ---------------- 六类分组卡 + 资产行 ---------------- */

function CategoryCard({
  ck, cat, filter, collapsed, onToggle, openIds, onToggleItem,
}: {
  ck: string;
  cat: ReconCategory;
  filter: LevelFilter;
  collapsed: boolean;
  onToggle: () => void;
  openIds: Record<string, boolean>;
  onToggleItem: (k: string) => void;
}) {
  const items = Array.isArray(cat.items) ? cat.items : [];
  const visible = items.filter((it) => keepByFilter(it, filter));
  const findCount = Array.isArray(cat.findings) ? cat.findings.length : 0;
  const meta = CATEGORY_META[cat.key || ''];
  const title = meta?.title || cat.title || cat.key || '未分类';
  const Icon = meta?.Icon || ScanSearch;
  return (
    <Card>
      <button type="button" onClick={onToggle} aria-expanded={!collapsed}
        className="flex w-full cursor-pointer items-center gap-2.5 rounded-t-md px-3.5 py-2.5 text-left transition-colors hover:bg-secondary/60 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-ring">
        <ChevronRight size={13}
          className={cn('shrink-0 text-ghost transition-transform duration-150', !collapsed && 'rotate-90')} />
        <Icon size={14} className="shrink-0 text-muted-foreground" />
        <span className="text-xs font-semibold uppercase tracking-[.05em] text-muted-foreground">{title}</span>
        <span className="font-mono text-[11px] tabular-nums text-ghost">{items.length}</span>
        {findCount > 0 && (
          <Badge tone="medium" title="该类目级问题数（资产级问题在各资产行内展开）">{findCount} 项类目问题</Badge>
        )}
        <span className="flex-1" />
        {filter && <span className="font-mono text-[10.5px] tabular-nums text-ghost">筛选后 {visible.length}</span>}
      </button>

      {!collapsed && (
        <div className="border-t border-border-soft">
          {cat.error && (
            <div className="m-3 flex items-start gap-2 rounded-md border border-destructive/30 bg-destructive-soft px-3 py-2 text-[12.5px] text-destructive">
              <CircleAlert size={14} className="mt-0.5 shrink-0" />
              <span className="min-w-0 break-all">该类资产侦查失败：{cat.error}</span>
            </div>
          )}
          {!items.length ? (
            cat.error ? null : (
              <EmptyState tone="ok" icon={<ScanSearch size={20} />} title="未发现此类资产"
                sub="该类别没有命中任何监听端口或进程特征——保持现状即可。" />
            )
          ) : !visible.length ? (
            <div className="px-4 py-6 text-center text-[12.5px] text-faint">当前过滤条件下没有此类资产</div>
          ) : (
            <div>
              {visible.map((it, i) => {
                const ak = `${ck}:${it.id || i}`;
                return (
                  <AssetRow key={ak} item={it} open={!!openIds[ak]}
                    onToggle={() => onToggleItem(ak)} />
                );
              })}
            </div>
          )}
        </div>
      )}
    </Card>
  );
}

function AssetRow({ item, open, onToggle }: { item: ReconAssetItem; open: boolean; onToggle: () => void }) {
  const kind = (item.kind || 'asset').toUpperCase().replace(/[_-]+/g, ' ');
  const listens = Array.isArray(item.listens) ? item.listens : [];
  const ports = listens.map(fmtListen).filter(Boolean).join(', ');
  const proc = item.process;
  const procText = proc ? [proc.name, proc.user].filter(Boolean).join(' · ') : '';
  const lv = levelOf(item);
  const lvMeta = LEVEL_META[lv] || { label: '未知', tone: 'neutral' };
  const evidence = Array.isArray(item.exposure?.evidence) ? item.exposure!.evidence!.filter(Boolean) : [];
  const findings = (Array.isArray(item.findings) ? item.findings : [])
    .map((f) => normalizeFinding(f, ''))
    .filter((f): f is NormalizedFinding => f != null);
  const details = item.details || {};
  const hasDetails = Object.keys(details).length > 0;
  const title = item.title || kind;
  const empty = !hasDetails && !evidence.length && !proc && !findings.length && !item.endpoint;

  return (
    <div className="border-b border-border-soft last:border-b-0">
      <button type="button" onClick={onToggle} aria-expanded={open}
        className="flex w-full cursor-pointer items-start gap-2.5 px-3.5 py-2.5 text-left transition-colors hover:bg-secondary/60 focus-visible:bg-secondary/60 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-ring">
        <ChevronRight size={13}
          className={cn('mt-0.5 shrink-0 text-ghost transition-transform duration-150', open && 'rotate-90')} />
        <Badge tone="neutral" className="mt-px shrink-0 font-mono text-[10.5px]">{kind}</Badge>
        <span className="min-w-0 flex-1">
          <span className="flex flex-wrap items-center gap-x-2.5 gap-y-1">
            <span className="font-medium break-words">{title}</span>
            {item.endpoint && (
              <span className="max-w-full truncate font-mono text-[10.5px] text-ghost" title={item.endpoint}>{item.endpoint}</span>
            )}
          </span>
          <span className="mt-0.5 flex flex-wrap items-center gap-x-3 gap-y-0.5 text-[11px] text-faint">
            {ports && <span className="font-mono">{ports}</span>}
            {procText && <span>{procText}</span>}
            {!ports && !procText && <span>无监听端口与进程信息</span>}
          </span>
        </span>
        {findings.length > 0 && (
          <span className="mt-0.5 flex shrink-0 items-center gap-1 text-[11px] text-warn" title={`该资产有 ${findings.length} 项问题`}>
            <TriangleAlert size={12} />
            <span className="font-mono tabular-nums">{findings.length}</span>
          </span>
        )}
        <Badge tone={lvMeta.tone} className="mt-px shrink-0"
          title={evidence.length ? `暴露判定：${evidence.join('；')}` : `暴露级别：${lvMeta.label}`}>
          {lvMeta.label}
        </Badge>
      </button>

      {open && (
        <div className="border-t border-border-soft bg-secondary/20 px-3.5 py-3">
          <div className="space-y-3">
            {item.endpoint && (
              <div className="flex flex-wrap items-center gap-2 text-[12px]">
                <span className="text-faint">访问地址</span>
                <span className="break-all font-mono text-[11.5px]">{item.endpoint}</span>
              </div>
            )}
            {hasDetails && (
              <SubSection title="要点详情">
                <AssetDetails item={item} />
              </SubSection>
            )}
            {evidence.length > 0 && (
              <SubSection title="暴露判定依据">
                <ul className="m-0 list-disc space-y-0.5 pl-4 text-[11.5px] leading-relaxed text-muted-foreground">
                  {evidence.map((e, i) => <li key={i}>{e}</li>)}
                </ul>
              </SubSection>
            )}
            {proc && <ProcessBlock p={proc} />}
            {findings.length > 0 && (
              <SubSection title={`该资产的问题 ${findings.length}`}>
                <div className="flex flex-col gap-1.5">
                  {findings.map((f) => <FindingRow key={f.key} f={f} />)}
                </div>
              </SubSection>
            )}
            {empty && <p className="text-xs text-faint">该资产仅有监听信息，没有更多可展开细节。</p>}
          </div>
        </div>
      )}
    </div>
  );
}

/* ---------------- 底部问题汇总 ---------------- */

function FindingsSummary({ categories }: { categories: ReconCategory[] }) {
  const list = useMemo(() => collectFindings(categories), [categories]);
  return (
    <Card className="p-4">
      <div className="mb-2.5 flex flex-wrap items-center gap-2.5">
        <CardTitle>发现的问题</CardTitle>
        <span className="font-mono text-[11px] tabular-nums text-ghost">{list.length}</span>
        <div className="flex-1" />
        <span className="text-[11px] text-ghost">聚合类目级与资产级问题（去重）</span>
      </div>
      {!list.length ? (
        <div className="rounded-md border border-border-soft bg-secondary/30 px-3.5 py-4 text-center text-[12.5px] text-faint">
          本轮侦查没有发现需要处置的问题——资产暴露面处于可接受范围。
        </div>
      ) : (
        <div className="flex flex-col gap-1.5">
          {list.map((f) => <FindingRow key={f.key} f={f} showSource />)}
        </div>
      )}
    </Card>
  );
}

/* ---------------- 状态：骨架 / 错误 ---------------- */

function ReconSkeleton() {
  return (
    <>
      <Card className="p-4">
        <div className="flex flex-wrap items-center gap-2.5">
          <Skeleton className="h-3 w-24" />
          <Skeleton className="h-3 w-14" />
          <div className="flex-1" />
          <Skeleton className="h-7 w-24 rounded-[7px]" />
        </div>
        <div className="mt-3 flex flex-wrap gap-1.5">
          {[64, 60, 62, 58, 58].map((w, i) => (
            <Skeleton key={i} className="h-5 rounded-full" style={{ width: w }} />
          ))}
        </div>
        <div className="mt-3 flex flex-wrap gap-3">
          <Skeleton className="h-3 w-40" />
          <Skeleton className="h-3 w-32" />
          <Skeleton className="h-3 w-28" />
        </div>
      </Card>
      <Card><SkeletonRows rows={8} /></Card>
    </>
  );
}

interface ReconErr { kind: 'tunnel' | 'busy' | 'off' | 'unsupported' | 'other'; note: string }

/* 隧道错误口径与 v2 一致；404/501 统一收敛成"该探针版本不支持资产侦查" */
function reconErr(e: unknown): ReconErr {
  if (e instanceof ApiError && e.status === 404) {
    return { kind: 'unsupported', note: '该探针版本不支持资产侦查' };
  }
  switch (liveErrorKind(e)) {
    case 'tunnel': return { kind: 'tunnel', note: '探针隧道未连接' };
    case 'busy': return { kind: 'busy', note: '探针忙，稍后重试' };
    case 'off': return { kind: 'off', note: '实时查询未启用' };
    case 'unsupported': return { kind: 'unsupported', note: '该探针版本不支持资产侦查' };
    default: return { kind: 'other', note: e instanceof Error ? e.message : String(e) };
  }
}

function ReconErrorState({ e, onRetry }: { e: ReconErr; onRetry: () => void }) {
  let info: { tone: 'info' | 'warn'; icon: ReactNode; title: string; sub: string };
  switch (e.kind) {
    case 'tunnel':
      info = { tone: 'warn', icon: <Unplug size={20} />, title: '无法读取资产侦查', sub: '探针隧道未连接——恢复后重试即可；此处不展示缓存数据。' };
      break;
    case 'busy':
      info = { tone: 'warn', icon: <CircleAlert size={20} />, title: '探针忙，稍后重试', sub: '侦查与主动探测有资源开销，请等待当前任务结束。' };
      break;
    case 'off':
      info = { tone: 'info', icon: <CircleAlert size={20} />, title: '实时查询未启用', sub: '资产侦查属于现场调查能力，需要服务端开启实时隧道并授予分析师及以上角色。' };
      break;
    case 'unsupported':
      info = { tone: 'warn', icon: <ScanSearch size={20} />, title: '该探针版本不支持资产侦查', sub: '请升级终端探针到包含资产侦查能力的版本后重试。' };
      break;
    default:
      info = { tone: 'warn', icon: <CircleAlert size={20} />, title: '资产侦查失败', sub: e.note || '未知错误，请稍后重试。' };
  }
  return (
    <Card>
      <EmptyState tone={info.tone} icon={info.icon} title={info.title} sub={info.sub}
        action={<Button size="sm" onClick={onRetry}>重试</Button>} />
    </Card>
  );
}

/* ---------------- 开发期假数据开关（与 liveFixture 同款；生产构建死分支剔除） ---------------- */

async function devFixture(): Promise<ReconFixtureApi | null> {
  if (!import.meta.env.DEV) return null;
  try { if (localStorage.getItem('hg_recon_fixture') !== '1') return null; } catch { return null; }
  const m = await import('../lib/reconFixture');
  return m.fixture;
}

/* ---------------- 主组件 ---------------- */

export function HostReconTab({ agentId }: { agentId: string }) {
  const [res, setRes] = useState<ReconResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [loadErr, setLoadErr] = useState<ReconErr | null>(null);
  const [freshAt, setFreshAt] = useState('');
  const [levelFilter, setLevelFilter] = useState<LevelFilter>('');
  const [collapsed, setCollapsed] = useState<Record<string, boolean>>({});
  const [openIds, setOpenIds] = useState<Record<string, boolean>>({});

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const fx = await devFixture();
      const d = fx
        ? await fx.recon()
        : await live.recon(agentId, { categories: CATEGORY_KEYS, probe: true });
      setRes(d);
      setLoadErr(null);
      setFreshAt(new Date().toLocaleTimeString('zh-CN', { hour12: false }));
    } catch (e) {
      // 失败清空：不留过期快照冒充现场（与实时进程/文件 Tab 同一诚实口径）
      setRes(null);
      setLoadErr(reconErr(e));
    } finally {
      setLoading(false);
    }
  }, [agentId]);

  useEffect(() => {
    setRes(null); setLoadErr(null); setFreshAt(''); setLevelFilter('');
    setCollapsed({}); setOpenIds({});
    void load();
  }, [load]);

  const categories = useMemo(() => res?.categories || [], [res]);
  const total = useMemo(
    () => categories.reduce((n, c) => n + (Array.isArray(c.items) ? c.items.length : 0), 0),
    [categories],
  );
  const counts = useMemo<Record<ReconExposureLevel, number>>(() => {
    const c: Record<ReconExposureLevel, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    for (const cat of categories) {
      for (const it of Array.isArray(cat.items) ? cat.items : []) {
        const lv = levelOf(it);
        if (lv in c) c[lv as ReconExposureLevel]++;
      }
    }
    return c;
  }, [categories]);

  return (
    <>
      {loadErr?.kind === 'tunnel' && (
        <div className="flex flex-wrap items-center gap-2.5 rounded-md border border-warn/30 bg-warn-soft px-3.5 py-2.5 text-[12.5px]">
          <Unplug size={15} className="shrink-0 text-warn" />
          <span className="min-w-0 flex-1">
            <b>探针隧道未连接</b>——探针离线、版本过旧或未开启隧道拨号（HG_AGENT_TUNNEL_ENABLED）。指令通道不受影响，隧道恢复后即可继续查询。
          </span>
          <Button size="sm" onClick={() => void load()}>重试</Button>
        </div>
      )}

      {res?.truncated && (
        <div className="flex flex-wrap items-center gap-2.5 rounded-md border border-warn/30 bg-warn-soft px-3.5 py-2.5 text-[12.5px]">
          <TriangleAlert size={15} className="shrink-0 text-warn" />
          <span className="min-w-0 flex-1">
            <b>侦查超时截断，结果不完整</b>——本轮仅返回已收集部分，可稍后重试或缩小侦查范围。
          </span>
        </div>
      )}

      {!res ? (
        loadErr ? <ReconErrorState e={loadErr} onRetry={() => void load()} /> : <ReconSkeleton />
      ) : (
        <>
          <ReconOverview res={res} counts={counts} total={total} freshAt={freshAt}
            loading={loading} filter={levelFilter} setFilter={setLevelFilter}
            onRefresh={() => void load()} />

          {categories.length === 0 ? (
            <Card>
              <EmptyState tone="ok" icon={<ScanSearch size={20} />} title="未发现任何资产"
                sub="本轮侦查没有命中六类资产特征——若预期有服务在运行，请确认探针版本与主动探测开关。" />
            </Card>
          ) : (
            categories.map((c, i) => {
              const ck = c.key || `cat-${i}`;
              return (
                <CategoryCard key={ck} ck={ck} cat={c} filter={levelFilter}
                  collapsed={!!collapsed[ck]}
                  onToggle={() => setCollapsed((v) => ({ ...v, [ck]: !v[ck] }))}
                  openIds={openIds}
                  onToggleItem={(k) => setOpenIds((v) => ({ ...v, [k]: !v[k] }))} />
              );
            })
          )}

          <FindingsSummary categories={categories} />

          <p className="px-1 text-[11px] text-ghost">
            资产侦查为点击时刻快照，不做自动轮询；单次预算 30 秒，主动探测仅访问本机回环地址。
          </p>
        </>
      )}
    </>
  );
}
