import { useCallback, useEffect, useMemo, useState, type ReactNode } from 'react';
import { CircleAlert, Info, ListChecks, RefreshCw, ShieldAlert, ShieldCheck, Unplug } from 'lucide-react';
import { ApiError, live, liveErrorKind } from '../lib/api';
import type { BaselineItem, BaselineStatus, LiveBaseline } from '../lib/types';
import { fmtTime } from '../lib/format';
import { Badge, Button, Card, CardTitle, EmptyState, Skeleton, SkeletonRows } from '../components/ui/basics';
import { cn } from '../lib/utils';

/* 主机详情「安全基线」Tab（docs/LIVE-TUNNEL.md §13.2，F5）。
   十个检查项全部由探针只读读取注册表/系统状态，服务端只做代理。
   UI 只负责三件事：四档计数 + 一句结论、按 fail→warn→pass→info 分组、
   当前值/建议值/证据原样呈现。status=info 是"读不到"而不是"合格"，
   必须在分组与文案里单独区分，避免把能力缺口伪装成安全。 */

const STATUS_META: Record<BaselineStatus, { label: string; tone: string; num: string; desc: string }> = {
  fail: { label: '未达标', tone: 'critical', num: 'text-crit', desc: '读到明确的危险值，建议优先修复' },
  warn: { label: '需关注', tone: 'medium', num: 'text-warn', desc: '值缺失或处于可接受但不完整的中间态' },
  pass: { label: '已达标', tone: 'resolved', num: 'text-ok', desc: '当前配置符合建议值' },
  info: { label: '无法判断', tone: 'neutral', num: 'text-muted-foreground', desc: '读取失败或权限不足，不拿默认值冒充实测' },
};

/* fail 永远置顶：值班视角先看"确定有问题"的，再看"可能有问题"的 */
const STATUS_ORDER: BaselineStatus[] = ['fail', 'warn', 'pass', 'info'];

const normStatus = (s: string): BaselineStatus =>
  (STATUS_ORDER as string[]).includes(s) ? (s as BaselineStatus) : 'info';

function conclusionOf(score: { pass: number; warn: number; fail: number }, total: number, info: number) {
  if (!total) {
    return { tone: 'neutral' as const, icon: <Info size={14} />, text: '本轮没有返回任何检查项——探针可能尚未实现该能力' };
  }
  if (score.fail > 0) {
    return {
      tone: 'crit' as const,
      icon: <ShieldAlert size={14} />,
      text: `${score.fail} 项未达标，建议优先修复 fail 项；另有 ${score.warn} 项需关注${info ? `、${info} 项无法判断` : ''}`,
    };
  }
  if (score.warn > 0) {
    return {
      tone: 'warn' as const,
      icon: <CircleAlert size={14} />,
      text: `没有未达标项，但有 ${score.warn} 项需关注${info ? `；另有 ${info} 项无法判断` : ''}`,
    };
  }
  if (info > 0) {
    return {
      tone: 'neutral' as const,
      icon: <Info size={14} />,
      text: `可判定项全部达标，但 ${info} 项因读取失败无法判断——不要把它当作已达标`,
    };
  }
  return {
    tone: 'ok' as const,
    icon: <ShieldCheck size={14} />,
    text: `${total} 项检查全部达标`,
  };
}

const CONCLUSION_CLASS: Record<'crit' | 'warn' | 'ok' | 'neutral', string> = {
  crit: 'text-crit',
  warn: 'text-warn',
  ok: 'text-ok',
  neutral: 'text-muted-foreground',
};

interface BaselineErr { kind: 'tunnel' | 'busy' | 'off' | 'unsupported' | 'other'; note: string }

/* 错误口径与 v2（HostReconTab）一致；404/501 都收敛成"该探针版本不支持"。
   新增端点未接线时服务端也可能直接 404，这里同样给升级提示而不是裸状态码。 */
function baselineErr(e: unknown): BaselineErr {
  if (e instanceof ApiError && e.status === 404) {
    return { kind: 'unsupported', note: '该探针版本不支持安全基线检查' };
  }
  switch (liveErrorKind(e)) {
    case 'tunnel': return { kind: 'tunnel', note: '探针隧道未连接' };
    case 'busy': return { kind: 'busy', note: '探针忙，稍后重试' };
    case 'off': return { kind: 'off', note: '实时查询未启用' };
    case 'unsupported': return { kind: 'unsupported', note: '该探针版本不支持安全基线检查' };
    default: return { kind: 'other', note: e instanceof Error ? e.message : String(e) };
  }
}

function BaselineErrorState({ e, onRetry }: { e: BaselineErr; onRetry: () => void }) {
  let info: { tone: 'info' | 'warn'; icon: ReactNode; title: string; sub: string };
  switch (e.kind) {
    case 'tunnel':
      info = {
        tone: 'warn', icon: <Unplug size={20} />, title: '无法读取安全基线',
        sub: '探针隧道未连接——探针离线、版本过旧或未开启隧道拨号；恢复后重试即可，此处不展示缓存数据。',
      };
      break;
    case 'busy':
      info = {
        tone: 'warn', icon: <CircleAlert size={20} />, title: '探针忙，稍后重试',
        sub: '基线检查需要探针执行十项只读查询，请等待当前任务结束后重试。',
      };
      break;
    case 'off':
      info = {
        tone: 'info', icon: <CircleAlert size={20} />, title: '实时查询未启用',
        sub: '安全基线属于现场只读检查，需要服务端开启实时隧道并授予分析师及以上角色。',
      };
      break;
    case 'unsupported':
      info = {
        tone: 'warn', icon: <ShieldAlert size={20} />, title: '该探针版本不支持安全基线',
        sub: '请升级终端探针到包含安全基线能力的版本后重试。',
      };
      break;
    default:
      info = {
        tone: 'warn', icon: <CircleAlert size={20} />, title: '安全基线检查失败',
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

function BaselineSkeleton() {
  return (
    <>
      <Card className="p-4">
        <div className="flex flex-wrap items-center gap-2.5">
          <Skeleton className="h-3 w-20" />
          <Skeleton className="h-3 w-14" />
          <div className="flex-1" />
          <Skeleton className="h-7 w-24 rounded-[7px]" />
        </div>
        <div className="mt-3 grid grid-cols-2 gap-px overflow-hidden rounded-md border border-border-soft bg-border-soft sm:grid-cols-4">
          {[0, 1, 2, 3].map((i) => (
            <div key={i} className="bg-card px-3.5 py-3">
              <Skeleton className="h-6 w-10" />
              <Skeleton className="mt-2 h-3 w-16" />
            </div>
          ))}
        </div>
        <Skeleton className="mt-3 h-3 w-2/3" />
      </Card>
      <Card><SkeletonRows rows={7} /></Card>
    </>
  );
}

function BaselineRow({ item, status }: { item: BaselineItem; status: BaselineStatus }) {
  const meta = STATUS_META[status];
  return (
    <div className="border-b border-border-soft px-4 py-3 last:border-b-0">
      <div className="flex flex-wrap items-center gap-2">
        <Badge tone={meta.tone}>{meta.label}</Badge>
        <span className="text-[13px] font-medium">{item.title || item.key}</span>
        {item.key && <span className="font-mono text-[10.5px] text-ghost">{item.key}</span>}
      </div>
      <dl className="mt-2 grid grid-cols-[52px_1fr] gap-x-3 gap-y-1.5 text-[12px]">
        <dt className="text-faint">当前</dt>
        <dd className="m-0 min-w-0 break-words text-muted-foreground">{item.current || '—'}</dd>
        <dt className="text-faint">建议</dt>
        <dd className="m-0 min-w-0 break-words text-muted-foreground">{item.recommended || '—'}</dd>
      </dl>
      {item.evidence && (
        <p className="mt-1.5 text-[11px] leading-relaxed text-faint">{item.evidence}</p>
      )}
    </div>
  );
}

export function HostBaselineTab({ agentId }: { agentId: string }) {
  const [res, setRes] = useState<LiveBaseline | null>(null);
  const [loading, setLoading] = useState(false);
  const [loadErr, setLoadErr] = useState<BaselineErr | null>(null);
  const [freshAt, setFreshAt] = useState('');

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const d = await live.baseline(agentId);
      setRes(d);
      setLoadErr(null);
      // generated_at 是探针时刻（可能带 UTC）；缺省时退回本地时刻并如实标注
      setFreshAt(d.generated_at ? fmtTime(d.generated_at) : new Date().toLocaleTimeString('zh-CN', { hour12: false }));
    } catch (e) {
      // 失败清空：基线是现场快照，过期数据比没有数据更危险
      setRes(null);
      setLoadErr(baselineErr(e));
    } finally {
      setLoading(false);
    }
  }, [agentId]);

  useEffect(() => {
    setRes(null); setLoadErr(null); setFreshAt('');
    void load();
  }, [load]);

  const items = useMemo(() => res?.items || [], [res]);
  const infoCount = useMemo(() => items.filter((it) => normStatus(it.status) === 'info').length, [items]);
  const score = useMemo(() => {
    const base = res?.score;
    if (base) {
      return {
        pass: base.pass || 0,
        warn: base.warn || 0,
        fail: base.fail || 0,
        total: base.total || items.length,
      };
    }
    return {
      pass: items.filter((it) => normStatus(it.status) === 'pass').length,
      warn: items.filter((it) => normStatus(it.status) === 'warn').length,
      fail: items.filter((it) => normStatus(it.status) === 'fail').length,
      total: items.length,
    };
  }, [res, items]);
  const groups = useMemo(
    () => STATUS_ORDER
      .map((status) => ({ status, rows: items.filter((it) => normStatus(it.status) === status) }))
      .filter((g) => g.rows.length > 0),
    [items],
  );
  const conclusion = conclusionOf(score, score.total, infoCount);

  return (
    <>
      {!res ? (
        loadErr ? <BaselineErrorState e={loadErr} onRetry={() => void load()} /> : <BaselineSkeleton />
      ) : (
        <>
          <Card className="p-4">
            <div className="flex flex-wrap items-center gap-2.5">
              <CardTitle>安全基线</CardTitle>
              <span className="font-mono text-[11px] tabular-nums text-ghost">{score.total} 项检查</span>
              <div className="flex-1" />
              {freshAt && <span className="text-[11px] text-ghost">更新于 {freshAt}</span>}
              <Button size="sm" disabled={loading} onClick={() => void load()} title="重新执行十项只读基线检查">
                <RefreshCw size={13} className={cn(loading && 'anim-spin')} />
                {loading ? '检查中…' : '重新检查'}
              </Button>
            </div>

            <div className="mt-3 grid grid-cols-2 gap-px overflow-hidden rounded-md border border-border-soft bg-border-soft sm:grid-cols-4">
              {([
                ['fail', score.fail],
                ['warn', score.warn],
                ['pass', score.pass],
                ['info', infoCount],
              ] as [BaselineStatus, number][]).map(([status, n]) => {
                const m = STATUS_META[status];
                return (
                  <div key={status} className="bg-card px-3.5 py-3" title={m.desc}>
                    <div className={cn('font-mono text-[26px] leading-none font-semibold tabular-nums', n ? m.num : 'text-ghost')}>
                      {n}
                    </div>
                    <div className="mt-1.5 text-[11px] text-faint">{m.label}</div>
                  </div>
                );
              })}
            </div>

            <p className={cn('mt-3 flex items-start gap-1.5 text-[12.5px] leading-relaxed', CONCLUSION_CLASS[conclusion.tone])}>
              <span className="mt-0.5 shrink-0">{conclusion.icon}</span>
              <span>{conclusion.text}</span>
            </p>
          </Card>

          {!items.length ? (
            <Card>
              <EmptyState tone="info" icon={<ListChecks size={20} />} title="本轮没有返回检查项"
                sub="探针可能尚未实现安全基线能力，或端点返回了空结果；请确认探针版本后重试。" />
            </Card>
          ) : (
            <Card>
              <div className="flex flex-wrap items-center gap-2.5 px-4 py-3">
                <CardTitle>检查项</CardTitle>
                <span className="font-mono text-[11px] tabular-nums text-ghost">{items.length}</span>
                <div className="flex-1" />
                <span className="text-[11px] text-ghost">fail → warn → pass → info 排序</span>
              </div>
              {groups.map((g) => {
                const m = STATUS_META[g.status];
                return (
                  <section key={g.status} aria-label={`${m.label} ${g.rows.length} 项`}>
                    <div className="flex flex-wrap items-center gap-2 border-y border-border-soft bg-secondary/30 px-4 py-2">
                      <Badge tone={m.tone}>{m.label}</Badge>
                      <span className="font-mono text-[11px] tabular-nums text-muted-foreground">{g.rows.length}</span>
                      <span className="text-[11px] text-faint">{m.desc}</span>
                    </div>
                    {g.rows.map((it, i) => (
                      <BaselineRow key={`${g.status}:${it.key || i}`} item={it} status={g.status} />
                    ))}
                  </section>
                );
              })}
            </Card>
          )}

          <p className="px-1 text-[11px] text-ghost">
            基线为点击时刻的只读快照，不做自动轮询；status=info 表示探针读不到该项，不代表已达标。
          </p>
        </>
      )}
    </>
  );
}
