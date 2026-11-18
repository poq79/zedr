import { useCallback, useEffect, useRef, useState } from 'react';
import { api } from '../lib/api';
import { dispatchAIContext } from '../lib/aiContext';
import { Badge, Button, Card, CardTitle, EmptyState, Skeleton } from '../components/ui/basics';
import { TimelineChart, SeverityDonut, BarList, type HourPoint } from '../components/charts';
import { useError } from '../lib/hooks';

interface Dashboard {
  total_hosts: number; online_hosts: number; alerts_24h: number;
  open_alerts: number; critical_open: number; malicious_count: number;
  false_positive: number; avg_response_min?: number; avg_score?: number;
  timeline: HourPoint[]; severity_dist: Record<string, number>;
  top_hosts?: { hostname: string; count: number }[];
  top_rules?: { name: string; count: number }[];
  top_mitre?: { tech: string; count: number }[];
}

export function OverviewPage() {
  const [d, setD] = useState<Dashboard | null>(null);
  const [loading, setLoading] = useState(true);
  const errorRender = useError();

  const load = useCallback(async () => {
    setLoading(true);
    try {
      setD(await api.get<Dashboard>('/api/v1/dashboard'));
    } catch (e) {
      errorRender.capture(e);
      setLoading(false);
      return;
    }
    setLoading(false);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => { load(); }, [load]);

  if (errorRender.rendered) return errorRender.rendered;

  const hostRate = d?.total_hosts ? Math.round((d.online_hosts / d.total_hosts) * 100) : 0;

  return (
    <div>
      <BriefingCard />

      {/* KPI 数据带：一格面板 + 内部发丝线分隔，替代四张浮动卡片。
          数字一律 mono——仪表读数是本系统的记忆锚点（UI-DESIGN §3）。
          进场编排：整页一次 staggered reveal（frontend-design skill 的洞见：
          一次编排好的入场比散落的微动效更有节奏感），每格错峰 70ms */}
      <div className="mb-3.5 grid grid-cols-2 divide-border-soft border border-border-soft rounded-md bg-card xl:grid-cols-4 xl:divide-x">
        <Kpi delay={0} loading={loading} label="受管主机" tone={hostRate < 60 ? 'warn' : 'ok'} value={d?.online_hosts ?? 0} suffix={d ? `/${d.total_hosts}` : ''} sub={`在线率 ${hostRate}%`} />
        <Kpi delay={70} loading={loading} label="近 24 小时告警" value={d?.alerts_24h ?? 0} sub={d ? `平均每小时 ${((d.alerts_24h || 0) / 24).toFixed(1)} 条` : ''} />
        <Kpi delay={140} loading={loading} label="待处置告警" tone="warn" value={d?.open_alerts ?? 0} sub="需人工确认" />
        <Kpi delay={210} loading={loading} label="严重且待处置" tone="crit" value={d?.critical_open ?? 0} sub={d ? `恶意判定 ${d.malicious_count} · 误报 ${d.false_positive}` : ''} />
      </div>

      {(d?.avg_response_min || 0) > 0 && (
        <div className="mb-3.5 flex items-center gap-3 rounded-md border border-border-soft bg-card px-4 py-2.5">
          <span className="rounded-[5px] border border-ok/25 bg-ok-soft px-1.5 py-0.5 font-mono text-[11px] font-semibold tracking-[.4px] text-ok">MTTR</span>
          <span className="text-[12.5px] text-muted-foreground">过去 7 天平均处置时长 <b className="font-mono text-[15px] tabular-nums text-foreground">{d!.avg_response_min!.toFixed(0)}</b> 分钟</span>
        </div>
      )}

      <div className="mb-3.5 grid gap-3.5 lg:grid-cols-3">
        <Card className="anim-page p-4 lg:col-span-2" style={{ animationDelay: '280ms' }}>
          <CardTitle className="mb-3.5">告警时间趋势（24h / 每小时）</CardTitle>
          <TimelineChart points={d?.timeline} loading={loading} />
        </Card>
        <Card className="anim-page p-4" style={{ animationDelay: '350ms' }}>
          <CardTitle className="mb-3.5">严重度分布</CardTitle>
          <SeverityDonut dist={d?.severity_dist} loading={loading} />
          <div className="mt-3.5 text-xs text-faint">
            平均置信分 <b className="font-mono tabular-nums text-foreground">{(d?.avg_score || 0).toFixed(1)}</b>
          </div>
        </Card>
      </div>

      <div className="grid gap-3.5 lg:grid-cols-3">
        <Card className="anim-page p-4" style={{ animationDelay: '420ms' }}>
          <CardTitle className="mb-3.5">主机告警排行</CardTitle>
          {loading ? <SkeletonRows3 /> : <BarList items={d?.top_hosts?.map((h) => ({ name: h.hostname, value: h.count }))} emptyText="暂无主机命中告警" />}
        </Card>
        <Card className="anim-page p-4" style={{ animationDelay: '490ms' }}>
          <CardTitle className="mb-3.5">规则命中排行</CardTitle>
          {loading ? <SkeletonRows3 /> : <BarList items={d?.top_rules?.map((r) => ({ name: r.name, value: r.count }))} emptyText="暂无规则命中" />}
        </Card>
        <Card className="anim-page p-4" style={{ animationDelay: '560ms' }}>
          <CardTitle className="mb-3.5">MITRE ATT&amp;CK 命中</CardTitle>
          {loading ? <SkeletonRows3 /> : <BarList items={d?.top_mitre?.map((m) => ({ name: m.tech, value: m.count }))} emptyText="暂无 ATT&CK 命中" />}
        </Card>
      </div>
    </div>
  );
}

function SkeletonRows3() {
  return <div className="space-y-2 py-1">{[46, 72, 58, 34].map((w, i) => <Skeleton key={i} style={{ width: `${w}%`, animationDelay: `${i * 0.12}s` }} />)}</div>;
}

function Kpi({ loading, label, value, suffix, sub, tone, delay }: {
  loading?: boolean; label: string; value: number | string; suffix?: string; sub?: string; tone?: 'warn' | 'crit' | 'ok'; delay?: number;
}) {
  const toneCls = tone === 'crit' ? 'text-crit' : tone === 'warn' ? 'text-warn' : tone === 'ok' ? 'text-ok' : '';
  const num = typeof value === 'number' ? value : null;
  const counted = useCountUp(num ?? 0);
  const shown = loading ? null : num === null ? value : counted;
  return (
    <div className="anim-page px-4 py-3.5" style={{ animationDelay: `${delay ?? 0}ms` }}>
      <div className="text-[11px] tracking-[.5px] text-faint">{label}</div>
      <div className={`anim-digit mt-1.5 font-mono text-[26px] leading-none font-semibold tabular-nums ${toneCls}`}>
        {loading ? <Skeleton className="h-6 w-16" /> : <>{shown}{suffix && <span className="text-[14px] text-faint">{suffix}</span>}</>}
      </div>
      <div className="mt-1.5 text-[11.5px] text-faint">{sub}</div>
    </div>
  );
}

/* KPI 读数滚动：数值落定时 from→target ease-out 计数（仪器读数语义，
   与 anim-digit 弹入叠加：入场形态 + 读数滚动）。首载从 0 滚起；
   reduced-motion 直达终值。 */
function useCountUp(target: number, dur = 550): number {
  const [v, setV] = useState(target);
  const fromRef = useRef(target);
  useEffect(() => {
    const from = fromRef.current;
    if (from === target) return;
    if (typeof matchMedia !== 'undefined' && matchMedia('(prefers-reduced-motion: reduce)').matches) {
      fromRef.current = target;
      setV(target);
      return;
    }
    let raf = 0;
    const t0 = performance.now();
    const tick = (now: number) => {
      const p = Math.min(1, (now - t0) / dur);
      setV(Math.round(from + (target - from) * (1 - Math.pow(1 - p, 3))));
      if (p < 1) raf = requestAnimationFrame(tick);
      else fromRef.current = target;
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, [target, dur]);
  return v;
}

export { EmptyState };

/* ---------------- 今日值班简报（主动式 AI，2026-11 对话升级轮） ----------------
   Copilot Today 三分法口径：需要立即关注 / 夜间漏斗 / 基础设施健康。
   简报是纯确定性聚合（零模型调用，可靠性优先于聪明），角标写具体
   ——"统计汇总"而非裸"AI"徽章（模糊 AI 标注反而增加回避）；
   "让 AI 解读"把简报作为作用域上下文喂给流式助手（用户主动点击才花 token）。 */

interface Briefing {
  window_hours: number; generated_at: string;
  alerts_new: number; critical_new: number; events_open: number;
  chain_hits: number; ops_pending: number; hosts_offline: number;
  top_rules?: { rule_id: string; count: number }[];
  recent_critical?: { id: string; title: string; hostname: string; score: number; occurred_at: string }[];
  narrative?: string; narrative_state?: string;
}

function BriefingCard() {
  const [b, setB] = useState<Briefing | null>(null);
  useEffect(() => {
    api.get<Briefing>('/api/v1/ai/briefing?hours=24&narrative=1').then(setB).catch(() => setB(null));
  }, []);

  const askText = b ? `结合这份值班简报，指出过去 ${b.window_hours} 小时最需要处理的三件事：` +
    `新增告警 ${b.alerts_new}（critical ${b.critical_new}）、新开事件 ${b.events_open}、攻击链命中 ${b.chain_hits}、` +
    `值班队列待审 ${b.ops_pending}、失联主机 ${b.hosts_offline}、` +
    `高发规则 ${(b.top_rules || []).map((r) => r.rule_id).join('/') || '无'}。` : '';
  const attention = (b?.critical_new || 0) + (b?.events_open || 0);

  return (
    <Card className="mb-3.5 px-4 pb-3.5 pt-3.5">
      <div className="mb-2.5 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <CardTitle>今日值班简报</CardTitle>
          {b?.narrative_state === 'ai'
            ? <Badge tone="info" title="统计骨架为确定性聚合；态势叙述由 AI 基于统计生成（narrative 槽位，30min 缓存）">AI 叙述 · 统计骨架 · 近 {b.window_hours}h</Badge>
            : <Badge tone="neutral" title={b?.narrative_state ? `AI 叙述未生成：${b.narrative_state}` : '纯确定性聚合，零模型调用'}>统计汇总 · 近 {b?.window_hours ?? 24}h</Badge>}
        </div>
        {!!b && (
          <Button size="sm" variant="ghost" onClick={() => dispatchAIContext(askText)}
            title="把简报作为上下文发给 AI 助手，让它解读并给优先级">
            让 AI 解读
          </Button>
        )}
      </div>
      {!b ? (
        <div className="text-[12px] text-faint">简报加载中…</div>
      ) : (
        <>
          {b.narrative && (
            <div className="mb-2.5 border-l-2 border-primary/30 pl-3 text-[12.5px] leading-[1.8] text-muted-foreground">
              {b.narrative}
            </div>
          )}
          <div className="grid grid-cols-2 gap-2 sm:grid-cols-5">
            {[
              { label: '需立即关注', value: attention, tone: attention ? 'crit' : 'ok', sub: `critical ${b.critical_new} · 新事件 ${b.events_open}` },
              { label: '新增告警', value: b.alerts_new, tone: 'neutral', sub: '全部严重度' },
              { label: '攻击链命中', value: b.chain_hits, tone: b.chain_hits ? 'warn' : 'neutral', sub: 'CHAIN-* 规则' },
              { label: '队列待审', value: b.ops_pending, tone: b.ops_pending ? 'warn' : 'ok', sub: 'AI 值班队列' },
              { label: '失联主机', value: b.hosts_offline, tone: b.hosts_offline ? 'warn' : 'ok', sub: '防护面缺口' },
            ].map((k) => (
              <div key={k.label} className="rounded-md border border-border-soft bg-secondary/40 px-3 py-2" title={k.sub}>
                <div className="text-[10.5px] text-faint">{k.label}</div>
                <div className={`mt-0.5 font-mono text-[17px] font-semibold tabular-nums ${k.tone === 'crit' ? 'text-crit' : k.tone === 'warn' ? 'text-warn' : k.tone === 'ok' ? 'text-ok' : 'text-foreground'}`}>{k.value}</div>
                <div className="text-[10px] text-faint">{k.sub}</div>
              </div>
            ))}
          </div>
          {!!b.recent_critical?.length && (
            <div className="mt-2.5">
              <div className="mb-1 text-[10.5px] font-semibold uppercase tracking-wide text-faint">最近的 critical</div>
              <div className="grid gap-1">
                {b.recent_critical.map((a) => (
                  <div key={a.id} className="flex items-center gap-2 text-[11.5px]">
                    <span className="rounded border border-crit/30 bg-crit-soft px-1.5 py-px text-[10px] font-semibold text-crit">严重</span>
                    <b className="min-w-0 flex-1 truncate" title={a.title}>{a.title}</b>
                    <span className="text-faint">{a.hostname} · {a.score} 分</span>
                    <a href={`#/alerts?open=${a.id}`} className="text-[11px] text-primary hover:underline">Open ›</a>
                  </div>
                ))}
              </div>
            </div>
          )}
          {!!b.top_rules?.length && (
            <div className="mt-2 text-[11px] text-faint">高发规则：{b.top_rules.map((r) => `${r.rule_id}×${r.count}`).join(' · ')}</div>
          )}
        </>
      )}
    </Card>
  );
}
