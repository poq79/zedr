import { useCallback, useEffect, useState } from 'react';
import { api } from '../lib/api';
import { Card, CardTitle, EmptyState, Skeleton } from '../components/ui/basics';
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
      {/* KPI 数据带：一格面板 + 内部发丝线分隔，替代四张浮动卡片。
          数字一律 mono——仪表读数是本系统的记忆锚点（UI-DESIGN §3） */}
      <div className="mb-3.5 grid grid-cols-2 divide-border-soft border border-border-soft rounded-md bg-card xl:grid-cols-4 xl:divide-x">
        <Kpi loading={loading} label="受管主机" tone={hostRate < 60 ? 'warn' : 'ok'} value={d?.online_hosts ?? 0} suffix={d ? `/${d.total_hosts}` : ''} sub={`在线率 ${hostRate}%`} />
        <Kpi loading={loading} label="近 24 小时告警" value={d?.alerts_24h ?? 0} sub={d ? `平均每小时 ${((d.alerts_24h || 0) / 24).toFixed(1)} 条` : ''} />
        <Kpi loading={loading} label="待处置告警" tone="warn" value={d?.open_alerts ?? 0} sub="需人工确认" />
        <Kpi loading={loading} label="严重且待处置" tone="crit" value={d?.critical_open ?? 0} sub={d ? `恶意判定 ${d.malicious_count} · 误报 ${d.false_positive}` : ''} />
      </div>

      {(d?.avg_response_min || 0) > 0 && (
        <div className="mb-3.5 flex items-center gap-3 rounded-md border border-border-soft bg-card px-4 py-2.5">
          <span className="rounded-[5px] border border-ok/25 bg-ok-soft px-1.5 py-0.5 font-mono text-[11px] font-semibold tracking-[.4px] text-ok">MTTR</span>
          <span className="text-[12.5px] text-muted-foreground">过去 7 天平均处置时长 <b className="font-mono text-[15px] tabular-nums text-foreground">{d!.avg_response_min!.toFixed(0)}</b> 分钟</span>
        </div>
      )}

      <div className="mb-3.5 grid gap-3.5 lg:grid-cols-3">
        <Card className="p-4 lg:col-span-2">
          <CardTitle className="mb-3.5">告警时间趋势（24h / 每小时）</CardTitle>
          <TimelineChart points={d?.timeline} loading={loading} />
        </Card>
        <Card className="p-4">
          <CardTitle className="mb-3.5">严重度分布</CardTitle>
          <SeverityDonut dist={d?.severity_dist} loading={loading} />
          <div className="mt-3.5 text-xs text-faint">
            平均置信分 <b className="font-mono tabular-nums text-foreground">{(d?.avg_score || 0).toFixed(1)}</b>
          </div>
        </Card>
      </div>

      <div className="grid gap-3.5 lg:grid-cols-3">
        <Card className="p-4">
          <CardTitle className="mb-3.5">主机告警排行</CardTitle>
          {loading ? <SkeletonRows3 /> : <BarList items={d?.top_hosts?.map((h) => ({ name: h.hostname, value: h.count }))} emptyText="暂无主机命中告警" />}
        </Card>
        <Card className="p-4">
          <CardTitle className="mb-3.5">规则命中排行</CardTitle>
          {loading ? <SkeletonRows3 /> : <BarList items={d?.top_rules?.map((r) => ({ name: r.name, value: r.count }))} emptyText="暂无规则命中" />}
        </Card>
        <Card className="p-4">
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

function Kpi({ loading, label, value, suffix, sub, tone }: {
  loading?: boolean; label: string; value: number | string; suffix?: string; sub?: string; tone?: 'warn' | 'crit' | 'ok';
}) {
  const toneCls = tone === 'crit' ? 'text-crit' : tone === 'warn' ? 'text-warn' : tone === 'ok' ? 'text-ok' : '';
  return (
    <div className="px-4 py-3.5">
      <div className="text-[11px] tracking-[.5px] text-faint">{label}</div>
      <div className={`anim-digit mt-1.5 font-mono text-[26px] leading-none font-semibold tabular-nums ${toneCls}`}>
        {loading ? <Skeleton className="h-6 w-16" /> : <>{value}{suffix && <span className="text-[14px] text-faint">{suffix}</span>}</>}
      </div>
      <div className="mt-1.5 text-[11.5px] text-faint">{sub}</div>
    </div>
  );
}

export { EmptyState };
