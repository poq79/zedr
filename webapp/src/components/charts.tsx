import { EmptyState, Skeleton } from './ui/basics';
import { ShieldCheck } from 'lucide-react';
import { SEV_LABEL } from '../lib/format';

/* 纯 SVG 图表：色彩走 CSS 变量（双主题自动适配），带生长/扫入动效 */

export interface HourPoint { bucket: string; total: number; critical: number }

export function TimelineChart({ points, loading }: { points?: HourPoint[]; loading?: boolean }) {
  if (loading) {
    return <div className="px-1 py-3"><Skeleton className="h-[130px] w-full" /></div>;
  }
  if (!points || !points.length) {
    return <EmptyState icon={<ShieldCheck size={20} />} title="所选时间范围内没有告警——环境安静" />;
  }

  const W = 680, H = 150, padL = 34, padB = 20, padT = 8;
  const innerW = W - padL - 8, innerH = H - padB - padT;
  const max = Math.max(1, ...points.map((p) => p.total));
  const bw = innerW / points.length;

  const grid: React.ReactNode[] = [];
  for (let i = 0; i <= 3; i++) {
    const v = Math.round((max / 3) * i);
    const y = padT + innerH - (i / 3) * innerH;
    grid.push(<line key={`g${i}`} x1={padL} y1={y} x2={W - 8} y2={y} stroke="var(--border-strong)" strokeWidth={1} />);
    grid.push(<text key={`t${i}`} x={padL - 6} y={y + 3.5} fontSize={9} fill="var(--faint)" textAnchor="end">{v}</text>);
  }

  const step = Math.max(1, Math.ceil(points.length / 6));
  const bars = points.map((p, i) => {
    if (i % step !== 0) return null;
    const d = new Date(p.bucket);
    const hh = String(d.getHours()).padStart(2, '0');
    const x = padL + i * bw + bw / 2;
    return <text key={`x${i}`} x={x} y={H - 5} fontSize={9} fill="var(--faint)" textAnchor="middle">{hh}:00</text>;
  });

  const rects = points.map((p, i) => {
    const h = (p.total / max) * innerH;
    const critH = p.total > 0 ? (p.critical / p.total) * h : 0;
    const x = padL + i * bw + Math.max(1, bw * 0.16);
    const w = Math.max(1, bw * 0.68);
    const y = padT + innerH - h;
    const delay = { animationDelay: `${i * 28}ms` };
    return (
      <g key={`b${i}`}>
        <rect className="cbar" style={{ ...delay, fill: 'var(--chart-bar)' }} x={x} y={y} width={w} height={Math.max(0, h - critH)} rx={2} opacity={0.75} />
        {critH > 0 && <rect className="cbar" style={{ ...delay, fill: 'var(--chart-crit)' }} x={x} y={padT + innerH - critH} width={w} height={critH} rx={2} />}
      </g>
    );
  });

  return (
    <div>
      <svg viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="none" className="block h-[150px] w-full">
        {grid}{rects}{bars}
      </svg>
      <div className="mt-2.5 flex flex-wrap gap-4 text-[11.5px] text-faint">
        <span className="inline-flex items-center gap-1.5"><i className="h-2 w-2 rounded-[2px]" style={{ background: 'var(--chart-bar)' }} />普通告警</span>
        <span className="inline-flex items-center gap-1.5"><i className="h-2 w-2 rounded-[2px]" style={{ background: 'var(--chart-crit)' }} />严重告警</span>
      </div>
    </div>
  );
}

const SEV_COLOR: Record<string, string> = {
  critical: 'var(--crit)', high: 'var(--destructive)', medium: 'var(--warn)',
  low: 'var(--faint)', info: 'var(--ghost)',
};

export function SeverityDonut({ dist, loading }: { dist?: Record<string, number>; loading?: boolean }) {
  if (loading) return <div className="grid place-items-center py-6"><Skeleton className="h-[120px] w-[120px] rounded-full" /></div>;
  const order: Array<keyof typeof SEV_COLOR> = ['critical', 'high', 'medium', 'low', 'info'];
  const total = order.reduce((a, k) => a + (dist?.[k] || 0), 0);
  if (!total) return <EmptyState icon={<ShieldCheck size={20} />} title="暂无告警分布——环境安静" />;

  const R = 46, C = 2 * Math.PI * R;
  let offset = 0;
  const arcs = order
    .filter((k) => (dist?.[k] || 0) > 0)
    .map((k) => {
      const v = dist![k];
      const len = (v / total) * C;
      const el = (
        <circle
          key={k} className="donut-arc" cx={60} cy={60} r={R} fill="none"
          style={{ stroke: SEV_COLOR[k], animationDelay: `${offset | 0}ms` }}
          strokeWidth={14} strokeDasharray={`${len - 2} ${C - len + 2}`} strokeDashoffset={-offset}
          transform="rotate(-90 60 60)" strokeLinecap="butt"
        />
      );
      offset += len;
      return el;
    });

  const rows = order.filter((k) => (dist?.[k] || 0) > 0).map((k) => (
    <div key={k} className="mb-1.5 flex items-center gap-2 text-xs">
      <i className="h-2 w-2 rounded-[2px]" style={{ background: SEV_COLOR[k] }} />
      <span className="flex-1 text-muted-foreground">{SEV_LABEL[k]}</span>
      <b className="tabular-nums">{dist![k]}</b>
    </div>
  ));

  return (
    <div className="flex items-center gap-4.5">
      <svg viewBox="0 0 120 120" width={120} height={120} className="shrink-0">
        <circle cx={60} cy={60} r={R} fill="none" stroke="var(--border)" strokeWidth={14} />
        {arcs}
        <text x={60} y={58} textAnchor="middle" fontSize={20} fontWeight={700} fill="var(--foreground)">{total}</text>
        <text x={60} y={74} textAnchor="middle" fontSize={9} fill="var(--faint)">总告警</text>
      </svg>
      <div className="flex-1">{rows}</div>
    </div>
  );
}

export function BarList({ items, emptyText = '暂无数据可供排行' }: {
  items?: { name: string; value: number }[]; emptyText?: string;
}) {
  if (!items || !items.length) return <div className="px-4 py-8 text-center text-[13px] text-faint">{emptyText}</div>;
  const max = Math.max(1, ...items.map((i) => i.value));
  return (
    <div>
      {items.map((it) => (
        <div key={it.name} className="mb-2 flex items-center gap-2.5 text-[12.5px]">
          <span className="w-[150px] truncate text-muted-foreground" title={it.name}>{it.name}</span>
          <span className="h-1.5 flex-1 overflow-hidden rounded-full bg-border-soft">
            <i className="block h-full rounded-full bg-gradient-to-r from-primary to-[var(--chart-crit)] transition-[width] duration-500" style={{ width: `${Math.max(2, (it.value / max) * 100)}%` }} />
          </span>
          <span className="w-9 text-right tabular-nums text-faint">{it.value}</span>
        </div>
      ))}
    </div>
  );
}
