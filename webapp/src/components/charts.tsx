import { useEffect, useRef, useState } from 'react';
import { EmptyState, Skeleton } from './ui/basics';
import { ShieldCheck } from 'lucide-react';
import { SEV_LABEL } from '../lib/format';

/* 纯 SVG 图表：色彩走 CSS 变量（双主题自动适配），带生长/扫入动效 */

export interface HourPoint { bucket: string; total: number; critical: number }

export function TimelineChart({ points, loading }: { points?: HourPoint[]; loading?: boolean }) {
  // viewBox 宽度必须与容器实测像素 1:1——否则 preserveAspectRatio="none" 会把
  // 坐标系连同 <text> 一起横向拉伸，时间刻度被拉成"2 3 : 0 0"（2026-11-14 用户实测）。
  // 测量 div 常驻（loading/空态也不卸载），保证 observer 在数据到达前已挂上。
  const wrapRef = useRef<HTMLDivElement>(null);
  const [vw, setVw] = useState(0);
  useEffect(() => {
    const el = wrapRef.current;
    if (!el) return;
    const ro = new ResizeObserver((entries) => {
      const w = entries[0]?.contentRect.width ?? 0;
      setVw((prev) => (Math.abs(prev - w) < 1 ? prev : Math.round(w)));
    });
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  let body: React.ReactNode;
  if (loading) {
    body = <div className="px-1 py-3"><Skeleton className="h-[130px] w-full" /></div>;
  } else if (!points || !points.length) {
    body = <EmptyState icon={<ShieldCheck size={20} />} title="所选时间范围内没有告警——环境安静" />;
  } else {
    body = <TimelineSvg points={points} width={vw} />;
  }
  return <div ref={wrapRef}>{body}</div>;
}

function TimelineSvg({ points, width }: { points: HourPoint[]; width: number }) {
  const W = width || 680, H = 150, padL = 34, padB = 20, padT = 8;
  const innerW = W - padL - 8, innerH = H - padB - padT;
  const max = Math.max(1, ...points.map((p) => p.total));
  const bw = innerW / points.length;
  // 悬停读数：SOC 想知道"峰值到底是哪个小时"——跟随鼠标的小时级提示
  const [hov, setHov] = useState<number | null>(null);
  const onMove = (e: React.MouseEvent<SVGSVGElement>) => {
    const rect = e.currentTarget.getBoundingClientRect();
    if (!rect.width) return;
    const px = ((e.clientX - rect.left) / rect.width) * W;
    const i = Math.floor((px - padL) / bw);
    setHov(i >= 0 && i < points.length ? i : null);
  };
  const hp = hov !== null ? points[hov] : null;
  const hhh = hp ? String(new Date(hp.bucket).getHours()).padStart(2, '0') : '';
  // 提示框左右钳制在卡内（首尾桶的居中定位会出界）
  const tipPct = hov === null ? 0 : Math.min(92, Math.max(8, ((padL + hov * bw + bw / 2) / W) * 100));

  const grid: React.ReactNode[] = [];
  for (let i = 0; i <= 3; i++) {
    const v = Math.round((max / 3) * i);
    const y = padT + innerH - (i / 3) * innerH;
    grid.push(<line key={`g${i}`} x1={padL} y1={y} x2={W - 8} y2={y} stroke="var(--border-strong)" strokeWidth={1} />);
    // 坐标轴读数用 mono——仪表刻度感是本设计系统的记忆锚点
    grid.push(<text key={`t${i}`} x={padL - 6} y={y + 3.5} fontSize={9} fill="var(--faint)" textAnchor="end" style={{ fontFamily: 'var(--font-mono)' }}>{v}</text>);
  }

  const step = Math.max(1, Math.ceil(points.length / 6));
  const bars = points.map((p, i) => {
    if (i % step !== 0) return null;
    const d = new Date(p.bucket);
    const hh = String(d.getHours()).padStart(2, '0');
    const x = padL + i * bw + bw / 2;
    return <text key={`x${i}`} x={x} y={H - 5} fontSize={9} fill="var(--faint)" textAnchor="middle" style={{ fontFamily: 'var(--font-mono)' }}>{hh}:00</text>;
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
    <div className="relative">
      <svg viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="none" className="block h-[150px] w-full cursor-crosshair" onMouseMove={onMove} onMouseLeave={() => setHov(null)}>
        {grid}{rects}{bars}
        {hov !== null && <line x1={padL + hov * bw} y1={padT} x2={padL + hov * bw} y2={padT + innerH} stroke="var(--border-strong)" strokeWidth={1} />}
      </svg>
      {hp && (
        <div className="pointer-events-none absolute top-0 z-10 -translate-x-1/2 whitespace-nowrap rounded border border-border-strong bg-popover px-2 py-1 text-[10.5px] shadow-lg"
          style={{ left: `${tipPct}%` }}>
          <span className="font-mono">{hhh}:00</span>
          <span className="ml-1.5 text-muted-foreground">{hp.total} 条</span>
          {hp.critical > 0 && <span className="ml-1 font-medium" style={{ color: 'var(--crit)' }}>critical {hp.critical}</span>}
        </div>
      )}
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
      <b className="font-mono tabular-nums">{dist![k]}</b>
    </div>
  ));

  return (
    <div className="flex items-center gap-4.5">
      <svg viewBox="0 0 120 120" width={120} height={120} className="shrink-0">
        <circle cx={60} cy={60} r={R} fill="none" stroke="var(--border)" strokeWidth={14} />
        {arcs}
        <text x={60} y={58} textAnchor="middle" fontSize={20} fontWeight={700} fill="var(--foreground)" className="anim-digit" style={{ fontFamily: 'var(--font-mono)' }}>{total}</text>
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
        <div key={it.name} className="mb-2 flex items-center gap-2.5 text-[12.5px]" title={`${it.name}：${it.value} 条 · 占比 ${Math.round((it.value / max) * 100)}%`}>
          <span className="w-[150px] truncate text-muted-foreground">{it.name}</span>
          {/* 实色条：蓝→粉渐变是 slop 清单典型项；仪器读数不需要装饰 */}
          <span className="h-1.5 flex-1 overflow-hidden rounded-[3px] bg-border-soft">
            <i className="block h-full rounded-[3px] transition-[width] duration-500" style={{ width: `${Math.max(2, (it.value / max) * 100)}%`, background: 'var(--chart-bar)' }} />
          </span>
          <span className="w-10 text-right font-mono tabular-nums text-faint">{it.value}</span>
        </div>
      ))}
    </div>
  );
}
