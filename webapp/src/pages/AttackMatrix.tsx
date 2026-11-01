import { useCallback, useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Crosshair } from 'lucide-react';
import { api } from '../lib/api';
import { Card, CardTitle, EmptyState, Skeleton } from '../components/ui/basics';
import { useError } from '../lib/hooks';
import type { AttackMatrix as Matrix } from '../lib/types';
import { cn } from '../lib/utils';

/* ATT&CK 战术×技术矩阵（GET /api/v1/attack/matrix）。
   格子四态是本页的语义核心：
   · 命中（有告警）——按 critical 数值着色深浅
   · 覆盖（有规则）——ok 边框：检出能力在位
   · 命中+覆盖——检出了且能力在位
   · 空白——该技术此窗口内无告警也无规则
   "只有命中没有覆盖 = 检出靠运气；只有覆盖没有命中 = 安静态（好事）"——domain.go */

const WINDOWS = [7, 30, 90, 365];

export function AttackMatrixPage() {
  const err = useError();
  const navigate = useNavigate();
  const [days, setDays] = useState(30);
  const [m, setM] = useState<Matrix | null>(null);
  const [loading, setLoading] = useState(true);

  const load = useCallback(async () => {
    setLoading(true);
    try { setM(await api.get<Matrix>(`/api/v1/attack/matrix?days=${days}`)); }
    catch (e) { err.capture(e); }
    finally { setLoading(false); }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [days]);

  useEffect(() => { load(); }, [load]);
  if (err.rendered) return err.rendered;

  const drill = (techId: string) => navigate(`/alerts?mitre=${encodeURIComponent(techId)}`);

  return (
    <div>
      {/* 摘要带：单面板 + 发丝线，与概览 KPI 同构 */}
      <div className="mb-3.5 grid grid-cols-2 divide-border-soft rounded-md border border-border-soft bg-card md:grid-cols-4 md:divide-x">
        <Stat label="命中的技术" value={m?.summary.techniques_hit ?? 0} sub="有真实告警" loading={loading} />
        <Stat label="已覆盖的技术" value={m?.summary.techniques_covered ?? 0} sub="有检测规则在位" loading={loading} />
        <Stat label="窗口内告警" value={m?.summary.total_alerts ?? 0} sub={`近 ${m?.window_days ?? days} 天`} loading={loading} mono />
        <Stat label="未映射告警" value={m?.summary.unmapped ?? 0} sub="技术编号在目录外" loading={loading} />
      </div>

      <div className="mb-3 flex items-center gap-2">
        <div className="flex-1" />
        <div className="flex items-center gap-1 rounded-md border border-border-soft bg-card p-0.5">
          {WINDOWS.map((w) => (
            <button key={w} onClick={() => setDays(w)}
              className={cn('cursor-pointer rounded-[5px] px-2.5 py-1 font-mono text-[11.5px] transition-colors',
                days === w ? 'bg-primary font-semibold text-primary-foreground' : 'text-muted-foreground hover:bg-accent')}>
              {w}d
            </button>
          ))}
        </div>
      </div>

      {!m && loading ? (
        <Card className="p-4"><Skeleton className="h-[420px] w-full" /></Card>
      ) : !m || !m.tactics.length ? (
        <Card><EmptyState tone="ok" icon={<Crosshair size={20} />} title="该窗口内没有 ATT&CK 命中——环境安静"
          sub="命中是坏事没发生，覆盖是坏事来了能抓。两者都看这张矩阵。" /></Card>
      ) : (
        <div className="flex gap-3 overflow-x-auto pb-2">
          {m.tactics.map((t) => (
            <Card key={t.id} className="w-[248px] shrink-0 p-3">
              <CardTitle className="mb-0.5">{t.name_zh}</CardTitle>
              <div className="mb-2.5 font-mono text-[10.5px] text-ghost">{t.id} · {t.name}</div>
              <div className="flex flex-col gap-1">
                {t.techniques.map((tech) => {
                  const hit = tech.alert_count > 0;
                  const covered = tech.rule_count > 0;
                  const intense = tech.critical_count > 0;
                  return (
                    <button key={tech.id} onClick={() => drill(tech.id)}
                      title={`${tech.id} ${tech.name_zh}\n告警 ${tech.alert_count}（未处置 ${tech.open_count} / 严重 ${tech.critical_count}）· 规则覆盖 ${tech.rule_count}${tech.last_seen ? `\n最后命中 ${tech.last_seen}` : ''}\n点击下钻告警`}
                      className={cn(
                        'flex cursor-pointer items-center gap-2 rounded-[5px] border px-2 py-1.5 text-left transition-colors',
                        hit && intense && 'border-crit/40 bg-crit-soft hover:border-crit/70',
                        hit && !intense && 'border-destructive/25 bg-destructive-soft hover:border-destructive/50',
                        !hit && covered && 'border-ok/30 bg-ok-soft hover:border-ok/60',
                        !hit && !covered && 'border-transparent hover:bg-accent',
                      )}>
                      <span className={cn('font-mono text-[11px]', hit ? 'text-foreground' : 'text-faint')}>{tech.id}</span>
                      <span className={cn('flex-1 truncate text-[11.5px]', hit ? 'font-medium text-foreground' : 'text-muted-foreground')}>{tech.name_zh || tech.name}</span>
                      {hit && <span className="font-mono text-[11px] font-semibold tabular-nums text-crit">{tech.alert_count}</span>}
                      {!hit && covered && <span className="text-[10px] text-ok">覆盖</span>}
                    </button>
                  );
                })}
                {!t.techniques.length && <div className="py-3 text-center text-[11px] text-ghost">无技术</div>}
              </div>
            </Card>
          ))}
        </div>
      )}

      <div className="mt-3 flex flex-wrap items-center gap-4 text-[11.5px] text-faint">
        <span className="inline-flex items-center gap-1.5"><i className="h-2.5 w-2.5 rounded-[3px] border border-crit/40 bg-crit-soft" />命中且含严重告警</span>
        <span className="inline-flex items-center gap-1.5"><i className="h-2.5 w-2.5 rounded-[3px] border border-destructive/25 bg-destructive-soft" />命中</span>
        <span className="inline-flex items-center gap-1.5"><i className="h-2.5 w-2.5 rounded-[3px] border border-ok/30 bg-ok-soft" />规则覆盖（安静态）</span>
        <span>点击任意格子 → 按技术编号精确下钻告警中心</span>
        {m && <span className="font-mono text-ghost">生成于 {new Date(m.generated_at).toLocaleTimeString('zh-CN', { hour12: false })}</span>}
      </div>
    </div>
  );
}

function Stat({ label, value, sub, loading, mono }: { label: string; value: number; sub: string; loading?: boolean; mono?: boolean }) {
  return (
    <div className="px-4 py-3.5">
      <div className="text-[11px] tracking-[.5px] text-faint">{label}</div>
      <div className={`mt-1.5 text-[24px] leading-none font-semibold tabular-nums ${mono ? 'font-mono' : ''}`}>
        {loading ? <Skeleton className="h-6 w-14" /> : value}
      </div>
      <div className="mt-1.5 text-[11.5px] text-faint">{sub}</div>
    </div>
  );
}
