// ReportPage（Misc.tsx 拆分生成，2026-11-22 god file 治理）。
import { useEffect, useState } from 'react';
import { api } from '../lib/api';
import { IntegrityReport } from '../lib/types';
import { useError } from '../lib/hooks';
import { cn } from '../lib/utils';
import { Card, SkeletonRows, Badge, CardTitle } from '../components/ui/basics';

interface WeeklyReport {
  alerts_week?: number; resolved_week?: number; fp_rate?: number;
  mttr_min?: number; hosts_active?: number;
  fp_ranking?: { rule_id: string; fp_rate: number; false_pos: number; handled: number; tune_candidate?: boolean }[];
  [k: string]: unknown;
}

export function ReportPage() {
  const err = useError();
  const [rep, setRep] = useState<WeeklyReport | null>(null);
  const [ig, setIg] = useState<IntegrityReport | null>(null);

  useEffect(() => {
    api.get<WeeklyReport>('/api/v1/report/weekly').then(setRep).catch(err.capture);
    api.get<IntegrityReport>('/api/v1/integrity').then(setIg).catch(() => setIg(null));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  if (err.rendered) return err.rendered;
  if (!rep) return <Card className="p-4"><SkeletonRows rows={6} /></Card>;

  return (
    <div className="space-y-3.5">
      <Card className="p-0">
        {/* 与概览 KPI 同构：单面板 + 发丝线分隔 + mono 读数 */}
        <div className="grid grid-cols-2 divide-border-soft md:grid-cols-4 md:divide-x">
          {([
            ['本周新增告警', rep.alerts_week, '过去 7 天'],
            ['本周已处置', rep.resolved_week, '含确认/解决/误报'],
            ['综合误报率', rep.fp_rate != null ? `${(rep.fp_rate * 100).toFixed(1)}%` : null, '已处置样本中的误报占比'],
            ['平均处置时长', rep.mttr_min != null ? `${Math.round(rep.mttr_min)} 分钟` : null, '创建 → 处置'],
          ] as [string, string | number | null, string][]).map(([label, v, sub]) => (
            <div key={label} className="px-4 py-3.5">
              <div className="text-[11px] tracking-[.5px] text-faint">{label}</div>
              <div className="anim-digit mt-1.5 font-mono text-[26px] leading-none font-semibold tabular-nums">{v ?? '—'}</div>
              <div className="mt-1.5 text-[11.5px] text-faint">{sub}</div>
            </div>
          ))}
        </div>
      </Card>

      <Card className="p-4">
        <CardTitle className="mb-3">误报率最高的规则（需 ≥5 次处置）</CardTitle>
        {(rep.fp_ranking || []).length ? (
          <>
            {rep.fp_ranking!.map((r) => (
              <div key={r.rule_id} className="mb-2 flex items-center gap-2.5">
                <span className="w-[90px] font-mono text-xs">{r.rule_id}</span>
                <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-border-soft">
                  <i className={cn('block h-full rounded-full', r.fp_rate > 0.5 ? 'bg-destructive' : 'bg-warn')} style={{ width: `${Math.round(r.fp_rate * 100)}%` }} />
                </div>
                <span className="w-28 text-xs text-faint">{r.false_pos}/{r.handled} 误报</span>
                <b className={cn('w-12 text-right', r.fp_rate > 0.5 ? 'text-destructive' : 'text-warn')}>{Math.round(r.fp_rate * 100)}%</b>
                {r.tune_candidate && <Badge tone="medium" title="已处置 ≥5 条且误报率 ≥80%：建议核对该规则的匹配条件与阈值，或为已确认的良性场景配置白名单">调优候选</Badge>}
              </div>
            ))}
            <div className="mt-2.5 text-xs text-faint">高误报规则建议核对命中样本后加白，或在规则页调整分值。</div>
          </>
        ) : <div className="px-2 py-6 text-center text-[13px] text-faint">处置样本不足，暂无排名</div>}
      </Card>

      {ig && (
        <Card className="p-4">
          <CardTitle className="mb-3">告警完整性链（日志防篡改校验）</CardTitle>
          <div className="mb-3 flex flex-wrap items-center gap-2">
            <Badge tone="resolved">完好 {ig.ok} 天</Badge>
            {ig.purged > 0 && <Badge tone="neutral">已按策略清理 {ig.purged} 天</Badge>}
            {ig.tampered > 0 && <Badge tone="critical">校验异常 {ig.tampered} 天</Badge>}
            <div className="flex-1" />
            <span className="text-[11.5px] text-faint">
              {ig.tampered === 0 ? '全链校验通过：告警记录未被篡改，可作为合规证据导出。' : '存在校验异常日期——请立即核对数据库访问记录。'}
            </span>
          </div>
          <div className="flex flex-wrap gap-1">
            {ig.days.map((d) => (
              <span key={d.day} title={`${d.day} · ${d.status === 'ok' ? '完好' : d.status === 'purged' ? '已清理' : '校验异常'}`}
                className={cn('h-4 w-4 rounded-[3px] border',
                  d.status === 'ok' && 'border-ok/30 bg-ok-soft',
                  d.status === 'purged' && 'border-border bg-secondary',
                  d.status === 'tampered' && 'border-crit/50 bg-crit-soft')} />
            ))}
          </div>
          <p className="mt-2.5 text-xs text-faint">每个方块代表一天：<span className="text-ok">绿=哈希链完好</span>，灰=按保留策略清理，<span className="text-crit">红=校验异常</span>。</p>
        </Card>
      )}

      <p className="text-xs text-faint">本报表按当前数据实时生成，可在浏览器中打印为 PDF 存档或发送给管理层。</p>
    </div>
  );
}

