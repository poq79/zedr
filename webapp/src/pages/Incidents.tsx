// IncidentsPage（Misc.tsx 拆分生成，2026-11-22 god file 治理）。
import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { RefreshCw, Sparkles, ShieldCheck } from 'lucide-react';
import { api } from '../lib/api';
import { Burst, Role, Incident } from '../lib/types';
import { relTime, SEV_LABEL, fmtTime } from '../lib/format';
import { useError } from '../lib/hooks';
import { cn } from '../lib/utils';
import { Card, Badge, Button, SkeletonRows, Select, CardTitle, EmptyState } from '../components/ui/basics';
import { useToast, useConfirm, Drawer } from '../components/ui/overlays';

const INCIDENT_STATUS_LABEL: Record<string, string> = {
  open: '待调查', investigating: '调查中', contained: '已遏制', resolved: '已解决',
};
const INCIDENT_STATUS_TONE: Record<string, string> = {
  open: 'critical', investigating: 'medium', contained: 'info', resolved: 'resolved',
};

/* ---- 事件级 AI 检测：攻击链叙事的数据契约（对应 /api/v1/incidents/{id}/narrative） ---- */
interface NarrativePhase {
  name: string; tactic: string; tactic_id: string;
  alerts: string[]; description: string;
}
interface NarrativeAction { type: string; target: string; detail: string; requires_approval: boolean }
interface IncidentNarrative {
  summary: string; risk_score: number;
  phases: NarrativePhase[]; missing_phases?: string[]; coverage?: string[];
  actions?: NarrativeAction[];
  grounded: boolean; uncited: number; untrusted_ignored: number;
  model: string; engine: string; latency_ms: number;
  degraded: boolean; degraded_reason?: string;
}
interface IncidentNarrativeView {
  incident_id: string; hostname: string; alert_total: number;
  narrative: IncidentNarrative; generated_at: string;
}

export function IncidentsPage({ user }: { user?: { role: Role } }) {
  const err = useError();
  const toast = useToast();
  const confirm = useConfirm();
  const navigate = useNavigate();
  const [data, setData] = useState<{ items: Incident[]; bursts: Burst[] } | null>(null);
  const [tick, setTick] = useState(0);
  const [status, setStatus] = useState('');
  const [busyId, setBusyId] = useState('');
  const [narr, setNarr] = useState<IncidentNarrativeView | null>(null);
  const [narrOpen, setNarrOpen] = useState(false);
  const [narrBusy, setNarrBusy] = useState('');
  const canWrite = !user || user.role !== 'viewer';

  useEffect(() => {
    const qs = new URLSearchParams({ limit: '100' });
    if (status) qs.set('status', status);
    api.get<{ items: Incident[]; bursts?: Burst[] }>(`/api/v1/incidents?${qs.toString()}`)
      .then((r) => setData({ items: r.items || [], bursts: r.bursts || [] }))
      .catch(err.capture);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [tick, status]);

  if (err.rendered) return err.rendered;
  if (!data) return <Card className="p-4"><SkeletonRows rows={5} /></Card>;

  const { items, bursts } = data;

  /* 状态机只允许前进：open → investigating → contained → resolved（contained 可直接 resolved） */
  const NEXT: Record<string, Array<{ to: Incident['status']; label: string; danger?: boolean; note: string }>> = {
    open: [
      { to: 'investigating', label: '开始调查', note: '事件进入调查阶段' },
      { to: 'contained', label: '已遏制', note: '威胁已遏制' },
      { to: 'resolved', label: '直接解决', note: '事件已解决' },
    ],
    investigating: [
      { to: 'contained', label: '已遏制', note: '威胁已遏制' },
      { to: 'resolved', label: '解决', note: '事件已解决' },
    ],
    contained: [
      { to: 'resolved', label: '解决', note: '事件已解决' },
    ],
  };

  const transition = async (it: Incident, to: Incident['status'], label: string, note: string) => {
    const ok = await confirm({
      title: `${label}：「${it.title}」？`,
      message: `状态 ${it.status} → ${to}。\n状态机只允许前进、不可回退（避免 SLA 计时失真）。`,
      okText: label, danger: to === 'resolved',
    });
    if (!ok) return;
    setBusyId(it.id);
    try {
      await api.post(`/api/v1/incidents/${encodeURIComponent(it.id)}/status`, { status: to, note });
      toast(`事件已更新为「${INCIDENT_STATUS_LABEL[to]}」`);
      setTick((t) => t + 1);
    } catch (e) { toast((e as Error).message, 'err'); }
    finally { setBusyId(''); }
  };

  /* AI 攻击链：有缓存直接开；没有则确认后生成（可能触发模型调用）。 */
  const openNarrative = async (it: Incident) => {
    setNarrBusy(it.id);
    try {
      const cached = await api.get<IncidentNarrativeView | null>(`/api/v1/incidents/${encodeURIComponent(it.id)}/narrative`);
      setNarrBusy('');
      if (cached) { setNarr(cached); setNarrOpen(true); return; }
      const ok = await confirm({
        title: '生成 AI 攻击链叙事？',
        message: '将把本事件的多条告警按时间线重建为攻击链（阶段 / 风险 / 缺失环节）。配置模型时会调用一次模型并消耗 token；未配置时由确定性引擎完成。',
        okText: '生成',
      });
      if (!ok) return;
      setNarrBusy(it.id);
      const v = await api.post<IncidentNarrativeView>(`/api/v1/incidents/${encodeURIComponent(it.id)}/narrate`, {});
      setNarr(v); setNarrOpen(true);
    } catch (e) { toast((e as Error).message, 'err'); }
    finally { setNarrBusy(''); }
  };

  return (
    <div>
      {bursts.length > 0 && (
        <Card className="mb-3 border-l-3 border-l-crit p-4" style={{ background: 'linear-gradient(90deg, var(--destructive-soft), transparent)' }}>
          <div className="flex flex-wrap items-center gap-2.5">
            <Badge tone="critical" className="text-xs">⚠ 跨主机爆发 ×{bursts.length}</Badge>
            <span className="text-[13px]">同一份载荷在多台主机同时出现——横向移动 / 蠕虫式投递信号，优先处置：</span>
          </div>
          {bursts.map((b, i) => (
            <div key={i} className="mt-2.5 rounded-lg bg-secondary px-3 py-2.5">
              <div className="flex flex-wrap items-center gap-2.5">
                <b className="font-mono text-xs">{b.hash.slice(0, 16)}…</b>
                <Badge tone="high">{b.host_count} 台主机</Badge>
                <Badge tone="info">{b.alert_count} 条告警</Badge>
                <Badge tone={b.peak_severity === 'critical' ? 'critical' : 'medium'}>{b.peak_severity}</Badge>
                <span className="text-xs text-faint">{b.hosts.join(' · ')}</span>
              </div>
              <div className="mt-1 text-xs text-faint">{b.title_sample || ''}</div>
            </div>
          ))}
        </Card>
      )}

      <div className="mb-3 flex flex-wrap items-center gap-2.5">
        <span className="text-xs text-faint">同主机 · 相邻间隔 ≤30 分钟的告警聚类为事件 · 状态机只前进</span>
        <div className="flex-1" />
        <Select value={status} onChange={(e) => setStatus(e.target.value)}>
          <option value="">全部状态</option>
          {Object.entries(INCIDENT_STATUS_LABEL).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
        </Select>
        <Button size="sm" onClick={() => setTick((t) => t + 1)}><RefreshCw size={13} /> 刷新</Button>
      </div>

      {!items.length ? (
        <Card><EmptyState icon={<ShieldCheck size={20} />} title="当前没有事件"
          sub="这是好事——说明各终端都在安静运行，没有形成攻击链的行为序列。事件会在多条相关告警出现时自动聚类并持久化。" /></Card>
      ) : items.map((it) => {
        const durSec = Math.max(0, (new Date(it.last_seen).getTime() - new Date(it.first_seen).getTime()) / 1000);
        const dur = durSec >= 3600 ? `${Math.round(durSec / 3600)} 小时` : durSec >= 60 ? `${Math.round(durSec / 60)} 分钟` : '<1 分钟';
        const nexts = canWrite ? (NEXT[it.status] || []) : [];
        return (
          <Card key={it.id} className={cn('mb-3 p-4', `border-l-3 ${it.peak_severity === 'critical' ? 'border-l-crit' : it.peak_severity === 'high' ? 'border-l-destructive' : it.peak_severity === 'medium' ? 'border-l-warn' : 'border-l-border'}`)}>
            <div className="flex flex-wrap items-center gap-3">
              <Badge tone={it.peak_severity} className="px-3 py-1 text-[13px]">{SEV_LABEL[it.peak_severity] || it.peak_severity}</Badge>
              <div className="min-w-[220px] flex-1">
                <div className="flex flex-wrap items-center gap-1.5 font-semibold">
                  {it.title}
                  <Badge tone="info">{it.alert_count} 条告警</Badge>
                  {it.open_count > 0 ? <Badge tone="medium">待处置 {it.open_count}</Badge> : <Badge tone="resolved">告警全部处置</Badge>}
                  <Badge tone={INCIDENT_STATUS_TONE[it.status] || 'neutral'} title="事件处置状态">{INCIDENT_STATUS_LABEL[it.status] || it.status}</Badge>
                </div>
                <div className="mt-1 text-xs text-faint">
                  {it.hostname} · {fmtTime(it.first_seen)} → {fmtTime(it.last_seen)} · 持续 {dur} · 峰值分 <b className="font-mono">{it.max_score}</b>
                </div>
              </div>
              <Button size="sm" variant="ghost" onClick={() => navigate(`/alerts?q=${encodeURIComponent(it.hostname)}`)}>该主机告警</Button>
              <Button size="sm" disabled={narrBusy === it.id} onClick={() => openNarrative(it)}>
                <Sparkles size={12} /> {narrBusy === it.id ? '重建中…' : 'AI 攻击链'}
              </Button>
            </div>
            <div className="mt-3 flex flex-wrap gap-1.5">
              {(it.processes || []).slice(0, 6).map((p, i) => <Badge key={`p${i}`} tone="neutral" title="进程">{p}</Badge>)}
              {(it.rule_ids || []).slice(0, 4).map((r, i) => <Badge key={`r${i}`} tone="neutral" title="规则" >{r}</Badge>)}
              {(it.mitre || []).slice(0, 6).map((m, i) => <Badge key={`m${i}`} tone="info">{m}</Badge>)}
            </div>
            {it.note && <div className="mt-2 text-xs text-faint">备注：{it.note}</div>}
            {nexts.length > 0 && (
              <div className="mt-2.5 flex flex-wrap items-center gap-1.5 border-t border-border-soft pt-2.5">
                <span className="mr-1 text-[11px] text-ghost">推进状态：</span>
                {nexts.map((n) => (
                  <Button key={n.to} size="sm" variant={n.to === 'resolved' ? 'ghost' : 'default'}
                    disabled={busyId === it.id}
                    onClick={() => transition(it, n.to, n.label, n.note)}>{n.label}</Button>
                ))}
              </div>
            )}
          </Card>
        );
      })}

      {/* AI 攻击链叙事抽屉（事件级检测 L6） */}
      <Drawer open={narrOpen} onClose={() => setNarrOpen(false)} width={720}
        title="AI 攻击链叙事"
        sub={narr ? `${narr.hostname} · ${narr.alert_total} 条告警 · ${narr.narrative.engine === 'llm' ? 'LLM 引擎' : '确定性重建'}` : ''}
        foot={narr && (
          <>
            <Button variant="ghost" onClick={() => setNarrOpen(false)}>关闭</Button>
            <Button variant="primary" disabled={narrBusy === narr.incident_id}
              onClick={() => { const it = items.find((x) => x.id === narr.incident_id); if (it) { setNarrOpen(false); setTimeout(() => openNarrative(it), 120); } }}>
              <RefreshCw size={12} /> 重新生成
            </Button>
          </>
        )}>
        {narr && (
          <div>
            <div className="mb-3 flex flex-wrap items-center gap-2">
              <Badge tone={narr.narrative.risk_score >= 70 ? 'critical' : narr.narrative.risk_score >= 40 ? 'high' : 'medium'}>
                风险 {narr.narrative.risk_score}
              </Badge>
              {narr.narrative.grounded
                ? <Badge tone="online">阶段全部可溯源</Badge>
                : <Badge tone="medium">{narr.narrative.uncited} 个阶段无引用</Badge>}
              {narr.narrative.untrusted_ignored > 0 && <Badge tone="high">注入已隔离 ×{narr.narrative.untrusted_ignored}</Badge>}
              {narr.narrative.degraded && <Badge tone="medium">降级：{narr.narrative.degraded_reason || '确定性重建'}</Badge>}
              <span className="text-[11px] text-faint">{narr.narrative.model || 'heuristic'} · {narr.narrative.latency_ms}ms · {relTime(narr.generated_at)}</span>
            </div>
            <p className="mb-4 text-[13px] leading-[1.8] text-foreground">{narr.narrative.summary}</p>

            <CardTitle className="mb-2">攻击链阶段（按 ATT&CK 战术顺序）</CardTitle>
            <div className="mb-4 grid gap-2">
              {narr.narrative.phases.map((p, i) => (
                <div key={`${p.tactic_id}-${i}`} className="rounded-lg border border-border-soft bg-secondary/40 p-3">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="grid h-5 w-5 place-items-center rounded-full bg-primary text-[10px] font-bold text-primary-foreground">{i + 1}</span>
                    <b className="text-[12.5px] text-foreground">{p.name}</b>
                    <Badge tone="info">{p.tactic}{p.tactic_id ? ` · ${p.tactic_id}` : ''}</Badge>
                    <Badge tone="neutral">{p.alerts.length} 条告警</Badge>
                  </div>
                  <p className="mt-1.5 text-[12px] leading-[1.7] text-muted-foreground">{p.description}</p>
                  {!!p.alerts.length && (
                    <div className="mt-1.5 flex flex-wrap gap-1">
                      {p.alerts.slice(0, 8).map((id) => (
                        <span key={id} className="rounded border border-border-soft px-1.5 py-0.5 font-mono text-[10.5px] text-ghost" title="证据告警 ID">{id}</span>
                      ))}
                    </div>
                  )}
                </div>
              ))}
            </div>

            {!!narr.narrative.missing_phases?.length && (
              <div className="mb-3 text-[12px] text-faint">
                未观测到：{narr.narrative.missing_phases.join('、')}（可能已发生但未被检出，或尚未发生）
              </div>
            )}

            {!!narr.narrative.actions?.length && (
              <div>
                <CardTitle className="mb-2">建议动作（全部需人工确认）</CardTitle>
                <div className="grid gap-1.5">
                  {narr.narrative.actions.map((a, i) => (
                    <div key={i} className="flex flex-wrap items-center gap-2 text-[12px]">
                      <Badge tone="medium">{a.type}</Badge>
                      <span className="font-mono text-[11.5px]">{a.target}</span>
                      <span className="text-muted-foreground">{a.detail}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}
      </Drawer>
    </div>
  );
}

/* ================= 运营周报 ================= */

interface WeeklyReport {
  alerts_week?: number; resolved_week?: number; fp_rate?: number;
  mttr_min?: number; hosts_active?: number;
  fp_ranking?: { rule_id: string; fp_rate: number; false_pos: number; handled: number; tune_candidate?: boolean }[];
  [k: string]: unknown;
}

