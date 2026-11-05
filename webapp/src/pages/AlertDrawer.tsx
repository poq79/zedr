import { useCallback, useEffect, useState } from 'react';
import { BrainCircuit, ShieldBan } from 'lucide-react';
import { api } from '../lib/api';
import type { Alert, Investigation } from '../lib/types';
import { SEV_LABEL, VERDICT_LABEL, LAYER_LABEL, fmtTime } from '../lib/format';
import { Badge, Button, Card, EmptyState, Skeleton, Tabs } from '../components/ui/basics';
import { Drawer, useToast, useConfirm } from '../components/ui/overlays';

interface TriageResp {
  verdict: 'malicious' | 'suspicious' | 'benign' | 'inconclusive' | string;
  confidence: number; engine?: string; model?: string; grounded?: boolean;
  uncited?: number; degraded?: boolean; degraded_reason?: string;
  untrusted_ignored?: number; latency_ms?: number; narrative?: string;
  reasoning?: { text: string; citations?: string[] }[];
  actions?: { type: string; target?: string; detail?: string; requires_approval?: boolean }[];
  attack_chain?: string[];
}

// 置信档位（调研 Confidence Thermometer 口径）：档位+百分比并用；
// 低置信度必须用同等视觉权重明示"需人工复核"——不要把弱推断渲染得
// 和强证据一样，那会训练分析师照单全收。
function confBand(c?: number): { label: string; tone: string; note: string } {
  const v = c || 0;
  if (v >= 0.7) return { label: '高置信', tone: 'resolved', note: '证据充分，结论可直接采信' };
  if (v >= 0.45) return { label: '中置信', tone: 'medium', note: '部分证据支持，建议结合上下文核对' };
  return { label: '低置信', tone: 'acknowledged', note: '证据不足——结论仅供参考，必须人工复核后再处置' };
}

const TRIAGE_VERDICT: Record<string, [string, string]> = {
  malicious: ['恶意', 'critical'], suspicious: ['可疑', 'medium'],
  benign: ['倾向误报', 'resolved'], inconclusive: ['证据不足', 'info'],
};

export function AlertDrawer({ alertId, onClose, onChanged, canWrite }: {
  alertId: string | null; onClose: () => void; onChanged: () => void; canWrite: boolean;
}) {
  const toast = useToast();
  const confirm = useConfirm();
  const [a, setA] = useState<Alert | null>(null);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState('');
  /* 证据链 / AI 研判 / 自动调查 / AI 调查 四卡：抽屉一屏一屏看 */
  const [tab, setTab] = useState<'evidence' | 'ai' | 'investigate' | 'agent'>('evidence');

  useEffect(() => {
    if (alertId == null) { setA(null); setErr(''); return; }
    setLoading(true); setErr('');
    api.get<Alert>(`/api/v1/alerts/${encodeURIComponent(alertId)}`)
      .then(setA)
      .catch((e) => setErr((e as Error).message))
      .finally(() => setLoading(false));
  }, [alertId]);

  const setStatus = async (status: string) => {
    if (!a) return;
    try {
      await api.post(`/api/v1/alerts/${a.id}/status`, { status });
      toast(`已标记为「${{ acknowledged: '已确认', resolved: '已解决', false_positive: '误报' }[status] || status}」`);
      onChanged();
      onClose();
    } catch (e) { toast((e as Error).message, 'err'); }
  };

  const allow = async (type: 'hash' | 'path') => {
    if (!a) return;
    const value = type === 'hash' ? a.hash_sha256 : a.image_path;
    if (!value) return toast(type === 'hash' ? '该告警没有文件哈希，无法按哈希加白' : '缺少镜像路径', 'warn');
    const ok = await confirm({
      title: type === 'hash' ? '将文件哈希加入白名单？' : '信任该路径？',
      message: type === 'hash'
        ? <>文件哈希：<code>{value}</code><br />加白后该文件在本机与服务端都不再告警，请确认这是可信程序。</>
        : <>该路径下的程序不再告警：<br /><code>{value}</code></>,
      danger: true, okText: type === 'hash' ? '仍要加白' : '信任此路径',
    });
    if (!ok) return;
    try {
      await api.post('/api/v1/allowlist', { type, value, note: `来自告警 ${a.id}（${a.process_name}）` });
      toast('已加入白名单');
      onChanged(); onClose();
    } catch (e) { toast((e as Error).message, 'err'); }
  };

  return (
    <Drawer
      open={alertId != null}
      onClose={onClose}
      width={820}
      title={loading ? '加载中…' : (a?.title || '告警详情')}
      sub={a && (
        <span className="flex flex-wrap items-center gap-2">
          <Badge tone={a.severity}>{SEV_LABEL[a.severity]}</Badge>
          {a.verdict && <Badge tone={a.verdict}>{VERDICT_LABEL[a.verdict]}</Badge>}
          <span>{fmtTime(a.created_at)}</span>
        </span>
      )}
      foot={a && canWrite && (
        <>
          <Button variant="primary" onClick={() => setStatus('acknowledged')}>确认处置</Button>
          <Button onClick={() => setStatus('resolved')}>标记已解决</Button>
          <Button onClick={() => setStatus('false_positive')}>标记误报</Button>
          <div className="flex-1" />
          <Button variant="ghost" onClick={() => allow('path')}><ShieldBan size={13} /> 信任此路径</Button>
          {a.hash_sha256 && <Button variant="ghost" onClick={() => allow('hash')}>按哈希加白</Button>}
        </>
      )}
    >
      {loading ? (
        <div className="space-y-3">{[70, 100, 85, 55].map((w, i) => <Skeleton key={i} style={{ width: `${w}%`, height: 14 }} />)}</div>
      ) : err ? (
        <EmptyState tone="warn" icon={<ShieldBan size={20} />} title={err} sub="可关闭后重试，或刷新页面。" />
      ) : a && (
        <div className="space-y-5">
          <Tabs className="mb-1" value={tab} onChange={(k) => setTab(k as 'evidence' | 'ai' | 'investigate' | 'agent')}
            tabs={[{ key: 'evidence', label: '证据链' }, { key: 'ai', label: 'AI 研判' }, { key: 'investigate', label: '自动调查' }, { key: 'agent', label: 'AI 调查' }]} />
          {tab === 'evidence' && (
            <div key="ev" className="anim-page space-y-5">
          {a.summary && (
            <Section title="结论">
              <div className="text-[12.5px] leading-[1.8]">{a.summary}</div>
            </Section>
          )}

          <Section title="置信分构成">
            <ScoreBar a={a} />
          </Section>

          <Section title="进程">
            <dl className="grid grid-cols-[110px_1fr] gap-x-3 gap-y-2 text-[12.5px]">
              <Kv k="进程名" v={a.process_name} mono />
              <Kv k="PID" v={String(a.pid)} mono />
              <Kv k="镜像路径" v={a.image_path} mono />
              <Kv k="SHA256" v={a.hash_sha256} mono />
              {a.cmdline && <><dt className="text-faint">命令行</dt><dd className="m-0 break-all"><pre className="m-0 rounded-lg border border-border bg-[var(--code-bg)] p-3 font-mono text-[11.5px] leading-[1.6] whitespace-pre-wrap text-[var(--code-fg)]">{a.cmdline}</pre></dd></>}
            </dl>
          </Section>

          {!!a.evidence?.signals?.length && (
            <Section title="命中信号">
              {a.evidence.signals.map((s, i) => (
                <div key={i} className="mb-1.5 flex items-start gap-2.5 rounded-lg border border-border-soft bg-secondary/60 px-3 py-2 text-[12.5px]" data-signal={i}>
                  <span className="mt-px shrink-0 rounded border border-border-soft bg-secondary px-1.5 py-0.5 text-[10px] tracking-[.4px] text-faint uppercase">{LAYER_LABEL[s.layer] || s.layer}</span>
                  <span className="min-w-0 flex-1">
                    <b>{s.name}</b>
                    {s.note && <div className="mt-0.5 text-xs text-faint">{s.note}</div>}
                  </span>
                  <span className="font-bold tabular-nums text-warn">+{s.score}</span>
                </div>
              ))}
            </Section>
          )}

          {!!a.evidence?.ancestry?.length && (
            <Section title="血缘链">
              <div className="font-mono text-xs leading-[1.9]">
                {a.evidence.ancestry.map((n, i) => (
                  <div key={i} style={{ paddingLeft: i * 14 }}>
                    <span className="text-faint">{i === 0 ? '●' : '└─'}</span>{' '}
                    <b className="font-sans">{n.name}</b> <span className="text-faint">PID {n.pid}</span>
                    {n.path && <div className="pl-5 font-sans text-[11.5px] break-all text-faint">{n.path}</div>}
                  </div>
                ))}
              </div>
            </Section>
          )}

          {!!a.evidence?.network?.length && (
            <Section title="网络连接">
              <table className="w-full text-xs">
                <thead><tr className="border-b border-border text-left text-faint">
                  <th className="py-1.5 pr-3 font-medium">协议</th><th className="py-1.5 pr-3 font-medium">本地</th>
                  <th className="py-1.5 pr-3 font-medium">远端</th><th className="py-1.5 font-medium">状态</th>
                </tr></thead>
                <tbody>
                  {a.evidence.network.map((c, i) => (
                    <tr key={i} className="border-b border-border-soft last:border-b-0">
                      <td className="py-2 pr-3 font-mono">{c.proto}</td>
                      <td className="py-2 pr-3 font-mono">{c.local_ip}:{c.local_port}</td>
                      <td className="py-2 pr-3 font-mono">{c.remote_ip}:{c.remote_port}</td>
                      <td className="py-2 text-faint">{c.state}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </Section>
          )}
            </div>
          )}
          {tab === 'ai' && (
            <div key="ai" className="anim-page"><AiPanel alertId={a.id} /></div>
          )}
          {tab === 'investigate' && (
            <div key="inv" className="anim-page"><InvestigatePanel alertId={a.id} /></div>
          )}
          {tab === 'agent' && (
            <div key="agent" className="anim-page"><AgentPanel alertId={a.id} /></div>
          )}
        </div>
      )}
    </Drawer>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section>
      <h3 className="mb-2.5 flex items-center gap-2 text-xs font-semibold tracking-[.5px] text-faint uppercase after:h-px after:flex-1 after:bg-border-soft after:content-['']">
        {title}
      </h3>
      {children}
    </section>
  );
}

function Kv({ k, v, mono }: { k: string; v?: string; mono?: boolean }) {
  return (<><dt className="text-faint">{k}</dt><dd className={`m-0 break-all ${mono ? 'font-mono text-xs' : ''}`}>{v || '-'}</dd></>);
}

function ScoreBar({ a }: { a: Alert }) {
  const ev = a.evidence || {};
  const parts: [string, number, string][] = [
    ['静态', ev.static_score || 0, 'var(--primary)'],
    ['关键词', ev.keyword_score || 0, 'var(--ok)'],
    ['规则', ev.rule_score || 0, 'var(--crit)'],
    ['血缘', ev.lineage_score || 0, 'var(--warn)'],
  ];
  const total = Math.max(1, parts.reduce((s, [, v]) => s + v, 0));
  return (
    <div>
      <div className="flex h-1.5 overflow-hidden rounded-full bg-border-soft">
        {parts.map(([n, v, c]) => <i key={n} style={{ width: `${(v / total) * 100}%`, background: c }} />)}
      </div>
      <div className="mt-2 flex flex-wrap gap-3 text-[11.5px] text-faint">
        {parts.map(([n, v, c]) => (
          <span key={n} className="inline-flex items-center gap-1.5"><i className="h-2 w-2 rounded-[2px]" style={{ background: c }} />{n} {v}</span>
        ))}
        <span className="ml-auto text-foreground">综合 <b>{a.score}</b> / 100</span>
      </div>
    </div>
  );
}

/* ---------------- AI 研判面板 ---------------- */

function AiPanel({ alertId }: { alertId: string }) {
  const toast = useToast();
  const [stats, setStats] = useState<{ enabled?: boolean; stats?: { model?: string; budget_used?: number; budget_cap?: number } } | null>(null);
  const [result, setResult] = useState<TriageResp | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    api.get<{ enabled?: boolean; stats?: { model?: string; budget_used?: number; budget_cap?: number } }>('/api/v1/ai/stats')
      .then(setStats).catch(() => setStats(null));
  }, [alertId]);

  const run = useCallback(async () => {
    setBusy(true);
    try {
      setResult(await api.post<TriageResp>(`/api/v1/alerts/${encodeURIComponent(alertId)}/triage`, {}));
    } catch (e) {
      toast(`分析失败：${(e as Error).message}`, 'err');
    } finally {
      setBusy(false);
    }
  }, [alertId, toast]);

  const engineBadge = stats
    ? (stats.enabled
      ? <Badge tone="resolved">模型 {stats.stats?.model || ''}</Badge>
      : <Badge tone="info">确定性引擎</Badge>)
    : <Badge tone="info">…</Badge>;

  return (
    <Section title="AI 研判">
      <div className="mb-2.5 flex flex-wrap items-center gap-2">
        {engineBadge}
        <Button size="sm" onClick={run} disabled={busy} className="ml-auto">
          <BrainCircuit size={13} /> {busy ? '分析中…' : result ? '重新分析' : '开始分析'}
        </Button>
      </div>
      <Card className="p-3.5">
        {!result && !busy && (
          <div className="text-xs leading-[1.8] text-faint">
            结合该告警的完整证据链做判断：给出结论、置信度、逐条可核对的理由，以及处置建议。
            <br />所有结论都会标注所依据的证据编号，可以逐条回到「命中信号」核对。
          </div>
        )}
        {busy && <div className="flex items-center gap-2 text-xs text-faint"><Skeleton className="w-40" /> 正在分析证据链…</div>}
        {result && <TriageBody r={result} />}
      </Card>
    </Section>
  );
}

function TriageBody({ r }: { r: TriageResp }) {
  const [vLabel, vTone] = TRIAGE_VERDICT[r.verdict] || ['未知', 'info'];
  const conf = Math.round((r.confidence || 0) * 100);
  return (
    <div className="text-[12.5px]">
      <div className="mb-3 flex flex-wrap items-center gap-2">
        <Badge tone={vTone} className="px-3 py-1 text-[14px]">{vLabel}</Badge>
        {(() => { const b = confBand(r.confidence); return <Badge tone={b.tone} title={b.note}>{b.label} {conf}%</Badge>; })()}
        <Badge tone={r.engine === 'llm' ? 'resolved' : 'info'}>{r.engine === 'llm' ? '大模型' : '确定性引擎'}</Badge>
        {r.model && <Badge tone="info">{r.model}</Badge>}
        <Badge tone={r.grounded ? 'resolved' : 'medium'}>{r.grounded ? '结论全部可溯源' : `${r.uncited} 条结论无引用`}</Badge>
        {r.degraded && <Badge tone="medium" title={r.degraded_reason}>已降级</Badge>}
        {(r.untrusted_ignored || 0) > 0 && (
          <Badge tone="critical" title="命令行/路径中包含试图操纵分析模型的指令，已隔离">拦截 {r.untrusted_ignored} 处注入</Badge>
        )}
        <span className="text-xs text-faint">{r.latency_ms || 0} ms</span>
      </div>

      {r.narrative && <div className="mb-3 leading-[1.8]">{r.narrative}</div>}

      <div className="mb-1.5 text-xs text-faint">判断依据（括号内为引用的证据编号）</div>
      {(r.reasoning || []).map((x, i) => {
        const isGuard = (x.text || '').startsWith('【护栏】');
        return (
          <div key={i} className={`mb-1.5 flex items-start justify-between gap-2.5 rounded-lg border px-3 py-2 ${isGuard ? 'border-crit/30 bg-crit-soft' : 'border-border-soft bg-secondary/60'}`}>
            <span className="min-w-0 flex-1">{x.text}</span>
            <span className="shrink-0 font-mono text-[11px]">
              {x.citations?.length
                ? x.citations.map((c) => <span key={c} className="mr-1 rounded border border-primary/30 bg-brand-soft px-1 py-px text-primary">{c}</span>)
                : <Badge tone="medium">无引用</Badge>}
            </span>
          </div>
        );
      })}

      <div className="mt-3.5 mb-1.5 text-xs text-faint">建议处置</div>
      {(r.actions || []).map((x, i) => (
        <div key={i} className="mb-1.5 flex items-start gap-2.5 rounded-lg border border-border-soft bg-secondary/60 px-3 py-2">
          <span className="mt-px shrink-0 rounded border border-border-soft bg-secondary px-1.5 py-0.5 text-[10px] tracking-[.4px] text-faint uppercase">{x.type}</span>
          <span className="min-w-0 flex-1">
            <b>{x.target || ''}</b>
            <div className="mt-0.5 text-xs text-faint">{x.detail || ''}</div>
          </span>
          <Badge tone={x.requires_approval ? 'medium' : 'info'}>{x.requires_approval ? '需人工确认' : '可自助'}</Badge>
        </div>
      ))}

      {!!r.attack_chain?.length && (
        <div className="mt-3">
          <div className="mb-1.5 text-xs text-faint">推测攻击链</div>
          <div className="font-mono text-xs leading-[1.9]">
            {r.attack_chain.map((c, i) => <div key={i}>{i + 1}. {c}</div>)}
          </div>
        </div>
      )}
    </div>
  );
}

/* Agentic 自动调查（POST /alerts/{id}/investigate）：
   五步确定性编排——每步都有 finding 与引用，建议动作标注服务端开关是否可用。 */
function InvestigatePanel({ alertId }: { alertId: string }) {
  const toast = useToast();
  const [inv, setInv] = useState<Investigation | null>(null);
  const [busy, setBusy] = useState(false);
  const [runErr, setRunErr] = useState('');

  const run = async () => {
    setBusy(true); setRunErr('');
    try {
      setInv(await api.post<Investigation>(`/api/v1/alerts/${encodeURIComponent(alertId)}/investigate`, {}));
    } catch (e) {
      setRunErr((e as Error).message);
      toast((e as Error).message, 'err');
    } finally { setBusy(false); }
  };

  const verdictTone = (v: string) => v === 'malicious' ? 'critical' : v === 'suspicious' ? 'medium' : v === 'benign' ? 'resolved' : 'info';

  return (
    <div>
      {!inv && (
        <div className="rounded-lg border border-border-soft bg-secondary/40 px-4 py-6 text-center">
          <p className="m-0 text-[12.5px] leading-[1.8] text-muted-foreground">
            自动调查会对这条告警执行五步确定性编排：<br />
            进程画像 → 家族/哈希关联 → 主机上下文 → 同源扩散 → 处置建议。<br />
            <span className="text-faint">每一步都给证据引用，不做黑盒判断。</span>
          </p>
          <Button variant="primary" className="mt-3.5" onClick={run} disabled={busy}>
            {busy ? '调查中…' : '开始自动调查'}
          </Button>
          {runErr && <div className="mt-2.5 text-xs text-destructive">{runErr}</div>}
        </div>
      )}

      {inv && (
        <div className="space-y-3">
          <div className="flex flex-wrap items-center gap-2.5 rounded-lg border border-border-soft bg-secondary/40 px-3.5 py-3">
            <span className="text-xs text-faint">研判建议</span>
            <Badge tone={verdictTone(inv.verdict_suggestion)}>{VERDICT_LABEL[inv.verdict_suggestion] || inv.verdict_suggestion}</Badge>
            {(() => { const b = confBand(inv.confidence); return <Badge tone={b.tone} title={b.note}>{b.label} {(inv.confidence * 100).toFixed(0)}%</Badge>; })()}
            <div className="flex-1" />
            <Button size="sm" variant="ghost" onClick={run} disabled={busy}>{busy ? '重算中…' : '重新调查'}</Button>
          </div>

          <div className="flex flex-col gap-1.5">
            {inv.steps.map((s, i) => (
              <div key={i} className="rounded-md border border-border-soft bg-card px-3.5 py-2.5" data-step={i}>
                <div className="flex items-center gap-2">
                  <span className="font-mono text-[11px] text-ghost">{String(i + 1).padStart(2, '0')}</span>
                  <b className="text-[12.5px]">{s.name}</b>
                  <span className="flex-1" />
                  {!!s.citations?.length && (
                    <span className="flex flex-wrap gap-1">
                      {s.citations.slice(0, 4).map((c) => <span key={c} className="rounded border border-primary/30 bg-brand-soft px-1 py-px font-mono text-[10.5px] text-primary">{c}</span>)}
                    </span>
                  )}
                </div>
                <div className="mt-1 text-[12.5px] leading-[1.7] text-muted-foreground">{s.finding}</div>
              </div>
            ))}
          </div>

          {!!inv.recommended_actions.length && (
            <div>
              <div className="mb-1.5 text-xs text-faint">建议处置</div>
              {inv.recommended_actions.map((a, i) => (
                <div key={i} className="mb-1.5 flex flex-wrap items-center gap-2.5 rounded-lg border border-border-soft bg-secondary/60 px-3 py-2">
                  <span className="rounded border border-border-soft bg-secondary px-1.5 py-0.5 font-mono text-[10.5px] uppercase text-faint">{a.action}</span>
                  <b className="min-w-0 flex-1 truncate font-mono text-[11.5px]" title={a.target}>{a.target || '-'}</b>
                  <Badge tone={a.available ? 'resolved' : 'neutral'}>{a.available ? '可用' : '服务端开关未启用'}</Badge>
                  {a.reason && <span className="w-full text-[11px] text-faint">{a.reason}</span>}
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

/* ---------------- Agentic 调查 v2 ---------------- */

interface AgentStepRec {
  step: number; tool: string; args?: string; result_preview?: string;
  result_bytes?: number; err?: string; latency_ms?: number;
}
interface AgentReportResp {
  summary: string; verdict: string; confidence: number;
  findings: { text: string; citations?: string[] }[];
  actions: { type: string; target?: string; detail?: string; requires_approval?: boolean }[];
  steps: AgentStepRec[]; tool_calls: number; steps_limit_reached: boolean;
  grounded: boolean; uncited: number; model?: string; engine: string;
  latency_ms: number; degraded: boolean; degraded_reason?: string;
}

function AgentPanel({ alertId }: { alertId: string }) {
  const toast = useToast();
  const [rep, setRep] = useState<AgentReportResp | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState('');

  useEffect(() => {
    api.get<AgentReportResp>(`/api/v1/alerts/${encodeURIComponent(alertId)}/agent-investigation`)
      .then(setRep).catch(() => { /* 无缓存是常态 */ });
  }, [alertId]);

  const run = async () => {
    setBusy(true); setErr('');
    try {
      setRep(await api.post<AgentReportResp>(`/api/v1/alerts/${encodeURIComponent(alertId)}/investigate/agent`, {}));
    } catch (e) {
      setErr((e as Error).message);
      toast((e as Error).message, 'err');
    } finally { setBusy(false); }
  };

  const verdictTone = (v: string) => v === 'malicious' ? 'critical' : v === 'suspicious' ? 'medium' : v === 'benign' ? 'resolved' : 'info';

  return (
    <div>
      {!rep && (
        <div className="rounded-lg border border-border-soft bg-secondary/40 px-4 py-6 text-center">
          <p className="m-0 text-[12.5px] leading-[1.8] text-muted-foreground">
            AI 调查让模型自主决定查什么：同哈希是否跨主机、是否命中情报库、<br />
            同指纹是否复发性误报、资产清单里有没有持久化痕迹——每一步工具调用都可见。<br />
            <span className="text-faint">工具只有只读七件；未配置模型时自动回退确定性五步。</span>
          </p>
          <Button variant="primary" className="mt-3.5" onClick={run} disabled={busy}>
            {busy ? '调查中…' : '开始 AI 调查'}
          </Button>
          {err && <div className="mt-2.5 text-xs text-destructive">{err}</div>}
        </div>
      )}

      {rep && (
        <div className="space-y-3">
          {err && <div className="text-xs text-destructive">{err}</div>}
          <div className="flex flex-wrap items-center gap-2 rounded-lg border border-border-soft bg-secondary/40 px-3.5 py-3">
            <Badge tone={verdictTone(rep.verdict)}>{VERDICT_LABEL[rep.verdict] || rep.verdict}</Badge>
            <span className="text-xs text-faint">置信度 <b className="font-mono text-foreground">{(rep.confidence * 100).toFixed(0)}%</b></span>
            <Badge tone={rep.engine === 'llm' ? 'resolved' : 'info'}>{rep.engine === 'llm' ? 'Agent（模型）' : '确定性回退'}</Badge>
            {rep.model && <Badge tone="info">{rep.model}</Badge>}
            <Badge tone={rep.grounded ? 'resolved' : 'medium'}>{rep.grounded ? '结论全部可溯源' : `${rep.uncited} 条结论无引用`}</Badge>
            {rep.steps_limit_reached && <Badge tone="medium" title="达到步数上限，模型用已有结果收尾">步数触顶</Badge>}
            {rep.degraded && <Badge tone="medium" title={rep.degraded_reason}>降级</Badge>}
            <span className="text-xs text-faint">{rep.tool_calls} 次工具调用 · {rep.latency_ms}ms</span>
            <div className="flex-1" />
            <Button size="sm" variant="ghost" onClick={run} disabled={busy}>{busy ? '重算中…' : '重新调查'}</Button>
          </div>

          {rep.degraded && rep.degraded_reason && (
            <div className="rounded-md border border-warn/30 bg-warn-soft px-3 py-2 text-[11.5px] text-warn">{rep.degraded_reason}</div>
          )}

          {rep.summary && <div className="text-[12.5px] leading-[1.8]">{rep.summary}</div>}

          <div className="mb-1.5 text-xs text-faint">调查发现（括号内为引用）</div>
          {rep.findings.map((f, i) => (
            <div key={i} className="mb-1.5 flex items-start justify-between gap-2.5 rounded-lg border border-border-soft bg-secondary/60 px-3 py-2 text-[12.5px]">
              <span className="min-w-0 flex-1">{f.text}</span>
              <span className="shrink-0 font-mono text-[11px]">
                {f.citations?.length
                  ? f.citations.map((c) => <span key={c} className="mr-1 rounded border border-primary/30 bg-brand-soft px-1 py-px text-primary">{c}</span>)
                  : <Badge tone="medium">无引用</Badge>}
              </span>
            </div>
          ))}

          <div className="mb-1.5 mt-3 text-xs text-faint">工具调用时间线</div>
          <div className="flex flex-col gap-1.5">
            {rep.steps.map((s, i) => (
              <div key={i} className="rounded-md border border-border-soft bg-card px-3.5 py-2.5">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="font-mono text-[11px] text-ghost">{String(s.step).padStart(2, '0')}</span>
                  <b className="font-mono text-[12px]">{s.tool}</b>
                  {s.args && <span className="max-w-[280px] truncate font-mono text-[11px] text-faint" title={s.args}>{s.args}</span>}
                  <span className="flex-1" />
                  {s.result_bytes !== undefined && <span className="font-mono text-[10.5px] text-ghost">{s.result_bytes}B</span>}
                  {s.err && <Badge tone="medium" title={s.err}>错误</Badge>}
                </div>
                {s.result_preview && <div className="mt-1 max-h-16 overflow-hidden text-[11.5px] leading-[1.6] text-muted-foreground">{s.result_preview}</div>}
                {s.err && <div className="mt-1 text-[11.5px] text-destructive">{s.err}</div>}
              </div>
            ))}
          </div>

          {!!rep.actions.length && (
            <div>
              <div className="mb-1.5 text-xs text-faint">建议处置（全部需人工确认）</div>
              {rep.actions.map((a, i) => (
                <div key={i} className="mb-1.5 flex items-start gap-2.5 rounded-lg border border-border-soft bg-secondary/60 px-3 py-2 text-[12px]">
                  <span className="mt-px shrink-0 rounded border border-border-soft bg-secondary px-1.5 py-0.5 text-[10px] tracking-[.4px] text-faint uppercase">{a.type}</span>
                  <span className="min-w-0 flex-1"><b>{a.target || ''}</b><div className="mt-0.5 text-[11.5px] text-faint">{a.detail || ''}</div></span>
                  <Badge tone="medium">需人工确认</Badge>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
