import { useCallback, useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { Bot, CheckCircle2, ChevronDown, History, KeyRound, Pencil, Plus, Save, XCircle, FlaskConical } from 'lucide-react';
import { cn } from '../lib/utils';
import { api } from '../lib/api';
import { Badge, Button, Card, CardTitle, EmptyState, Input, Select, SkeletonRows } from '../components/ui/basics';
import { Drawer, useConfirm, useToast } from '../components/ui/overlays';
import { useError } from '../lib/hooks';
import { relTime, SEV_LABEL } from '../lib/format';

/* AI 平台：统一模型服务接入（Provider）+ 任务槽位差异 + 成本上限
   + 提示词模板 + 技能包。全部 admin-only；保存即时热生效（引擎热重载）。

   人性化口径：同一个模型服务只配一次（URL / Key / 默认模型 / 参数），
   任务槽位只声明差异（专用模型 / 专用思考强度 / 开关），留空跟随默认。
   "调查走另一家服务商"这类少数场景走槽位高级覆盖（默认折叠）。 */

interface ProviderView {
  base_url: string; model: string; effort: string;
  temperature: number; max_tokens: number; timeout_sec: number;
  has_key: boolean; key_hint?: string; source: string;
}
interface SlotView {
  enabled: boolean;
  model: string; effort: string;
  effective_model: string; effective_effort: string;
  override_base_url?: string; override_key_hint?: string;
  override_temperature?: number; override_max_tokens?: number; override_timeout_sec?: number;
  override_has_key?: boolean;
}
interface AIConfigView {
  provider: ProviderView;
  slots: Record<string, SlotView>;
  hourly_tokens: number; cache_ttl_sec: number;
  engine: string; engine_model: string;
  prompt_overridden: Record<string, boolean>;
  skill_count: number;
}
interface PromptVersion { version: number; content: string; created_by: string; created_at: string }
interface AIPrompt { task: string; content: string; updated_by: string; updated_at?: string; versions: PromptVersion[] }
interface AISkill {
  id: string; task: string; name: string; content: string;
  enabled: boolean; sort: number; created_by: string; created_at: string; updated_at: string;
}
interface ProbeResult { ok: boolean; latency_ms: number; models?: string[]; detail: string }

interface EvalMetrics {
  total: number; accuracy: number; malicious_recall: number; fp_rate: number; fn_rate: number;
  suspicious_not_benign: number; grounded_rate: number; uncited_ratio: number;
  approval_violations: number; injection_total: number; injection_intercepted: number;
  injection_flips: number; scanner_false_pos: number;
  avg_latency_ms: number; p95_latency_ms: number; degraded: number; errors: number;
  narrative_total?: number; narrative_grounded_rate?: number;
  narrative_tactic_coverage?: number; narrative_risk_ok?: number;
  narrative_injection_flips?: number;
}
interface EvalFailure { id: string; suite: string; expected: string; actual: string; why: string }
interface EvalRun {
  mode: string; engine: string; suite: string; started_at: string; duration_ms: number;
  metrics: EvalMetrics; violations?: string[]; passed: boolean; failures?: EvalFailure[];
}

const SLOT_META: Record<string, { label: string; desc: string }> = {
  triage: { label: '研判', desc: '告警研判：逐条结论带证据引用' },
  hunt: { label: '狩猎', desc: '自然语言查告警，翻译为受控查询' },
  investigate: { label: '调查', desc: '自动调查编排' },
  narrative: { label: '叙事', desc: '事件级攻击链重建（长上下文，可单独配强模型）' },
};
const SLOT_KEYS = ['triage', 'hunt', 'investigate', 'narrative'];

interface SlotStat { calls: number; avg_ms: number }
interface EngineStats { slots?: Record<string, SlotStat>; narrated?: number; triaged?: number }

/* 槽位前端草稿：主面（enabled/model/effort）+ 高级覆盖。
   key_draft 是正在输入的新密钥（空=保留旧值）；clear_key 标记删除已存密钥。 */
interface SlotDraft {
  enabled: boolean;
  model: string; effort: string;
  ov_base_url: string; ov_key_draft: string; ov_clear_key: boolean;
  ov_temperature: number | ''; ov_max_tokens: number | ''; ov_timeout_sec: number | '';
}

function slotToDraft(sv: SlotView): SlotDraft {
  return {
    enabled: sv.enabled, model: sv.model, effort: sv.effort,
    ov_base_url: sv.override_base_url || '', ov_key_draft: '', ov_clear_key: false,
    ov_temperature: sv.override_temperature ?? '',
    ov_max_tokens: sv.override_max_tokens ?? '',
    ov_timeout_sec: sv.override_timeout_sec ?? '',
  };
}

/* ---------------- 统一服务接入卡片 ---------------- */
function ProviderCard({ p, onTest, testing, probe }: {
  p: ProviderView; onTest: () => void; testing: boolean; probe: ProbeResult | null;
}) {
  return (
    <Card className="p-4">
      <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
        <div>
          <div className="flex items-center gap-2">
            <b className="text-[13px] text-foreground">模型服务（统一接入）</b>
            <Badge tone={p.source === 'db' ? 'info' : p.source === 'env' ? 'medium' : 'neutral'}>
              {p.source === 'db' ? '后台配置' : p.source === 'env' ? '环境变量引导' : '未配置'}
            </Badge>
          </div>
          <p className="mt-0.5 text-[11.5px] text-faint">
            兼容任何 OpenAI 协议服务（OpenAI / DeepSeek / 通义 / Kimi / 火山方舟 / vLLM / Ollama）。
            填服务商文档给出的 Base URL；已带 /v1 或 /api/.../v3 时不会重复拼接。
            配置一次，全部任务槽位共用；调用失败自动降级到确定性分析。
          </p>
        </div>
        <Button size="sm" onClick={onTest} disabled={testing || !p.base_url}>
          <FlaskConical size={12} /> {testing ? '测试中…' : '测试连接'}
        </Button>
      </div>

      <div className="grid grid-cols-2 gap-2.5 xl:grid-cols-4">
        <label className="col-span-2">
          <span className="mb-1 block text-[11px] text-faint">服务地址（OpenAI 兼容 Base URL）</span>
          <Input data-provider="base_url" defaultValue={p.base_url}
            placeholder="https://api.deepseek.com" spellCheck={false} />
        </label>
        <label>
          <span className="mb-1 flex items-center gap-1 text-[11px] text-faint">
            <KeyRound size={11} /> API Key
            {p.has_key && <span className="text-ok">已配置 {p.key_hint}</span>}
          </span>
          <Input data-provider="api_key" type="password" autoComplete="new-password"
            placeholder={p.has_key ? '留空保留现有密钥' : 'sk-…'} spellCheck={false} />
        </label>
        <label>
          <span className="mb-1 block text-[11px] text-faint">默认模型（槽位留空时跟随）</span>
          <Input data-provider="model" defaultValue={p.model} placeholder="deepseek-chat"
            spellCheck={false} list="models-provider" />
          <datalist id="models-provider">
            {(probe?.models || []).slice(0, 50).map((m) => <option key={m} value={m} />)}
          </datalist>
        </label>
        <label>
          <span className="mb-1 block text-[11px] text-faint">默认思考强度（仅推理模型）</span>
          <Select data-provider="effort" defaultValue={p.effort}>
            {['off', 'low', 'medium', 'high'].map((v) => <option key={v} value={v}>{v}</option>)}
          </Select>
        </label>
        <label>
          <span className="mb-1 block text-[11px] text-faint">温度（0-2）</span>
          <Input data-provider="temperature" type="number" step="0.05" min="0" max="2"
            defaultValue={p.temperature} />
        </label>
        <label>
          <span className="mb-1 block text-[11px] text-faint">超时（秒）</span>
          <Input data-provider="timeout_sec" type="number" min="3" max="300" defaultValue={p.timeout_sec} />
        </label>
        <label>
          <span className="mb-1 block text-[11px] text-faint">单次输出上限（tokens）</span>
          <Input data-provider="max_tokens" type="number" min="100" max="32000" step="100"
            defaultValue={p.max_tokens} />
        </label>
      </div>

      {probe && (
        <div className="mt-3 flex items-center gap-1.5 text-[11.5px]">
          {probe.ok
            ? <CheckCircle2 size={13} className="shrink-0 text-ok" />
            : <XCircle size={13} className="shrink-0 text-destructive" />}
          <span className={probe.ok ? 'text-muted-foreground' : 'text-destructive'}>
            {probe.detail} · {probe.latency_ms}ms
          </span>
        </div>
      )}
    </Card>
  );
}

/* ---------------- 任务槽位行 ---------------- */
function SlotRow({ task, draft, sv, onChange }: {
  task: string; draft: SlotDraft; sv: SlotView; onChange: (d: SlotDraft) => void;
}) {
  const meta = SLOT_META[task];
  const set = (patch: Partial<SlotDraft>) => onChange({ ...draft, ...patch });
  const hasOverride = !!(draft.ov_base_url || draft.ov_key_draft || draft.ov_clear_key ||
    draft.ov_temperature !== '' || draft.ov_max_tokens !== '' || draft.ov_timeout_sec !== '' ||
    sv.override_has_key);

  return (
    <div className="border-b border-border-soft px-3.5 py-3 last:border-b-0">
      <div className="flex flex-wrap items-center gap-x-3 gap-y-2">
        <Switch checked={draft.enabled} onChange={(v) => set({ enabled: v })}
          label={meta.label} title={meta.desc} />
        <label className="min-w-[220px] flex-1">
          <Input value={draft.model} onChange={(e) => set({ model: e.target.value })}
            placeholder={`留空跟随默认（${sv.effective_model || '未配置'}）`} spellCheck={false}
            list="models-provider" className="h-8" />
        </label>
        <label>
          <Select value={draft.effort} onChange={(e) => set({ effort: e.target.value })} className="h-8">
            <option value="">强度跟随默认（{sv.effective_effort}）</option>
            {['off', 'low', 'medium', 'high'].map((v) => <option key={v} value={v}>{v}</option>)}
          </Select>
        </label>
        <span className="min-w-[180px] flex-1 truncate text-[11px] text-faint" title={meta.desc}>
          生效：{sv.effective_model ? `${sv.effective_model} · 强度 ${sv.effective_effort}` : '未配置，走确定性分析'}
        </span>
      </div>

      {/* 高级覆盖：默认折叠。覆盖项非空 = 使用槽位专属值。 */}
      <details className="mt-1.5" open={hasOverride}>
        <summary className="flex w-fit cursor-pointer list-none items-center gap-1 text-[11px] text-faint hover:text-muted-foreground">
          <ChevronDown size={11} /> 高级覆盖{hasOverride && '（已设置）'}
        </summary>
        <div className="mt-2 grid grid-cols-2 gap-2 xl:grid-cols-4">
          <label>
            <span className="mb-1 block text-[10.5px] text-faint">覆盖服务地址（空=统一接入）</span>
            <Input value={draft.ov_base_url} onChange={(e) => set({ ov_base_url: e.target.value })}
              placeholder={p_placeholder(sv)} spellCheck={false} className="h-8 font-mono text-[11.5px]" />
          </label>
          <label>
            <span className="mb-1 flex items-center gap-1 text-[10.5px] text-faint">
              覆盖 API Key {sv.override_has_key && <span className="text-ok">已配置 {sv.override_key_hint}</span>}
            </span>
            <Input type="password" autoComplete="new-password" value={draft.ov_key_draft}
              onChange={(e) => set({ ov_key_draft: e.target.value, ov_clear_key: false })}
              placeholder={sv.override_has_key ? '留空保留' : '空=用统一 Key'} spellCheck={false} className="h-8" />
          </label>
          <label>
            <span className="mb-1 block text-[10.5px] text-faint">覆盖温度（空=默认）</span>
            <Input type="number" step="0.05" min="0" max="2" value={draft.ov_temperature}
              onChange={(e) => set({ ov_temperature: e.target.value === '' ? '' : Number(e.target.value) })}
              className="h-8" />
          </label>
          <label>
            <span className="mb-1 block text-[10.5px] text-faint">覆盖超时（空=默认）</span>
            <Input type="number" min="3" max="300" value={draft.ov_timeout_sec}
              onChange={(e) => set({ ov_timeout_sec: e.target.value === '' ? '' : Number(e.target.value) })}
              className="h-8" />
          </label>
        </div>
        {sv.override_has_key && !draft.ov_key_draft && (
          <button type="button" className="mt-1.5 cursor-pointer text-[11px] text-destructive hover:underline"
            onClick={() => set({ ov_clear_key: true })}>
            清除此槽位的覆盖密钥（改用统一 Key）
          </button>
        )}
      </details>
    </div>
  );
}

function p_placeholder(sv: SlotView) {
  return sv.override_base_url || 'https://other-provider.example.com';
}

/* ---------------- 评测指标格 ---------------- */
function EvalCell({ label, v, tone }: { label: string; v: string; tone?: 'warn' }) {
  return (
    <div>
      <div className="text-[10.5px] text-faint">{label}</div>
      <div className={tone === 'warn' ? 'font-mono font-semibold text-warn' : 'font-mono font-semibold text-foreground'}>{v}</div>
    </div>
  );
}

/* ---------------- 开关 ---------------- */
function Switch({ checked, onChange, label, title }: {
  checked: boolean; onChange: (v: boolean) => void; label: string; title?: string;
}) {
  return (
    <button type="button" role="switch" aria-checked={checked} aria-label={label} title={title}
      onClick={() => onChange(!checked)}
      className="flex shrink-0 cursor-pointer items-center gap-2 text-[12px] text-foreground">
      <span className={`relative inline-block h-4.5 w-8 rounded-full border transition-colors duration-150 ${checked ? 'border-ok/40 bg-ok-soft' : 'border-border bg-secondary'}`}>
        <span className={`absolute top-[1px] h-3.5 w-3.5 rounded-full transition-all duration-150 ${checked ? 'left-[16px] bg-ok' : 'left-[1px] bg-muted-foreground'}`} />
      </span>
      <b className="font-semibold">{label}</b>
    </button>
  );
}

/* ---------------- 页面 ---------------- */
export function AISettingsPage({ user }: { user: { role: string } }) {
  const err = useError();
  const toast = useToast();
  const confirm = useConfirm();
  const isAdmin = user.role === 'admin';

  const [cfg, setCfg] = useState<AIConfigView | null>(null);
  const [providerClearKey, setProviderClearKey] = useState(false);
  const [slotDrafts, setSlotDrafts] = useState<Record<string, SlotDraft>>({});
  const [probe, setProbe] = useState<ProbeResult | null>(null);
  const [testing, setTesting] = useState(false);
  const [saving, setSaving] = useState(false);
  const [budget, setBudget] = useState({ hourly_tokens: 200000, cache_ttl_sec: 300 });

  const [prompts, setPrompts] = useState<Record<string, AIPrompt> | null>(null);
  const [promptTab, setPromptTab] = useState('triage');
  const [promptDraft, setPromptDraft] = useState('');
  const [promptBusy, setPromptBusy] = useState(false);

  const [skills, setSkills] = useState<AISkill[] | null>(null);
  const [skillEdit, setSkillEdit] = useState<AISkill | null>(null);

  const [lastEval, setLastEval] = useState<EvalRun | null>(null);
  const [evalRunning, setEvalRunning] = useState<string | null>(null);
  const [engineStats, setEngineStats] = useState<EngineStats | null>(null);

  const load = useCallback(async () => {
    try {
      const [c, p, s, e, st] = await Promise.all([
        api.get<AIConfigView>('/api/v1/ai/config'),
        api.get<Record<string, AIPrompt>>('/api/v1/ai/prompts'),
        api.get<AISkill[]>('/api/v1/ai/skills'),
        api.get<EvalRun | null>('/api/v1/ai/eval/last'),
        api.get<{ stats?: EngineStats }>('/api/v1/ai/stats'),
      ]);
      setLastEval(e);
      setEngineStats(st.stats || null);
      setCfg(c);
      setProviderClearKey(false);
      setSlotDrafts(Object.fromEntries(SLOT_KEYS.map((t) => [t, slotToDraft(c.slots[t])])));
      setBudget({ hourly_tokens: c.hourly_tokens, cache_ttl_sec: c.cache_ttl_sec });
      setPrompts(p);
      setPromptDraft(p.triage?.content ?? '');
      setSkills(s || []);
    } catch (e) { err.capture(e); }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => { if (isAdmin) load(); }, [isAdmin, load]);
  if (!isAdmin) {
    return <Card><EmptyState tone="warn" icon={<Bot size={20} />} title="AI 平台仅管理员可见"
      sub="模型接入、提示词与技能包影响全局判定行为与成本，需要管理员权限。" /></Card>;
  }
  if (err.rendered) return err.rendered;

  const providerEl = (name: string) =>
    document.querySelector<HTMLInputElement>(`[data-provider="${name}"]`);

  /* API Key 输入框是非受控的（与同卡片其它字段一致），必须直接读 DOM。
     这里曾用一份从未被 onChange 更新的 state，导致用户输入的 Key 永远
     以空串提交：测试连接报 401、保存也静默丢掉密钥。 */
  const providerKeyValue = () => providerEl('api_key')?.value.trim() ?? '';

  /* 保存：Provider（含未受控输入框的现值）+ 槽位差异 + 预算。
     api_key 留空 = 保留旧值；clear_key = 显式清除。 */
  const saveConfig = async () => {
    if (!cfg) return;
    setSaving(true);
    try {
      const body = {
        provider: {
          base_url: providerEl('base_url')?.value.trim() ?? cfg.provider.base_url,
          model: providerEl('model')?.value.trim() ?? cfg.provider.model,
          effort: providerEl('effort')?.value ?? cfg.provider.effort,
          temperature: Number(providerEl('temperature')?.value) || 0,
          max_tokens: Number(providerEl('max_tokens')?.value) || 0,
          timeout_sec: Number(providerEl('timeout_sec')?.value) || 0,
          api_key: providerKeyValue(), clear_key: providerClearKey,
        },
        slots: Object.fromEntries(SLOT_KEYS.map((t) => {
          const d = slotDrafts[t];
          return [t, {
            enabled: d.enabled, model: d.model.trim(), effort: d.effort,
            base_url: d.ov_base_url.trim(), api_key: d.ov_key_draft, clear_key: d.ov_clear_key,
            temperature: d.ov_temperature === '' ? 0 : d.ov_temperature,
            max_tokens: d.ov_max_tokens === '' ? 0 : d.ov_max_tokens,
            timeout_sec: d.ov_timeout_sec === '' ? 0 : d.ov_timeout_sec,
          }];
        })),
        hourly_tokens: budget.hourly_tokens, cache_ttl_sec: budget.cache_ttl_sec,
      };
      const next = await api.put<AIConfigView>('/api/v1/ai/config', body);
      setCfg(next);
      setProviderClearKey(false);
      // 非受控输入框不会因 React 重渲染而清空——手动清掉，避免明文密钥
      // 长期留在页面上，也避免下次保存把旧 Key 再提交一遍。
      const keyEl = providerEl('api_key');
      if (keyEl) keyEl.value = '';
      setSlotDrafts(Object.fromEntries(SLOT_KEYS.map((t) => [t, slotToDraft(next.slots[t])])));
      setProbe(null); // 配置可能已变，旧拨测结论不再可信
      toast('AI 配置已保存并热生效');
    } catch (e) { toast((e as Error).message, 'err'); }
    finally { setSaving(false); }
  };

  const testProvider = async () => {
    const base = providerEl('base_url')?.value.trim();
    if (!base) { toast('先填写服务地址', 'err'); return; }
    setTesting(true);
    try {
      const res = await api.post<ProbeResult>('/api/v1/ai/config/test', {
        base_url: base, api_key: providerKeyValue(),
        model: providerEl('model')?.value.trim(), timeout_sec: Number(providerEl('timeout_sec')?.value) || 45,
      });
      setProbe(res);
      if (!res.ok) toast(res.detail, 'err');
    } catch (e) { toast((e as Error).message, 'err'); }
    finally { setTesting(false); }
  };

  /* 质量评测 */
  const runEval = async (mode: 'heuristic' | 'llm') => {
    if (mode === 'llm') {
      const ok = await confirm({
        title: '运行 LLM 质量评测？',
        message: '将用当前生效的模型/提示词/技能包对约 44 条样本逐条调用模型，消耗约 7-10 万 tokens（计入小时预算）。合成夹具验证的是契约回归，不是真实世界准确率。',
        okText: '开始评测',
      });
      if (!ok) return;
    }
    setEvalRunning(mode);
    try {
      const rr = await api.post<EvalRun>('/api/v1/ai/eval/run', { mode });
      setLastEval(rr);
      toast(rr.passed ? '评测通过' : `评测未通过：${rr.violations?.[0] || '存在失败样本'}`, rr.passed ? 'ok' : 'err');
    } catch (e) { toast((e as Error).message, 'err'); }
    finally { setEvalRunning(null); }
  };

  /* 提示词 */
  const switchPromptTab = (key: string) => {
    setPromptTab(key);
    setPromptDraft(prompts?.[key]?.content ?? '');
  };
  const savePrompt = async () => {
    setPromptBusy(true);
    try {
      await api.put(`/api/v1/ai/prompts/${promptTab}`, { content: promptDraft });
      toast('提示词已保存并热生效');
      setPrompts(await api.get<Record<string, AIPrompt>>('/api/v1/ai/prompts'));
    } catch (e) { toast((e as Error).message, 'err'); }
    finally { setPromptBusy(false); }
  };
  const rollbackPrompt = async () => {
    const cur = prompts?.[promptTab];
    if (!cur?.versions?.length) { toast('没有可回滚的历史版本', 'err'); return; }
    const target = cur.versions[0]; // 历史按版本降序，第一个是上一个生效版本
    const ok = await confirm({
      title: `回滚到版本 ${target.version}？`,
      message: `当前内容将被 ${target.created_by || '-'} 在 ${relTime(target.created_at)} 保存的版本覆盖（回滚本身也会留一条新版本记录）。`,
      okText: '回滚',
    });
    if (!ok) return;
    try {
      await api.post(`/api/v1/ai/prompts/${promptTab}/rollback`, { version: target.version });
      toast(`已回滚到版本 ${target.version}`);
      const p = await api.get<Record<string, AIPrompt>>('/api/v1/ai/prompts');
      setPrompts(p);
      setPromptDraft(p[promptTab]?.content ?? '');
    } catch (e) { toast((e as Error).message, 'err'); }
  };

  /* 技能包 */
  const saveSkill = async (sk: AISkill) => {
    try {
      await api.post('/api/v1/ai/skills', sk);
      toast('技能包已保存并热生效');
      setSkillEdit(null);
      setSkills(await api.get<AISkill[]>('/api/v1/ai/skills'));
    } catch (e) { toast((e as Error).message, 'err'); }
  };
  const toggleSkill = async (sk: AISkill) => {
    try {
      await api.post('/api/v1/ai/skills', { ...sk, enabled: !sk.enabled });
      setSkills(await api.get<AISkill[]>('/api/v1/ai/skills'));
    } catch (e) { toast((e as Error).message, 'err'); }
  };
  const deleteSkill = async (sk: AISkill) => {
    const ok = await confirm({
      title: `删除技能包「${sk.name}」？`,
      message: '该环境知识将立即从模型提示词中移除。',
      danger: true, okText: '删除',
    });
    if (!ok) return;
    try {
      await api.del(`/api/v1/ai/skills/${encodeURIComponent(sk.id)}`);
      toast('已删除');
      setSkills(await api.get<AISkill[]>('/api/v1/ai/skills'));
    } catch (e) { toast((e as Error).message, 'err'); }
  };

  const curPrompt = prompts?.[promptTab];

  return (
    <div>
      {/* 引擎状态行 */}
      <div className="mb-3.5 flex flex-wrap items-center gap-2 text-[12px] text-muted-foreground">
        <Bot size={14} />
        <span>当前引擎：</span>
        <Badge tone={cfg?.engine === 'llm' ? 'info' : 'neutral'}>
          {cfg?.engine === 'llm' ? `LLM · ${cfg.engine_model || '-'}` : '确定性启发式'}
        </Badge>
        {cfg?.engine !== 'llm' && (
          <span className="text-faint">未配置模型时所有 AI 功能照常可用，结论由确定性引擎给出并标注。</span>
        )}
        {engineStats?.slots && Object.keys(engineStats.slots).length > 0 && (
          <span className="ml-auto flex flex-wrap items-center gap-2 text-[11px] text-faint">
            <span>按能力用量：</span>
            {Object.entries(engineStats.slots).map(([slot, st]) => (
              <span key={slot} className="font-mono">
                {SLOT_META[slot]?.label || slot} {st.calls}次/{st.avg_ms}ms
              </span>
            ))}
          </span>
        )}
      </div>

      {/* 统一服务接入 + 任务槽位 */}
      <div className="mb-1.5 flex items-center justify-between">
        <CardTitle>模型接入</CardTitle>
        <Button variant="primary" size="sm" onClick={saveConfig} disabled={saving}>
          <Save size={12} /> {saving ? '保存中…' : '保存全部并热生效'}
        </Button>
      </div>
      {!cfg ? (
        <Card className="mb-4 px-2 pb-2"><SkeletonRows rows={4} /></Card>
      ) : (
        <div className="mb-4 grid gap-3">
          <ProviderCard p={cfg.provider} onTest={testProvider} testing={testing} probe={probe} />
          <Card>
            <div className="border-b border-border-soft px-3.5 pb-2 pt-3">
              <CardTitle>任务槽位（留空即跟随统一接入）</CardTitle>
            </div>
            {SLOT_KEYS.map((task) => (
              <SlotRow key={task} task={task} sv={cfg.slots[task]}
                draft={slotDrafts[task] ?? slotToDraft(cfg.slots[task])}
                onChange={(d) => setSlotDrafts((prev) => ({ ...prev, [task]: d }))} />
            ))}
          </Card>
          <Card className="p-4">
            <CardTitle>成本与缓存</CardTitle>
            <div className="mt-3 grid max-w-[560px] grid-cols-2 gap-2.5">
              <label>
                <span className="mb-1 block text-[11px] text-faint">每小时 token 硬上限（触顶自动降级）</span>
                <Input type="number" min="1000" step="1000" value={budget.hourly_tokens}
                  onChange={(e) => setBudget((b) => ({ ...b, hourly_tokens: Number(e.target.value) || 1000 }))} />
              </label>
              <label>
                <span className="mb-1 block text-[11px] text-faint">研判结果缓存（秒）</span>
                <Input type="number" min="0" max="3600" step="30" value={budget.cache_ttl_sec}
                  onChange={(e) => setBudget((b) => ({ ...b, cache_ttl_sec: Number(e.target.value) || 0 }))} />
              </label>
            </div>
          </Card>
        </div>
      )}

      {/* 质量评测 */}
      <Card className="mb-4 px-2 pb-3 pt-3.5">
        <div className="mb-2 flex flex-wrap items-center justify-between gap-2 px-2">
          <div>
            <CardTitle>质量评测（回归基线）</CardTitle>
            <p className="mt-0.5 text-[11px] text-faint">
              合成告警集 + 注入对抗集 · 一致率 / 误报率 / 漏检率 / 注入拦截分开统计 · 结构评测零 token
            </p>
          </div>
          <div className="flex gap-2">
            <Button size="sm" onClick={() => runEval('heuristic')} disabled={!!evalRunning}>
              {evalRunning === 'heuristic' ? '运行中…' : '运行结构评测'}
            </Button>
            <Button size="sm" variant="primary" onClick={() => runEval('llm')} disabled={!!evalRunning}>
              {evalRunning === 'llm' ? '评测中…' : '运行质量评测（LLM）'}
            </Button>
          </div>
        </div>
        {!lastEval ? (
          <div className="px-2 pb-1 text-[12px] text-faint">
            还没有评测记录。建议先跑结构评测（零 token）建立基线，配置模型后再跑质量评测。
          </div>
        ) : (
          <div className="px-2">
            <div className="mb-2 flex flex-wrap items-center gap-2 text-[11.5px]">
              <Badge tone={lastEval.passed ? 'online' : 'critical'}>{lastEval.passed ? '通过' : '未通过'}</Badge>
              <span className="text-muted-foreground">
                {lastEval.mode === 'llm' ? 'LLM 质量评测' : '结构评测'} · {lastEval.metrics.total} 样本 ·{' '}
                {relTime(lastEval.started_at)} · 耗时 {Math.max(1, Math.round(lastEval.duration_ms / 1000))}s
              </span>
            </div>
            <div className="grid grid-cols-2 gap-x-4 gap-y-1.5 text-[12px] md:grid-cols-4 xl:grid-cols-7">
              <EvalCell label="一致率" v={`${(lastEval.metrics.accuracy * 100).toFixed(0)}%`} />
              <EvalCell label="恶意召回" v={`${(lastEval.metrics.malicious_recall * 100).toFixed(0)}%`} />
              <EvalCell label="误报率" v={`${(lastEval.metrics.fp_rate * 100).toFixed(0)}%`} tone={lastEval.metrics.fp_rate > 0.1 ? 'warn' : undefined} />
              <EvalCell label="漏检率" v={`${(lastEval.metrics.fn_rate * 100).toFixed(0)}%`} tone={lastEval.metrics.fn_rate > 0.1 ? 'warn' : undefined} />
              <EvalCell label="注入拦截" v={`${(lastEval.metrics.injection_intercepted * 100).toFixed(0)}%`} tone={lastEval.metrics.injection_intercepted < 1 ? 'warn' : undefined} />
              <EvalCell label="可溯源率" v={`${(lastEval.metrics.grounded_rate * 100).toFixed(0)}%`} />
              <EvalCell label="平均延迟" v={`${lastEval.metrics.avg_latency_ms.toFixed(0)}ms`} />
            </div>
            {!!lastEval.metrics.narrative_total && (
              <div className="mt-1.5 grid grid-cols-2 gap-x-4 gap-y-1.5 border-t border-border-soft pt-1.5 text-[12px] md:grid-cols-4">
                <EvalCell label={`叙事可溯源（${lastEval.metrics.narrative_total} 事件）`}
                  v={`${((lastEval.metrics.narrative_grounded_rate || 0) * 100).toFixed(0)}%`} />
                <EvalCell label="战术覆盖" v={`${((lastEval.metrics.narrative_tactic_coverage || 0) * 100).toFixed(0)}%`} />
                <EvalCell label="风险达标" v={`${((lastEval.metrics.narrative_risk_ok || 0) * 100).toFixed(0)}%`} />
                <EvalCell label="叙事注入翻转" v={`${lastEval.metrics.narrative_injection_flips || 0}`}
                  tone={(lastEval.metrics.narrative_injection_flips || 0) > 0 ? 'warn' : undefined} />
              </div>
            )}
            {!!lastEval.violations?.length && (
              <ul className="mt-2 grid gap-0.5 text-[11.5px] text-destructive">
                {lastEval.violations.map((v) => <li key={v}>· {v}</li>)}
              </ul>
            )}
            {!!lastEval.failures?.length && (
              <details className="mt-2">
                <summary className="cursor-pointer text-[11px] text-faint">失败样本 {lastEval.failures.length} 条</summary>
                <table className="mt-1.5 w-full text-[12px]">
                  <thead><tr className="border-b border-border-soft text-left text-[11px] text-faint">
                    {['样本', '预期', '实际', '原因'].map((h) => <th key={h} className="px-2 py-1.5 font-semibold">{h}</th>)}
                  </tr></thead>
                  <tbody>
                    {lastEval.failures.slice(0, 20).map((f) => (
                      <tr key={f.id} className="border-b border-border-soft last:border-b-0">
                        <td className="px-2 py-1.5 font-mono text-[11.5px]">{f.id}</td>
                        <td className="px-2 py-1.5">{f.expected}</td>
                        <td className="px-2 py-1.5">{f.actual}</td>
                        <td className="px-2 py-1.5 text-muted-foreground">{f.why}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </details>
            )}
          </div>
        )}
      </Card>

      <OpsQueueCard />

      <QualityCard />

      {/* 提示词模板 */}
      <Card className="mb-4 p-4">
        <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
          <CardTitle>提示词模板（覆盖内置默认 · 输出契约由引擎强制追加）</CardTitle>
          <div className="flex items-center gap-2">
            <Select value={promptTab} onChange={(e) => switchPromptTab(e.target.value)} className="h-8">
              {SLOT_KEYS.map((t) => (
                <option key={t} value={t}>
                  {SLOT_META[t].label}{cfg?.prompt_overridden?.[t] ? '（已覆盖）' : ''}
                </option>
              ))}
            </Select>
            <Button size="sm" variant="ghost" onClick={rollbackPrompt}
              disabled={promptBusy || !curPrompt?.versions?.length} title="回滚到上一版本">
              <History size={12} /> 回滚
            </Button>
            <Button size="sm" variant="primary" onClick={savePrompt} disabled={promptBusy}>
              <Save size={12} /> 保存
            </Button>
          </div>
        </div>
        {!prompts ? <SkeletonRows rows={3} /> : (
          <>
            <textarea
              value={promptDraft} onChange={(e) => setPromptDraft(e.target.value)}
              spellCheck={false}
              className="h-72 w-full resize-y rounded-[7px] border border-input bg-card p-3 font-mono text-[12px] leading-[1.7] text-foreground outline-none transition-colors focus:border-primary focus:ring-3 focus:ring-brand-soft"
              placeholder="留空使用内置默认。研判模板必须保留 untrusted 隔离纪律与 citations 证据引用要求，否则保存会被拒绝。"
            />
            <div className="mt-2 flex flex-wrap items-center justify-between gap-2 text-[11px] text-faint">
              <span>
                研判模板硬校验：必须包含 <code className="font-mono text-muted-foreground">untrusted</code> 与{' '}
                <code className="font-mono text-muted-foreground">citations</code>；输出 JSON 格式段由引擎追加，无需手写。
              </span>
              {curPrompt?.versions?.length ? (
                <span>历史 {curPrompt.versions.length} 版 · 最近 {curPrompt.updated_by || '-'} · {relTime(curPrompt.updated_at || curPrompt.versions[0].created_at)}</span>
              ) : <span>尚未覆盖，使用内置默认</span>}
            </div>
          </>
        )}
      </Card>

      {/* 技能包 */}
      <Card className="px-2 py-3.5">
        <div className="mb-2 flex items-center justify-between px-2">
          <CardTitle>环境技能包（追加到模型提示词的环境知识）</CardTitle>
          <Button size="sm" onClick={() => setSkillEdit({ id: '', task: 'triage', name: '', content: '', enabled: true, sort: 0, created_by: '', created_at: '', updated_at: '' })}>
            <Plus size={12} /> 新建技能包
          </Button>
        </div>
        {!skills ? <SkeletonRows rows={3} /> : !skills.length ? (
          <EmptyState tone="info" icon={<Bot size={18} />} title="还没有技能包"
            sub={<>把"这台环境里什么是正常的"写成语义化条目（例如某内网工具的用途、某个计划任务的负责人），<br />模型研判时会把它们当背景知识而不是判定指令。</>} />
        ) : (
          <table className="w-full text-[13px]">
            <thead><tr className="border-b border-border-soft text-left text-[11px] tracking-[.06em] text-faint uppercase">
              {['名称', '作用域', '内容摘要', '状态', '更新时间', ''].map((h) => <th key={h} className="px-3.5 py-2.5 font-semibold">{h}</th>)}
            </tr></thead>
            <tbody>
              {skills.map((sk) => (
                <tr key={sk.id} className="border-b border-border-soft transition-colors last:border-b-0 hover:bg-secondary">
                  <td className="px-3.5 py-2.5 font-medium">{sk.name}</td>
                  <td className="px-3.5 py-2.5"><Badge tone="neutral">{SLOT_META[sk.task]?.label ?? '全部任务'}</Badge></td>
                  <td className="max-w-[380px] truncate px-3.5 py-2.5 text-muted-foreground" title={sk.content}>{sk.content}</td>
                  <td className="px-3.5 py-2.5">
                    <button type="button" onClick={() => toggleSkill(sk)}
                      className="cursor-pointer"><Badge tone={sk.enabled ? 'online' : 'neutral'}>{sk.enabled ? '启用' : '停用'}</Badge></button>
                  </td>
                  <td className="px-3.5 py-2.5 text-xs text-faint">{relTime(sk.updated_at)}</td>
                  <td className="px-3.5 py-2.5 text-right">
                    <Button size="sm" variant="ghost" onClick={() => setSkillEdit(sk)}><Pencil size={12} /> 编辑</Button>
                    <Button size="sm" variant="ghost" onClick={() => deleteSkill(sk)} className="ml-1">删除</Button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>

      {/* 技能包编辑抽屉 */}
      <Drawer open={!!skillEdit} onClose={() => setSkillEdit(null)} title={skillEdit?.id ? '编辑技能包' : '新建技能包'}
        sub="内容会以「背景知识」身份追加进模型提示词，不改变输出契约与证据引用要求"
        foot={skillEdit && (
          <>
            <Button variant="ghost" onClick={() => setSkillEdit(null)}>取消</Button>
            <Button variant="primary" onClick={() => saveSkill(skillEdit)}><Save size={12} /> 保存</Button>
          </>
        )}>
        {skillEdit && (
          <div className="grid gap-3">
            <label>
              <span className="mb-1.5 block text-[11.5px] text-faint">名称（它是什么）</span>
              <Input value={skillEdit.name} onChange={(e) => setSkillEdit({ ...skillEdit, name: e.target.value })}
                placeholder="例：内网运维工具说明" maxLength={100} />
            </label>
            <label>
              <span className="mb-1.5 block text-[11.5px] text-faint">作用域</span>
              <Select value={skillEdit.task} onChange={(e) => setSkillEdit({ ...skillEdit, task: e.target.value })}>
                <option value="triage">研判</option>
                <option value="hunt">狩猎</option>
                <option value="investigate">调查</option>
                <option value="all">全部任务</option>
              </Select>
            </label>
            <label>
              <span className="mb-1.5 block text-[11.5px] text-faint">内容（建议一段一个事实，上限 4096 字节）</span>
              <textarea value={skillEdit.content} spellCheck={false}
                onChange={(e) => setSkillEdit({ ...skillEdit, content: e.target.value })}
                className="h-40 w-full resize-y rounded-[7px] border border-input bg-card p-3 text-[13px] leading-[1.7] text-foreground outline-none transition-colors focus:border-primary focus:ring-3 focus:ring-brand-soft"
                placeholder={'例：hostsync.exe 是运维部统一的时钟同步工具，签名有效，安装于 Program Files，每日 03:00 计划任务触发属正常行为。'} />
            </label>
            <label className="flex items-center gap-2 text-[12.5px] text-muted-foreground">
              <Switch checked={skillEdit.enabled} onChange={(v) => setSkillEdit({ ...skillEdit, enabled: v })} label="启用" />
            </label>
          </div>
        )}
      </Drawer>
    </div>
  );
}

/* ---------------- 研判质量运营闭环 ---------------- */
interface QualityReport {
  sampled: number; agree_rate: number; ai_fp_rate: number; ai_miss_rate: number;
  counts?: Record<string, number>; unscored: number;
  disagreements?: { alert_id: string; title: string; hostname: string;
    ai_verdict: string; ai_confidence: number; ai_source: string;
    analyst_said: string; kind: string; occurred_at: string }[];
}

// 研判质量对账（Prophet 信任三步的第一步：先度量再谈自治）。
// AI 说"有问题/没问题" × 分析师处置（真阳性/误报/良性）→ 四格矩阵。
// ai_miss 是最危险的一格：AI 说没问题、结果真是攻击——头号监控指标。
function QualityCard() {
  const [rep, setRep] = useState<QualityReport | null>(null);
  useEffect(() => {
    api.get<QualityReport>('/api/v1/ai/quality/report').then(setRep).catch(() => setRep(null));
  }, []);
  const pct = (v?: number) => `${Math.round((v || 0) * 100)}%`;

  const cells: { key: string; label: string; tone: string; title: string }[] = [
    { key: 'tp_agree', label: '预警正确', tone: 'resolved', title: 'AI 说有问题，分析师确认真阳性' },
    { key: 'noise_agree', label: '降噪正确', tone: 'resolved', title: 'AI 说没问题，分析师判误报/良性' },
    { key: 'ai_fp', label: 'AI 误报', tone: 'critical', title: 'AI 说有问题，分析师判良性/误报——最毁信任的一格' },
    { key: 'ai_miss', label: 'AI 漏报', tone: 'medium', title: 'AI 说没问题，分析师判真阳性——最危险的一格' },
  ];

  return (
    <Card className="mb-4 px-2 pb-3 pt-3.5">
      <div className="mb-2 flex items-center justify-between px-2">
        <div>
          <CardTitle>研判质量</CardTitle>
          <p className="mt-0.5 text-[11px] text-faint">
            AI/调查结论 × 分析师处置结案理由的对账矩阵——调提示词和阈值前先看这里，盲调没有意义
          </p>
        </div>
        {rep && <Badge tone={rep.sampled ? 'info' : 'neutral'}>样本 {rep.sampled}</Badge>}
      </div>
      {!rep ? (
        <div className="px-2 pb-1 text-[12px] text-faint">对账数据加载中…</div>
      ) : !rep.sampled ? (
        <div className="px-2 pb-1 text-[12px] text-faint">
          还没有可对账的样本：在值班队列用结案理由（真阳性/误报/良性）处理建议，或把告警标记为误报后，这里会自动累积。
          {rep.unscored > 0 && <>（另有 {rep.unscored} 条已处理但未给定性理由，不计入）</>}
        </div>
      ) : (
        <>
          <div className="grid grid-cols-2 gap-1.5 px-2 sm:grid-cols-4">
            {cells.map((c) => (
              <div key={c.key} className="rounded-md border border-border-soft bg-card px-3 py-2" title={c.title}>
                <div className="text-[10.5px] text-faint">{c.label}</div>
                <div className="mt-0.5 flex items-baseline gap-1.5">
                  <b className={cn('text-[18px] font-semibold', c.tone === 'critical' ? 'text-crit' : c.tone === 'medium' ? 'text-warn' : 'text-ok')}>{rep.counts?.[c.key] ?? 0}</b>
                  <span className="text-[10.5px] text-faint">{pct((rep.counts?.[c.key] ?? 0) / rep.sampled)}</span>
                </div>
              </div>
            ))}
          </div>
          <div className="mt-2 px-2 text-[11px] text-faint">
            一致率 <b className="text-foreground">{pct(rep.agree_rate)}</b>
            {rep.unscored > 0 && <> · 已处理未定性 {rep.unscored} 条不计入</>}
          </div>
          {!!rep.disagreements?.length && (
            <div className="mt-2 px-2">
              <div className="mb-1.5 text-[10.5px] font-semibold uppercase tracking-wide text-faint">最近分歧（点开人工复核）</div>
              <div className="grid gap-1">
                {rep.disagreements.map((d) => (
                  <div key={d.alert_id} className="flex flex-wrap items-center gap-2 rounded-md border border-border-soft bg-card px-2.5 py-1.5 text-[11.5px]">
                    <Badge tone={d.kind === 'ai_miss' ? 'medium' : 'critical'}>{d.kind === 'ai_miss' ? 'AI 漏报' : 'AI 误报'}</Badge>
                    <b className="min-w-0 flex-1 truncate" title={d.title}>{d.title}</b>
                    <span className="text-faint" title={`AI 判定 ${d.ai_verdict}（${d.ai_source === 'ai' ? '模型' : '确定性'}）`}>
                      AI：{VERDICT_META[d.ai_verdict]?.label || d.ai_verdict} {Math.round((d.ai_confidence || 0) * 100)}%
                    </span>
                    <span className="text-faint">分析师：{d.analyst_said === 'true_positive' ? '真阳性' : d.analyst_said === 'known_benign' ? '良性' : '误报'}</span>
                    <Link to={`/alerts?open=${encodeURIComponent(d.alert_id)}`} className="text-[11px] text-primary underline-offset-2 hover:underline">复核</Link>
                  </div>
                ))}
              </div>
            </div>
          )}
        </>
      )}
    </Card>
  );
}

/* ---------------- AI 值班队列（方向 C）——值班工作台 ---------------- */
interface OpsItem {
  id: string; alert_id: string; title: string; hostname: string; severity: string;
  score: number; verdict: string; confidence: number; summary: string;
  findings?: { text: string; citations?: string[] }[];
  actions?: { type: string; target?: string; detail?: string }[];
  engine: string; created_at: string; status: string;
  reviewed_by?: string; reviewed_at?: string; review_reason?: string;
  occurrences?: number; last_alert_id?: string; last_seen_at?: string;
}

// 判定芯片：中文 + 语义色。历史条目里存有旧枚举串（"benign-需人工确认"），
// 按关键词兜底到证据不足，避免直接显示原始英文。
const VERDICT_META: Record<string, { label: string; tone: string }> = {
  malicious: { label: '恶意', tone: 'malicious' },
  suspicious: { label: '可疑', tone: 'suspicious' },
  inconclusive: { label: '证据不足', tone: 'acknowledged' },
  benign: { label: '倾向误报', tone: 'resolved' },
};
function verdictMeta(v: string) {
  if (VERDICT_META[v]) return VERDICT_META[v];
  if (v.includes('benign')) return { label: '证据不足（旧）', tone: 'acknowledged' };
  return { label: v, tone: 'neutral' };
}

// 结案理由码（业界 closure reason codes：TP 与 BTP 分开——把"真实但
// 预期"记成"误报"会误导后续调优方向）。与服务端 OpsReviewReasons 对齐。
const OPS_REASONS: [string, string][] = [
  ['false_positive', '误报（规则/阈值打错对象）'],
  ['known_benign', '真实但良性（运维/软件自启等）'],
  ['duplicate', '重复告警'],
  ['test_exercise', '测试或攻防演练'],
  ['true_positive', '真阳性，转入人工处置'],
  ['other', '其他'],
];
const REASON_LABEL: Record<string, string> = Object.fromEntries(OPS_REASONS);

function OpsQueueCard() {
  const toast = useToast();
  const confirm = useConfirm();
  const [items, setItems] = useState<OpsItem[] | null>(null);
  const [busy, setBusy] = useState('');
  const [tab, setTab] = useState<'pending' | 'processed' | 'all'>('pending');
  const [vFilter, setVFilter] = useState<string>('all');
  const [reason, setReason] = useState('false_positive');
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [expanded, setExpanded] = useState<string | null>(null);
  const [allowTips, setAllowTips] = useState<Record<string, { type: string; value: string }>>({});

  const load = useCallback(async () => {
    try { setItems(await api.get<OpsItem[]>('/api/v1/ai/ops/queue')); } catch { setItems([]); }
  }, []);
  useEffect(() => { load(); }, [load]);

  const patchItem = (fresh: OpsItem) =>
    setItems((prev) => (prev || []).map((x) => (x.id === fresh.id ? fresh : x)));

  const review = async (it: OpsItem, action: 'approve' | 'dismiss') => {
    setBusy(it.id);
    try {
      const rr = await api.post<{ item: OpsItem; allowlist_suggestion?: { type: string; value: string } }>(
        `/api/v1/ai/ops/${encodeURIComponent(it.id)}/review`, { action, reason: action === 'dismiss' ? reason : '' });
      patchItem(rr.item);
      setSelected((prev) => { const n = new Set(prev); n.delete(it.id); return n; });
      toast(action === 'approve' ? '已认可建议（处置仍需人工执行）' : `已忽略（${REASON_LABEL[reason] || reason}）`);
      if (rr.allowlist_suggestion) {
        setAllowTips((prev) => ({ ...prev, [it.id]: rr.allowlist_suggestion! }));
      }
    } catch (e) { toast((e as Error).message, 'err'); }
    finally { setBusy(''); }
  };

  const bulk = async (action: 'approve' | 'dismiss') => {
    const ids = Array.from(selected);
    if (!ids.length) return;
    const ok = await confirm({
      title: action === 'dismiss' ? `批量忽略 ${ids.length} 条建议？` : `批量认可 ${ids.length} 条建议？`,
      message: `结案理由：${REASON_LABEL[reason] || reason}。${action === 'approve' ? '认可只记录决定，处置仍需人工执行。' : '忽略后这些条目移入已处理。'}`,
      okText: '确认批量',
    });
    if (!ok) return;
    setBusy('bulk');
    try {
      const rr = await api.post<{ updated: OpsItem[]; skipped: number; allowlist_suggestions?: { type: string; value: string }[] }>(
        '/api/v1/ai/ops/bulk-review', { ids, action, reason: action === 'dismiss' ? reason : '' });
      setItems((prev) => (prev || []).map((x) => rr.updated.find((u) => u.id === x.id) || x));
      setSelected(new Set());
      toast(`已批量处理 ${rr.updated.length} 条${rr.skipped ? `，跳过 ${rr.skipped} 条已处理` : ''}`);
      if (rr.allowlist_suggestions?.length) {
        toast(`有 ${rr.allowlist_suggestions.length} 条误报建议可加白降噪，展开条目查看`, 'warn');
      }
    } catch (e) { toast((e as Error).message, 'err'); }
    finally { setBusy(''); }
  };

  // 一键加白（降噪闭环的最后一环）：走既有加白端点，服务端自动回收
  // 未处置告警并审计。只在此处、由人显式点击，AI 永不代执行。
  const addToAllowlist = async (it: OpsItem) => {
    const tip = allowTips[it.id];
    if (!tip) return;
    setBusy(it.id);
    try {
      const rr = await api.post<{ recycled_alerts: number }>('/api/v1/allowlist', {
        type: tip.type, value: tip.value,
        note: `值班误报反馈（${it.title}）`,
      });
      toast(`已加白 ${tip.type}，自动回收未处置告警 ${rr.recycled_alerts} 条`);
      setAllowTips((prev) => { const n = { ...prev }; delete n[it.id]; return n; });
    } catch (e) { toast((e as Error).message, 'err'); }
    finally { setBusy(''); }
  };

  const reeval = async (it: OpsItem) => {
    setBusy(it.id);
    try {
      const fresh = await api.post<OpsItem>(`/api/v1/ai/ops/${encodeURIComponent(it.id)}/reevaluate`, {});
      patchItem(fresh);
      toast(`已按当前调查逻辑重评：${verdictMeta(fresh.verdict).label}（置信 ${Math.round((fresh.confidence || 0) * 100)}%）`);
    } catch (e) { toast((e as Error).message, 'err'); }
    finally { setBusy(''); }
  };

  const all = items || [];
  const pending = all.filter((x) => x.status === 'pending');
  const shown = all.filter((x) =>
    tab === 'pending' ? x.status === 'pending' : tab === 'processed' ? x.status !== 'pending' : true,
  ).filter((x) => vFilter === 'all' || x.verdict === vFilter)
   .slice(0, 20);
  const nBenign = pending.filter((x) => x.verdict === 'benign').length;
  const nInconclusive = pending.filter((x) => x.verdict === 'inconclusive').length;
  const selPending = Array.from(selected).filter((id) => pending.some((x) => x.id === id));

  return (
    <Card className="mb-4 px-2 pb-3 pt-3.5">
      <div className="mb-2 flex items-center justify-between px-2">
        <div>
          <CardTitle>AI 值班队列</CardTitle>
          <p className="mt-0.5 text-[11px] text-faint">
            critical 告警自动触发确定性调查；同主机同类爆发聚合为一条代表条目；审批只记录决定，绝不自动执行处置
          </p>
        </div>
        <Badge tone={pending.length ? 'medium' : 'neutral'}>{pending.length} 待审</Badge>
      </div>

      {/* 统计行：值班先看盘子再看条目 */}
      {!!all.length && (
        <div className="mb-2 flex flex-wrap items-center gap-2 px-2 text-[11px] text-faint">
          <span>待审 {pending.length}</span>
          <span>·</span><span>倾向误报 {nBenign}</span>
          <span>·</span><span>证据不足 {nInconclusive}</span>
          <span>·</span><span>已处理 {all.length - pending.length}</span>
        </div>
      )}

      <div className="mb-2 flex flex-wrap items-center gap-2 px-2">
        <div className="flex items-center gap-1 rounded-md border border-border-soft bg-card p-0.5" role="group" aria-label="队列筛选">
          {([['pending', '待审'], ['processed', '已处理'], ['all', '全部']] as const).map(([v, label]) => (
            <button key={v} type="button" onClick={() => setTab(v)} aria-pressed={tab === v}
              className={`cursor-pointer rounded-[5px] px-2.5 py-1 text-[11.5px] transition-colors ${tab === v ? 'bg-secondary font-medium text-foreground' : 'text-muted-foreground hover:text-foreground'}`}>{label}</button>
          ))}
        </div>
        <div className="flex items-center gap-1 rounded-md border border-border-soft bg-card p-0.5" role="group" aria-label="判定筛选">
          <button type="button" onClick={() => setVFilter('all')} aria-pressed={vFilter === 'all'}
            className={`cursor-pointer rounded-[5px] px-2.5 py-1 text-[11.5px] transition-colors ${vFilter === 'all' ? 'bg-secondary font-medium text-foreground' : 'text-muted-foreground hover:text-foreground'}`}>全部判定</button>
          {Object.entries(VERDICT_META).map(([v, m]) => (
            <button key={v} type="button" onClick={() => setVFilter(v)} aria-pressed={vFilter === v}
              className={`cursor-pointer rounded-[5px] px-2.5 py-1 text-[11.5px] transition-colors ${vFilter === v ? 'bg-secondary font-medium text-foreground' : 'text-muted-foreground hover:text-foreground'}`}>{m.label}</button>
          ))}
        </div>
        <div className="ml-auto flex items-center gap-1.5">
          <Select value={reason} onChange={(e) => setReason(e.target.value)} aria-label="结案理由" className="h-7 text-[11px]">
            {OPS_REASONS.map(([v, label]) => <option key={v} value={v}>{label}</option>)}
          </Select>
        </div>
      </div>

      {/* 批量操作条：爆发场景逐条点审批不现实 */}
      {selPending.length > 0 && (
        <div className="mb-2 flex flex-wrap items-center gap-2 rounded-md border border-border-soft bg-brand-soft px-3 py-1.5 text-[12px]">
          <b>已选 {selPending.length} 条</b>
          <span className="text-faint">结案理由：{REASON_LABEL[reason] || reason}</span>
          <Button size="sm" variant="ghost" disabled={busy === 'bulk'} onClick={() => bulk('dismiss')}>批量忽略</Button>
          <Button size="sm" variant="ghost" disabled={busy === 'bulk'} onClick={() => bulk('approve')}>批量认可</Button>
          <Button size="sm" variant="ghost" onClick={() => setSelected(new Set())}>取消选择</Button>
        </div>
      )}

      {!items ? <SkeletonRows rows={2} /> : !shown.length ? (
        <div className="px-2 pb-1 text-[12px] text-faint">
          {tab === 'pending' && !pending.length ? '队列已清空——critical 告警出现时会自动入队。' : '当前筛选下没有条目。'}
        </div>
      ) : (
        <div className="grid gap-1.5 px-2">
          {shown.map((it) => {
            const vm = verdictMeta(it.verdict);
            const open = expanded === it.id;
            const isPending = it.status === 'pending';
            const burst = it.occurrences ? it.occurrences + 1 : 1;
            return (
              <div key={it.id} className="rounded-md border border-border-soft bg-card px-3 py-2">
                <div className="flex flex-wrap items-center gap-2 text-[12px]">
                  {isPending && (
                    <input type="checkbox" className="row-sel accent-[var(--primary)]" aria-label={`选择 ${it.title}`}
                      checked={selected.has(it.id)} onChange={(e) => {
                        setSelected((prev) => { const n = new Set(prev); if (e.target.checked) n.add(it.id); else n.delete(it.id); return n; });
                      }} />
                  )}
                  <Badge tone={it.severity}>{SEV_LABEL[it.severity] || it.severity}</Badge>
                  <b className="min-w-0 flex-1 truncate" title={it.title}>{it.title}</b>
                  {burst > 1 && <Badge tone="medium" title={`同类告警在此条目入队后又触发 ${it.occurrences} 次；打开原告警看最新一条`}>爆发 ×{burst}</Badge>}
                  <span className="text-faint">{it.hostname} · {it.score} 分</span>
                  <Badge tone={vm.tone} title={`调查判定：${it.verdict} · 置信 ${Math.round((it.confidence || 0) * 100)}%`}>
                    {vm.label} {Math.round((it.confidence || 0) * 100)}%
                  </Badge>
                  <Badge tone={isPending ? 'medium' : it.status === 'approved' ? 'resolved' : 'neutral'}>
                    {isPending ? '待审' : it.status === 'approved' ? '已认可' : '已忽略'}
                  </Badge>
                </div>
                <div className="mt-1 text-[11.5px] leading-[1.6] text-muted-foreground">{it.summary}</div>
                {!isPending && it.review_reason && (
                  <div className="mt-0.5 text-[11px] text-faint">
                    结案理由：{REASON_LABEL[it.review_reason] || it.review_reason}
                    {it.reviewed_by && <> · {it.reviewed_by} · {relTime(it.reviewed_at)}</>}
                  </div>
                )}

                <div className="mt-1.5 flex flex-wrap items-center gap-1.5">
                  <Button size="sm" variant="ghost" onClick={() => setExpanded(open ? null : it.id)} aria-expanded={open}>
                    <ChevronDown className={`size-3.5 transition-transform ${open ? 'rotate-180' : ''}`} />
                    {open ? '收起详情' : '查看详情'}
                  </Button>
                  <Link to={`/alerts?open=${encodeURIComponent(it.last_alert_id || it.alert_id)}`} className="inline-flex h-7 items-center rounded-[7px] border border-border px-2 text-[11.5px] text-muted-foreground transition-colors hover:bg-accent hover:text-foreground">
                    打开原告警{burst > 1 ? '（最新）' : ''}
                  </Link>
                  {isPending && (
                    <Button size="sm" variant="ghost" disabled={busy === it.id} onClick={() => reeval(it)} title="调查规则改进后，用当前逻辑重评这条建议">
                      重新评估
                    </Button>
                  )}
                </div>

                {open && (
                  <div className="mt-2 rounded-md border border-border-soft bg-background px-3 py-2.5">
                    <div className="mb-1.5 text-[10.5px] font-semibold uppercase tracking-wide text-faint">调查证据（五步确定性 · {it.engine === 'heuristic' ? '规则版' : it.engine}）</div>
                    <ol className="grid gap-1.5">
                      {(it.findings || []).map((f, i) => (
                        <li key={i} className="text-[11.5px] leading-[1.65] text-muted-foreground">
                          <span className="mr-1 font-mono text-faint">{i + 1}.</span>{f.text}
                          {!!f.citations?.length && (
                            <span className="ml-1.5 font-mono text-[10px] text-faint">[{f.citations.map((c, j) => j < 3 ? c : '…').slice(0, 4).join(' · ')}]</span>
                          )}
                        </li>
                      ))}
                      {!(it.findings || []).length && <li className="text-[11.5px] text-faint">本条目为旧版入队快照，无证据记录——点「重新评估」按当前调查逻辑重跑。</li>}
                    </ol>
                    {!!it.actions?.length && (
                      <>
                        <div className="mb-1.5 mt-2.5 text-[10.5px] font-semibold uppercase tracking-wide text-faint">建议动作（都不自动执行）</div>
                        <div className="grid gap-1">
                          {it.actions.filter((a) => a.target).map((a, i) => (
                            <div key={i} className="flex flex-wrap items-baseline gap-1.5 text-[11.5px]">
                              <span className="rounded border border-border-soft px-1.5 py-0.5 font-mono text-[10.5px] text-faint">{a.type}:{a.target}</span>
                              {a.detail && <span className="text-[11px] text-faint">{a.detail}</span>}
                            </div>
                          ))}
                        </div>
                      </>
                    )}
                    {allowTips[it.id] && isPending && (
                      <div className="mt-2.5 rounded-md border border-warn/30 bg-warn-soft px-3 py-2 text-[11.5px]">
                        你标记了误报/确认良性。若同类告警确实不需要再告警，可把
                        <span className="mx-1 font-mono text-[10.5px]">{allowTips[it.id].type}:{allowTips[it.id].value.length > 24 ? allowTips[it.id].value.slice(0, 24) + '…' : allowTips[it.id].value}</span>
                        加入白名单——服务端会自动回收未处置的同类告警（可在白名单页撤销）。
                        <Button size="sm" variant="ghost" className="ml-1.5" disabled={busy === it.id} onClick={() => addToAllowlist(it)}>一键加白</Button>
                      </div>
                    )}
                    <div className="mt-2 text-[10.5px] text-faint">
                      入队于 {relTime(it.created_at)}{it.last_seen_at && <> · 爆发最近一次 {relTime(it.last_seen_at)}</>} · 来源 {it.engine === 'heuristic' ? '确定性调查（零模型调用）' : it.engine}
                    </div>
                  </div>
                )}

                {isPending && (
                  <div className="mt-1.5 flex gap-1.5">
                    <Button size="sm" variant="primary" disabled={busy === it.id} onClick={() => review(it, 'approve')}>认可建议</Button>
                    <Button size="sm" variant="ghost" disabled={busy === it.id} onClick={() => review(it, 'dismiss')} title={`按当前结案理由：${REASON_LABEL[reason] || reason}`}>忽略</Button>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </Card>
  );
}

