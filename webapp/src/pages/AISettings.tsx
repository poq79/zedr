import { useCallback, useEffect, useState } from 'react';
import { Bot, CheckCircle2, History, Pencil, Plus, Save, XCircle, FlaskConical, KeyRound } from 'lucide-react';
import { api } from '../lib/api';
import { Badge, Button, Card, CardTitle, EmptyState, Input, Select, SkeletonRows } from '../components/ui/basics';
import { Drawer, useConfirm, useToast } from '../components/ui/overlays';
import { useError } from '../lib/hooks';
import { relTime } from '../lib/format';

/* AI 平台：模型接入（任务槽位）/ 成本上限 / 提示词模板 / 技能包。
   全部 admin-only；保存即时热生效（引擎热重载，无需重启服务）。 */

interface SlotView {
  provider: string; base_url: string; model: string; effort: string;
  temperature: number; max_tokens: number; timeout_sec: number; enabled: boolean;
  has_key: boolean; key_hint?: string; source: string;
  // 仅前端编辑态：key_draft 是正在输入的新密钥（空=保留旧值），
  // clear_key 标记本次保存要删除已存密钥。不回传给 GET 结构。
  key_draft?: string; clear_key?: boolean;
}
interface AIConfigView {
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

const SLOT_META: Record<string, { label: string; desc: string }> = {
  triage: { label: '研判', desc: '告警研判：快模型控成本，逐条结论带证据引用' },
  hunt: { label: '狩猎', desc: '自然语言查告警：翻译为受控查询，值可变、结构不可变' },
  investigate: { label: '调查', desc: '自动调查编排；未单独配置时自动使用研判槽位' },
};

const SLOT_KEYS = ['triage', 'hunt', 'investigate'];
const EMPTY_SLOT: SlotView = {
  provider: 'openai', base_url: '', model: '', effort: 'off',
  temperature: 0.1, max_tokens: 1400, timeout_sec: 45,
  enabled: false, has_key: false, source: 'db',
};

/* ---------------- 槽位卡片 ---------------- */
function SlotCard({ task, slot, onChange, onTest, testing, probe }: {
  task: string; slot: SlotView; onChange: (s: SlotView) => void;
  onTest: () => void; testing: boolean; probe: ProbeResult | null;
}) {
  const meta = SLOT_META[task];
  const set = (patch: Partial<SlotView>) => onChange({ ...slot, ...patch });

  return (
    <Card className="p-4">
      <div className="mb-3 flex items-center justify-between">
        <div>
          <div className="flex items-center gap-2">
            <b className="text-[13px] text-foreground">{meta.label}</b>
            <Badge tone={slot.source === 'env' ? 'medium' : 'info'}>
              {slot.source === 'env' ? '环境变量引导' : '后台配置'}
            </Badge>
          </div>
          <p className="mt-0.5 text-[11.5px] text-faint">{meta.desc}</p>
        </div>
        <Switch checked={slot.enabled} onChange={(v) => set({ enabled: v })} label={slot.enabled ? '已启用' : '已停用'} />
      </div>

      <div className="grid grid-cols-2 gap-2.5">
        <label className="col-span-2">
          <span className="mb-1 block text-[11px] text-faint">服务地址（OpenAI 兼容 /v1）</span>
          <Input value={slot.base_url} onChange={(e) => set({ base_url: e.target.value })}
            placeholder="https://api.deepseek.com" spellCheck={false} />
        </label>
        <label className="col-span-2">
          <span className="mb-1 flex items-center gap-1 text-[11px] text-faint">
            <KeyRound size={11} /> API Key
            {slot.has_key && <span className="text-ok">已配置 {slot.key_hint}</span>}
          </span>
          <Input type="password" value={slot.key_draft ?? ''} autoComplete="new-password"
            onChange={(e) => set({ ...slot, key_draft: e.target.value })}
            placeholder={slot.has_key ? '留空保留现有密钥' : 'sk-…'} spellCheck={false} />
        </label>
        <label>
          <span className="mb-1 block text-[11px] text-faint">模型名称</span>
          <Input value={slot.model} onChange={(e) => set({ model: e.target.value })}
            placeholder="deepseek-chat" spellCheck={false} list={`models-${task}`} />
          <datalist id={`models-${task}`}>
            {(probe?.models || []).slice(0, 50).map((m) => <option key={m} value={m} />)}
          </datalist>
        </label>
        <label>
          <span className="mb-1 block text-[11px] text-faint">思考强度（仅推理模型）</span>
          <Select value={slot.effort} onChange={(e) => set({ effort: e.target.value })}>
            {['off', 'low', 'medium', 'high'].map((v) => <option key={v} value={v}>{v}</option>)}
          </Select>
        </label>
        <label>
          <span className="mb-1 block text-[11px] text-faint">温度（0-2）</span>
          <Input type="number" step="0.05" min="0" max="2" value={slot.temperature}
            onChange={(e) => set({ temperature: Number(e.target.value) || 0 })} />
        </label>
        <label>
          <span className="mb-1 block text-[11px] text-faint">超时（秒）</span>
          <Input type="number" min="3" max="300" value={slot.timeout_sec}
            onChange={(e) => set({ timeout_sec: Number(e.target.value) || 45 })} />
        </label>
      </div>

      <div className="mt-3 flex items-center gap-2.5">
        <Button size="sm" onClick={onTest} disabled={testing || !slot.base_url}>
          <FlaskConical size={12} /> {testing ? '测试中…' : '测试连接'}
        </Button>
        {slot.has_key && (
          <Button size="sm" variant="ghost"
            onClick={() => onChange({ ...slot, clear_key: true })}
            title="删除已保存的密钥">清除密钥</Button>
        )}
        {probe && (
          <span className="flex min-w-0 flex-1 items-center gap-1.5 text-[11.5px]">
            {probe.ok
              ? <CheckCircle2 size={13} className="shrink-0 text-ok" />
              : <XCircle size={13} className="shrink-0 text-destructive" />}
            <span className="truncate text-muted-foreground" title={probe.detail}>
              {probe.detail} · {probe.latency_ms}ms
            </span>
          </span>
        )}
      </div>
    </Card>
  );
}

/* ---------------- 开关 ---------------- */
function Switch({ checked, onChange, label }: { checked: boolean; onChange: (v: boolean) => void; label: string }) {
  return (
    <button type="button" role="switch" aria-checked={checked} aria-label={label}
      onClick={() => onChange(!checked)}
      className="flex cursor-pointer items-center gap-2 text-[11.5px] text-muted-foreground">
      <span className={`relative inline-block h-4.5 w-8 rounded-full border transition-colors duration-150 ${checked ? 'border-ok/40 bg-ok-soft' : 'border-border bg-secondary'}`}>
        <span className={`absolute top-[1px] h-3.5 w-3.5 rounded-full transition-all duration-150 ${checked ? 'left-[16px] bg-ok' : 'left-[1px] bg-muted-foreground'}`} />
      </span>
      {label}
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
  const [slots, setSlots] = useState<Record<string, SlotView>>({});
  const [budget, setBudget] = useState({ hourly_tokens: 200000, cache_ttl_sec: 300 });
  const [probes, setProbes] = useState<Record<string, ProbeResult>>({});
  const [testing, setTesting] = useState<Record<string, boolean>>({});
  const [saving, setSaving] = useState(false);

  const [prompts, setPrompts] = useState<Record<string, AIPrompt> | null>(null);
  const [promptTab, setPromptTab] = useState('triage');
  const [promptDraft, setPromptDraft] = useState('');
  const [promptBusy, setPromptBusy] = useState(false);

  const [skills, setSkills] = useState<AISkill[] | null>(null);
  const [skillEdit, setSkillEdit] = useState<AISkill | null>(null);

  const load = useCallback(async () => {
    try {
      const [c, p, s] = await Promise.all([
        api.get<AIConfigView>('/api/v1/ai/config'),
        api.get<Record<string, AIPrompt>>('/api/v1/ai/prompts'),
        api.get<AISkill[]>('/api/v1/ai/skills'),
      ]);
      setCfg(c);
      setSlots({ ...c.slots });
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

  /* 保存槽位 + 预算：api_key 留空 = 保留旧值（服务端合并语义） */
  const saveConfig = async () => {
    setSaving(true);
    try {
      const body: { slots: Record<string, unknown>; hourly_tokens: number; cache_ttl_sec: number } = {
        slots: {}, hourly_tokens: budget.hourly_tokens, cache_ttl_sec: budget.cache_ttl_sec,
      };
      for (const task of SLOT_KEYS) {
        const s = slots[task] as (SlotView & { key_draft?: string; clear_key?: boolean }) | undefined;
        if (!s) continue;
        body.slots[task] = {
          provider: s.provider || 'openai', base_url: s.base_url?.trim(), model: s.model?.trim(),
          effort: s.effort, temperature: s.temperature, max_tokens: s.max_tokens, timeout_sec: s.timeout_sec,
          enabled: s.enabled, api_key: s.key_draft ?? '', clear_key: !!s.clear_key,
        };
      }
      const next = await api.put<AIConfigView>('/api/v1/ai/config', body);
      setCfg(next);
      setSlots({ ...next.slots });
      toast('AI 配置已保存并热生效');
    } catch (e) { toast((e as Error).message, 'err'); }
    finally { setSaving(false); }
  };

  const testSlot = async (task: string) => {
    const s = slots[task] as (SlotView & { key_draft?: string }) | undefined;
    if (!s?.base_url) { toast('先填写服务地址', 'err'); return; }
    setTesting((t) => ({ ...t, [task]: true }));
    try {
      const res = await api.post<ProbeResult>('/api/v1/ai/config/test', {
        task, base_url: s.base_url.trim(), api_key: s.key_draft ?? '',
        model: s.model, timeout_sec: s.timeout_sec,
      });
      setProbes((p) => ({ ...p, [task]: res }));
      if (!res.ok) toast(res.detail, 'err');
    } catch (e) { toast((e as Error).message, 'err'); }
    finally { setTesting((t) => ({ ...t, [task]: false })); }
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
      const p = await api.get<Record<string, AIPrompt>>('/api/v1/ai/prompts');
      setPrompts(p);
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
      <div className="mb-3.5 flex items-center gap-2 text-[12px] text-muted-foreground">
        <Bot size={14} />
        <span>当前引擎：</span>
        <Badge tone={cfg?.engine === 'llm' ? 'info' : 'neutral'}>
          {cfg?.engine === 'llm' ? `LLM · ${cfg.engine_model || '-'}` : '确定性启发式'}
        </Badge>
        {cfg?.engine !== 'llm' && (
          <span className="text-faint">未配置模型时所有 AI 功能照常可用，结论由确定性引擎给出并标注。</span>
        )}
      </div>

      {/* 模型槽位 */}
      <div className="mb-1.5 flex items-center justify-between">
        <CardTitle>模型接入（任务槽位）</CardTitle>
        <Button variant="primary" size="sm" onClick={saveConfig} disabled={saving}>
          <Save size={12} /> {saving ? '保存中…' : '保存全部并热生效'}
        </Button>
      </div>
      <p className="mb-2.5 text-[11.5px] text-faint">
        兼容任何 OpenAI 协议服务（OpenAI / DeepSeek / 通义 / Kimi / vLLM / Ollama）。
        保存前可逐槽位拨测；调用失败会自动降级到确定性分析，判定不会中断。
      </p>
      <div className="mb-4 grid grid-cols-1 gap-3 xl:grid-cols-3">
        {!cfg ? (
          <Card className="col-span-full px-2 pb-2"><SkeletonRows rows={3} /></Card>
        ) : SLOT_KEYS.map((task) => (
          <SlotCard key={task} task={task} slot={slots[task] || EMPTY_SLOT}
            onChange={(s) => setSlots((prev) => ({ ...prev, [task]: s }))}
            onTest={() => testSlot(task)} testing={!!testing[task]} probe={probes[task] || null} />
        ))}
      </div>

      {/* 成本与缓存 */}
      <Card className="mb-4 p-4">
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
