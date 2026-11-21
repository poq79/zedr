import { useCallback, useEffect, useMemo, useState } from 'react';
import { Ban, CirclePlay, Copy, Eye, FlaskConical, Pencil, Plus, RefreshCw, Sigma as SigmaIcon, Trash2 } from 'lucide-react';
import { api } from '../lib/api';
import type { Rule, RuleCondition, RuleSchema, Severity } from '../lib/types';
import { SEV_LABEL } from '../lib/format';
import { Badge, Button, Card, CardTitle, EmptyState, Input, Select, SkeletonRows, Tabs } from '../components/ui/basics';
import { Drawer, useToast, useConfirm } from '../components/ui/overlays';
import { useError } from '../lib/hooks';

/* 规则中心（RESEARCH-RULE-OPS §4）：模板 → 表单 → 观察模式 → 转正的
   运营闭环。设计原则是"简单的事默认简单，复杂的能力藏在第二层"：
   运营者 90% 的场景选模板改几个值就能保存；完整 DSL 留在高级 JSON 视图。 */

const OBSERVE_HINT =
  '观察模式下探针照常求值这条规则，但只记录命中次数、不产生告警。' +
  '新规则建议先观察一段时间（业界惯例 ≥7 天），确认现网命中面符合预期再转正。';

type GroupKey = 'all' | 'any' | 'none';

/** 编辑器里的条件行：value 保持原始文本，保存时按字段类型转换。 */
interface CondRow { field: string; op: string; value: string }

interface EditorState {
  id: string;
  name: string;
  description: string;
  severity: Severity;
  score: number;
  mitre: string;
  mode: 'observe' | 'active';
  enabled: boolean;
  all: CondRow[];
  any: CondRow[];
  none: CondRow[];
  jsonMode: boolean;
  jsonText: string;
}

const GROUP_LABEL: Record<GroupKey, string> = { all: '全部满足', any: '任一满足', none: '全不满足' };
const GROUP_HINT: Record<GroupKey, string> = {
  all: '组内每个条件都成立（AND）',
  any: '组内至少一个条件成立（OR）',
  none: '组内条件都不成立时才继续（用于排除已知安全场景）',
};

/** 这些操作符的 value 恒为列表（逗号分隔文本 → 数组）。 */
const LIST_VALUE_OPS = new Set(['in', 'nin', 'any_in_list', 'list_has_any']);

const emptyRow = (): CondRow => ({ field: 'process.name', op: 'in', value: '' });

const blankEditor = (): EditorState => ({
  id: '', name: '', description: '', severity: 'medium', score: 30, mitre: '',
  mode: 'observe', enabled: true,
  all: [emptyRow()], any: [], none: [],
  jsonMode: false, jsonText: '',
});

/** 把 Definition JSON 反序列化回条件行（值转回可编辑文本）。 */
function rowsFrom(def: { all?: RuleCondition[]; any?: RuleCondition[]; none?: RuleCondition[] }): Pick<EditorState, 'all' | 'any' | 'none'> {
  const conv = (cs?: RuleCondition[]): CondRow[] =>
    (cs || []).map((c) => ({
      field: String(c.field || 'process.name'),
      op: String(c.op || 'eq'),
      value: Array.isArray(c.value) ? c.value.join(', ') : String(c.value ?? ''),
    }));
  return { all: conv(def.all), any: conv(def.any), none: conv(def.none) };
}

/* ================= 页面 ================= */

export function RulesCenterPage({ user }: { user: { role: string } }) {
  const err = useError();
  const toast = useToast();
  const confirm = useConfirm();
  const isAdmin = user.role === 'admin';
  const canWrite = user.role !== 'viewer';

  const [rules, setRules] = useState<Rule[] | null>(null);
  const [schema, setSchema] = useState<RuleSchema | null>(null);
  const [q, setQ] = useState('');
  const [sigmaOpen, setSigmaOpen] = useState(false);
  const [editor, setEditor] = useState<EditorState | null>(null);

  const load = useCallback(async () => {
    try {
      const [r, s] = await Promise.all([
        api.get<{ items: Rule[] }>('/api/v1/rules'),
        api.get<RuleSchema>('/api/v1/rules/schema'),
      ]);
      setRules(r.items || []);
      setSchema(s);
    } catch (e) { err.capture(e); }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => { load(); }, [load]);
  if (err.rendered) return err.rendered;

  const filtered = useMemo(() => {
    if (!rules) return null;
    const kw = q.trim().toLowerCase();
    if (!kw) return rules;
    return rules.filter((r) =>
      r.id.toLowerCase().includes(kw) || r.name.toLowerCase().includes(kw) ||
      (r.description || '').toLowerCase().includes(kw));
  }, [rules, q]);

  const stats = useMemo(() => {
    const list = rules || [];
    return {
      total: list.length,
      enabled: list.filter((r) => r.enabled && r.mode !== 'observe').length,
      observe: list.filter((r) => r.enabled && r.mode === 'observe').length,
      custom: list.filter((r) => !r.builtin).length,
    };
  }, [rules]);

  /* 启停 / 观察切换 / 删除 —— 行内高频动作 */
  const toggle = async (r: Rule) => {
    try {
      await api.post(`/api/v1/rules/${encodeURIComponent(r.id)}/toggle`, { enabled: !r.enabled });
      toast(r.enabled ? '已禁用该规则' : '已启用该规则');
      load();
    } catch (e) { toast((e as Error).message, 'err'); }
  };

  const setMode = async (r: Rule, mode: 'observe' | 'active') => {
    try {
      await api.post(`/api/v1/rules/${encodeURIComponent(r.id)}/mode`, { mode });
      toast(mode === 'observe'
        ? '已转入观察模式：命中只计数不告警，等观察数据稳定后再转正'
        : '已转正：规则命中开始参与告警');
      load();
    } catch (e) { toast((e as Error).message, 'err'); }
  };

  const remove = async (r: Rule) => {
    const ok = await confirm({
      title: '删除自定义规则？',
      message: `规则 ${r.id}（${r.name}）将从规则包中移除，全部终端在下次同步后不再执行该检测。`,
      danger: true, okText: '删除',
    });
    if (!ok) return;
    try {
      await api.del(`/api/v1/rules/${encodeURIComponent(r.id)}`);
      toast('已删除');
      load();
    } catch (e) { toast((e as Error).message, 'err'); }
  };

  /* 克隆内置规则为自定义起点：内置内容属产品发布物（重启播种会还原），
     本地化调整的正确姿势是克隆后改克隆体 */
  const clone = (r: Rule) => {
    let def: { all?: RuleCondition[]; any?: RuleCondition[]; none?: RuleCondition[] } = {};
    try { def = JSON.parse(r.definition); } catch { /* 空定义兜底 */ }
    setEditor({
      ...blankEditor(),
      id: '',
      name: `克隆 · ${r.name}`,
      description: r.description,
      severity: r.severity, score: r.score,
      mitre: (r.mitre || []).join(', '),
      mode: 'observe',
      ...rowsFrom(def),
    });
  };

  const edit = (r: Rule) => {
    let def: { all?: RuleCondition[]; any?: RuleCondition[]; none?: RuleCondition[] } = {};
    try { def = JSON.parse(r.definition); } catch { /* 保存时后端会校验 */ }
    setEditor({
      ...blankEditor(),
      id: r.id,
      name: r.name,
      description: r.description,
      severity: r.severity, score: r.score,
      mitre: (r.mitre || []).join(', '),
      mode: r.mode === 'observe' ? 'observe' : 'active',
      enabled: r.enabled,
      ...rowsFrom(def),
    });
  };

  return (
    <div className="space-y-3.5">
      {/* KPI 数据带：与总览页同构（一格面板 + 发丝线分隔，数字 mono） */}
      <div className="grid grid-cols-2 divide-border-soft border border-border-soft rounded-md bg-card xl:grid-cols-4 xl:divide-x">
        {[
          { label: '规则总数', v: stats.total, sub: '内置 + 自定义' },
          { label: '告警中', v: stats.enabled, sub: '启用且正常模式' },
          { label: '观察中', v: stats.observe, sub: '只计数不告警' },
          { label: '自定义', v: stats.custom, sub: '可编辑可删除' },
        ].map((k) => (
          <div key={k.label} className="px-4 py-3.5">
            <div className="text-[11px] tracking-[.06em] uppercase text-faint">{k.label}</div>
            <div className="mt-1.5 font-mono text-[26px] leading-none font-semibold tabular-nums">{k.v}</div>
            <div className="mt-1 text-[11px] text-faint">{k.sub}</div>
          </div>
        ))}
      </div>

      <div className="mb-0 flex items-center gap-2.5">
        <Input value={q} onChange={(e) => setQ(e.target.value)} placeholder="搜索规则 ID / 名称 / 描述" className="max-w-[280px]" />
        <div className="flex-1" />
        {canWrite && (
          <>
            <Button variant="ghost" onClick={() => { setEditor(blankEditor()); }}>
              <FlaskConical size={13} /> 从模板新建
            </Button>
            <Button variant="ghost" onClick={() => setSigmaOpen(true)}>
              <SigmaIcon size={13} /> 导入 Sigma
            </Button>
            <Button variant="primary" onClick={() => setEditor(blankEditor())}><Plus size={13} /> 新建规则</Button>
          </>
        )}
        <Button size="sm" variant="ghost" onClick={load}><RefreshCw size={13} /></Button>
      </div>

      {!filtered ? <Card className="px-2 pb-2"><SkeletonRows rows={8} /></Card> : !filtered.length ? (
        <Card><EmptyState icon={<CirclePlay size={20} />} title={q ? '没有匹配的规则' : '还没有规则'}
          sub={q ? '换个关键词试试。' : '内置规则已随服务端播种。想加自己的检测，选一个模板改几个值即可。'} /></Card>
      ) : (
        <Card className="overflow-x-auto px-2 py-3.5">
          <table className="w-full text-[13px]">
            <thead><tr className="border-b border-border-soft text-left text-[11px] tracking-[.06em] text-faint uppercase">
              {['规则 ID', '名称', '严重度', '分值', 'ATT&CK', '来源', '状态', '观察命中', '操作'].map((h) => <th key={h} className="px-3.5 py-2.5 font-semibold">{h}</th>)}
            </tr></thead>
            <tbody>
              {filtered.map((r) => {
                const observing = r.enabled && r.mode === 'observe';
                return (
                  <tr key={r.id} className="border-b border-border-soft last:border-b-0 hover:bg-secondary align-middle">
                    <td className="px-3.5 py-2.5 font-mono text-xs">{r.id}</td>
                    <td className="px-3.5 py-2.5">
                      <div className="font-medium">
                        {r.name}
                        {observing && (
                          <Badge tone="info" className="ml-2" title="观察模式：命中只计数、不产生告警">观察中</Badge>
                        )}
                      </div>
                      <div className="mt-0.5 max-w-[460px] text-xs text-faint">{r.description}</div>
                    </td>
                    <td className="px-3.5 py-2.5"><Badge tone={r.severity}>{SEV_LABEL[r.severity]}</Badge></td>
                    <td className="px-3.5 py-2.5 font-mono font-bold tabular-nums">{r.score}</td>
                    <td className="px-3.5 py-2.5 font-mono text-xs text-faint">{(r.mitre || []).join(', ') || '-'}</td>
                    <td className="px-3.5 py-2.5 text-xs text-faint">{r.builtin ? '内置' : '自定义'}</td>
                    <td className="px-3.5 py-2.5">
                      {r.enabled
                        ? <Badge tone="resolved">启用</Badge>
                        : <Badge tone="neutral">禁用</Badge>}
                    </td>
                    <td className="px-3.5 py-2.5 font-mono text-xs tabular-nums" title="全部终端当前运行期观察命中之和（探针重启后从零计）">
                      {observing ? (r.observed_hits ?? 0) : <span className="text-faint">-</span>}
                    </td>
                    <td className="px-3.5 py-2.5">
                      <div className="flex flex-wrap gap-1.5">
                        {canWrite && (
                          <Button size="sm" variant="ghost" onClick={() => toggle(r)}>{r.enabled ? '禁用' : '启用'}</Button>
                        )}
                        {canWrite && r.enabled && (
                          <Button size="sm" variant="ghost"
                            title={observing ? '转正：命中开始产生告警' : '转入观察：命中只计数不告警'}
                            onClick={() => setMode(r, observing ? 'active' : 'observe')}>
                            {observing ? '转正' : '观察'}
                          </Button>
                        )}
                        {!r.builtin && canWrite && (
                          <Button size="sm" variant="ghost" onClick={() => edit(r)}><Pencil size={12} /> 编辑</Button>
                        )}
                        {canWrite && (
                          <Button size="sm" variant="ghost" title={r.builtin ? '克隆为自定义规则再修改' : '以此规则为模板新建'}
                            onClick={() => clone(r)}><Copy size={12} /> 克隆</Button>
                        )}
                        {!r.builtin && isAdmin && (
                          <Button size="sm" variant="ghost" onClick={() => remove(r)}><Trash2 size={12} /></Button>
                        )}
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </Card>
      )}

      {/* 编辑抽屉 */}
      {editor && (
        <RuleEditorDrawer
          state={editor}
          schema={schema}
          onClose={() => setEditor(null)}
          onSaved={() => { setEditor(null); load(); }}
        />
      )}
      <SigmaImportDrawer open={sigmaOpen} onClose={() => setSigmaOpen(false)} onImported={() => { setSigmaOpen(false); load(); }} />
    </div>
  );
}

/* ================= 编辑抽屉 ================= */

function RuleEditorDrawer({ state, schema, onClose, onSaved }: {
  state: EditorState;
  schema: RuleSchema | null;
  onClose: () => void;
  onSaved: () => void;
}) {
  const toast = useToast();
  const [s, setS] = useState<EditorState>(state);
  const [busy, setBusy] = useState(false);
  const isEdit = !!s.id;
  const upd = (patch: Partial<EditorState>) => setS((p) => ({ ...p, ...patch }));

  const opsFor = (field: string) => {
    const fd = schema?.fields.find((f) => f.field === field);
    const ops = (schema?.ops || []).filter((o) => !o.kinds || (fd && o.kinds.includes(fd.kind)));
    return ops.length ? ops : schema?.ops || [];
  };

  /* 模板 → 表单（仅新建时可改模板；编辑中下拉展示为不可用提示） */
  const onTemplatePick = (tplId: string) => {
    const tp = schema?.templates.find((t) => t.id === tplId);
    if (!tp) return;
    setS((p) => ({
      ...p,
      name: tp.name,
      description: tp.description,
      severity: tp.severity, score: tp.score,
      mitre: (tp.mitre || []).join(', '),
      ...rowsFrom(tp.definition),
      jsonMode: false, jsonText: '',
    }));
  };

  /* JSON 视图 ⇄ 表单视图：进 JSON 时序列化当前表单；出 JSON 时解析回表单，
     解析失败留在 JSON 视图（不丢用户输入） */
  const enterJson = () => {
    const def = buildDefinition(s);
    setS((p) => ({ ...p, jsonMode: true, jsonText: JSON.stringify(def, null, 2) }));
  };
  const leaveJson = () => {
    try {
      const def = JSON.parse(s.jsonText);
      setS((p) => ({ ...p, jsonMode: false, ...rowsFrom(def), jsonText: '' }));
    } catch {
      toast('JSON 尚未合法，修正后再切回表单视图', 'warn');
    }
  };

  const save = async () => {
    if (!s.name.trim()) return toast('请填写规则名称', 'warn');
    let definition: string;
    if (s.jsonMode) {
      try { JSON.parse(s.jsonText); definition = s.jsonText.trim(); }
      catch { return toast('规则定义不是合法 JSON', 'err'); }
    } else {
      if (!s.all.length && !s.any.length && !s.none.length) return toast('至少需要一个条件', 'warn');
      definition = JSON.stringify(buildDefinition(s));
    }
    setBusy(true);
    try {
      await api.post('/api/v1/rules', {
        id: s.id.trim(),
        name: s.name.trim(),
        description: s.description.trim(),
        severity: s.severity,
        score: Number(s.score) || 30,
        mitre: s.mitre.split(',').map((x) => x.trim()).filter(Boolean),
        enabled: s.enabled,
        mode: s.mode,
        definition,
      });
      toast(isEdit ? '规则已更新并下发' : '规则已保存并下发（观察模式可在列表转正）');
      onSaved();
    } catch (e) { toast((e as Error).message, 'err'); } finally { setBusy(false); }
  };

  return (
    <Drawer open onClose={onClose} title={isEdit ? `编辑规则 ${s.id}` : '新建规则'}
      sub="保存即编译校验并签名下发；新规则建议保持观察模式跑一段时间再转正"
      foot={
        <>
          <Button variant="primary" onClick={save} disabled={busy}>{busy ? '保存中…' : '保存并下发'}</Button>
          <Button variant="ghost" onClick={onClose}>取消</Button>
        </>
      }>
      <div className="space-y-4">
        {/* 模板选择：新建时的第一入口 */}
        {!isEdit && schema && (
          <label className="block">
            <span className="mb-1.5 block text-[11.5px] text-faint">从模板开始（选定后可再改任意字段）</span>
            <Select className="w-full" defaultValue="" onChange={(e) => e.target.value && onTemplatePick(e.target.value)}>
              <option value="" disabled>选择模板…</option>
              {schema.templates.map((t) => <option key={t.id} value={t.id}>{t.name}</option>)}
            </Select>
            {(() => {
              const tp = schema.templates.find((t) => t.name === s.name);
              return tp ? <div className="mt-1.5 text-[11.5px] text-faint">{tp.description}</div> : null;
            })()}
          </label>
        )}

        <div className="grid gap-3 sm:grid-cols-2">
          <label className="block"><span className="mb-1.5 block text-[11.5px] text-faint">名称</span>
            <Input value={s.name} onChange={(e) => upd({ name: e.target.value })} className="w-full" placeholder="例如：可疑的登录脚本执行" />
          </label>
          <label className="block"><span className="mb-1.5 block text-[11.5px] text-faint">ATT&amp;CK（逗号分隔，可空）</span>
            <Input value={s.mitre} onChange={(e) => upd({ mitre: e.target.value })} className="w-full font-mono text-xs" placeholder="T1059.001" />
          </label>
        </div>
        <label className="block"><span className="mb-1.5 block text-[11.5px] text-faint">描述（会出现在告警详情里）</span>
          <Input value={s.description} onChange={(e) => upd({ description: e.target.value })} className="w-full" placeholder="这条规则为什么值得告警" />
        </label>
        <div className="grid gap-3 sm:grid-cols-3">
          <label className="block"><span className="mb-1.5 block text-[11.5px] text-faint">严重度</span>
            <Select value={s.severity} onChange={(e) => upd({ severity: e.target.value as Severity })} className="w-full">
              {Object.entries(SEV_LABEL).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
            </Select>
          </label>
          <label className="block"><span className="mb-1.5 block text-[11.5px] text-faint">分值（1-100，70 分到恶意线）</span>
            <Input type="number" min={1} max={100} value={s.score} onChange={(e) => upd({ score: parseInt(e.target.value, 10) || 30 })} className="w-full font-mono tabular-nums" />
          </label>
          <label className="block"><span className="mb-1.5 block text-[11.5px] text-faint">执行模式</span>
            <Select value={s.mode} onChange={(e) => upd({ mode: e.target.value as 'observe' | 'active' })} className="w-full">
              <option value="observe">观察（只计数不告警）</option>
              <option value="active">正常（参与告警）</option>
            </Select>
          </label>
        </div>
        {s.mode === 'observe' && (
          <div className="flex items-start gap-2 rounded-[7px] border border-border-soft bg-secondary px-3 py-2.5 text-[12px] text-muted-foreground">
            <Eye size={14} className="mt-0.5 shrink-0 text-info" />
            <span>{OBSERVE_HINT}</span>
          </div>
        )}

        {/* 条件体：表单视图 / JSON 高级视图 */}
        <div>
          <div className="mb-2.5 flex items-center">
            <CardTitle>条件定义</CardTitle>
            <div className="flex-1" />
            <Tabs
              tabs={[{ key: 'form', label: '表单' }, { key: 'json', label: '高级 JSON' }]}
              value={s.jsonMode ? 'json' : 'form'}
              onChange={(k) => (k === 'json' ? enterJson() : leaveJson())}
            />
          </div>

          {s.jsonMode ? (
            <textarea
              rows={14}
              value={s.jsonText}
              onChange={(e) => upd({ jsonText: e.target.value })}
              className="w-full rounded-[7px] border border-input bg-card p-3 font-mono text-xs leading-[1.6] text-foreground outline-none focus:border-primary"
              spellCheck={false}
            />
          ) : (
            <div className="space-y-3">
              {schema && (['all', 'any', 'none'] as GroupKey[]).map((g) => (
                <div key={g} className="rounded-[7px] border border-border-soft p-3">
                  <div className="mb-2 flex items-center gap-2">
                    <span className="text-[12px] font-semibold">{GROUP_LABEL[g]}</span>
                    <span className="text-[11px] text-faint">{GROUP_HINT[g]}</span>
                    <div className="flex-1" />
                    <Button size="sm" variant="ghost" onClick={() => upd({ [g]: [...s[g], emptyRow()] } as Partial<EditorState>)}>
                      <Plus size={12} /> 加条件
                    </Button>
                  </div>
                  {s[g].length === 0 ? (
                    <div className="text-[11.5px] text-faint">（空——{g === 'none' ? '没有要排除的场景' : '可留空'}）</div>
                  ) : (
                    <div className="space-y-2">
                      {s[g].map((row, i) => (
                        <div key={`${g}-${i}`} className="grid items-center gap-2 sm:grid-cols-[minmax(0,1.2fr)_minmax(0,1fr)_minmax(0,1.6fr)_auto]">
                          <Select value={row.field} className="w-full font-mono text-xs"
                            onChange={(e) => {
                              const field = e.target.value;
                              // 换字段时操作符重置为该字段类型的第一个合法操作符
                              const firstOp = opsFor(field)[0]?.op || 'eq';
                              const rows = [...s[g]]; rows[i] = { field, op: firstOp, value: '' };
                              upd({ [g]: rows } as Partial<EditorState>);
                            }}>
                            {Object.entries(schema.fields.reduce<Record<string, typeof schema.fields>>((acc, f) => {
                              (acc[f.group] = acc[f.group] || []).push(f);
                              return acc;
                            }, {})).map(([grp, fs]) => (
                              <optgroup key={grp} label={grp}>
                                {fs.map((f) => <option key={f.field} value={f.field} title={f.desc}>{f.field}</option>)}
                              </optgroup>
                            ))}
                          </Select>
                          <Select value={row.op} className="w-full"
                            onChange={(e) => {
                              const rows = [...s[g]]; rows[i] = { ...row, op: e.target.value };
                              upd({ [g]: rows } as Partial<EditorState>);
                            }}>
                            {opsFor(row.field).map((o) => <option key={o.op} value={o.op} title={o.desc}>{o.op}</option>)}
                          </Select>
                          {row.op === 'exists' ? (
                            <div className="text-[11.5px] text-faint">（exists 无需值）</div>
                          ) : opsFor(row.field).find((o) => o.op === row.op)?.kinds?.[0] === 'bool' || (schema.fields.find((f) => f.field === row.field)?.kind === 'bool') ? (
                            <Select value={row.value || 'true'} className="w-full"
                              onChange={(e) => {
                                const rows = [...s[g]]; rows[i] = { ...row, value: e.target.value };
                                upd({ [g]: rows } as Partial<EditorState>);
                              }}>
                              <option value="true">true</option>
                              <option value="false">false</option>
                            </Select>
                          ) : (
                            <Input value={row.value} className="w-full font-mono text-xs"
                              placeholder={LIST_VALUE_OPS.has(row.op) ? '多个值用英文逗号分隔' : (schema.fields.find((f) => f.field === row.field)?.example || '值')}
                              onChange={(e) => {
                                const rows = [...s[g]]; rows[i] = { ...row, value: e.target.value };
                                upd({ [g]: rows } as Partial<EditorState>);
                              }} />
                          )}
                          <Button size="sm" variant="ghost" title="移除该条件"
                            onClick={() => upd({ [g]: s[g].filter((_, j) => j !== i) } as Partial<EditorState>)}>
                            <Ban size={12} />
                          </Button>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              ))}
              <div className="text-[11.5px] text-faint">
                保存时服务端会按引擎白名单严格校验字段与操作符——拼错的字段在这一步就会报错，而不是上线后静默失效。
              </div>
            </div>
          )}
        </div>
      </div>
    </Drawer>
  );
}

function buildDefinition(s: EditorState): { all?: RuleCondition[]; any?: RuleCondition[]; none?: RuleCondition[] } {
  // typedValue 需要 schema —— 这里从行数据直接转换（bool/int/列表）
  const conv = (rows: CondRow[]): RuleCondition[] => {
    const out: RuleCondition[] = [];
    for (const r of rows) {
      if (!r.field || !r.op) continue;
      let value: unknown = r.value;
      if (LIST_VALUE_OPS.has(r.op)) {
        value = r.value.split(',').map((x) => x.trim()).filter(Boolean);
      } else if (r.value === 'true' && BOOL_FIELDS.has(r.field)) value = true;
      else if (r.value === 'false' && BOOL_FIELDS.has(r.field)) value = false;
      else if (INT_FIELDS.has(r.field)) { const n = parseInt(r.value, 10); value = isNaN(n) ? r.value : n; }
      out.push({ field: r.field, op: r.op, value });
    }
    return out;
  };
  const def: { all?: RuleCondition[]; any?: RuleCondition[]; none?: RuleCondition[] } = {};
  if (s.all.length) def.all = conv(s.all);
  if (s.any.length) def.any = conv(s.any);
  if (s.none.length) def.none = conv(s.none);
  return def;
}

/* 字段类型表（与 rules_meta.go 的 Schema() 同步维护——这里是渲染期
   兜底，schema 接口可用时以接口数据为准） */
const BOOL_FIELDS = new Set([
  'process.signed', 'process.signature_ok', 'process.elevated',
  'process.in_system', 'process.dir_writable', 'network.has_public_remote',
]);
const INT_FIELDS = new Set(['process.session', 'process.depth', 'network.count', 'module.unsigned_count', 'module.non_system_count']);

/* ---------------- Sigma 批量导入（M1，2026-11-21） ----------------
   三态报告：created（observe 模式入库）/ skipped（门禁拒绝+原因）。
   转换门禁见 internal/rules/sigma.go——只收 windows/process_creation、
   status=stable/test，导入即观察模式，人工转正。 */

interface SigmaImportReport {
  docs: number;
  created: { id: string; name: string; severity: string; mode: string }[];
  skipped: { title: string; reason: string }[];
  total_generated: number;
}

function SigmaImportDrawer({ open, onClose, onImported }: { open: boolean; onClose: () => void; onImported: () => void }) {
  const toast = useToast();
  const [text, setText] = useState('');
  const [busy, setBusy] = useState(false);
  const [report, setReport] = useState<SigmaImportReport | null>(null);

  const submit = async () => {
    if (!text.trim()) return;
    setBusy(true);
    try {
      const rep = await api.post<SigmaImportReport>('/api/v1/rules/sigma-import', { yaml: text });
      setReport(rep);
      setText('');
      onImported();
      toast(`导入完成：新增 ${rep.created.length} 条，跳过 ${rep.skipped.length} 条`);
    } catch (e) {
      toast((e as Error).message, 'err');
    } finally { setBusy(false); }
  };

  const onFile = (f: File | undefined) => {
    if (!f) return;
    const rd = new FileReader();
    rd.onload = () => setText(String(rd.result || ''));
    rd.readAsText(f);
  };

  return (
    <Drawer open={open} onClose={onClose} title="导入 Sigma 规则" width={760}>
      <p className="mt-0 mb-3 text-[12px] leading-[1.8] text-muted-foreground">
        粘贴 Sigma YAML（支持多文档 <code>---</code> 分隔）。导入的规则一律进入<b>观察模式</b>且默认停用——
        先观察命中量与误报面，人工转正后才会参与打分告警。仅支持 <code>category: process_creation</code>、
        <code>status: stable/test</code>；其余类别/级别逐条给出拒绝原因。
      </p>
      <textarea
        value={text}
        onChange={(e) => setText(e.target.value)}
        rows={10}
        spellCheck={false}
        placeholder="粘贴 Sigma YAML（支持多文档 --- 分隔）…"
        className="w-full rounded-md border border-border-soft bg-background px-3 py-2.5 font-mono text-[11.5px] leading-[1.7] text-foreground"
      />
      <div className="mt-2 flex items-center gap-2.5">
        <input type="file" accept=".yml,.yaml,.txt" onChange={(e) => onFile(e.target.files?.[0])}
          className="text-[11.5px] text-muted-foreground" aria-label="从文件读取 Sigma YAML" />
        <div className="flex-1" />
        <Button variant="primary" disabled={busy || !text.trim()} onClick={submit}>
          {busy ? '导入中…' : '转换并导入'}
        </Button>
      </div>

      {report && (
        <div className="mt-3 rounded-md border border-border-soft bg-secondary/40 px-3.5 py-3">
          <div className="mb-1.5 text-[12px]">
            文档 {report.docs} 份 · 展开规则 {report.total_generated} 条 · 入库 <b className="text-ok">{report.created.length}</b> · 跳过 <b className="text-warn">{report.skipped.length}</b>
          </div>
          {!!report.created.length && (
            <div className="mt-1.5">
              <div className="mb-1 text-[10.5px] font-semibold uppercase tracking-wide text-faint">已入库（观察模式 · 停用）</div>
              {report.created.map((r) => (
                <div key={r.id} className="flex items-center gap-2 py-0.5 text-[11.5px]">
                  <span className="font-mono text-faint">{r.id}</span>
                  <span className="min-w-0 flex-1 truncate">{r.name}</span>
                  <Badge tone={r.severity}>{SEV_LABEL[r.severity] || r.severity}</Badge>
                  <Badge tone="info">观察</Badge>
                </div>
              ))}
            </div>
          )}
          {!!report.skipped.length && (
            <div className="mt-2">
              <div className="mb-1 text-[10.5px] font-semibold uppercase tracking-wide text-faint">跳过（附原因）</div>
              {report.skipped.map((s, i) => (
                <div key={i} className="py-0.5 text-[11.5px]">
                  <b className="text-warn">{s.title}</b>
                  <span className="ml-1.5 text-faint">{s.reason}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </Drawer>
  );
}
