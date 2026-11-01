import { useCallback, useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { KeyRound, Monitor, Plus, RefreshCw, ShieldCheck } from 'lucide-react';
import { api } from '../lib/api';
import type { Host, AllowEntry, AuditRow, User as UserRow, Severity, Role, IntegrityReport } from '../lib/types';
import { SEV_LABEL, relTime, fmtTime } from '../lib/format';
import { Badge, Button, Card, CardTitle, EmptyState, Input, Select, SkeletonRows } from '../components/ui/basics';
import { useToast, useConfirm } from '../components/ui/overlays';
import { useError } from '../lib/hooks';
import { cn } from '../lib/utils';

/* ================= 主机终端 ================= */
/* 主机详情已升级为整页 /hosts/:id（见 HostDetail.tsx） */

export function HostsPage() {
  const err = useError();
  const navigate = useNavigate();
  const [hosts, setHosts] = useState<Host[] | null>(null);

  const load = useCallback(async () => {
    try { setHosts((await api.get<{ items: Host[] }>('/api/v1/hosts')).items || []); }
    catch (e) { err.capture(e); }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => { load(); }, [load]);
  if (err.rendered) return err.rendered;

  return (
    <div>
      {!hosts ? <Card className="px-2 pb-2"><SkeletonRows rows={5} /></Card> : !hosts.length ? (
        <Card><EmptyState tone="info" icon={<Monitor size={20} />} title="还没有终端注册"
          sub={<>在目标机器上启动 <b>secagent.exe</b>，并配置正确的<br /><code className="rounded bg-brand-soft px-1 font-mono text-[11px] text-primary">HG_AGENT_SERVER_URL</code> 与 <code className="rounded bg-brand-soft px-1 font-mono text-[11px] text-primary">HG_AGENT_ENROLL_TOKEN</code>。<br />终端注册后约 30 秒内会出现在这里。</>} /></Card>
      ) : (
        <Card className="overflow-x-auto px-2 py-3.5">
          <table className="w-full text-[13px]">
            <thead><tr className="border-b border-border-soft text-left text-[11px] tracking-[.06em] text-faint uppercase">
              {['状态', '主机', '系统', '运行账号', '进程数', 'CPU', '内存', '待处置', '最后心跳'].map((h) => <th key={h} className="px-3.5 py-2.5 font-semibold">{h}</th>)}
            </tr></thead>
            <tbody>
              {hosts.map((h) => (
                <tr key={h.id} onClick={() => navigate(`/hosts/${h.id}`)}
                  className="cursor-pointer border-b border-border-soft transition-colors last:border-b-0 hover:bg-secondary">
                  <td className="px-3.5 py-2.5">
                    <Badge tone={h.status}>{h.status === 'online' ? '在线' : '离线'}</Badge>
                    {(h.clock_skew_ms || 0) > 10000 && (
                      <div className="mt-1"><Badge tone="medium" title="终端与服务端时钟偏移超过 10 秒">时钟偏移 {Math.round(h.clock_skew_ms! / 1000)}s</Badge></div>
                    )}
                  </td>
                  <td className="px-3.5 py-2.5"><b>{h.hostname}</b><div className="font-mono text-xs text-faint">{h.id}</div></td>
                  <td className="px-3.5 py-2.5 text-xs text-faint">{h.os_version || '-'}<br />{h.arch || ''} · v{h.version || '-'}</td>
                  <td className="px-3.5 py-2.5 font-mono text-xs">{h.username || '-'}</td>
                  <td className="px-3.5 py-2.5 tabular-nums">{h.proc_count || 0}</td>
                  <td className="px-3.5 py-2.5 tabular-nums">{(h.cpu_percent || 0).toFixed(1)}%</td>
                  <td className="px-3.5 py-2.5 tabular-nums">{(h.mem_mb || 0).toFixed(0)} MB</td>
                  <td className="px-3.5 py-2.5">{h.open_alerts ? <Badge tone="critical">{h.open_alerts}</Badge> : <span className="text-faint">0</span>}</td>
                  <td className="px-3.5 py-2.5 text-xs text-faint" title={fmtTime(h.last_seen_at)}>{relTime(h.last_seen_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
          <p className="mt-2 px-3.5 text-xs text-faint">点击任意一行进入主机详情整页：系统概要 · 网络适配器 · 监听端口 · 服务 · 计划任务 · 自启动 · 处置指令 · 指令历史。终端默认每 30 秒心跳一次。</p>
        </Card>
      )}
    </div>
  );
}

/* ================= 检测规则 ================= */

interface Rule { id: string; name: string; description?: string; severity: Severity; score: number; mitre?: string[]; builtin?: boolean; enabled: boolean }

export function RulesPage({ user }: { user: { role: Role } }) {
  const err = useError();
  const toast = useToast();
  const canWrite = user.role !== 'viewer';
  const [rules, setRules] = useState<Rule[] | null>(null);
  const [editorOpen, setEditorOpen] = useState(false);

  const load = useCallback(async () => {
    try { setRules((await api.get<{ items: Rule[] }>('/api/v1/rules')).items || []); }
    catch (e) { err.capture(e); }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => { load(); }, [load]);
  if (err.rendered) return err.rendered;

  const toggle = async (r: Rule) => {
    try {
      await api.post(`/api/v1/rules/${encodeURIComponent(r.id)}/toggle`, { enabled: !r.enabled });
      toast(r.enabled ? '已禁用该规则' : '已启用该规则');
      load();
    } catch (e) { toast((e as Error).message, 'err'); }
  };

  return (
    <div>
      <div className="mb-3.5 flex items-center gap-2.5">
        <span className="text-xs text-faint">共 {rules?.length ?? 0} 条规则 · 内置规则可禁用但不可删除</span>
        <div className="flex-1" />
        {canWrite && <Button size="sm" variant="primary" onClick={() => setEditorOpen((v) => !v)}><Plus size={13} /> 新建规则</Button>}
      </div>

      {!rules ? <Card className="px-2 pb-2"><SkeletonRows rows={6} /></Card> : (
        <Card className="overflow-x-auto px-2 py-3.5">
          <table className="w-full text-[13px]">
            <thead><tr className="border-b border-border-soft text-left text-[11px] tracking-[.06em] text-faint uppercase">
              {['规则 ID', '名称', '严重度', '分值', 'ATT&CK', '来源', '状态', '操作'].map((h) => <th key={h} className="px-3.5 py-2.5 font-semibold">{h}</th>)}
            </tr></thead>
            <tbody>
              {rules.map((r) => (
                <tr key={r.id} className="border-b border-border-soft last:border-b-0 hover:bg-secondary">
                  <td className="px-3.5 py-2.5 font-mono text-xs">{r.id}</td>
                  <td className="px-3.5 py-2.5"><div className="font-medium">{r.name}</div><div className="mt-0.5 max-w-[520px] text-xs text-faint">{r.description}</div></td>
                  <td className="px-3.5 py-2.5"><Badge tone={r.severity}>{SEV_LABEL[r.severity]}</Badge></td>
                  <td className="px-3.5 py-2.5 font-bold">{r.score}</td>
                  <td className="px-3.5 py-2.5 font-mono text-xs text-faint">{(r.mitre || []).join(', ') || '-'}</td>
                  <td className="px-3.5 py-2.5 text-xs text-faint">{r.builtin ? '内置' : '自定义'}</td>
                  <td className="px-3.5 py-2.5">{r.enabled ? <Badge tone="resolved">启用</Badge> : <Badge tone="info">禁用</Badge>}</td>
                  <td className="px-3.5 py-2.5">{canWrite && <Button size="sm" variant="ghost" onClick={() => toggle(r)}>{r.enabled ? '禁用' : '启用'}</Button>}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </Card>
      )}

      {canWrite && <RuleEditor open={editorOpen} onClose={() => setEditorOpen(false)} onSaved={() => { setEditorOpen(false); load(); }} />}
    </div>
  );
}

function RuleEditor({ open, onClose, onSaved }: { open: boolean; onClose: () => void; onSaved: () => void }) {
  const toast = useToast();
  const [busy, setBusy] = useState(false);
  if (!open) return null;

  const save = async () => {
    const g = (id: string) => (document.getElementById(id) as HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement).value;
    const def = g('rDef').trim();
    try { JSON.parse(def); } catch { return toast('规则定义不是合法 JSON', 'err'); }
    setBusy(true);
    try {
      await api.post('/api/v1/rules', {
        id: g('rId').trim(), name: g('rName').trim(), severity: g('rSeverity'),
        score: Number(g('rScore')) || 30,
        mitre: g('rMitre').split(',').map((s) => s.trim()).filter(Boolean),
        definition: JSON.parse(def),
      });
      toast('规则已保存并下发');
      onSaved();
    } catch (e) { toast((e as Error).message, 'err'); } finally { setBusy(false); }
  };

  return (
    <Card className="mt-3.5 p-4">
      <CardTitle className="mb-3">新建 / 更新规则</CardTitle>
      <div className="mb-3 grid gap-3 sm:grid-cols-2">
        <label className="block"><span className="mb-1.5 block text-[11.5px] text-faint">规则 ID（留空自动生成）</span><Input id="rId" className="w-full" placeholder="HG-C-xxxx" /></label>
        <label className="block"><span className="mb-1.5 block text-[11.5px] text-faint">名称</span><Input id="rName" className="w-full" placeholder="例如：可疑的登录脚本执行" /></label>
      </div>
      <div className="mb-3 grid gap-3 sm:grid-cols-3">
        <label className="block"><span className="mb-1.5 block text-[11.5px] text-faint">严重度</span>
          <Select id="rSeverity" className="w-full">{Object.entries(SEV_LABEL).map(([k, v]) => <option key={k} value={k}>{v}</option>)}</Select>
        </label>
        <label className="block"><span className="mb-1.5 block text-[11.5px] text-faint">分值（1-100）</span><Input id="rScore" type="number" defaultValue={30} min={1} max={100} className="w-full" /></label>
        <label className="block"><span className="mb-1.5 block text-[11.5px] text-faint">ATT&amp;CK（逗号分隔）</span><Input id="rMitre" className="w-full" placeholder="T1059.001" /></label>
      </div>
      <label className="block"><span className="mb-1.5 block text-[11.5px] text-faint">规则定义（JSON：all / any / none）</span>
        <textarea id="rDef" rows={10} className="w-full rounded-[7px] border border-input bg-card p-3 font-mono text-xs leading-[1.6] text-foreground outline-none focus:border-primary" defaultValue={`{
  "all": [
    { "field": "process.name", "op": "in", "value": ["powershell.exe"] }
  ],
  "any": [
    { "field": "process.cmdline", "op": "icontains", "value": "invoke-" }
  ]
}`} />
      </label>
      <div className="mt-3 flex gap-2">
        <Button variant="primary" onClick={save} disabled={busy}>保存并下发</Button>
        <Button variant="ghost" onClick={onClose}>取消</Button>
      </div>
    </Card>
  );
}

/* ================= 白名单 ================= */

export function AllowlistPage({ user }: { user: { role: Role } }) {
  const err = useError();
  const toast = useToast();
  const confirm = useConfirm();
  const canWrite = user.role !== 'viewer';
  const [items, setItems] = useState<AllowEntry[] | null>(null);
  const [form, setForm] = useState({ type: 'hash', value: '', note: '' });

  const load = useCallback(async () => {
    try { setItems((await api.get<{ items: AllowEntry[] }>('/api/v1/allowlist')).items || []); }
    catch (e) { err.capture(e); }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => { load(); }, [load]);
  if (err.rendered) return err.rendered;

  const add = async () => {
    if (!form.value.trim()) return toast('请填写加白内容', 'warn');
    try {
      await api.post('/api/v1/allowlist', { type: form.type, value: form.value.trim(), note: form.note.trim() });
      toast('已加入白名单');
      setForm({ type: form.type, value: '', note: '' });
      load();
    } catch (e) { toast((e as Error).message, 'err'); }
  };

  const remove = async (e: AllowEntry) => {
    const ok = await confirm({
      title: '删除该白名单项？',
      message: '删除后相关检测会重新生效，该对象若仍有可疑行为会再次告警。',
      danger: true, okText: '删除',
    });
    if (!ok) return;
    try {
      await api.del(`/api/v1/allowlist/${encodeURIComponent(e.id)}`);
      toast('已删除');
      load();
    } catch (ex) { toast((ex as Error).message, 'err'); }
  };

  return (
    <div className="space-y-3.5">
      {canWrite && (
        <Card className="p-4">
          <CardTitle className="mb-3">新增白名单</CardTitle>
          <div className="grid items-end gap-2.5 sm:grid-cols-[130px_1fr_1fr_auto]">
            <label className="block"><span className="mb-1.5 block text-[11.5px] text-faint">类型</span>
              <Select value={form.type} onChange={(e) => setForm((f) => ({ ...f, type: e.target.value }))} className="w-full">
                <option value="hash">哈希</option><option value="path">路径</option>
              </Select>
            </label>
            <label className="block"><span className="mb-1.5 block text-[11.5px] text-faint">内容（SHA256 或路径）</span>
              <Input value={form.value} onChange={(e) => setForm((f) => ({ ...f, value: e.target.value }))} className="w-full font-mono text-xs" placeholder="7f3a91c0…" />
            </label>
            <label className="block"><span className="mb-1.5 block text-[11.5px] text-faint">备注</span>
              <Input value={form.note} onChange={(e) => setForm((f) => ({ ...f, note: e.target.value }))} className="w-full" placeholder="为什么加白（会进入审计）" />
            </label>
            <Button variant="primary" onClick={add}><Plus size={13} /> 添加</Button>
          </div>
        </Card>
      )}

      {!items ? <Card className="px-2 pb-2"><SkeletonRows rows={4} /></Card> : !items.length ? (
        <Card><EmptyState icon={<ShieldCheck size={20} />} title="白名单为空"
          sub="加白名单能让确认安全的对象不再告警。可在告警详情里一键添加，或在这里手动新增。" /></Card>
      ) : (
        <Card className="overflow-x-auto px-2 py-3.5">
          <table className="w-full text-[13px]">
            <thead><tr className="border-b border-border-soft text-left text-[11px] tracking-[.06em] text-faint uppercase">
              {['类型', '内容', '备注', '添加人', '时间', '操作'].map((h) => <th key={h} className="px-3.5 py-2.5 font-semibold">{h}</th>)}
            </tr></thead>
            <tbody>
              {items.map((e) => (
                <tr key={e.id} className="border-b border-border-soft last:border-b-0 hover:bg-secondary">
                  <td className="px-3.5 py-2.5"><Badge tone="info">{e.type}</Badge></td>
                  <td className="max-w-[420px] px-3.5 py-2.5 font-mono text-xs break-all">{e.value}</td>
                  <td className="px-3.5 py-2.5 text-xs">{e.note || <span className="text-faint">-</span>}</td>
                  <td className="px-3.5 py-2.5 text-xs text-faint">{e.created_by || '-'}</td>
                  <td className="px-3.5 py-2.5 text-xs text-faint">{e.created_at ? relTime(e.created_at) : '-'}</td>
                  <td className="px-3.5 py-2.5">{canWrite && <Button size="sm" variant="ghost" onClick={() => remove(e)}>删除</Button>}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </Card>
      )}
    </div>
  );
}

/* ================= 审计日志 ================= */

/* 审计动作语义化：原始 action 串保留在 title 里可查，界面给中文与色彩 */
const AUDIT_LABEL: Record<string, string> = {
  'alert.status': '告警处置', 'alert.bulk_status': '批量处置', 'alert.triage': 'AI 研判',
  'ai.hunt': 'AI 狩猎', 'host.delete': '删除主机', 'host.command': '下发指令',
  'ioc.add': '添加 IOC', 'ioc.delete': '删除 IOC',
  'rule.upsert': '规则变更', 'rule.toggle': '规则启停', 'rule.delete': '删除规则',
  'allowlist.add': '添加白名单', 'allowlist.delete': '删除白名单',
  'auth.login': '登录', 'auth.logout': '退出登录', 'auth.change_password': '修改密码',
  'user.create': '创建账号',
};
const auditTone = (a: string): string =>
  /delete|terminate/.test(a) ? 'critical' : /command|status|bulk/.test(a) ? 'info' : /add|upsert/.test(a) ? 'ok' : 'neutral';

export function AuditPage() {
  const err = useError();
  const [rows, setRows] = useState<AuditRow[] | null>(null);

  useEffect(() => {
    api.get<{ items: AuditRow[] }>('/api/v1/audit?limit=300')
      .then((r) => setRows(r.items || []))
      .catch(err.capture);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  if (err.rendered) return err.rendered;

  return !rows ? <Card className="px-2 pb-2"><SkeletonRows rows={8} /></Card> : !rows.length ? (
    <Card><EmptyState icon={<ShieldCheck size={20} />} title="暂无审计记录"
      sub="登录、处置、规则变更等关键操作都会留痕在这里，方便回溯与合规检查。" /></Card>
  ) : (
    <Card className="overflow-x-auto px-2 py-3.5">
      <table className="w-full text-[13px]">
        <thead><tr className="border-b border-border-soft text-left text-[11px] tracking-[.06em] text-faint uppercase">
          {['时间', '操作人', '动作', '目标', '详情', '来源 IP'].map((h) => <th key={h} className="px-3.5 py-2.5 font-semibold">{h}</th>)}
        </tr></thead>
        <tbody>
          {rows.map((l) => (
            <tr key={l.id} className="border-b border-border-soft last:border-b-0 hover:bg-secondary">
              <td className="px-3.5 py-2.5 text-xs text-faint">{fmtTime((l as AuditRow & { created_at: string }).created_at)}</td>
              <td className="px-3.5 py-2.5 text-xs">{(l as AuditRow & { username?: string }).username || '-'}</td>
              <td className="px-3.5 py-2.5">
                <Badge tone={auditTone(l.action)} title={l.action}>{AUDIT_LABEL[l.action] || l.action}</Badge>
              </td>
              <td className="px-3.5 py-2.5 font-mono text-xs break-all text-faint" title={(l as AuditRow & { target?: string }).target}>{(l as AuditRow & { target?: string }).target || '-'}</td>
              <td className="px-3.5 py-2.5 text-xs">{l.detail || '-'}</td>
              <td className="px-3.5 py-2.5 font-mono text-xs text-faint">{(l as AuditRow & { ip?: string }).ip || '-'}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </Card>
  );
}

/* ================= 账号管理 ================= */

type UserAcc = UserRow & { display_name?: string; disabled?: boolean; last_login_at?: string; created_at?: string };

export function UsersPage({ self, onPasswordChanged }: { self: { username: string }; onPasswordChanged?: () => void }) {
  const err = useError();
  const toast = useToast();
  const [users, setUsers] = useState<UserAcc[] | null>(null);
  const [form, setForm] = useState({ username: '', display_name: '', password: '', role: 'viewer' });
  const [pw, setPw] = useState({ old: '', neu: '' });

  const load = useCallback(async () => {
    try { setUsers(((await api.get<{ items: UserRow[] }>('/api/v1/users')).items || []) as UserAcc[]); }
    catch (e) { err.capture(e); }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => { load(); }, [load]);
  if (err.rendered) return err.rendered;

  const add = async () => {
    try {
      await api.post('/api/v1/users', { ...form, username: form.username.trim() });
      toast('账号已创建');
      setForm({ username: '', display_name: '', password: '', role: 'viewer' });
      load();
    } catch (e) { toast((e as Error).message, 'err'); }
  };

  const changePw = async () => {
    if (pw.neu.length < 8) return toast('新密码至少 8 位', 'warn');
    try {
      await api.post('/api/v1/auth/change-password', { old_password: pw.old, new_password: pw.neu });
      toast('密码已修改，下次登录使用新密码');
      setPw({ old: '', neu: '' });
      onPasswordChanged?.();
    } catch (e) { toast((e as Error).message, 'err'); }
  };

  return (
    <div className="space-y-3.5">
      <Card className="p-4">
        <CardTitle className="mb-3">新建账号</CardTitle>
        <div className="grid items-end gap-2.5 lg:grid-cols-[1fr_1fr_1fr_140px_auto]">
          <label className="block"><span className="mb-1.5 block text-[11.5px] text-faint">用户名</span><Input value={form.username} onChange={(e) => setForm((f) => ({ ...f, username: e.target.value }))} className="w-full" /></label>
          <label className="block"><span className="mb-1.5 block text-[11.5px] text-faint">显示名</span><Input value={form.display_name} onChange={(e) => setForm((f) => ({ ...f, display_name: e.target.value }))} className="w-full" /></label>
          <label className="block"><span className="mb-1.5 block text-[11.5px] text-faint">初始密码（≥8 位）</span><Input type="password" value={form.password} onChange={(e) => setForm((f) => ({ ...f, password: e.target.value }))} className="w-full" /></label>
          <label className="block"><span className="mb-1.5 block text-[11.5px] text-faint">角色</span>
            <Select value={form.role} onChange={(e) => setForm((f) => ({ ...f, role: e.target.value }))} className="w-full">
              <option value="viewer">只读</option><option value="analyst">分析师</option><option value="admin">管理员</option>
            </Select>
          </label>
          <Button variant="primary" onClick={add}>创建</Button>
        </div>
      </Card>

      <Card className="p-4">
        <CardTitle className="mb-3">修改我的密码（{self.username}）</CardTitle>
        <div className="grid items-end gap-2.5 sm:grid-cols-[1fr_1fr_auto]">
          <label className="block"><span className="mb-1.5 block text-[11.5px] text-faint">当前密码</span><Input type="password" value={pw.old} onChange={(e) => setPw((p) => ({ ...p, old: e.target.value }))} className="w-full" /></label>
          <label className="block"><span className="mb-1.5 block text-[11.5px] text-faint">新密码（≥8 位）</span><Input type="password" value={pw.neu} onChange={(e) => setPw((p) => ({ ...p, neu: e.target.value }))} className="w-full" /></label>
          <Button onClick={changePw}><KeyRound size={13} /> 修改密码</Button>
        </div>
      </Card>

      {!users ? <Card className="px-2 pb-2"><SkeletonRows rows={3} /></Card> : (
        <Card className="overflow-x-auto px-2 py-3.5">
          <table className="w-full text-[13px]">
            <thead><tr className="border-b border-border-soft text-left text-[11px] tracking-[.06em] text-faint uppercase">
              {['用户名', '显示名', '角色', '状态', '最近登录', '创建时间'].map((h) => <th key={h} className="px-3.5 py-2.5 font-semibold">{h}</th>)}
            </tr></thead>
            <tbody>
              {users.map((u) => (
                <tr key={u.id} className="border-b border-border-soft last:border-b-0 hover:bg-secondary">
                  <td className="px-3.5 py-2.5 font-mono text-xs">{u.username}</td>
                  <td className="px-3.5 py-2.5">{u.display_name || '-'}</td>
                  <td className="px-3.5 py-2.5"><Badge tone="info">{u.role}</Badge></td>
                  <td className="px-3.5 py-2.5">{u.disabled ? <Badge tone="offline">禁用</Badge> : <Badge tone="online">正常</Badge>}</td>
                  <td className="px-3.5 py-2.5 text-xs text-faint">{u.last_login_at ? fmtTime(u.last_login_at) : '从未登录'}</td>
                  <td className="px-3.5 py-2.5 text-xs text-faint">{fmtTime(u.created_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </Card>
      )}
    </div>
  );
}

/* ================= 事件（攻击链聚类） ================= */

interface Incident {
  peak_severity: Severity; hostname: string; alert_count: number; open_count: number;
  started_at: string; last_at: string; duration_sec: number; max_score: number;
  alert_ids: number[]; processes?: string[]; mitre?: string[];
}
interface Burst { hash: string; host_count: number; alert_count: number; peak_severity: Severity; hosts: string[]; title_sample?: string }

export function IncidentsPage({ onOpenAlert }: { onOpenAlert: (id: number) => void }) {
  const err = useError();
  const [data, setData] = useState<{ items: Incident[]; bursts: Burst[] } | null>(null);
  const [tick, setTick] = useState(0);

  useEffect(() => {
    api.get<{ items: Incident[]; bursts?: Burst[] }>('/api/v1/incidents?limit=50')
      .then((r) => setData({ items: r.items || [], bursts: r.bursts || [] }))
      .catch(err.capture);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [tick]);

  if (err.rendered) return err.rendered;
  if (!data) return <Card className="p-4"><SkeletonRows rows={5} /></Card>;

  const { items, bursts } = data;

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

      <div className="mb-3 flex items-center gap-2.5">
        <h2 className="m-0 text-base font-semibold">事件</h2>
        <span className="text-xs text-faint">未处置告警按「同主机 · 相邻间隔 ≤ 30 分钟」聚类 · 共 {items.length} 个活跃事件</span>
        <div className="flex-1" />
        <Button size="sm" onClick={() => setTick((t) => t + 1)}><RefreshCw size={13} /> 刷新</Button>
      </div>

      {!items.length ? (
        <Card><EmptyState icon={<ShieldCheck size={20} />} title="当前没有告警聚合成事件"
          sub="这是好事——说明各终端都在安静运行，没有形成攻击链的行为序列。事件会在多条相关告警出现时自动聚类。" /></Card>
      ) : items.map((it, idx) => {
        const dur = it.duration_sec > 0
          ? (it.duration_sec >= 3600 ? `${Math.round(it.duration_sec / 3600)} 小时` : `${Math.max(1, Math.round(it.duration_sec / 60))} 分钟`)
          : '<1 分钟';
        return (
          <Card key={idx} className={cn('mb-3 p-4 transition-colors hover:border-l-primary', `border-l-3 ${it.peak_severity === 'critical' ? 'border-l-crit' : it.peak_severity === 'high' ? 'border-l-destructive' : it.peak_severity === 'medium' ? 'border-l-warn' : 'border-l-border'}`)}>
            <div className="flex flex-wrap items-center gap-3">
              <Badge tone={it.peak_severity} className="px-3 py-1 text-[13px]">{SEV_LABEL[it.peak_severity] || it.peak_severity}</Badge>
              <div className="min-w-[200px] flex-1">
                <div className="font-semibold">
                  {it.hostname}
                  <Badge tone="info" className="ml-2">{it.alert_count} 条告警</Badge>
                  {it.open_count < it.alert_count && <Badge tone="neutral" className="ml-1.5">已处置 {it.alert_count - it.open_count}</Badge>}
                </div>
                <div className="mt-1 text-xs text-faint">
                  {fmtTime(it.started_at)} → {fmtTime(it.last_at)} · 持续 {dur} · 峰值分 <b className="font-mono">{it.max_score}</b>
                </div>
              </div>
              <Button size="sm" variant="primary" onClick={() => onOpenAlert(it.alert_ids[it.alert_ids.length - 1])}>查看最新告警</Button>
            </div>
            <div className="mt-3 flex flex-wrap gap-1.5">
              {(it.processes || []).slice(0, 6).map((p, i) => <Badge key={`p${i}`} tone="neutral" title="进程">{p}</Badge>)}
              {(it.mitre || []).slice(0, 6).map((m, i) => <Badge key={`m${i}`} tone="info">{m}</Badge>)}
            </div>
            <div className="mt-2.5 flex flex-wrap gap-1.5 border-t border-border-soft pt-2.5">
              {it.alert_ids.map((id, i) => (
                <Button key={id} size="sm" variant="ghost" onClick={() => onOpenAlert(id)}>告警 {i + 1}</Button>
              ))}
            </div>
          </Card>
        );
      })}
    </div>
  );
}

/* ================= 运营周报 ================= */

interface WeeklyReport {
  alerts_week?: number; resolved_week?: number; fp_rate?: number;
  mttr_min?: number; hosts_active?: number;
  fp_ranking?: { rule_id: string; fp_rate: number; false_pos: number; handled: number }[];
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
      <Card className="p-4">
        <CardTitle className="mb-3">本周概览</CardTitle>
        <div className="grid grid-cols-2 gap-3.5 lg:grid-cols-4">
          {[
            ['本周新增告警', rep.alerts_week],
            ['本周已处置', rep.resolved_week],
            ['综合误报率', rep.fp_rate != null ? `${(rep.fp_rate * 100).toFixed(1)}%` : null],
            ['平均处置时长', rep.mttr_min != null ? `${Math.round(rep.mttr_min)} 分钟` : null],
          ].map(([label, v]) => (
            <div key={label as string} className="rounded-lg border border-border-soft bg-secondary/40 p-3">
              <div className="text-xs text-faint">{label as string}</div>
              <div className="anim-digit mt-1.5 text-[22px] font-bold tabular-nums">{(v as number | null) ?? '-'}</div>
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
