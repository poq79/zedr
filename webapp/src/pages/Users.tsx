// UsersPage（Misc.tsx 拆分生成，2026-11-22 god file 治理）。
import { useEffect, useState, useCallback } from 'react';
import { KeyRound } from 'lucide-react';
import QRCode from 'qrcode';
import { setMFAPolicy, api, disableMFA, getMFAPolicy, enrollMFA, confirmMFA } from '../lib/api';
import type { User as UserRow } from '../lib/types';
import { fmtTime } from '../lib/format';
import { useError } from '../lib/hooks';
import { Select, Card, SkeletonRows, Input, CardTitle, Badge, Button } from '../components/ui/basics';
import { useToast } from '../components/ui/overlays';

export function UsersPage({ self, onPasswordChanged }: { self: { username: string; role: string }; onPasswordChanged?: () => void }) {
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

      <MfaCard />
      {self.role === 'admin' && <MfaPolicyCard />}

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

/* ---------------- MFA（TOTP 双因素）卡（S2，2026-11-21） ----------------
   本体=按账号 opt-in（GitLab 形态）：不启用则登录流程零变化；
   admin 可在下方策略开关配置强制范围（默认双关）。 */

function MfaCard() {
  const toast = useToast();
  const [me, setMe] = useState<{ mfa_enabled?: boolean } | null>(null);
  const [enroll, setEnroll] = useState<{ secret: string; qr: string } | null>(null);
  const [code, setCode] = useState('');
  const [pw, setPw] = useState('');
  const [busy, setBusy] = useState(false);

  const loadMe = useCallback(async () => {
    try { setMe(await api.me() as { mfa_enabled?: boolean }); } catch { /* 保持现状 */ }
  }, []);
  useEffect(() => { loadMe(); }, [loadMe]);

  const startEnroll = async () => {
    setBusy(true);
    try {
      const en = await enrollMFA();
      setEnroll({ secret: en.secret, qr: await QRCode.toDataURL(en.otpauth_url, { width: 160, margin: 1 }) });
    } catch (e) { toast((e as Error).message, 'err'); }
    finally { setBusy(false); }
  };

  const doConfirm = async () => {
    setBusy(true);
    try {
      await confirmMFA(code.trim());
      setEnroll(null); setCode('');
      toast('双因素验证已启用——下次登录需输入验证码');
      loadMe();
    } catch (e) { toast((e as Error).message, 'err'); }
    finally { setBusy(false); }
  };

  const doDisable = async () => {
    setBusy(true);
    try {
      await disableMFA(pw, code.trim());
      setPw(''); setCode('');
      toast('双因素验证已停用');
      loadMe();
    } catch (e) { toast((e as Error).message, 'err'); }
    finally { setBusy(false); }
  };

  return (
    <Card className="p-4">
      <CardTitle className="mb-3">双因素验证（TOTP）</CardTitle>
      {!me ? (
        <div className="text-[12px] text-faint">加载中…</div>
      ) : me.mfa_enabled ? (
        <div className="grid items-end gap-2.5 sm:grid-cols-[1fr_1fr_auto]">
          <label className="block"><span className="mb-1.5 block text-[11.5px] text-faint">当前密码</span><Input type="password" value={pw} onChange={(e) => setPw(e.target.value)} className="w-full" /></label>
          <label className="block"><span className="mb-1.5 block text-[11.5px] text-faint">TOTP 验证码</span><Input value={code} onChange={(e) => setCode(e.target.value.replace(/\D/g, '').slice(0, 6))} maxLength={6} className="w-full font-mono" /></label>
          <Button variant="ghost" disabled={busy || !pw || code.length !== 6} onClick={doDisable}>停用双因素</Button>
        </div>
      ) : (
        <>
          {!enroll ? (
            <div className="flex items-center gap-3">
              <span className="text-[12px] text-faint">当前未启用。启用后登录需输入 TOTP App 的 6 位验证码。</span>
              <Button size="sm" variant="primary" disabled={busy} onClick={startEnroll}>启用双因素</Button>
            </div>
          ) : (
            <div className="flex flex-wrap items-start gap-4">
              <img src={enroll.qr} alt="TOTP 绑定二维码" className="rounded-md border border-border-soft bg-white p-1.5" />
              <div className="min-w-0 flex-1">
                <div className="text-[10.5px] text-faint">无法扫码时手动录入密钥：</div>
                <div className="mt-0.5 break-all font-mono text-[11px] text-foreground">{enroll.secret}</div>
                <Input value={code} onChange={(e) => setCode(e.target.value.replace(/\D/g, '').slice(0, 6))} maxLength={6}
                  placeholder="输入 App 显示的 6 位验证码" className="mt-2 w-full font-mono" />
                <div className="mt-2 flex gap-2">
                  <Button size="sm" variant="primary" disabled={busy || code.length !== 6} onClick={doConfirm}>确认绑定</Button>
                  <Button size="sm" variant="ghost" onClick={() => setEnroll(null)}>取消</Button>
                </div>
              </div>
            </div>
          )}
        </>
      )}
    </Card>
  );
}

function MfaPolicyCard() {
  const toast = useToast();
  const [pol, setPol] = useState<{ require_admins: boolean; require_all: boolean } | null>(null);
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    getMFAPolicy().then(setPol).catch(() => setPol(null));
  }, []);
  const update = async (patch: { require_admins?: boolean; require_all?: boolean }) => {
    if (!pol) return;
    const next = { ...pol, ...patch };
    setBusy(true);
    try {
      const saved = await setMFAPolicy(next.require_admins, next.require_all);
      setPol(saved);
      toast('MFA 策略已更新（登录时实时生效）');
    } catch (e) { toast((e as Error).message, 'err'); }
    finally { setBusy(false); }
  };

  return (
    <Card className="p-4">
      <CardTitle className="mb-1.5">MFA 强制策略</CardTitle>
      <p className="mt-0 mb-3 text-[11.5px] leading-[1.7] text-faint">
        热生效：登录时实时读取。命中策略且账号未绑定双因素时，登录环节会强制完成绑定。
        本机测试环境保持双关即可（未绑定账号零负担）。
      </p>
      {!pol ? (
        <div className="text-[12px] text-faint">加载中…</div>
      ) : (
        <div className="grid gap-2">
          {[
            { key: 'require_admins' as const, label: '管理员账号强制双因素', desc: 'CISA admin-first 口径：生产环境建议开启' },
            { key: 'require_all' as const, label: '全部账号强制双因素', desc: '命中且未绑定的账号会在登录环节被要求完成绑定' },
          ].map((row) => (
            <label key={row.key} className="flex cursor-pointer items-center gap-2.5 rounded-md border border-border-soft bg-secondary/40 px-3 py-2">
              <input type="checkbox" checked={pol[row.key]} disabled={busy}
                onChange={(e) => update({ [row.key]: e.target.checked })} className="accent-[var(--primary)]" />
              <div>
                <div className="text-[12px] text-foreground">{row.label}</div>
                <div className="text-[10.5px] text-faint">{row.desc}</div>
              </div>
            </label>
          ))}
        </div>
      )}
    </Card>
  );
}

/* ================= 事件（攻击链聚类） ================= */

