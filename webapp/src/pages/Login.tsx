import { useEffect, useState, type FormEvent } from 'react';
import { TriangleAlert, ShieldCheck } from 'lucide-react';
import { api } from '../lib/api';
import { Button, Input } from '../components/ui/basics';
import type { User } from '../lib/types';

export function LoginPage({ onLogin }: { onLogin: (u: User) => void }) {
  const [err, setErr] = useState('');
  const [busy, setBusy] = useState(false);
  const [caps, setCaps] = useState(false);
  const [user, setUser] = useState(() => localStorage.getItem('hg_last_user') || '');

  useEffect(() => {
    const up = (e: KeyboardEvent) => setCaps(e.getModifierState?.('CapsLock') ?? false);
    window.addEventListener('keydown', up);
    window.addEventListener('keyup', up);
    return () => { window.removeEventListener('keydown', up); window.removeEventListener('keyup', up); };
  }, []);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    const pass = (document.getElementById('loginPass') as HTMLInputElement)?.value ?? '';
    setBusy(true); setErr('');
    try {
      const u = await api.login(user.trim(), pass);
      localStorage.setItem('hg_last_user', user.trim());
      onLogin(u);
    } catch (ex) {
      setErr(ex instanceof Error ? ex.message : '登录失败');
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="fixed inset-0 z-100 grid place-items-center bg-[radial-gradient(ellipse_at_50%_-10%,#14213a_0%,var(--background)_55%)] light:bg-[radial-gradient(ellipse_at_50%_-10%,#dbe7f7_0%,var(--background)_55%)]">
      <form
        onSubmit={submit} autoComplete="on"
        className="w-[380px] rounded-lg border border-border bg-card p-7 shadow-2xl"
        style={{ animation: 'page-in 400ms cubic-bezier(.22,1,.36,1)' }}
      >
        <div className="mb-5.5 flex items-center gap-3.5">
          <div className="grid h-11.5 w-11.5 shrink-0 place-items-center rounded-xl bg-gradient-to-br from-primary to-[var(--ok)] text-[22px] font-extrabold text-[#06101f] shadow-[0_8px_24px_rgba(75,147,255,.28)]">
            <ShieldCheck size={24} strokeWidth={2} />
          </div>
          <div>
            <h1 className="m-0 text-xl font-bold tracking-tight">HostGuard</h1>
            <p className="m-0 text-[12.5px] text-faint">主机进程安全检测 · 总控管理后台</p>
          </div>
        </div>

        {err && (
          <div className="anim-shake mb-3.5 rounded-lg border border-destructive/30 bg-destructive-soft px-3 py-2.5 text-[12.5px] text-destructive">
            {err}
          </div>
        )}

        <label className="mb-3 block">
          <span className="mb-1.5 block text-[11.5px] text-faint">账号</span>
          <Input id="loginUser" name="username" autoComplete="username" placeholder="admin" required className="w-full" value={user} onChange={(e) => setUser(e.target.value)} />
        </label>
        <label className="mb-4 block">
          <span className="mb-1.5 block text-[11.5px] text-faint">密码</span>
          <Input id="loginPass" name="password" type="password" autoComplete="current-password" placeholder="••••••••" required className="w-full" />
          {caps && (
            <span className="anim-shake mt-2 flex items-center gap-1.5 rounded-[7px] border border-warn/30 bg-warn-soft px-2.5 py-1.5 text-[11.5px] text-warn">
              <TriangleAlert size={13} strokeWidth={2} /> 已开启大写锁定（Caps Lock）
            </span>
          )}
        </label>

        <Button variant="primary" type="submit" disabled={busy} className="h-9 w-full">
          {busy ? '登录中…' : '登录'}
        </Button>

        <p className="m-0 mt-4 text-[11.5px] leading-[1.7] text-faint">
          首次部署时，服务端日志会打印一次初始管理员密码。登录后请尽快在「账号管理」页修改。
        </p>
      </form>
    </div>
  );
}
