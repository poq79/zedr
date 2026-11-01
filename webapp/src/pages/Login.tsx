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

  /* 服务端状态：/health 公开端点，运维信息直接可见（DESIGN.md §4.1） */
  const [srv, setSrv] = useState<{ status: string; uptime: number; version: string } | null>(null);
  useEffect(() => {
    let alive = true;
    fetch('/health', { credentials: 'same-origin' })
      .then((r) => (r.ok ? r.json() : null))
      .then((d) => { if (alive && d && d.status) setSrv(d); })
      .catch(() => { /* 状态点显示未响应 */ });
    return () => { alive = false; };
  }, []);

  return (
    // 分屏登录（Vercel/Linear auth 模式）：左品牌叙事 · 右极简表单，蓝图见 webapp/DESIGN.md §4.1
    <div className="fixed inset-0 z-100 flex bg-background">
      {/* 左屏：恒暗品牌面板（双主题不变，身份识别） */}
      <div className="relative hidden w-[46%] shrink-0 flex-col justify-between overflow-hidden border-r border-border-soft bg-[#05080f] p-10 lg:flex">
        {/* 蓝图网格纹理：全站唯一允许的装饰纹理，44px 仪器网格 */}
        <div
          className="pointer-events-none absolute inset-0"
          style={{
            backgroundImage:
              'linear-gradient(rgba(148,170,200,.07) 1px, transparent 1px), linear-gradient(90deg, rgba(148,170,200,.07) 1px, transparent 1px)',
            backgroundSize: '44px 44px',
          }}
        />
        <div className="relative flex items-center gap-2.5">
          <div className="grid h-8 w-8 place-items-center rounded-md bg-primary text-[14px] font-bold text-primary-foreground">H</div>
          <b className="text-[15px] tracking-[.2px] text-foreground">HostGuard</b>
        </div>

        <div className="relative">
          <h2 className="m-0 text-[26px] font-semibold leading-[1.4] tracking-tight text-foreground">
            看见主机上每一次进程的<br />落地与执行。
          </h2>
          {/* 管线叙事母题：五层检测的真实事实，禁止换成营销话术 */}
          <div className="mt-7 max-w-[430px] rounded-md border border-border-soft bg-[#0a101c] p-4 font-mono text-[12px] leading-[2.1]">
            <div className="mb-1.5 text-[10px] tracking-[1.2px] text-faint">DETECTION PIPELINE · 五层检测流水线</div>
            {[
              ['[1/5 指纹]', '进程静态画像 · 签名 / 路径 / 哈希'],
              ['[2/5 关键词]', '命令行语义扫描'],
              ['[3/5 规则]', '36 条内置 · 签名包热下发'],
              ['[4/5 血缘]', '进程祖先链 · 行为时序'],
              ['[5/5 融合]', '五层加权评分 → 判定 / 抑制'],
            ].map(([tag, desc]) => (
              <div key={tag} className="flex gap-3 whitespace-nowrap">
                <span className="shrink-0 text-primary">{tag}</span>
                <span className="text-muted-foreground">{desc}</span>
              </div>
            ))}
          </div>
        </div>

        <div className="relative font-mono text-[11px] text-faint">
          HOSTGUARD EDR · WINDOWS AGENT + SERVER{srv ? ` · v${srv.version}` : ''}
        </div>
      </div>

      {/* 右屏：表单面板 */}
      <div className="relative flex min-w-0 flex-1 flex-col items-center justify-center px-6">
        <form
          onSubmit={submit} autoComplete="on"
          className="w-[380px] max-w-full rounded-lg border border-border bg-card p-7"
          style={{ animation: 'page-in 400ms cubic-bezier(.22,1,.36,1)' }}
        >
          <div className="mb-5.5 flex items-center gap-3.5">
            <div className="grid h-11.5 w-11.5 shrink-0 place-items-center rounded-xl bg-primary text-[22px] font-extrabold text-primary-foreground">
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

        {/* 表单下的真实运维信息行：服务端状态（实时 /health）· 密码恢复路径 · 版权 */}
        <div className="mt-5 flex flex-wrap items-center justify-center gap-x-4 gap-y-1.5 text-[11.5px] text-faint">
          <span className="inline-flex items-center gap-1.5">
            <i className={`h-1.5 w-1.5 rounded-full ${srv ? 'bg-ok' : 'bg-destructive'}`} />
            {srv ? <>服务端运行中 · <span className="font-mono">v{srv.version}</span> · 已运行 <span className="font-mono">{Math.floor(srv.uptime / 3600)}h{Math.floor((srv.uptime % 3600) / 60)}m</span></> : '服务端未响应'}
          </span>
          <span className="text-ghost">|</span>
          <span>忘记密码：<span className="font-mono">bin/resetadmin.exe</span></span>
          <span className="text-ghost">|</span>
          <span>© 2026 HostGuard</span>
        </div>
      </div>
    </div>
  );
}
