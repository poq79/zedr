import { useEffect, useRef, useState } from 'react';
import { NavLink, Outlet, useLocation, useNavigate } from 'react-router-dom';
import {
  LayoutDashboard, TriangleAlert, GitBranch, BarChart3, Monitor,
  ShieldCheck, ShieldBan, ScrollText, Users, LogOut, RefreshCw, Settings,
  Moon, Sun, Rows3, Keyboard, CircleDot,
} from 'lucide-react';
import { cn } from '../lib/utils';
import { Button } from './ui/basics';
import { useToast } from './ui/overlays';
import { getTheme, toggleDense, toggleTheme } from '../lib/theme';
import { ROLE_LABEL } from '../lib/format';
import type { User } from '../lib/types';
import { api } from '../lib/api';
import { ShortcutsDialog } from './ShortcutsDialog';

export const ROUTES = [
  { to: '/overview', label: '概览', icon: LayoutDashboard },
  { to: '/alerts', label: '告警中心', icon: TriangleAlert, badge: 'alerts' as const },
  { to: '/incidents', label: '事件', icon: GitBranch },
  { to: '/report', label: '报表', icon: BarChart3 },
  { to: '/hosts', label: '主机终端', icon: Monitor },
  { to: '/rules', label: '检测规则', icon: ShieldCheck },
  { to: '/allowlist', label: '白名单', icon: ShieldBan },
  { to: '/audit', label: '审计日志', icon: ScrollText, adminOnly: true },
  { to: '/users', label: '账号管理', icon: Users, adminOnly: true },
];

const TITLES: Record<string, string> = {
  overview: '概览', alerts: '告警中心', incidents: '事件（攻击链聚类）', report: '运营周报',
  hosts: '主机终端', rules: '检测规则', allowlist: '白名单与降噪', audit: '审计日志', users: '账号管理',
};

export function AppShell({ user, onLogout, unread, live, onRefresh, freshness, children }: {
  user: User; onLogout: () => void; unread: number; live: boolean;
  onRefresh: () => void; freshness: string; children: React.ReactNode;
}) {
  const loc = useLocation();
  const navigate = useNavigate();
  const toast = useToast();
  const [menuOpen, setMenuOpen] = useState(false);
  const [dense, setDense] = useState(document.body.classList.contains('dense'));
  const [shortcutsOpen, setShortcutsOpen] = useState(false);
  const menuRef = useRef<HTMLDivElement>(null);

  const isAdmin = user.role === 'admin';
  const title = TITLES[loc.pathname.replace(/^\//, '')] || '概览';

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const t = e.target as HTMLElement;
      if (t && (t.tagName === 'INPUT' || t.tagName === 'TEXTAREA' || t.isContentEditable)) return;
      if (e.key === '?') { e.preventDefault(); setShortcutsOpen((v) => !v); }
      if (e.key.toLowerCase() === 'r') onRefresh();
      if (e.key.toLowerCase() === 'g') {
        const once = (e2: KeyboardEvent) => {
          const map: Record<string, string> = { o: '/overview', a: '/alerts', i: '/incidents', h: '/hosts', r: '/rules', w: '/allowlist', l: '/audit', u: '/users' };
          const dest = map[e2.key.toLowerCase()];
          if (dest) navigate(dest);
          window.removeEventListener('keydown', once, true);
        };
        window.addEventListener('keydown', once, true);
      }
    };
    document.addEventListener('keydown', onKey);
    return () => document.removeEventListener('keydown', onKey);
  }, [navigate, onRefresh]);

  useEffect(() => {
    const onClick = (e: MouseEvent) => {
      if (menuRef.current && !menuRef.current.contains(e.target as Node)) setMenuOpen(false);
    };
    document.addEventListener('click', onClick);
    return () => document.removeEventListener('click', onClick);
  }, []);

  const logout = async () => {
    await api.logout();
    toast('已退出登录');
    onLogout();
  };

  return (
    <div className="flex h-screen overflow-hidden">
      <aside className="flex w-[220px] shrink-0 flex-col border-r border-border bg-sidebar px-3 py-4 text-sidebar-foreground">
        <div className="flex items-center gap-2.5 px-2 pb-4">
          {/* 纯色徽标：渐变块+英文装饰字是 slop 清单典型项；方块只承载品牌识别 */}
          <div className="grid h-[30px] w-[30px] place-items-center rounded-md bg-primary text-[15px] font-bold text-primary-foreground">H</div>
          <b className="text-[15px] tracking-[.2px] text-foreground">HostGuard</b>
        </div>

        <nav className="mt-1.5 flex flex-col gap-0.5">
          {ROUTES.filter((r) => !r.adminOnly || isAdmin).map((r) => (
            <NavLink
              key={r.to}
              to={r.to}
              className={({ isActive }) => cn(
                'flex items-center gap-2.5 rounded-lg px-3 py-2 text-[13.5px] transition-colors duration-150',
                'hover:bg-accent hover:text-foreground',
                isActive ? 'bg-brand-soft font-medium text-foreground shadow-[inset_2px_0_0_var(--primary)]' : 'text-muted-foreground',
              )}
            >
              <r.icon size={16} strokeWidth={1.6} className={cn('shrink-0 opacity-85', loc.pathname === r.to && 'text-primary opacity-100')} />
              {r.label}
              {r.badge === 'alerts' && unread > 0 && (
                <span key={unread} className="anim-badge ml-auto rounded-full bg-crit px-1.5 py-px text-[10.5px] font-bold text-[#1a0508]">
                  {unread > 99 ? '99+' : unread}
                </span>
              )}
            </NavLink>
          ))}
        </nav>

        <div className="mt-auto border-t border-border-soft pt-3.5">
          <div className="flex items-center gap-2.5 px-2 py-1.5">
            <div className="grid h-7 w-7 place-items-center rounded-full border border-border bg-secondary text-xs text-primary">{(user.username || 'U').slice(0, 1).toUpperCase()}</div>
            <div className="overflow-hidden leading-[1.25]">
              <b className="block truncate text-[12.5px]">{user.username}</b>
              <span className="text-[10.5px] text-faint">{ROLE_LABEL[user.role] || user.role}</span>
            </div>
          </div>
          <button
            onClick={logout}
            className="mt-1.5 flex w-full items-center gap-2.5 rounded-lg px-3 py-2 text-left text-[13.5px] text-muted-foreground transition-colors hover:bg-accent hover:text-foreground"
          >
            <LogOut size={16} strokeWidth={1.7} className="shrink-0" /> 退出登录
          </button>
        </div>
      </aside>

      <div className="flex min-w-0 flex-1 flex-col overflow-hidden">
        {/* 顶栏纯平：毛玻璃（backdrop-blur）在反模式清单里，发丝线就够 */}
        <header className="flex h-14 shrink-0 items-center gap-3.5 border-b border-border-soft bg-background px-5">
          <h1 className="m-0 text-[15px] font-semibold tracking-[.2px]">{title}</h1>
          <div className="flex-1" />
          <span className={cn('flex items-center gap-1.5 text-[11.5px] text-faint', !live && 'opacity-80')}>
            <CircleDot size={11} className={cn(live ? 'text-ok' : 'text-ghost')} style={live ? { animation: 'pulse-dot 2.4s infinite' } : undefined} />
            {live ? '实时通道已连接' : '实时通道重连中…'}
          </span>
          <span className="inline-flex items-center gap-1 text-[11px] text-ghost" title="数据最后更新时间">
            <RefreshCw size={12} className="hidden" />
            更新于 <span className="font-mono">{freshness}</span>
          </span>
          <Button variant="ghost" size="sm" onClick={onRefresh} title="重新拉取数据（R）">
            <RefreshCw size={13} strokeWidth={1.8} /> 刷新
          </Button>
          <div className="relative" ref={menuRef}>
            <Button
              variant="ghost" size="icon" aria-haspopup="menu" aria-expanded={menuOpen}
              onClick={(e) => { e.stopPropagation(); setMenuOpen((v) => !v); }}
            >
              <Settings size={15} strokeWidth={1.7} />
            </Button>
            {menuOpen && (
              <div className="anim-pop absolute top-[calc(100%+8px)] right-0 z-90 min-w-[220px] rounded-md border border-border-strong bg-popover p-1 shadow-2xl" role="menu">
                <MenuItem
                  icon={getTheme() === 'light' ? <Moon size={14} /> : <Sun size={14} />}
                  label="切换亮 / 暗主题"
                  onClick={() => { toggleTheme(); setMenuOpen(false); }}
                />
                <MenuItem
                  icon={dense ? <Rows3 size={14} className="text-primary" /> : <Rows3 size={14} />}
                  label="紧凑密度（大屏值班）"
                  check={dense}
                  onClick={() => setDense(toggleDense())}
                />
                <div className="mx-1.5 my-1 h-px bg-border-soft" />
                <MenuItem icon={<Keyboard size={14} />} label="键盘快捷键（?）" onClick={() => { setMenuOpen(false); setShortcutsOpen(true); }} />
              </div>
            )}
          </div>
        </header>
        <main className="flex-1 overflow-y-auto px-5 pt-5 pb-10">
          <div key={loc.pathname} className="anim-page">{children}</div>
        </main>
      </div>

      <ShortcutsDialog open={shortcutsOpen} onClose={() => setShortcutsOpen(false)} />
      <Outlet />
    </div>
  );
}

function MenuItem({ icon, label, check, onClick }: { icon: React.ReactNode; label: string; check?: boolean; onClick: () => void }) {
  return (
    <button
      role="menuitem"
      onClick={onClick}
      className="flex w-full cursor-pointer items-center gap-2.5 rounded-[7px] border-0 bg-transparent px-2.5 py-2 text-left text-[12.5px] text-foreground transition-colors hover:bg-accent"
    >
      <span className="text-faint">{icon}</span>
      {label}
      {check !== undefined && (
        <span className={cn('ml-auto text-xs', check ? 'text-primary' : 'text-transparent')}>●</span>
      )}
    </button>
  );
}
