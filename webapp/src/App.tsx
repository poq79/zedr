import { useCallback, useEffect, useState } from 'react';
import { HashRouter, Navigate, Route, Routes, useLocation } from 'react-router-dom';
import { api } from './lib/api';
import { initDense, initTheme } from './lib/theme';
import type { Alert, User } from './lib/types';
import { AppShell } from './components/AppShell';
import { CommandPalette } from './components/CommandPalette';
import { ShortcutsDialog } from './components/ShortcutsDialog';
import { ConfirmProvider, ToastProvider, useToast } from './components/ui/overlays';
import { LoginPage } from './pages/Login';
import { OverviewPage } from './pages/Overview';
import { Alerts } from './pages/Alerts';
import { AttackMatrixPage } from './pages/AttackMatrix';
import { HuntPage } from './pages/Hunt';
import { HostDetailPage } from './pages/HostDetail';
import { IntelPage } from './pages/Intel';
import { IncidentsPage, ReportPage, HostsPage, RulesPage, AllowlistPage, AuditPage, UsersPage } from './pages/Misc';
import { AISettingsPage } from './pages/AISettings';

function AppInner() {
  const [user, setUser] = useState<User | null>(null);
  const [booted, setBooted] = useState(false);
  const [unread, setUnread] = useState(0);
  const [live, setLive] = useState(false);
  const [refreshTick, setRefreshTick] = useState(0);
  const [freshness, setFreshness] = useState('--:--:--');
  const [cmdOpen, setCmdOpen] = useState(false);
  const [keysOpen, setKeysOpen] = useState(false);
  const location = useLocation();
  const toast = useToast();

  /* 启动：恢复会话（HttpOnly Cookie 刷新 → /me） */
  useEffect(() => {
    initTheme(); initDense();
    (async () => {
      try {
        if (await api.tryRefresh()) setUser(await api.me());
      } catch { /* 落到登录页 */ }
      setBooted(true);
    })();
  }, []);

  /* 会话失效广播 → 回登录页 */
  useEffect(() => {
    const onUnauth = () => setUser(null);
    window.addEventListener('hg-unauth', onUnauth);
    return () => window.removeEventListener('hg-unauth', onUnauth);
  }, []);

  /* SSE：一次性票据；断线 5s 后重取票据重连（EventSource 自带重连会复用旧票，必须重建） */
  useEffect(() => {
    if (!user) return;
    let es: EventSource | null = null;
    let timer: ReturnType<typeof setTimeout>;
    let alive = true;

    const connect = async () => {
      try {
        const res = await api.post<{ ticket: string }>('/api/v1/stream/ticket', {});
        es = new EventSource(`/api/v1/stream/alerts?ticket=${encodeURIComponent(res.ticket)}`);
      } catch {
        setLive(false);
        if (alive) timer = setTimeout(connect, 5000);
        return;
      }
      if (!alive) { es?.close(); return; }
      es.addEventListener('ready', () => setLive(true));
      es.addEventListener('alert', (ev) => {
        try {
          const a = JSON.parse((ev as MessageEvent).data) as Alert;
          setUnread((n) => n + 1);
          if (a.severity === 'critical' || a.severity === 'high') {
            toast(`新告警：${a.hostname} · ${a.title}`, 'warn');
          }
          if (location.pathname === '/overview') setRefreshTick((t) => t + 1);
        } catch { /* 忽略坏帧 */ }
      });
      es.onerror = () => {
        setLive(false);
        es?.close(); es = null;
        if (alive) timer = setTimeout(connect, 5000);
      };
    };
    connect();
    return () => { alive = false; clearTimeout(timer); es?.close(); setLive(false); };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [user]);

  /* Ctrl+K 命令面板 */
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') { e.preventDefault(); setCmdOpen((v) => !v); }
    };
    document.addEventListener('keydown', onKey);
    return () => document.removeEventListener('keydown', onKey);
  }, []);

  /* 进入告警页清未读 */
  useEffect(() => {
    if (location.pathname === '/alerts') setUnread(0);
  }, [location.pathname]);

  const refresh = useCallback(() => {
    setRefreshTick((t) => t + 1);
    setFreshness(new Date().toLocaleTimeString('zh-CN', { hour12: false }));
  }, []);

  useEffect(() => {
    if (user) setFreshness(new Date().toLocaleTimeString('zh-CN', { hour12: false }));
  }, [user, refreshTick]);

  const exportCurrent = useCallback(() => {
    window.dispatchEvent(new CustomEvent('hg-export'));
  }, []);

  if (!booted) return null;

  if (!user) {
    return (
      <>
        <LoginPage onLogin={(u) => { setUser(u); setUnread(0); refresh(); }} />
        <ShortcutsDialog open={keysOpen} onClose={() => setKeysOpen(false)} />
      </>
    );
  }

  return (
    <>
      <Routes>
        {/* path="*"：无 path 且无 children 的 Route 在 RR v7 不参与匹配，
            会导致登录后整个 AppShell 不挂载（控制台空白），见 login 后
            "No routes matched location /" 运行时警告 */}
        <Route
          path="*"
          element={
            <AppShell
              user={user} unread={unread} live={live}
              onRefresh={refresh} freshness={freshness}
              onLogout={() => setUser(null)}
            >
              <Routes>
                <Route path="/" element={<Navigate to="/overview" replace />} />
                <Route path="/overview" element={<OverviewPage key={`o${refreshTick}`} />} />
                <Route path="/alerts" element={<Alerts key={`a${refreshTick}`} user={user} />} />
                <Route path="/hunt" element={<HuntPage key={`h${refreshTick}`} />} />
                <Route path="/incidents" element={<IncidentsPage key={`i${refreshTick}`} user={user} />} />
                <Route path="/attack" element={<AttackMatrixPage key={`m${refreshTick}`} />} />
                <Route path="/intel" element={<IntelPage key={`io${refreshTick}`} user={user} />} />
                <Route path="/report" element={<ReportPage key={`r${refreshTick}`} />} />
                <Route path="/hosts" element={<HostsPage key={`h${refreshTick}`} />} />
                <Route path="/hosts/:id" element={<HostDetailPage key="host-detail" user={user} />} />
                <Route path="/rules" element={<RulesPage key={`ru${refreshTick}`} user={user} />} />
                <Route path="/allowlist" element={<AllowlistPage key={`w${refreshTick}`} user={user} />} />
                <Route path="/audit" element={<AuditPage key={`l${refreshTick}`} />} />
                <Route path="/users" element={<UsersPage key={`u${refreshTick}`} self={user} />} />
                <Route path="/ai" element={<AISettingsPage key={`ai${refreshTick}`} user={user} />} />
                <Route path="*" element={<Navigate to="/overview" replace />} />
              </Routes>
            </AppShell>
          }
        />
      </Routes>
      <CommandPalette open={cmdOpen} setOpen={setCmdOpen} onExport={exportCurrent} onShortcuts={() => setKeysOpen(true)} />
      <ShortcutsDialog open={keysOpen} onClose={() => setKeysOpen(false)} />
    </>
  );
}

export default function App() {
  return (
    <ToastProvider>
      <ConfirmProvider>
        <HashRouter>
          <AppInner />
        </HashRouter>
      </ConfirmProvider>
    </ToastProvider>
  );
}
