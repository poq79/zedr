import { useCallback, useEffect, useMemo, useState, type ReactNode } from 'react';
import {
  CircleAlert, RefreshCw, ShieldAlert, ShieldCheck, TriangleAlert, Unplug, Users,
} from 'lucide-react';
import { ApiError, live, liveErrorKind } from '../lib/api';
import type { AccountUser, LiveAccounts } from '../lib/types';
import { fmtTime, relTime } from '../lib/format';
import { Badge, Button, Card, CardTitle, EmptyState, Skeleton, SkeletonRows } from '../components/ui/basics';
import { cn } from '../lib/utils';

/* 主机详情「账户与会话」Tab（docs/LIVE-TUNNEL.md §13.3，F5）。
   数据全部来自探针的 NetAPI 只读枚举（账户表/管理员组/密码策略）。
   本页回答三个值班问题：谁有管理员、谁能长期不换密码、哪些账户异常。
   风险提示只做"事实汇总"，不替代安全策略——管理员>2 是提示而非违规。 */

const dash = (n: number) => (n > 0 ? String(n) : '—');

const fmtLogon = (unix: number): { text: string; title?: string; never: boolean } => {
  if (!unix || unix <= 0) return { text: '从未登录', never: true };
  const iso = new Date(unix * 1000).toISOString();
  return { text: fmtTime(iso), title: relTime(iso), never: false };
};

const userNames = (users: AccountUser[], max = 4): string => {
  const names = users.map((u) => u.name).filter(Boolean);
  return names.slice(0, max).join('、') + (names.length > max ? ` 等 ${names.length} 个` : '');
};

interface AccountsErr { kind: 'tunnel' | 'busy' | 'off' | 'unsupported' | 'other'; note: string }

/* 错误口径同 v2；accounts 的 403 既可能是实时隧道关闭，也可能是探针
   不是本地管理员（NetAPI 拒绝），文案把两种可能都说清楚。 */
function accountsErr(e: unknown): AccountsErr {
  if (e instanceof ApiError && e.status === 404) {
    return { kind: 'unsupported', note: '该探针版本不支持账户枚举' };
  }
  switch (liveErrorKind(e)) {
    case 'tunnel': return { kind: 'tunnel', note: '探针隧道未连接' };
    case 'busy': return { kind: 'busy', note: '探针忙，稍后重试' };
    case 'off': return { kind: 'off', note: '实时查询未启用或探针权限不足' };
    case 'unsupported': return { kind: 'unsupported', note: '该探针版本不支持账户枚举' };
    default: return { kind: 'other', note: e instanceof Error ? e.message : String(e) };
  }
}

function AccountsErrorState({ e, onRetry }: { e: AccountsErr; onRetry: () => void }) {
  let info: { tone: 'info' | 'warn'; icon: ReactNode; title: string; sub: string };
  switch (e.kind) {
    case 'tunnel':
      info = {
        tone: 'warn', icon: <Unplug size={20} />, title: '无法读取账户信息',
        sub: '探针隧道未连接——探针离线、版本过旧或未开启隧道拨号；恢复后重试即可，此处不展示缓存数据。',
      };
      break;
    case 'busy':
      info = {
        tone: 'warn', icon: <CircleAlert size={20} />, title: '探针忙，稍后重试',
        sub: '账户枚举与管理员组查询需要访问安全账户管理器，请等待当前任务结束后重试。',
      };
      break;
    case 'off':
      info = {
        tone: 'info', icon: <CircleAlert size={20} />, title: '实时查询未启用或权限不足',
        sub: '账户枚举需要服务端开启实时隧道并授予分析师及以上角色；探针侧还需要本地管理员权限。',
      };
      break;
    case 'unsupported':
      info = {
        tone: 'warn', icon: <ShieldAlert size={20} />, title: '该探针版本不支持账户枚举',
        sub: '请升级终端探针到包含账户与会话能力的版本后重试。',
      };
      break;
    default:
      info = {
        tone: 'warn', icon: <CircleAlert size={20} />, title: '账户枚举失败',
        sub: e.note || '未知错误，请稍后重试。',
      };
  }
  return (
    <Card>
      <EmptyState tone={info.tone} icon={info.icon} title={info.title} sub={info.sub}
        action={<Button size="sm" onClick={onRetry}>重试</Button>} />
    </Card>
  );
}

function AccountsSkeleton() {
  return (
    <>
      <Card className="p-4">
        <div className="flex flex-wrap items-center gap-2.5">
          <Skeleton className="h-3 w-20" />
          <div className="flex-1" />
          <Skeleton className="h-7 w-20 rounded-[7px]" />
        </div>
        <div className="mt-3 grid grid-cols-1 gap-px overflow-hidden rounded-md border border-border-soft bg-border-soft sm:grid-cols-3">
          {[0, 1, 2].map((i) => (
            <div key={i} className="bg-card px-3.5 py-3">
              <Skeleton className="h-3 w-16" />
              <Skeleton className="mt-2 h-5 w-12" />
            </div>
          ))}
        </div>
        <Skeleton className="mt-3 h-3 w-1/2" />
      </Card>
      <Card><SkeletonRows rows={7} /></Card>
    </>
  );
}

function PolicyCell({ label, value, hint }: { label: string; value: string; hint: string }) {
  return (
    <div className="bg-card px-3.5 py-3" title={hint}>
      <div className="text-[11px] text-faint">{label}</div>
      <div className={cn('mt-1.5 font-mono text-[20px] leading-none font-semibold tabular-nums',
        value === '—' ? 'text-ghost' : 'text-foreground')}>
        {value}
      </div>
    </div>
  );
}

function AccountRow({ u }: { u: AccountUser }) {
  const logon = fmtLogon(u.last_logon_unix);
  const oldPwd = !u.disabled && u.password_age_days > 90;
  return (
    <tr className="border-b border-border-soft transition-colors last:border-b-0 hover:bg-secondary/40">
      <td className="px-3.5 py-2">
        <span className="block font-mono text-[11.5px] font-medium" title={u.sid || undefined}>{u.name || '—'}</span>
        {u.sid && <span className="mt-0.5 block max-w-[260px] truncate font-mono text-[10px] text-ghost" title={u.sid}>{u.sid}</span>}
      </td>
      <td className="px-3.5 py-2">
        {u.is_admin ? <Badge tone="info">管理员</Badge> : <span className="text-faint">标准用户</span>}
      </td>
      <td className="px-3.5 py-2">
        {u.disabled ? <Badge tone="neutral">禁用</Badge> : <Badge tone="resolved">启用</Badge>}
      </td>
      <td className="px-3.5 py-2">
        {u.password_never_expires
          ? <Badge tone={u.disabled ? 'neutral' : 'high'}
              title={u.disabled ? '账户已禁用，风险降低' : '密码永不过期：泄露后不会因到期而失效'}>永不过期</Badge>
          : <span className="text-faint">否</span>}
      </td>
      <td className={cn('px-3.5 py-2 font-mono tabular-nums', oldPwd ? 'text-warn' : 'text-muted-foreground')}>
        <span title={oldPwd ? '密码超过 90 天未更改' : undefined}>
          {u.password_age_days >= 0 ? `${u.password_age_days} 天` : '—'}
        </span>
      </td>
      <td className="px-3.5 py-2 text-[12px]">
        <span className={cn(logon.never && 'text-faint')} title={logon.title}>{logon.text}</span>
      </td>
      <td className="max-w-[260px] px-3.5 py-2">
        <span className="block truncate text-[11.5px] text-faint" title={u.comment || undefined}>{u.comment || '—'}</span>
      </td>
    </tr>
  );
}

export function HostAccountsTab({ agentId }: { agentId: string }) {
  const [res, setRes] = useState<LiveAccounts | null>(null);
  const [loading, setLoading] = useState(false);
  const [loadErr, setLoadErr] = useState<AccountsErr | null>(null);
  const [freshAt, setFreshAt] = useState('');

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const d = await live.accounts(agentId);
      setRes(d);
      setLoadErr(null);
      setFreshAt(d.generated_at ? fmtTime(d.generated_at) : new Date().toLocaleTimeString('zh-CN', { hour12: false }));
    } catch (e) {
      // 失败清空，不拿旧账户表冒充当前状态
      setRes(null);
      setLoadErr(accountsErr(e));
    } finally {
      setLoading(false);
    }
  }, [agentId]);

  useEffect(() => {
    setRes(null); setLoadErr(null); setFreshAt('');
    void load();
  }, [load]);

  const users = useMemo(() => res?.users || [], [res]);
  const admins = useMemo(() => {
    const listed = res?.administrators || [];
    // 管理员组枚举失败时后端会返回空数组；此时退回 is_admin 标记，避免把
    // "没读到"误显示成"没有管理员"。
    if (listed.length) return listed;
    return users.filter((u) => u.is_admin).map((u) => u.name);
  }, [res, users]);
  const adminCount = admins.length;

  const risks = useMemo(() => {
    const out: { key: string; text: string }[] = [];
    if (adminCount > 2) {
      out.push({ key: 'admins', text: `管理员数量偏多：${adminCount} 个账户在管理员组（建议不超过 2 个）` });
    }
    const never = users.filter((u) => !u.disabled && u.password_never_expires);
    if (never.length) {
      out.push({ key: 'never', text: `${never.length} 个启用账户密码永不过期：${userNames(never)}` });
    }
    const stale = users.filter((u) => !u.disabled && u.password_age_days > 90);
    if (stale.length) {
      out.push({ key: 'age', text: `${stale.length} 个启用账户密码超过 90 天未更改：${userNames(stale)}` });
    }
    return out;
  }, [users, adminCount]);

  const sorted = useMemo(() => [...users].sort((a, b) => {
    if (a.is_admin !== b.is_admin) return a.is_admin ? -1 : 1;
    if (a.disabled !== b.disabled) return a.disabled ? 1 : -1;
    return a.name.localeCompare(b.name, 'zh-CN');
  }), [users]);

  const policy = res?.policy;

  return (
    <>
      {!res ? (
        loadErr ? <AccountsErrorState e={loadErr} onRetry={() => void load()} /> : <AccountsSkeleton />
      ) : (
        <>
          <Card className="p-4">
            <div className="flex flex-wrap items-center gap-2.5">
              <CardTitle>密码策略</CardTitle>
              <span className="font-mono text-[11px] tabular-nums text-ghost">{users.length} 个本地账户</span>
              {adminCount > 0 && (
                <span className="font-mono text-[11px] tabular-nums text-ghost">管理员 {adminCount}</span>
              )}
              <div className="flex-1" />
              {freshAt && <span className="text-[11px] text-ghost">更新于 {freshAt}</span>}
              <Button size="sm" disabled={loading} onClick={() => void load()} title="重新枚举本地账户与密码策略">
                <RefreshCw size={13} className={cn(loading && 'anim-spin')} />
                {loading ? '刷新中…' : '刷新'}
              </Button>
            </div>

            <div className="mt-3 grid grid-cols-1 gap-px overflow-hidden rounded-md border border-border-soft bg-border-soft sm:grid-cols-3">
              <PolicyCell label="最短密码长度" value={dash(policy?.min_password_length || 0)}
                hint="0 表示未设置最小长度限制" />
              <PolicyCell label="最长有效期" value={policy?.max_age_days ? `${policy.max_age_days} 天` : '—'}
                hint="0 表示密码永不过期（不限制有效期）" />
              <PolicyCell label="账户锁定阈值" value={dash(policy?.lockout_threshold || 0)}
                hint="0 表示未启用账户锁定策略" />
            </div>
            <p className="mt-2 text-[11px] text-ghost">
              0 值显示为 —：最短长度/锁定阈值为 0 表示不限制或未启用，最长有效期为 0 表示永不过期。
            </p>
          </Card>

          <Card className={cn('p-3.5', risks.length > 0 ? 'border-warn/30 bg-warn-soft' : 'border-ok/25 bg-ok-soft')}>
            <div className="flex items-start gap-2.5">
              {risks.length > 0
                ? <TriangleAlert size={15} className="mt-0.5 shrink-0 text-warn" />
                : <ShieldCheck size={15} className="mt-0.5 shrink-0 text-ok" />}
              <div className="min-w-0">
                <div className={cn('text-[12.5px] font-medium', risks.length > 0 ? 'text-warn' : 'text-ok')}>
                  {risks.length > 0 ? `账户风险 ${risks.length} 项` : '账户基线未发现明显风险'}
                </div>
                {risks.length > 0 ? (
                  <ul className="m-0 mt-1 list-disc space-y-0.5 pl-4 text-[12px] leading-relaxed text-muted-foreground">
                    {risks.map((r) => <li key={r.key}>{r.text}</li>)}
                  </ul>
                ) : (
                  <p className="mt-1 text-[11.5px] text-faint">管理员数量、密码有效期与密码年龄均在建议范围内。</p>
                )}
              </div>
            </div>
          </Card>

          <Card className="px-2 py-3.5">
            <div className="mb-1 flex flex-wrap items-center gap-2.5 px-2.5">
              <CardTitle>本地账户</CardTitle>
              <span className="font-mono text-[11px] tabular-nums text-ghost">{users.length}</span>
              <div className="flex-1" />
              <span className="text-[11px] text-ghost">管理员优先 · 启用优先 · 按名称排序</span>
            </div>
            {!users.length ? (
              <EmptyState tone="info" icon={<Users size={20} />} title="没有枚举到本地账户"
                sub="探针返回了空账户表；若机器上有本地账户，请确认探针权限与版本。" />
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-[12.5px]">
                  <thead>
                    <tr className="border-b border-border-soft text-left text-[11px] tracking-[.06em] text-faint uppercase">
                      {['账户', '角色', '状态', '密码永不过期', '密码年龄', '最后登录', '备注'].map((h) => (
                        <th key={h} className="px-3.5 py-2 font-semibold">{h}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {sorted.map((u) => <AccountRow key={`${u.sid}:${u.name}`} u={u} />)}
                  </tbody>
                </table>
              </div>
            )}
          </Card>

          <p className="px-1 text-[11px] text-ghost">
            账户数据为点击时刻快照，不做自动轮询；管理员判定取本地 Administrators 组的直接成员，嵌套组不会展开。
          </p>
        </>
      )}
    </>
  );
}
