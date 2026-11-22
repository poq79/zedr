// 审计日志页（Misc.tsx 拆分生成，2026-11-22 god file 治理）。
import { useEffect, useState } from 'react';
import { ShieldCheck } from 'lucide-react';
import { api } from '../lib/api';
import { AuditRow } from '../lib/types';
import type { User as UserRow } from '../lib/types';
import { fmtTime } from '../lib/format';
import { useError } from '../lib/hooks';
import { Badge, Card, EmptyState, SkeletonRows } from '../components/ui/basics';

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

