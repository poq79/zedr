import { useCallback, useEffect, useMemo, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { ChevronLeft, ChevronRight, Download, Search } from 'lucide-react';
import { api } from '../lib/api';
import type { Alert, AlertStatus, Severity, User, Verdict } from '../lib/types';
import { SEV_LABEL, STATUS_LABEL, VERDICT_LABEL, relTime, fmtTime } from '../lib/format';
import { Badge, Button, Card, EmptyState, Input, Select, SkeletonRows } from '../components/ui/basics';
import { useToast, useConfirm } from '../components/ui/overlays';
import { AlertDrawer } from './AlertDrawer';
import { cn } from '../lib/utils';
import { ShieldCheck } from 'lucide-react';

const PAGE_SIZE = 20;

type SortKey = 'time' | 'score' | 'severity';
const SEV_RANK: Record<Severity, number> = { critical: 3, high: 2, medium: 1, low: 0, info: 0 };

export function Alerts({ user }: { user: User }) {
  const toast = useToast();
  const confirm = useConfirm();
  const [rows, setRows] = useState<Alert[] | null>(null);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [filters, setFilters] = useState({ q: '', status: '', severity: '', verdict: '', mitre: '' });
  const [page, setPage] = useState(1);
  const [sortKey, setSortKey] = useState<SortKey>('time');
  const [sortDesc, setSortDesc] = useState(true);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [focusIdx, setFocusIdx] = useState(-1);
  const [openId, setOpenId] = useState<string | null>(null);
  const [refreshTick, setRefreshTick] = useState(0);
  const [searchParams, setSearchParams] = useSearchParams();

  /* 事件页跳转：/alerts?open=ID 直接打开对应详情 */
  useEffect(() => {
    const open = searchParams.get('open');
    const mitre = searchParams.get('mitre');
    const q = searchParams.get('q');
    if (open) { setOpenId(open); }
    // ATT&CK 矩阵格子下钻：?mitre=T1059 精确过滤（后端 CSV 定界匹配，不会误中 T1059.001）
    if (mitre) { setFilters((f) => ({ ...f, mitre })); }
    // 事件页/主机页跳转：?q=hostname 按关键词定位（同搜索框语义）
    if (q) { setFilters((f) => ({ ...f, q })); }
    if (open || mitre || q) { setSearchParams({}, { replace: true }); }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const canWrite = user.role !== 'viewer';

  const load = useCallback(async () => {
    setLoading(true);
    const qs = new URLSearchParams({ page: String(page), page_size: String(PAGE_SIZE) });
    if (filters.q) qs.set('q', filters.q);
    if (filters.status) qs.set('status', filters.status);
    if (filters.severity) qs.set('severity', filters.severity);
    if (filters.verdict) qs.set('verdict', filters.verdict);
    if (filters.mitre) qs.set('mitre', filters.mitre);
    try {
      const res = await api.get<{ items: Alert[]; total: number }>(`/api/v1/alerts?${qs.toString()}`);
      setRows(res.items || []);
      setTotal(res.total || 0);
    } catch {
      setRows([]);
    } finally {
      setLoading(false);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [page, filters, refreshTick]);

  useEffect(() => { load(); }, [load]);
  useEffect(() => {
    const onExport = () => exportCsv();
    window.addEventListener('hg-export', onExport);
    return () => window.removeEventListener('hg-export', onExport);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [rows]);

  const items = useMemo(() => {
    const arr = [...(rows || [])];
    arr.sort((a, b) => {
      let d = 0;
      if (sortKey === 'score') d = a.score - b.score;
      else if (sortKey === 'severity') d = SEV_RANK[a.severity] - SEV_RANK[b.severity];
      else d = new Date(a.created_at).getTime() - new Date(b.created_at).getTime();
      return sortDesc ? -d : d;
    });
    return arr;
  }, [rows, sortKey, sortDesc]);

  const setFilter = (k: keyof typeof filters, v: string) => { setFilters((f) => ({ ...f, [k]: v })); setPage(1); };

  const toggleRow = (id: string, checked: boolean) => {
    setSelected((s) => { const n = new Set(s); checked ? n.add(id) : n.delete(id); return n; });
  };
  const allChecked = items.length > 0 && items.every((a) => selected.has(a.id));
  const toggleAll = () => {
    setSelected(allChecked ? new Set() : new Set(items.map((a) => a.id)));
  };

  const pages = Math.max(1, Math.ceil(total / PAGE_SIZE));

  const bulk = async (status: AlertStatus) => {
    const ids = Array.from(selected);
    if (!ids.length) return;
    const ok = await confirm({
      title: `批量标记 ${ids.length} 条告警？`,
      message: `选中的告警将全部标记为「${STATUS_LABEL[status]}」。该操作会写入审计日志。`,
      okText: '标记',
    });
    if (!ok) return;
    try {
      const r = await api.post<{ updated: number[]; failed: number[] }>('/api/v1/alerts/bulk-status', { ids, status, note: '批量处置' });
      const failed = r.failed || [];
      toast(failed.length ? `已完成，${failed.length} 条未成功：${failed.join(', ')}` : `已将 ${ids.length} 条告警标记为「${STATUS_LABEL[status]}」`, failed.length ? 'warn' : 'ok');
      setSelected(new Set());
      setRefreshTick((t) => t + 1);
    } catch (e) { toast((e as Error).message, 'err'); }
  };

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const t = e.target as HTMLElement;
      if (t && (t.tagName === 'INPUT' || t.tagName === 'SELECT' || t.tagName === 'TEXTAREA')) return;
      if (openId !== null) return;
      if (e.key === 'a' || e.key === 'A') { e.preventDefault(); toggleAll(); }
      else if (e.key === 'j' || e.key === 'J') setFocusIdx((i) => Math.min(i + 1, items.length - 1));
      else if (e.key === 'k' || e.key === 'K') setFocusIdx((i) => Math.max(i - 1, 0));
      else if (e.key === 'Enter' && focusIdx >= 0 && items[focusIdx]) setOpenId(items[focusIdx].id);
      else if (canWrite && ['1', '2', '3', '4'].includes(e.key) && selected.size) {
        const map: Record<string, AlertStatus> = { '1': 'open', '2': 'acknowledged', '3': 'resolved', '4': 'false_positive' };
        bulk(map[e.key]);
      }
    };
    document.addEventListener('keydown', onKey);
    return () => document.removeEventListener('keydown', onKey);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [items, focusIdx, openId, selected, canWrite]);

  const exportCsv = () => {
    if (!items.length) return toast('当前没有可导出的告警', 'warn');
    const cols = ['id', 'severity', 'status', 'score', 'hostname', 'process_name', 'pid', 'title', 'created_at'];
    const esc = (v: unknown) => `"${String(v ?? '').replace(/"/g, '""')}"`;
    const csv = '\uFEFF' + [cols.join(','), ...items.map((a) => cols.map((c) => esc((a as unknown as Record<string, unknown>)[c])).join(','))].join('\n');
    const url = URL.createObjectURL(new Blob([csv], { type: 'text/csv' }));
    const a = document.createElement('a');
    a.href = url; a.download = `zedr-alerts-${new Date().toISOString().slice(0, 10)}.csv`; a.click();
    URL.revokeObjectURL(url);
    toast(`已导出 ${items.length} 条告警`);
  };

  const sortBtn = (key: SortKey, label: string, extra?: string) => (
    <button
      onClick={() => { if (sortKey === key) setSortDesc((d) => !d); else { setSortKey(key); setSortDesc(true); } }}
      className={cn('cursor-pointer border-0 bg-transparent p-0 text-inherit hover:text-foreground', extra)}
    >
      {label}{sortKey === key ? (sortDesc ? ' ↓' : ' ↑') : ''}
    </button>
  );

  return (
    <div>
      <div className="mb-3.5 flex flex-wrap items-center gap-2.5">
        <div className="relative">
          <Search size={14} className="pointer-events-none absolute top-1/2 left-3 -translate-y-1/2 text-ghost" />
          <Input
            placeholder="搜索进程名 / 路径 / 命令行 / 主机" value={filters.q}
            onChange={(e) => setFilter('q', e.target.value)} className="w-[260px] pl-8" />
        </div>
        <Select value={filters.status} onChange={(e) => setFilter('status', e.target.value)}>
          <option value="">全部状态</option>
          {Object.entries(STATUS_LABEL).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
        </Select>
        <Select value={filters.severity} onChange={(e) => setFilter('severity', e.target.value)}>
          <option value="">全部严重度</option>
          {Object.entries(SEV_LABEL).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
        </Select>
        <Select value={filters.verdict} onChange={(e) => setFilter('verdict', e.target.value)}>
          <option value="">全部结论</option>
          {Object.entries(VERDICT_LABEL).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
        </Select>
        {filters.mitre && (
          <Badge tone="info" className="gap-1.5">
            <span className="font-mono">{filters.mitre}</span>
            <button aria-label="清除 ATT&CK 过滤" onClick={() => setFilter('mitre', '')} className="ml-0.5 cursor-pointer font-bold leading-none opacity-70 hover:opacity-100">×</button>
          </Badge>
        )}
        <div className="flex-1" />
        <Button size="sm" onClick={exportCsv}><Download size={13} /> 导出 CSV</Button>
      </div>

      <Card className="overflow-hidden px-2 pb-2">
        {loading ? <SkeletonRows rows={8} /> : !items.length ? (
          <EmptyState
            icon={<ShieldCheck size={20} />}
            title="没有符合条件的告警"
            sub="当前筛选下没有命中记录。这可能意味着环境确实安静，也可以试试放宽时间范围或严重度筛选。"
          />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-[13px]">
              <thead>
                <tr className="border-b border-border-soft text-left text-[11px] tracking-[.06em] text-faint uppercase">
                  <th className="sticky top-0 z-1 bg-card px-3.5 py-2.5 font-semibold" style={{ width: 36 }}>
                    <input type="checkbox" checked={allChecked} onChange={toggleAll} title="全选当前页 (A)" className="accent-[var(--primary)]" />
                  </th>
                  <th className="sticky top-0 z-1 bg-card px-3.5 py-2.5 font-semibold" style={{ width: 64 }}>严重度</th>
                  <th className="sticky top-0 z-1 bg-card px-3.5 py-2.5 font-semibold">告警</th>
                  <th className="sticky top-0 z-1 bg-card px-3.5 py-2.5 font-semibold" style={{ width: 120 }}>主机</th>
                  <th className="sticky top-0 z-1 bg-card px-3.5 py-2.5 font-semibold" style={{ width: 170 }}>进程</th>
                  <th className="sticky top-0 z-1 bg-card px-3.5 py-2.5 text-right font-semibold" style={{ width: 64 }}>{sortBtn('score', '分值')}</th>
                  <th className="sticky top-0 z-1 bg-card px-3.5 py-2.5 font-semibold" style={{ width: 88 }}>状态</th>
                  <th className="sticky top-0 z-1 bg-card px-3.5 py-2.5 font-semibold" style={{ width: 110 }}>{sortBtn('time', '时间')}</th>
                </tr>
              </thead>
              <tbody>
                {items.map((a, i) => (
                  <tr
                    key={a.id}
                    onClick={() => setOpenId(a.id)}
                    className={cn(
                      'cursor-pointer border-b border-border-soft transition-colors last:border-b-0',
                      'hover:bg-secondary',
                      selected.has(a.id) && 'bg-brand-soft shadow-[inset_3px_0_0_var(--primary)]',
                      focusIdx === i && 'shadow-[inset_2px_0_0_var(--ok)]',
                    )}
                  >
                    <td className="px-3.5 py-2.5" onClick={(e) => e.stopPropagation()}>
                      <input type="checkbox" checked={selected.has(a.id)} onChange={(e) => toggleRow(a.id, e.target.checked)} className="row-sel accent-[var(--primary)]" />
                    </td>
                    <td className="px-3.5 py-2.5"><Badge tone={a.severity}>{SEV_LABEL[a.severity]}</Badge></td>
                    <td className="px-3.5 py-2.5">
                      <div className="font-medium">{a.title}</div>
                      <div className="mt-0.5 text-xs text-faint">{(a.rule_ids || []).join(' · ') || '-'}</div>
                    </td>
                    <td className="px-3.5 py-2.5">{a.hostname}{a.duplicate ? <span className="text-xs text-faint"> ×{a.duplicate + 1}</span> : null}</td>
                    <td className="px-3.5 py-2.5 font-mono text-xs">{a.process_name}<span className="text-faint"> :{a.pid}</span></td>
                    <td className={cn('px-3.5 py-2.5 text-right font-bold tabular-nums', a.score >= 70 ? 'text-crit' : a.score >= 40 ? 'text-warn' : 'text-muted-foreground')}>{a.score}</td>
                    <td className="px-3.5 py-2.5"><Badge tone={a.status}>{STATUS_LABEL[a.status]}</Badge></td>
                    <td className="px-3.5 py-2.5 text-xs text-faint" title={fmtTime(a.created_at)}>{relTime(a.created_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      <div className="mt-3.5 flex items-center justify-end gap-2.5 text-xs text-faint">
        <span>共 {total} 条 · 第 {page}/{pages} 页</span>
        <Button size="sm" disabled={page <= 1} onClick={() => setPage((p) => p - 1)} aria-label="上一页"><ChevronLeft size={13} /></Button>
        <Button size="sm" disabled={page >= pages} onClick={() => setPage((p) => p + 1)} aria-label="下一页"><ChevronRight size={13} /></Button>
      </div>

      {selected.size > 0 && canWrite && (
        <div
          className="fixed bottom-5 left-1/2 z-60 flex -translate-x-1/2 items-center gap-2.5 rounded-xl border border-border-strong bg-popover px-3.5 py-2.5 shadow-2xl"
          style={{ animation: 'page-in 180ms cubic-bezier(.22,1,.36,1)' }}
        >
          <b className="border-r border-border pr-2.5">已选 {selected.size} 条</b>
          <Button size="sm" onClick={() => bulk('acknowledged')}>标记已确认</Button>
          <Button size="sm" onClick={() => bulk('resolved')}>标记已解决</Button>
          <Button size="sm" variant="danger" onClick={() => bulk('false_positive')}>标记误报</Button>
          <Button size="sm" variant="ghost" onClick={() => setSelected(new Set())}>清空</Button>
        </div>
      )}

      <AlertDrawer
        alertId={openId}
        onClose={() => setOpenId(null)}
        onChanged={() => setRefreshTick((t) => t + 1)}
        canWrite={canWrite}
      />
    </div>
  );
}

export type { Verdict };
