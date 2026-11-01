import { useCallback, useEffect, useState, type FormEvent } from 'react';
import { Fingerprint, Plus, Trash2 } from 'lucide-react';
import { api } from '../lib/api';
import type { IOC } from '../lib/types';
import { relTime, fmtTime } from '../lib/format';
import { Badge, Button, Card, EmptyState, Input, SkeletonRows } from '../components/ui/basics';
import { useToast, useConfirm } from '../components/ui/overlays';
import { useError } from '../lib/hooks';

/* 威胁情报 IOC（SHA256 指标）：列表 + 添加 + 删除。
   与规则/白名单同属"策略"组——它是一种检测输入，随签名包热下发到终端。 */

const HASH_RE = /^[0-9a-fA-F]{64}$/;

export function IntelPage({ user }: { user: { role: string } }) {
  const err = useError();
  const toast = useToast();
  const confirm = useConfirm();
  const canWrite = user.role !== 'viewer';
  const [items, setItems] = useState<IOC[] | null>(null);
  const [hash, setHash] = useState('');
  const [note, setNote] = useState('');
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    try { setItems((await api.get<{ items: IOC[] }>('/api/v1/iocs')).items || []); }
    catch (e) { err.capture(e); }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => { load(); }, [load]);
  if (err.rendered) return err.rendered;

  const add = async (e: FormEvent) => {
    e.preventDefault();
    const h = hash.trim().toLowerCase();
    if (!HASH_RE.test(h)) { toast('需要完整的 64 位 SHA-256 十六进制哈希', 'err'); return; }
    setBusy(true);
    try {
      await api.post('/api/v1/iocs', { hash: h, note: note.trim() });
      toast('IOC 已添加，将随签名包下发到全部终端');
      setHash(''); setNote('');
      load();
    } catch (ex) { toast((ex as Error).message, 'err'); }
    finally { setBusy(false); }
  };

  const remove = async (ioc: IOC) => {
    const ok = await confirm({
      title: '删除这条 IOC？',
      message: `哈希 ${ioc.hash.slice(0, 16)}… 将从下发名单移除，终端侧下一轮签名包同步后不再按它拦截。`,
      danger: true, okText: '删除',
    });
    if (!ok) return;
    try {
      await api.del(`/api/v1/iocs/${encodeURIComponent(ioc.id)}`);
      toast('已删除');
      load();
    } catch (ex) { toast((ex as Error).message, 'err'); }
  };

  return (
    <div>
      {canWrite && (
        <Card className="mb-3.5 p-4">
          <form onSubmit={add} className="flex flex-wrap items-end gap-2.5">
            <label className="min-w-[340px] flex-1">
              <span className="mb-1.5 block text-[11.5px] text-faint">SHA-256 哈希（64 位十六进制）</span>
              <Input value={hash} onChange={(e) => setHash(e.target.value)} placeholder="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                className="w-full font-mono text-[12px]" required spellCheck={false} />
            </label>
            <label className="min-w-[200px]">
              <span className="mb-1.5 block text-[11.5px] text-faint">备注（它是什么 / 来源）</span>
              <Input value={note} onChange={(e) => setNote(e.target.value)} placeholder="例：应急样本 · CERT 通报" className="w-full" />
            </label>
            <Button variant="primary" type="submit" disabled={busy}><Plus size={13} /> 添加 IOC</Button>
          </form>
        </Card>
      )}

      {!items ? (
        <Card className="px-2 pb-2"><SkeletonRows rows={4} /></Card>
      ) : !items.length ? (
        <Card><EmptyState tone="info" icon={<Fingerprint size={20} />} title="还没有录入任何 IOC"
          sub={<>把已知恶意样本的 SHA-256 加进来（比如研判页拿到的进程哈希），<br />服务端会打进签名包，终端在下一轮规则同步时热加载——落地即拦截。</>} /></Card>
      ) : (
        <Card className="overflow-x-auto px-2 py-3.5">
          <table className="w-full text-[13px]">
            <thead><tr className="border-b border-border-soft text-left text-[11px] tracking-[.06em] text-faint uppercase">
              {['哈希', '备注', '添加人', '添加时间', canWrite ? '操作' : ''].filter(Boolean).map((h) => <th key={h} className="px-3.5 py-2.5 font-semibold">{h}</th>)}
            </tr></thead>
            <tbody>
              {items.map((ioc) => (
                <tr key={ioc.id} className="border-b border-border-soft transition-colors last:border-b-0 hover:bg-secondary">
                  <td className="px-3.5 py-2.5">
                    <span className="font-mono text-[11.5px]" title={ioc.hash}>{ioc.hash.slice(0, 24)}…</span>
                    <Badge tone="neutral" className="ml-2">SHA256</Badge>
                  </td>
                  <td className="px-3.5 py-2.5 text-muted-foreground">{ioc.note || <span className="text-ghost">-</span>}</td>
                  <td className="px-3.5 py-2.5 font-mono text-xs">{ioc.created_by || '-'}</td>
                  <td className="px-3.5 py-2.5 text-xs text-faint" title={fmtTime(ioc.created_at)}>{relTime(ioc.created_at)}</td>
                  {canWrite && (
                    <td className="px-3.5 py-2.5">
                      <Button size="sm" variant="ghost" onClick={() => remove(ioc)} aria-label={`删除 ${ioc.hash.slice(0, 12)}`}>
                        <Trash2 size={13} className="text-destructive" /> 删除
                      </Button>
                    </td>
                  )}
                </tr>
              ))}
            </tbody>
          </table>
          <p className="mt-2 px-3.5 text-xs text-faint">共 {items.length} 条 · 通过规则签名包（HMAC 验签）下发，终端热加载，无需重启探针。</p>
        </Card>
      )}
    </div>
  );
}
