import { useCallback, useEffect, useMemo, useState } from 'react';
import { Fingerprint, Plus, Trash2 } from 'lucide-react';
import { api } from '../lib/api';
import type { IntelItem, IOC } from '../lib/types';
import { relTime, fmtTime } from '../lib/format';
import { Badge, Button, Card, EmptyState, Input, SkeletonRows, Tabs } from '../components/ui/basics';
import { useToast, useConfirm } from '../components/ui/overlays';
import { useError } from '../lib/hooks';

/* 威胁情报（黑名单）：哈希 / IP / 路径 / 关键词 四类，列表 + 添加 + 删除
   + 命中统计。与规则/白名单同属"策略"组——它是检测输入，随签名包热下发：
   哈希走独立 IOC 包（老探针兼容），IP/路径/关键词随规则包（双签名覆盖）。
   域名/URL 情报当前不做：探针无 DNS/网络内容遥测，见 TRADEOFFS。 */

const HASH_RE = /^[0-9a-fA-F]{64}$/;
const IP_RE = /^[0-9a-fA-F.:]{3,45}$/;

type TabKey = 'hash' | 'ip' | 'path' | 'keyword';

interface Row {
  kind: TabKey;
  id: string;
  value: string;
  note: string;
  name?: string;
  score?: number;
  mitre?: string;
  hits: number;
  created_by: string;
  created_at: string;
}

const TAB_META: Record<TabKey, { label: string; valueLabel: string; placeholder: string; hint: string }> = {
  hash: {
    label: '文件哈希', valueLabel: 'SHA-256 哈希（64 位十六进制）',
    placeholder: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    hint: '最精确的黑名单：单凭命中即达恶意判定线。适用于研判确认的恶意样本。',
  },
  ip: {
    label: '恶意 IP', valueLabel: 'IPv4 / IPv6 地址',
    placeholder: '203.0.113.9',
    hint: '进程连接的远端地址精确匹配（不支持网段）。适合已知 C2 / 恶意基础设施。',
  },
  path: {
    label: '恶意路径', valueLabel: '镜像完整路径（精确匹配）',
    placeholder: 'C:\\Users\\Public\\malware.exe',
    hint: '按文件完整路径精确匹配（大小写不敏感）。要按目录/通配放行检测请用规则中心写规则。',
  },
  keyword: {
    label: '关键词', valueLabel: '命令行 / 进程名关键词',
    placeholder: '例：--coinhive 或 恶意工具名.exe',
    hint: '与内置关键词层同管线（大小写不敏感、共享 40 分帽）。分值即命中加成，拿不准先从低分起步。',
  },
};

export function IntelPage({ user }: { user: { role: string } }) {
  const err = useError();
  const toast = useToast();
  const confirm = useConfirm();
  const canWrite = user.role !== 'viewer';
  const [tab, setTab] = useState<TabKey>('hash');
  const [hashes, setHashes] = useState<IOC[] | null>(null);
  const [intel, setIntel] = useState<IntelItem[] | null>(null);
  const [value, setValue] = useState('');
  const [note, setNote] = useState('');
  const [name, setName] = useState('');
  const [score, setScore] = useState(25);
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    try {
      const [h, it] = await Promise.all([
        api.get<{ items: IOC[] }>('/api/v1/iocs'),
        api.get<{ items: IntelItem[] }>('/api/v1/intel'),
      ]);
      setHashes(h.items || []);
      setIntel(it.items || []);
    } catch (e) { err.capture(e); }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => { load(); }, [load]);
  if (err.rendered) return err.rendered;

  const rows = useMemo<Row[]>(() => {
    const h = (hashes || []).map<Row>((x) => ({
      kind: 'hash', id: x.id, value: x.hash, note: x.note || '',
      hits: x.hits || 0, created_by: x.created_by || '', created_at: x.created_at,
    }));
    const it = (intel || []).map<Row>((x) => ({
      kind: x.type as TabKey, id: x.id, value: x.value, note: x.note || '',
      name: x.name, score: x.score, mitre: x.mitre,
      hits: x.hits || 0, created_by: x.created_by || '', created_at: x.created_at,
    }));
    return [...h, ...it].filter((r) => r.kind === tab)
      .sort((a, b) => b.hits - a.hits || (b.created_at > a.created_at ? 1 : -1));
  }, [hashes, intel, tab]);

  const counts = useMemo(() => {
    const all = [...(hashes || []).map(() => 'hash' as TabKey), ...(intel || []).map((x) => x.type as TabKey)];
    return {
      hash: all.filter((t) => t === 'hash').length,
      ip: all.filter((t) => t === 'ip').length,
      path: all.filter((t) => t === 'path').length,
      keyword: all.filter((t) => t === 'keyword').length,
    };
  }, [hashes, intel]);

  const meta = TAB_META[tab];

  const add = async () => {
    const v = value.trim();
    setBusy(true);
    try {
      if (tab === 'hash') {
        const h = v.toLowerCase();
        if (!HASH_RE.test(h)) { toast('需要完整的 64 位 SHA-256 十六进制哈希', 'err'); return; }
        await api.post('/api/v1/iocs', { hash: h, note: note.trim() });
        toast('IOC 已添加，将随签名包下发到全部终端');
      } else {
        if (tab === 'ip' && !IP_RE.test(v)) { toast('不是合法的 IP 地址', 'err'); return; }
        if (!v) { toast('请填写内容', 'warn'); return; }
        await api.post('/api/v1/intel', {
          type: tab, value: v, score: tab === 'keyword' ? score : 0,
          name: name.trim(), note: note.trim(),
        });
        toast('情报已添加，将随规则包下发到全部终端');
      }
      setValue(''); setNote(''); setName(''); setScore(25);
      load();
    } catch (e) { toast((e as Error).message, 'err'); }
    finally { setBusy(false); }
  };

  const remove = async (r: Row) => {
    const ok = await confirm({
      title: '删除这条威胁情报？',
      message: `${TAB_META[r.kind].label} ${r.value.slice(0, 48)}${r.value.length > 48 ? '…' : ''} 将从下发名单移除，终端下一轮同步后不再按它告警。`,
      danger: true, okText: '删除',
    });
    if (!ok) return;
    try {
      await api.del(`/api/v1/${r.kind === 'hash' ? 'iocs' : 'intel'}/${encodeURIComponent(r.id)}`);
      toast('已删除');
      load();
    } catch (e) { toast((e as Error).message, 'err'); }
  };

  return (
    <div>
      {canWrite && (
        <Card className="mb-3.5 p-4">
          <Tabs
            tabs={[
              { key: 'hash', label: TAB_META.hash.label, count: counts.hash },
              { key: 'ip', label: TAB_META.ip.label, count: counts.ip },
              { key: 'path', label: TAB_META.path.label, count: counts.path },
              { key: 'keyword', label: TAB_META.keyword.label, count: counts.keyword },
            ]}
            value={tab}
            onChange={(k) => setTab(k as TabKey)}
          />
          <div className="mt-3 flex flex-wrap items-end gap-2.5">
            <label className={tab === 'hash' ? 'min-w-[340px] flex-1' : 'min-w-[240px] flex-1'}>
              <span className="mb-1.5 block text-[11.5px] text-faint">{meta.valueLabel}</span>
              <Input value={value} onChange={(e) => setValue(e.target.value)} placeholder={meta.placeholder}
                className="w-full font-mono text-[12px]" spellCheck={false} />
            </label>
            {tab === 'keyword' && (
              <>
                <label className="w-[140px]">
                  <span className="mb-1.5 block text-[11.5px] text-faint">分值（5-40）</span>
                  <Input type="number" min={5} max={40} value={score}
                    onChange={(e) => setScore(parseInt(e.target.value, 10) || 25)}
                    className="w-full font-mono tabular-nums" />
                </label>
                <label className="min-w-[160px]">
                  <span className="mb-1.5 block text-[11.5px] text-faint">告警展示名</span>
                  <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="默认同关键词" className="w-full" />
                </label>
              </>
            )}
            <label className="min-w-[200px]">
              <span className="mb-1.5 block text-[11.5px] text-faint">备注（它是什么 / 来源）</span>
              <Input value={note} onChange={(e) => setNote(e.target.value)} placeholder="例：应急样本 · CERT 通报" className="w-full" />
            </label>
            <Button variant="primary" onClick={add} disabled={busy}><Plus size={13} /> 添加情报</Button>
          </div>
          <div className="mt-2.5 text-[11.5px] text-faint">{meta.hint}</div>
        </Card>
      )}

      {!rows ? (
        <Card className="px-2 pb-2"><SkeletonRows rows={4} /></Card>
      ) : !rows.length ? (
        <Card><EmptyState tone="info" icon={<Fingerprint size={20} />} title={`还没有${meta.label}情报`}
          sub={<>把确认恶意的{meta.label}加进来（研判页也可一键加黑），<br />服务端打进签名包，终端在下一轮同步时热加载——命中即参与判定。</>} /></Card>
      ) : (
        <Card className="overflow-x-auto px-2 py-3.5">
          <table className="w-full text-[13px]">
            <thead><tr className="border-b border-border-soft text-left text-[11px] tracking-[.06em] text-faint uppercase">
              {['内容', ...(tab === 'keyword' ? ['展示名/分值'] : []), '命中', '备注', '添加人', '添加时间', canWrite ? '操作' : ''].filter(Boolean).map((h) => <th key={h} className="px-3.5 py-2.5 font-semibold">{h}</th>)}
            </tr></thead>
            <tbody>
              {rows.map((r) => (
                <tr key={r.kind + r.id} className="border-b border-border-soft transition-colors last:border-b-0 hover:bg-secondary">
                  <td className="max-w-[420px] px-3.5 py-2.5">
                    <span className="font-mono text-[11.5px] break-all" title={r.value}>
                      {r.kind === 'hash' ? r.value.slice(0, 24) + '…' : r.value}
                    </span>
                    <Badge tone={r.kind === 'hash' ? 'neutral' : 'info'} className="ml-2">{TAB_META[r.kind].label}</Badge>
                  </td>
                  {tab === 'keyword' && (
                    <td className="px-3.5 py-2.5 text-xs">
                      {r.name || '-'} <span className="ml-1.5 font-mono tabular-nums text-faint">+{r.score}</span>
                      {r.mitre && <span className="ml-1.5 font-mono text-[11px] text-faint">{r.mitre}</span>}
                    </td>
                  )}
                  <td className="px-3.5 py-2.5 font-mono text-xs tabular-nums" title="全部终端本次运行期命中之和（探针重启后从零计）">
                    {r.hits > 0 ? r.hits : <span className="text-ghost">0</span>}
                  </td>
                  <td className="px-3.5 py-2.5 text-muted-foreground">{r.note || <span className="text-ghost">-</span>}</td>
                  <td className="px-3.5 py-2.5 font-mono text-xs">{r.created_by || '-'}</td>
                  <td className="px-3.5 py-2.5 text-xs text-faint" title={fmtTime(r.created_at)}>{relTime(r.created_at)}</td>
                  {canWrite && (
                    <td className="px-3.5 py-2.5">
                      <Button size="sm" variant="ghost" onClick={() => remove(r)} aria-label={`删除 ${r.value.slice(0, 12)}`}>
                        <Trash2 size={13} className="text-destructive" /> 删除
                      </Button>
                    </td>
                  )}
                </tr>
              ))}
            </tbody>
          </table>
          <p className="mt-2 px-3.5 text-xs text-faint">
            共 {rows.length} 条 · 签名包（HMAC 验签）热下发，无需重启探针 · 命中列为全终端观察口径之和
          </p>
        </Card>
      )}
    </div>
  );
}
