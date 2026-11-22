// AllowlistPage（Misc.tsx 拆分生成，2026-11-22 god file 治理）。
import { useEffect, useState, useCallback } from 'react';
import { Plus, ShieldCheck } from 'lucide-react';
import { api } from '../lib/api';
import { Role, AllowEntry } from '../lib/types';
import { relTime } from '../lib/format';
import { useError } from '../lib/hooks';
import { Card, Badge, Button, SkeletonRows, Input, Select, CardTitle, EmptyState } from '../components/ui/basics';
import { useToast, useConfirm } from '../components/ui/overlays';

          <p className="mt-2 px-3.5 text-xs text-faint">点击任意一行进入主机详情整页：系统概要 · 网络适配器 · 监听端口 · 服务 · 计划任务 · 自启动 · 处置指令 · 指令历史。终端默认每 30 秒心跳一次。</p>
          </Card>
        </>
      )}
    </div>
  );
}


/* ================= 白名单（例外与降噪） =================
   检测规则页已升级为「规则中心」整页（pages/RulesCenter.tsx）；
   白名单是它的姊妹能力：规则管"什么该响"，这里管"什么确认安全"。 */

/** 五种加白类型：类型语义直接写进选项与提示——加白最大的风险是
    条目太宽把真攻击也洗白了，提示里把"怎么写才窄"讲清楚。 */
const ALLOW_TYPES: { value: string; label: string; hint: string; placeholder: string }[] = [
  { value: 'hash', label: '文件哈希 SHA256', hint: '单个文件的精确匹配，最窄最安全。适用于"这个文件确认安全"。', placeholder: '64 位十六进制 SHA256，如 7f3a91c0…' },
  { value: 'path', label: '路径', hint: '镜像路径匹配：指向文件为精确匹配，以 \\ 结尾则匹配整个目录。目录越深越窄越安全。', placeholder: 'C:\\Tools\\procmon.exe 或 C:\\Tools\\Sysinternals\\' },
  { value: 'signer', label: '签名主体', hint: '按可信签名者匹配——一条加白覆盖该厂商全部签名文件，适合标准化软件资产。', placeholder: '签名主体名，如 Contoso Ltd' },
  { value: 'pair', label: '父子进程对', hint: '格式 parent.exe>child.exe：只放行特定启动组合，比整条命令行加白窄得多。', placeholder: 'deployment-agent.exe>cmd.exe' },
  { value: 'cmdline', label: '命令行片段', hint: '包含匹配（不区分大小写）。务必写得尽量窄——命令行是最容易被攻击者复用的维度。', placeholder: '如 --backup-mode' },
];

export function AllowlistPage({ user }: { user: { role: Role } }) {
  const err = useError();
  const toast = useToast();
  const confirm = useConfirm();
  const canWrite = user.role !== 'viewer';
  const isAdmin = user.role === 'admin';
  const [items, setItems] = useState<AllowEntry[] | null>(null);
  const [form, setForm] = useState({ type: 'hash', value: '', note: '' });
  const typeMeta = ALLOW_TYPES.find((t) => t.value === form.type) || ALLOW_TYPES[0];

  const load = useCallback(async () => {
    try { setItems((await api.get<{ items: AllowEntry[] }>('/api/v1/allowlist')).items || []); }
    catch (e) { err.capture(e); }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => { load(); }, [load]);
  if (err.rendered) return err.rendered;

  const add = async () => {
    if (!form.value.trim()) return toast('请填写加白内容', 'warn');
    try {
      await api.post('/api/v1/allowlist', { type: form.type, value: form.value.trim(), note: form.note.trim() });
      toast('已加入白名单（匹配的历史未处置告警已一并回收）');
      setForm({ type: form.type, value: '', note: '' });
      load();
    } catch (e) { toast((e as Error).message, 'err'); }
  };

  const remove = async (e: AllowEntry) => {
    const ok = await confirm({
      title: '删除该白名单项？',
      message: '删除后相关检测会重新生效，该对象若仍有可疑行为会再次告警。',
      danger: true, okText: '删除',
    });
    if (!ok) return;
    try {
      await api.del(`/api/v1/allowlist/${encodeURIComponent(e.id)}`);
      toast('已删除');
      load();
    } catch (ex) { toast((ex as Error).message, 'err'); }
  };

  /* 导出/导入（adminOnly）：白名单是误报治理资产，重建环境时
     "导出→导入"直通，格式与导出文件对称 */
  const exportList = async () => {
    try {
      const blob = await api.download('/api/v1/allowlist/export');
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url; a.download = 'zedr-allowlist.json'; a.click();
      URL.revokeObjectURL(url);
    } catch (e) { toast((e as Error).message, 'err'); }
  };

  const importList = async (file: File) => {
    let entries: { type: string; value: string; note?: string }[] = [];
    try {
      const data = JSON.parse(await file.text());
      if (Array.isArray(data?.entries)) entries = data.entries;
      else if (Array.isArray(data?.items)) entries = data.items;
      else if (Array.isArray(data)) entries = data;
    } catch {
      return toast('文件不是合法 JSON（应使用本页导出的格式）', 'err');
    }
    if (!entries.length) return toast('文件里没有可导入的条目', 'warn');
    try {
      const res = await api.post<{ added: number; skipped: number; failed: number }>('/api/v1/allowlist/import', { entries });
      toast(`导入完成：新增 ${res.added} · 已存在跳过 ${res.skipped} · 失败 ${res.failed}`);
      load();
    } catch (e) { toast((e as Error).message, 'err'); }
  };

  return (
    <div className="space-y-3.5">
      {canWrite && (
        <Card className="p-4">
          <CardTitle className="mb-3">新增白名单</CardTitle>
          <div className="grid items-end gap-2.5 sm:grid-cols-[170px_1fr_1fr_auto]">
            <label className="block"><span className="mb-1.5 block text-[11.5px] text-faint">类型</span>
              <Select value={form.type} onChange={(e) => setForm((f) => ({ ...f, type: e.target.value }))} className="w-full">
                {ALLOW_TYPES.map((t) => <option key={t.value} value={t.value}>{t.label}</option>)}
              </Select>
            </label>
            <label className="block"><span className="mb-1.5 block text-[11.5px] text-faint">内容</span>
              <Input value={form.value} onChange={(e) => setForm((f) => ({ ...f, value: e.target.value }))} className="w-full font-mono text-xs" placeholder={typeMeta.placeholder} />
            </label>
            <label className="block"><span className="mb-1.5 block text-[11.5px] text-faint">备注</span>
              <Input value={form.note} onChange={(e) => setForm((f) => ({ ...f, note: e.target.value }))} className="w-full" placeholder="为什么加白（会进入审计）" />
            </label>
            <Button variant="primary" onClick={add}><Plus size={13} /> 添加</Button>
          </div>
          <div className="mt-2.5 text-[11.5px] text-faint">{typeMeta.hint}</div>
        </Card>
      )}

      {!items ? <Card className="px-2 pb-2"><SkeletonRows rows={4} /></Card> : !items.length ? (
        <Card><EmptyState icon={<ShieldCheck size={20} />} title="白名单为空"
          sub="加白名单能让确认安全的对象不再告警。可在告警详情里一键添加，或在这里手动新增。" /></Card>
      ) : (
        <Card className="overflow-x-auto px-2 py-3.5">
          <div className="mb-2 flex items-center px-3.5">
            <span className="text-[11px] tracking-[.06em] uppercase text-faint">共 {items.length} 条 · 加白即回收历史未处置告警</span>
            <div className="flex-1" />
            {isAdmin && (
              <label className="cursor-pointer">
                <input type="file" accept="application/json" className="hidden"
                  onChange={(e) => { const f = e.target.files?.[0]; if (f) importList(f); e.target.value = ''; }} />
                <Button size="sm" variant="ghost">导入</Button>
              </label>
            )}
            {isAdmin && <Button size="sm" variant="ghost" onClick={exportList}>导出</Button>}
          </div>
          <table className="w-full text-[13px]">
            <thead><tr className="border-b border-border-soft text-left text-[11px] tracking-[.06em] text-faint uppercase">
              {['类型', '内容', '备注', '添加人', '时间', '操作'].map((h) => <th key={h} className="px-3.5 py-2.5 font-semibold">{h}</th>)}
            </tr></thead>
            <tbody>
              {items.map((e) => (
                <tr key={e.id} className="border-b border-border-soft last:border-b-0 hover:bg-secondary">
                  <td className="px-3.5 py-2.5">
                    <Badge tone="info">{ALLOW_TYPES.find((t) => t.value === e.type)?.label || e.type}</Badge>
                  </td>
                  <td className="max-w-[420px] px-3.5 py-2.5 font-mono text-xs break-all">{e.value}</td>
                  <td className="px-3.5 py-2.5 text-xs">{e.note || <span className="text-faint">-</span>}</td>
                  <td className="px-3.5 py-2.5 text-xs text-faint">{e.created_by || '-'}</td>
                  <td className="px-3.5 py-2.5 text-xs text-faint">{e.created_at ? relTime(e.created_at) : '-'}</td>
                  <td className="px-3.5 py-2.5">{canWrite && <Button size="sm" variant="ghost" onClick={() => remove(e)}>删除</Button>}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </Card>
      )}
    </div>
  );
}

/* ================= 审计日志 ================= */

/* 审计动作语义化：原始 action 串保留在 title 里可查，界面给中文与色彩 */
