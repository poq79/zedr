import { useCallback, useEffect, useState } from 'react';
import { ScanSearch, Wrench } from 'lucide-react';
import { api } from '../lib/api';
import type { HuntResult } from '../lib/types';
import { SEV_LABEL, relTime } from '../lib/format';
import { Badge, Button, Card, CardTitle, EmptyState, Input, SkeletonRows } from '../components/ui/basics';
import { AlertDrawer } from './AlertDrawer';
import { useError } from '../lib/hooks';

/* AI 狩猎 v2（POST /api/v1/ai/hunt）：自然语言 → 受控 DSL → 告警。
   页面的信任设计：先展示"AI 把你的话理解成了什么条件"（explain + 过滤器
   逐条 mono 列出），分析师确认意图没被曲解再往下看结果——
   模型永远接触不到 SQL，这里展示的就是它仅有的全部权力。

   多轮会话：追问时把最近几轮"问题 + 当时理解"带给翻译器（仅 LLM 引擎；
   确定性引擎只解析当前句，避免历史关键词污染过滤器）。会话状态在浏览器，
   服务端无状态。 */

interface TurnRecord { query: string; explain: string; total: number }

const FIELD_LABEL: Record<string, string> = {
  process_name: '进程名', image_path: '文件路径', cmdline: '命令行',
  hash_sha256: 'SHA256', verdict: '结论', severity: '严重度', score: '分值≥',
  signed: '签名', proc_user: '运行账号', hostname: '主机', rule_ids: '规则', status: '状态',
};

const EXAMPLES = [
  '最近 24 小时的严重告警',
  'powershell 相关的命令行',
  '未签名程序从临时目录执行',
  '得分 60 以上的可疑告警',
  'Administrator 账号运行的进程',
];

export function HuntPage() {
  const err = useError();
  const [q, setQ] = useState('');
  const [busy, setBusy] = useState(false);
  const [res, setRes] = useState<HuntResult | null>(null);
  const [engine, setEngine] = useState<string>('');
  const [openId, setOpenId] = useState<string | null>(null);
  const [turns, setTurns] = useState<TurnRecord[]>([]);

  useEffect(() => {
    api.get<{ stats?: { engine?: string } }>('/api/v1/ai/stats')
      .then((r) => setEngine(r.stats?.engine || 'deterministic'))
      .catch(() => setEngine('deterministic'));
  }, []);

  const run = useCallback(async (query: string, withHistory: boolean) => {
    const text = query.trim();
    if (!text) return;
    setBusy(true);
    try {
      const history = withHistory ? turns.slice(-5).map((t) => ({ query: t.query, explain: t.explain })) : [];
      const r = await api.post<HuntResult>('/api/v1/ai/hunt', { query: text, history });
      setRes(r);
      setTurns((prev) => [...prev, { query: text, explain: r.query.explain || '', total: r.total }].slice(-10));
    } catch (e) { err.capture(e); }
    finally { setBusy(false); }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [turns]);

  if (err.rendered) return err.rendered;

  return (
    <div>
      {/* 查询条 */}
      <Card className="mb-3.5 p-4">
        <form onSubmit={(e) => { e.preventDefault(); run(q, turns.length > 0); }} className="flex items-center gap-2.5">
          <div className="relative flex-1">
            <ScanSearch size={16} className="pointer-events-none absolute top-1/2 left-3 -translate-y-1/2 text-ghost" />
            <Input value={q} onChange={(e) => setQ(e.target.value)} placeholder="用自然语言描述你要找的告警；有会话时可直接追问（例：只要其中未签名的）"
              className="h-10 w-full pl-9 text-[13.5px]" maxLength={500} spellCheck={false} />
          </div>
          <Button variant="primary" type="submit" disabled={busy || !q.trim()} className="h-10 px-5">
            {busy ? '狩猎中…' : '开始狩猎'}
          </Button>
        </form>
        <div className="mt-2.5 flex flex-wrap items-center gap-1.5">
          {EXAMPLES.map((ex) => (
            <button key={ex} onClick={() => { setQ(ex); setTurns([]); run(ex, false); }}
              className="cursor-pointer rounded-full border border-border-soft bg-secondary px-2.5 py-1 text-[11.5px] text-muted-foreground transition-colors hover:border-border-strong hover:text-foreground">
              {ex}
            </button>
          ))}
          <div className="flex-1" />
          <span className="inline-flex items-center gap-1.5 text-[11px] text-ghost" title={engine === 'llm' ? '已配置大模型' : '未配置模型，由确定性引擎完成翻译与研判'}>
            <Wrench size={11} />
            {engine === 'llm' ? 'LLM 引擎' : '确定性引擎（未配置模型）'}
          </span>
        </div>
      </Card>

      {/* 会话历史（多轮追问） */}
      {turns.length > 0 && (
        <Card className="mb-3.5 px-4 py-2.5">
          <div className="flex flex-wrap items-center gap-2 text-[11.5px]">
            <span className="text-faint">本次会话：</span>
            {turns.map((t, i) => (
              <span key={i} className="inline-flex items-center gap-1 rounded-full border border-border-soft bg-secondary px-2 py-0.5" title={t.explain}>
                <span className="max-w-[240px] truncate">{t.query}</span>
                <span className="font-mono text-[10.5px] text-ghost">{t.total}条</span>
              </span>
            ))}
            <div className="flex-1" />
            <button onClick={() => { setTurns([]); setRes(null); }}
              className="cursor-pointer text-[11px] text-faint hover:text-foreground">清空会话</button>
          </div>
          {engine !== 'llm' && (
            <div className="mt-1 text-[10.5px] text-ghost">确定性引擎不消费历史上下文（追问按当前句解析）。</div>
          )}
        </Card>
      )}

      {/* 翻译可视化：AI 理解成了什么条件 */}
      {res && (
        <Card className="mb-3.5 p-4">
          <CardTitle className="mb-2.5">查询翻译 · AI 理解为</CardTitle>
          {res.query.explain && <p className="mb-3 text-[13px] leading-[1.7] text-foreground">{res.query.explain}</p>}
          {res.query.filters.length ? (
            <div className="flex flex-wrap gap-1.5">
              {res.query.filters.map((f, i) => (
                <span key={i} className="inline-flex items-center gap-1.5 rounded-[5px] border border-border-soft bg-secondary px-2 py-1 font-mono text-[11.5px]">
                  <span className="text-faint">{FIELD_LABEL[f.field] || f.field}</span>
                  <span className="text-ghost">{f.op}</span>
                  <span className="text-foreground">{f.value || (f.values || []).join('|')}</span>
                </span>
              ))}
            </div>
          ) : <div className="text-[12.5px] text-faint">无条件过滤（返回最近告警）</div>}
          <div className="mt-2.5 flex gap-4 font-mono text-[11px] text-ghost">
            <span>limit={res.query.limit}</span>
            <span>since={res.query.since_sec ? `${Math.round(res.query.since_sec / 3600)}h` : '全部'}</span>
            <span>order={res.query.order_by}{res.query.desc ? ' desc' : ''}</span>
            <span>target={res.query.target}</span>
          </div>
        </Card>
      )}

      {/* 结果 */}
      {res && (
        <Card className="px-2 py-3.5">
          <div className="mb-1 flex items-center gap-2.5 px-3.5">
            <span className="text-[12.5px] text-muted-foreground">命中 <b className="font-mono tabular-nums text-foreground">{res.total}</b> 条</span>
            <div className="flex-1" />
            <span className="text-[11px] text-ghost">点击行查看完整证据链与处置</span>
          </div>
          {!res.alerts.length ? (
            <EmptyState tone="ok" icon={<ScanSearch size={20} />} title="该条件下没有告警——环境安静" />
          ) : (
            <table className="mt-1 w-full text-[13px]">
              <thead><tr className="border-b border-border-soft text-left text-[11px] tracking-[.06em] text-faint uppercase">
                {['严重度', '告警', '进程', '主机', '分值', '时间'].map((h) => <th key={h} className="px-3.5 py-2.5 font-semibold">{h}</th>)}
              </tr></thead>
              <tbody>
                {res.alerts.map((a) => (
                  <tr key={a.id} onClick={() => setOpenId(a.id)}
                    className="cursor-pointer border-b border-border-soft transition-colors last:border-b-0 hover:bg-secondary">
                    <td className="px-3.5 py-2.5"><Badge tone={a.severity}>{SEV_LABEL[a.severity] || a.severity}</Badge></td>
                    <td className="max-w-[360px] px-3.5 py-2.5"><div className="truncate font-medium">{a.title}</div></td>
                    <td className="px-3.5 py-2.5 font-mono text-xs">{a.process_name}{a.cmdline ? <div className="mt-0.5 max-w-[280px] truncate text-[11px] text-ghost" title={a.cmdline}>{a.cmdline}</div> : null}</td>
                    <td className="px-3.5 py-2.5 text-xs text-muted-foreground">{a.hostname}</td>
                    <td className="px-3.5 py-2.5 font-mono font-semibold tabular-nums">{a.score}</td>
                    <td className="px-3.5 py-2.5 text-xs text-faint" title={a.created_at}>{relTime(a.created_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Card>
      )}

      {!res && !busy && (
        <Card>
          <EmptyState tone="info" icon={<ScanSearch size={20} />} title="用一句话狩猎"
            sub={<>描述特征而不是拼写条件：进程、路径、命令行、哈希、结论、严重度、分值、签名、账号、主机、规则。<br />查询会被翻译成<span className="text-foreground">受控条件</span>（模型接触不到 SQL），翻译结果会先展示给你确认。</>} />
        </Card>
      )}
      {busy && <Card className="px-2 pb-2"><SkeletonRows rows={4} /></Card>}

      <AlertDrawer alertId={openId} onClose={() => setOpenId(null)} onChanged={() => run(q, true)} canWrite />
    </div>
  );
}
