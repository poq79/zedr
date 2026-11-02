import { useEffect, useRef, useState } from 'react';
import { Bot, Send, Sparkles, X } from 'lucide-react';
import { api } from '../lib/api';
import { Badge, Button, Card, Input } from './ui/basics';
import { useToast } from './ui/overlays';

/* 全局 AI 助手（方向 B）：右下角悬浮面板，多轮对话 + 工具调用轨迹。
   纪律与 Agent 调查同源：只读工具、每次工具调用可见、无模型时诚实降级。 */

interface ToolStep {
  step: number; tool: string; args?: string; result_preview?: string;
  result_bytes?: number; err?: string;
}
interface ChatReply {
  answer: string; steps?: ToolStep[]; tool_calls?: number; steps_limit_reached?: boolean;
  model?: string; engine?: string; latency_ms?: number;
  degraded?: boolean; degraded_reason?: string;
}
interface Msg {
  role: 'user' | 'assistant';
  content: string;
  reply?: ChatReply;
}

const STARTERS = [
  '最近 24 小时有哪些高危告警？',
  '哪台主机风险最高？',
  '当前 AI 引擎和预算状态如何？',
];

export function AiAssistant() {
  const toast = useToast();
  const [open, setOpen] = useState(false);
  const [input, setInput] = useState('');
  const [busy, setBusy] = useState(false);
  const [msgs, setMsgs] = useState<Msg[]>([]);
  const [lastEngine, setLastEngine] = useState<string>('');
  const listRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    api.get<{ stats?: { engine?: string } }>('/api/v1/ai/stats')
      .then((r) => setLastEngine(r.stats?.engine || 'heuristic')).catch(() => {});
  }, [open]);

  useEffect(() => {
    listRef.current?.scrollTo({ top: listRef.current.scrollHeight, behavior: 'smooth' });
  }, [msgs, busy]);

  const ask = async (text: string) => {
    const q = text.trim();
    if (!q || busy) return;
    const history = msgs.slice(-6).map((m) => ({ role: m.role, content: m.content }));
    setMsgs((prev) => [...prev, { role: 'user', content: q }]);
    setInput('');
    setBusy(true);
    try {
      const rep = await api.post<ChatReply>('/api/v1/ai/chat', { question: q, history });
      setMsgs((prev) => [...prev, { role: 'assistant', content: rep.answer, reply: rep }]);
      if (rep.degraded) toast(rep.degraded_reason || 'AI 助手已降级', 'warn');
    } catch (e) {
      toast((e as Error).message, 'err');
    } finally { setBusy(false); }
  };

  return (
    <>
      {!open && (
        <button onClick={() => setOpen(true)} aria-label="打开 AI 助手"
          className="fixed bottom-5 right-5 z-40 grid h-11 w-11 cursor-pointer place-items-center rounded-full border border-primary/30 bg-primary text-primary-foreground shadow-lg transition-transform hover:scale-105">
          <Sparkles size={18} />
        </button>
      )}
      {open && (
        <Card className="fixed bottom-5 right-5 z-40 flex h-[520px] w-[400px] flex-col overflow-hidden p-0 shadow-2xl">
          <div className="flex items-center gap-2 border-b border-border-soft px-3.5 py-2.5">
            <Bot size={14} className="text-primary" />
            <b className="text-[13px]">AI 助手</b>
            <Badge tone={lastEngine === 'llm' ? 'resolved' : 'info'}>
              {lastEngine === 'llm' ? '模型引擎' : '未配置模型'}
            </Badge>
            <div className="flex-1" />
            <button onClick={() => setOpen(false)} aria-label="关闭"
              className="cursor-pointer rounded p-1 text-faint hover:bg-secondary hover:text-foreground"><X size={14} /></button>
          </div>

          <div ref={listRef} className="flex-1 space-y-2.5 overflow-y-auto px-3.5 py-3">
            {msgs.length === 0 && (
              <div className="space-y-2">
                <p className="text-[12px] leading-[1.7] text-faint">问平台里的事实（告警/事件/主机/情报），需要时我会调用只读工具核实，每一步都可见。</p>
                {STARTERS.map((s) => (
                  <button key={s} onClick={() => ask(s)}
                    className="block w-full cursor-pointer rounded-md border border-border-soft bg-secondary px-2.5 py-1.5 text-left text-[12px] text-muted-foreground hover:border-border-strong hover:text-foreground">
                    {s}
                  </button>
                ))}
              </div>
            )}
            {msgs.map((m, i) => (
              <div key={i}>
                {m.role === 'user' ? (
                  <div className="ml-10 rounded-lg rounded-br-sm bg-primary px-3 py-2 text-[12.5px] text-primary-foreground">{m.content}</div>
                ) : (
                  <div className="mr-4 space-y-1.5">
                    <div className="rounded-lg rounded-bl-sm border border-border-soft bg-card px-3 py-2 text-[12.5px] leading-[1.7] whitespace-pre-wrap">
                      {m.content || (m.reply?.degraded ? <span className="text-faint">{m.reply.degraded_reason}</span> : '')}
                    </div>
                    {!!m.reply?.steps?.length && (
                      <details className="text-[11px] text-faint">
                        <summary className="cursor-pointer select-none">工具调用 {m.reply.tool_calls} 次 {m.reply.steps_limit_reached ? '（步数触顶）' : ''}</summary>
                        <div className="mt-1 grid gap-1">
                          {m.reply.steps.map((s, j) => (
                            <div key={j} className="rounded border border-border-soft bg-secondary/60 px-2 py-1 font-mono">
                              <span className="text-ghost">{String(s.step).padStart(2, '0')}</span> {s.tool}
                              {s.args && <span className="ml-1 truncate text-ghost" title={s.args}>{s.args.slice(0, 80)}</span>}
                              {s.err && <div className="text-destructive">{s.err}</div>}
                              {s.result_preview && <div className="mt-0.5 max-h-10 overflow-hidden text-muted-foreground">{s.result_preview}</div>}
                            </div>
                          ))}
                        </div>
                      </details>
                    )}
                    {m.reply && (
                      <div className="flex gap-3 text-[10.5px] text-ghost">
                        <span>{m.reply.engine === 'llm' ? m.reply.model : '确定性/降级'}</span>
                        <span>{m.reply.latency_ms || 0}ms</span>
                      </div>
                    )}
                  </div>
                )}
              </div>
            ))}
            {busy && <div className="mr-4 rounded-lg border border-border-soft bg-card px-3 py-2 text-[12px] text-faint">正在查证…</div>}
          </div>

          <form onSubmit={(e) => { e.preventDefault(); ask(input); }}
            className="flex items-center gap-2 border-t border-border-soft p-2.5">
            <Input value={input} onChange={(e) => setInput(e.target.value)} maxLength={500}
              placeholder="问点什么…（Enter 发送）" className="h-9 flex-1" />
            <Button type="submit" variant="primary" size="sm" disabled={busy || !input.trim()} aria-label="发送">
              <Send size={12} />
            </Button>
          </form>
        </Card>
      )}
    </>
  );
}
