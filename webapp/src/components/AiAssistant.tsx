import { useCallback, useEffect, useRef, useState } from 'react';
import { Bot, Eraser, Send, Square, X } from 'lucide-react';
import { api, authHeaders } from '../lib/api';
import { Badge, Button, Card, Input } from './ui/basics';
import { useToast } from './ui/overlays';

/* 全局 AI 助手 2.0（2026-11 对话升级）：流式打字机 + 可折叠思考块 +
   工具调用实时时间线 + 停止生成（保留部分内容）+ 建议追问 + 告警 ID
   溯源跳转 + 本地会话持久化。纪律与 Agent 调查同源：只读工具、每一步
   可见、无模型时诚实降级。协议调研（2026-11-09，来源见 overview.md）：
   EventSource 不支持 POST，用 fetch + ReadableStream 自解析 SSE 帧。 */

interface ToolStep {
  step: number; tool: string; args?: string; result_preview?: string;
  result_bytes?: number; err?: string; running?: boolean;
}
interface ChatReply {
  answer: string; steps?: ToolStep[]; tool_calls?: number; steps_limit_reached?: boolean;
  model?: string; engine?: string; latency_ms?: number;
  degraded?: boolean; degraded_reason?: string; followups?: string[];
}
interface Msg {
  role: 'user' | 'assistant';
  content: string;
  reply?: ChatReply;
  thinking?: string;
  steps?: ToolStep[];
  streaming?: boolean;
}

// StreamEv 是 SSE 事件载荷的宽松视图（字段按 event 类型分支取用）。
type StreamEv = { [k: string]: unknown };

const LS_KEY = 'zedr_ai_chat_v1';

// 快捷动作库（Purple AI Quick Starts 同款）：空态给方向，不用猜第一句
const STARTERS = [
  '现在最需要处理的告警是什么？',
  '过去 24 小时有没有疑似暴破成功的登录？',
  '哪台主机最近新增了自启动项？',
  '总结一下今天的攻击面变化',
  '当前 AI 引擎和预算状态如何？',
  '最新的 critical 告警里有没有同哈希跨主机？',
];

// 32 位十六进制 = 告警 ID：正文里的引用渲染成可点击 chip（M365 Copilot
// 的教训：引用不可点击等于没有引用）。哈希前缀（16 位）不命中，保持纯文本。
function linkAlertIds(text: string): (string | { id: string })[] {
  const parts: (string | { id: string })[] = [];
  const re = /\b[0-9a-f]{32}\b/g;
  let last = 0;
  for (const m of text.matchAll(re)) {
    if (m.index! > last) parts.push(text.slice(last, m.index));
    parts.push({ id: m[0] });
    last = m.index! + m[0].length;
  }
  if (last < text.length) parts.push(text.slice(last));
  return parts;
}

function AnswerText({ text }: { text: string }) {
  return (
    <>
      {linkAlertIds(text).map((p, i) =>
        typeof p === 'string' ? <span key={i}>{p}</span> : (
          <a key={i} href={`#/alerts?open=${p.id}`} target="_blank" rel="noreferrer"
            className="mx-0.5 inline-flex items-center rounded border border-border-soft bg-secondary px-1 py-px font-mono text-[10px] text-primary hover:underline"
            title={`打开告警 ${p.id}`}>
            告警 {p.id.slice(0, 8)}
          </a>
        ),
      )}
    </>
  );
}

export function AiAssistant() {
  const toast = useToast();
  const [open, setOpen] = useState(false);
  const [input, setInput] = useState('');
  const [busy, setBusy] = useState(false);
  const [thinking, setThinking] = useState(false);
  const [msgs, setMsgs] = useState<Msg[]>(() => {
    try {
      const raw = localStorage.getItem(LS_KEY);
      return raw ? (JSON.parse(raw) as Msg[]) : [];
    } catch { return []; }
  });
  const [lastEngine, setLastEngine] = useState<string>('');
  const listRef = useRef<HTMLDivElement>(null);
  const abortRef = useRef<AbortController | null>(null);

  useEffect(() => {
    // 持久化：strip streaming 标记后落 localStorage，刷新不丢会话
    try {
      const clean = msgs.slice(-60).map((m) => ({ ...m, streaming: false }));
      localStorage.setItem(LS_KEY, JSON.stringify(clean));
    } catch { /* 配额满等静默放弃——对话历史不是关键数据 */ }
  }, [msgs]);

  useEffect(() => {
    api.get<{ stats?: { engine?: string } }>('/api/v1/ai/stats')
      .then((r) => setLastEngine(r.stats?.engine || 'heuristic')).catch(() => {});
  }, [open]);

  useEffect(() => {
    listRef.current?.scrollTo({ top: listRef.current.scrollHeight, behavior: 'smooth' });
  }, [msgs, busy, thinking]);

  const patchLast = (fn: (m: Msg) => Msg) =>
    setMsgs((prev) => {
      if (!prev.length || prev[prev.length - 1].role !== 'assistant') return prev;
      return [...prev.slice(0, -1), fn(prev[prev.length - 1])];
    });

  const finalizeLast = (rep: ChatReply) =>
    setMsgs((prev) => {
      if (!prev.length || prev[prev.length - 1].role !== 'assistant') return prev;
      const cur = prev[prev.length - 1];
      return [...prev.slice(0, -1), { ...cur, streaming: false, content: rep.answer || cur.content, reply: rep }];
    });

  const stop = () => {
    abortRef.current?.abort();
    setBusy(false);
    setThinking(false);
    patchLast((m) => ({
      ...m, streaming: false,
      content: m.content ? m.content + '\n\n（已停止生成）' : '（已停止生成）',
    }));
  };

  const ask = useCallback(async (text: string) => {
    const q = text.trim();
    if (!q || busy) return;
    const history = msgs.slice(-6).map((m) => ({ role: m.role, content: m.content }));
    setMsgs((prev) => [...prev, { role: 'user', content: q }, { role: 'assistant', content: '', streaming: true, steps: [] }]);
    setInput('');
    setBusy(true);
    setThinking(false);
    const ac = new AbortController();
    abortRef.current = ac;
    try {
      const res = await fetch('/api/v1/ai/chat/stream', {
        method: 'POST',
        headers: authHeaders('text/event-stream'),
        credentials: 'same-origin',
        body: JSON.stringify({ question: q, history }),
        signal: ac.signal,
      });
      if (!res.ok || !res.body) throw new Error('stream unavailable');
      const reader = res.body.getReader();
      const decoder = new TextDecoder();
      let buffer = '';
      let sawDone = false;
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });
        // SSE 按 \n\n 分帧，半帧留在 buffer（协议分帧纪律）
        let idx: number;
        while ((idx = buffer.indexOf('\n\n')) >= 0) {
          const frame = buffer.slice(0, idx);
          buffer = buffer.slice(idx + 2);
          let event = 'message';
          const dataLines: string[] = [];
          for (const line of frame.split('\n')) {
            if (line.startsWith('event:')) event = line.slice(6).trim();
            else if (line.startsWith('data:')) dataLines.push(line.slice(5).trim());
          }
          if (!dataLines.length) continue;
          let ev: StreamEv | null = null;
          try { ev = JSON.parse(dataLines.join('\n')); } catch { continue; }
          if (!ev) continue;
          if (event === 'delta' && typeof ev.text === 'string') {
            patchLast((m) => ({ ...m, content: m.content + ev.text }));
          } else if (event === 'thinking') {
            setThinking(true);
            patchLast((m) => ({ ...m, thinking: (m.thinking || '') + (ev.text || '') }));
          } else if (event === 'tool_start') {
            setThinking(false);
            patchLast((m) => ({ ...m, steps: [...(m.steps || []), {
              step: Number(ev.step), tool: String(ev.tool), args: typeof ev.args === 'string' ? ev.args : '', running: true,
            }] }));
          } else if (event === 'tool_end') {
            patchLast((m) => {
              const steps = [...(m.steps || [])];
              for (let i = steps.length - 1; i >= 0; i--) {
                if (steps[i].running && steps[i].tool === ev.tool) {
                  steps[i] = { ...steps[i], running: false,
                    result_preview: typeof ev.result_preview === 'string' ? ev.result_preview : undefined,
                    result_bytes: typeof ev.result_bytes === 'number' ? ev.result_bytes : undefined,
                    err: typeof ev.err === 'string' ? ev.err : undefined };
                  break;
                }
              }
              return { ...m, steps };
            });
          } else if (event === 'done') {
            sawDone = true;
            setThinking(false);
            if (ev.report) finalizeLast(ev.report as ChatReply);
          } else if (event === 'error') {
            toast(String(ev.text || '对话失败'), 'err');
          }
        }
      }
      if (!sawDone) {
        // 流中断且无 done：保留已收内容并如实标注
        patchLast((m) => ({ ...m, streaming: false, content: m.content || '（连接中断，未收到完整回答）' }));
      }
    } catch (e) {
      if ((e as Error).name === 'AbortError') return; // stop() 已处理占位消息
      // 流式不可用（老版本服务端/网络错误）：回退非流式，体验不倒退
      try {
        const rep = await api.post<ChatReply>('/api/v1/ai/chat', { question: q, history });
        finalizeLast(rep);
        if (rep.degraded) toast(rep.degraded_reason || 'AI 助手已降级', 'warn');
      } catch (e2) {
        toast((e2 as Error).message, 'err');
        patchLast((m) => ({ ...m, streaming: false, content: m.content || '（请求失败）' }));
      }
    } finally {
      setBusy(false);
      setThinking(false);
      abortRef.current = null;
    }
  }, [busy, msgs, toast]);

  return (
    <>
      {!open && (
        <button onClick={() => setOpen(true)} aria-label="打开 AI 助手"
          className="fixed bottom-5 right-5 z-40 grid h-11 w-11 cursor-pointer place-items-center rounded-full border border-primary/30 bg-primary text-primary-foreground shadow-lg transition-transform hover:scale-105">
          <span className="text-[16px]">✦</span>
        </button>
      )}
      {open && (
        <Card className="fixed bottom-5 right-5 z-40 flex h-[560px] w-[420px] flex-col overflow-hidden p-0 shadow-2xl">
          <div className="flex items-center gap-2 border-b border-border-soft px-3.5 py-2.5">
            <Bot size={14} className="text-primary" />
            <b className="text-[13px]">AI 助手</b>
            <Badge tone={lastEngine === 'llm' ? 'resolved' : 'info'}>
              {lastEngine === 'llm' ? '模型引擎' : '未配置模型'}
            </Badge>
            <div className="flex-1" />
            <button onClick={() => { if (!busy && msgs.length) { setMsgs([]); toast('会话已清空'); } }}
              disabled={busy || !msgs.length} aria-label="清空会话" title="清空会话"
              className="cursor-pointer rounded p-1 text-faint hover:bg-secondary hover:text-foreground disabled:opacity-40"><Eraser size={14} /></button>
            <button onClick={() => setOpen(false)} aria-label="关闭"
              className="cursor-pointer rounded p-1 text-faint hover:bg-secondary hover:text-foreground"><X size={14} /></button>
          </div>

          <div ref={listRef} className="flex-1 space-y-2.5 overflow-y-auto px-3.5 py-3">
            {msgs.length === 0 && (
              <div className="space-y-2">
                <p className="text-[12px] leading-[1.7] text-faint">问平台里的事实（告警/事件/主机/情报/实时进程），需要时我会调用只读工具核实，每一步都实时可见。</p>
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
                    {m.thinking && (
                      <details className="rounded-md border border-border-soft bg-secondary/50 px-2.5 py-1.5 text-[11px] text-faint">
                        <summary className="cursor-pointer select-none">思考过程</summary>
                        <div className="mt-1 max-h-32 overflow-y-auto whitespace-pre-wrap font-mono text-[10.5px] leading-[1.6]">{m.thinking}</div>
                      </details>
                    )}
                    <div className="rounded-lg rounded-bl-sm border border-border-soft bg-card px-3 py-2 text-[12.5px] leading-[1.7] whitespace-pre-wrap">
                      {m.content ? <AnswerText text={m.content} /> : (m.reply?.degraded ? <span className="text-faint">{m.reply.degraded_reason}</span> : m.streaming ? <span className="text-faint">…</span> : '')}
                      {m.streaming && <span className="ml-0.5 inline-block h-3.5 w-[2px] animate-pulse bg-primary align-middle" />}
                    </div>
                    {!!m.steps?.length && (
                      <details className="text-[11px] text-faint">
                        <summary className="cursor-pointer select-none">工具调用 {m.reply?.tool_calls ?? m.steps.length} 次{m.reply?.steps_limit_reached ? '（步数触顶）' : ''}</summary>
                        <div className="mt-1 grid gap-1">
                          {m.steps.map((s, j) => (
                            <details key={j} className="rounded border border-border-soft bg-secondary/60 px-2 py-1">
                              <summary className="cursor-pointer select-none font-mono">
                                <span className="text-ghost">{String(s.step).padStart(2, '0')}</span> {s.tool}
                                {s.running && <span className="ml-1 animate-pulse text-primary">运行中…</span>}
                                {s.err && <span className="ml-1 text-destructive">失败</span>}
                                {!s.running && !s.err && s.result_bytes !== undefined && <span className="ml-1 text-ghost">{s.result_bytes}B</span>}
                              </summary>
                              {s.args && <div className="mt-0.5 break-all font-mono text-[10px] text-ghost" title={s.args}>args: {s.args.slice(0, 200)}</div>}
                              {s.err && <div className="text-destructive">{s.err}</div>}
                              {s.result_preview && <div className="mt-0.5 max-h-24 overflow-y-auto whitespace-pre-wrap font-mono text-[10.5px] text-muted-foreground">{s.result_preview}</div>}
                            </details>
                          ))}
                        </div>
                      </details>
                    )}
                    {m.reply && (
                      <>
                        <div className="flex gap-3 text-[10.5px] text-ghost">
                          <span>{m.reply.engine === 'llm' ? m.reply.model : '确定性/降级'}</span>
                          <span>{m.reply.latency_ms || 0}ms</span>
                        </div>
                        {!!m.reply.followups?.length && i === msgs.length - 1 && !busy && (
                          <div className="flex flex-wrap gap-1">
                            {m.reply.followups.map((f) => (
                              <button key={f} onClick={() => ask(f)}
                                className="cursor-pointer rounded-full border border-border-soft bg-secondary px-2 py-0.5 text-[11px] text-muted-foreground hover:border-border-strong hover:text-foreground">
                                {f}
                              </button>
                            ))}
                          </div>
                        )}
                      </>
                    )}
                  </div>
                )}
              </div>
            ))}
            {busy && thinking && (
              <div className="mr-4 rounded-md border border-border-soft bg-secondary/50 px-3 py-1.5 text-[11.5px] text-faint">
                <span className="animate-pulse">思考中…</span>
              </div>
            )}
          </div>

          <form onSubmit={(e) => { e.preventDefault(); ask(input); }}
            className="flex items-center gap-2 border-t border-border-soft p-2.5">
            <Input value={input} onChange={(e) => setInput(e.target.value)} maxLength={500}
              placeholder="问点什么…（Enter 发送）" className="h-9 flex-1" disabled={busy} />
            {busy ? (
              <Button type="button" variant="ghost" size="sm" onClick={stop} aria-label="停止生成" title="停止生成（保留已生成内容）">
                <Square size={12} />
              </Button>
            ) : (
              <Button type="submit" variant="primary" size="sm" disabled={!input.trim()} aria-label="发送">
                <Send size={12} />
              </Button>
            )}
          </form>
        </Card>
      )}
    </>
  );
}
