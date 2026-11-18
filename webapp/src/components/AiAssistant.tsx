import { useCallback, useEffect, useRef, useState } from 'react';
import { Eraser, Plus, Send, Square, X } from 'lucide-react';
import { api, authHeaders } from '../lib/api';
import { stripDSML } from '../lib/aiContext';
import { Badge, Button, Card, Input, Select } from './ui/basics';
import { useToast } from './ui/overlays';

/* 全局 AI 助手 2.1：流式对话 + 作用域上下文（chip 可摘除）+ 多会话。
   纪律与 Agent 调查同源：只读工具、每一步可见、无模型时诚实降级。
   作用域对话（2026-11-11 定向调研）：告警/主机详情"问 AI"入口经
   window 事件注入"当前正在看的对象"裁剪摘要——chip 行是审计面
   （发送前可见、可逐个摘除），scope 注入到本轮消息尾部紧贴问题
   （防 lost in the middle），并随消息固化进会话历史。 */

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
  scope?: string; // 发送时固化的上下文快照（回看历史仍锚定当时对象）
  streaming?: boolean;
}
interface Session {
  id: string; name: string; updated: number; msgs: Msg[];
}

const LS_KEY = 'zedr_ai_sessions_v1';
const CONTEXT_EVENT = 'zedr:ai-context';

// 快捷动作库（Purple AI Quick Starts 同款）：空态给方向，不用猜第一句
const STARTERS = [
  '现在最需要处理的告警是什么？',
  '过去 24 小时有没有疑似暴破成功的登录？',
  '哪台主机最近新增了自启动项？',
  '总结一下今天的攻击面变化',
  '当前 AI 引擎和预算状态如何？',
  '最新的 critical 告警里有没有同哈希跨主机？',
];

// "/" 斜杠命令候选：与快捷动作同源（快捷动作的输入栏入口）。
// 刻意不做宏替换——选中后整句填充，发送前仍可编辑（发送前可见）。
const SLASH_CMDS = STARTERS;

/* ---- 助手标识「哨兵脉冲」（2026-11-14，用户裁决空态要有标志性动效）----
   四点星核=助手本体（几何 SVG 重绘，替代 FAB 时代的字符 ✦——顺手修复
   UI-DESIGN §5 禁字符图标）；外扩方环=检测信号外扩（EDR 语境，Carbon 几何
   语言不用圆环堆叠）；边界框+方位刻度=主机取景框。动效语义：环外扩节奏
   即助手状态——在场（慢）与工作中（快），非装饰动效。色彩全走
   currentColor/主色变量（零新色相，双主题自适应），reduced-motion 由
   index.css 全局块降级为静态标。 */
function AssistantMark({ size = 44, busy = false, still = false }: { size?: number; busy?: boolean; still?: boolean }) {
  const detail = size >= 32;
  return (
    <svg className="asst-mark" data-busy={busy || undefined} width={size} height={size} viewBox="0 0 48 48" fill="none" aria-hidden="true">
      {!still && (
        <>
          <rect className="am-ping" x="9" y="9" width="30" height="30" rx="8" style={{ stroke: 'var(--primary)' }} strokeWidth="1" />
          <rect className="am-ping am-ping2" x="9" y="9" width="30" height="30" rx="8" style={{ stroke: 'var(--primary)' }} strokeWidth="1" />
        </>
      )}
      <rect x="7.5" y="7.5" width="33" height="33" rx="7" style={{ stroke: 'var(--border-strong)' }} strokeWidth="1.25" />
      {detail && (
        <g style={{ stroke: 'var(--faint)' }} strokeWidth="1.25">
          <line x1="24" y1="4.5" x2="24" y2="9.5" /><line x1="24" y1="38.5" x2="24" y2="43.5" />
          <line x1="4.5" y1="24" x2="9.5" y2="24" /><line x1="38.5" y1="24" x2="43.5" y2="24" />
        </g>
      )}
      <path className="am-core"
        d="M24 13.5C25.2 20.3 27.7 22.8 34.5 24C27.7 25.2 25.2 27.7 24 34.5C22.8 27.7 20.3 25.2 13.5 24C20.3 22.8 22.8 20.3 24 13.5Z"
        style={{ fill: 'currentColor' }} />
    </svg>
  );
}

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

function newSession(): Session {
  return { id: `s${Date.now()}${Math.floor(Math.random() * 1000)}`, name: '新会话', updated: Date.now(), msgs: [] };
}

function loadSessions(): { list: Session[]; active: string } {
  try {
    const raw = localStorage.getItem(LS_KEY);
    if (raw) {
      const list = JSON.parse(raw) as Session[];
      if (list.length) {
        list.sort((a, b) => b.updated - a.updated);
        return { list: list.slice(0, 20), active: list[0].id };
      }
    }
  } catch { /* 损坏即重置——对话历史不是关键数据 */ }
  const s = newSession();
  return { list: [s], active: s.id };
}

export function AiAssistant() {
  const toast = useToast();
  const [open, setOpen] = useState(false);
  const [input, setInput] = useState('');
  const [busy, setBusy] = useState(false);
  const [thinking, setThinking] = useState(false);
  // 初始化只跑一次 loadSessions：内部会生成新会话，两次调用会拿到
  // 两个不同 id，activeId 与列表永不匹配（本轮实测踩过）
  const [boot] = useState(() => loadSessions());
  const [sessions, setSessions] = useState<Session[]>(boot.list);
  const [activeId, setActiveId] = useState<string>(boot.active);
  const [scope, setScope] = useState(''); // 待发送的上下文 chip（可摘除）
  const [lastEngine, setLastEngine] = useState<string>('');
  const [slashOpen, setSlashOpen] = useState(false);
  const listRef = useRef<HTMLDivElement>(null);
  const abortRef = useRef<AbortController | null>(null);
  const busyRef = useRef(false);

  const active = sessions.find((s) => s.id === activeId) || sessions[0];
  const slashCandidates = SLASH_CMDS.filter((c) => c.toLowerCase().includes(input.replace(/^\/+/, '').toLowerCase())).slice(0, 6);
  const msgs = active?.msgs || [];

  useEffect(() => {
    // 持久化：strip streaming 标记后落 localStorage，刷新不丢
    try {
      const clean = sessions.map((s) => ({
        ...s, updated: s.id === activeId ? Date.now() : s.updated,
        msgs: s.msgs.slice(-60).map((m) => ({ ...m, streaming: false, thinking: m.thinking ? stripDSML(m.thinking) : undefined })),
      }));
      localStorage.setItem(LS_KEY, JSON.stringify(clean.slice(0, 20)));
    } catch { /* 配额满等静默放弃 */ }
  }, [sessions, activeId]);

  useEffect(() => {
    api.get<{ stats?: { engine?: string } }>('/api/v1/ai/stats')
      .then((r) => setLastEngine(r.stats?.engine || 'heuristic')).catch(() => {});
  }, [open]);

  // 作用域上下文入口：告警/主机详情的"问 AI"按钮与总览简报的
  // "让 AI 解读"经 window 事件注入。chip 常驻输入栏上方，可摘除。
  useEffect(() => {
    const onCtx = (e: Event) => {
      const d = (e as CustomEvent<{ text: string; open?: boolean }>).detail;
      if (!d?.text) return;
      setScope(d.text);
      if (d.open) setOpen(true);
    };
    window.addEventListener(CONTEXT_EVENT, onCtx);
    return () => window.removeEventListener(CONTEXT_EVENT, onCtx);
  }, []);

  useEffect(() => {
    listRef.current?.scrollTo({ top: listRef.current.scrollHeight, behavior: 'smooth' });
  }, [msgs, busy, thinking]);

  const updateActive = (fn: (s: Session) => Session) =>
    setSessions((prev) => prev.map((s) => (s.id === activeId ? fn(s) : s)));

  const patchLast = (fn: (m: Msg) => Msg) =>
    updateActive((s) => {
      if (!s.msgs.length || s.msgs[s.msgs.length - 1].role !== 'assistant') return s;
      return { ...s, msgs: [...s.msgs.slice(0, -1), fn(s.msgs[s.msgs.length - 1])] };
    });

  const finalizeLast = (rep: ChatReply) =>
    updateActive((s) => {
      if (!s.msgs.length || s.msgs[s.msgs.length - 1].role !== 'assistant') return s;
      const cur = s.msgs[s.msgs.length - 1];
      return { ...s, msgs: [...s.msgs.slice(0, -1), { ...cur, streaming: false, content: rep.answer || cur.content, reply: rep }] };
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
    if (!q || busyRef.current) return;
    busyRef.current = true;
    setBusy(true);
    setThinking(false);
    const usedScope = scope; // 固化进消息记录（回看历史仍锚定当时对象）
    const history = msgs.slice(-6).map((m) => ({ role: m.role, content: m.content }));
    updateActive((s) => {
      // 首条用户消息命名会话（截 18 字）
      const name = s.name === '新会话' && !s.msgs.length ? (q.length > 18 ? q.slice(0, 18) + '…' : q) : s.name;
      return { ...s, name, msgs: [...s.msgs, { role: 'user', content: q, scope: usedScope || undefined }, { role: 'assistant', content: '', streaming: true, steps: [] }] };
    });
    setInput('');
    const ac = new AbortController();
    abortRef.current = ac;
    try {
      const res = await fetch('/api/v1/ai/chat/stream', {
        method: 'POST',
        headers: authHeaders('text/event-stream'),
        credentials: 'same-origin',
        body: JSON.stringify({ question: q, scope: usedScope, history }),
        signal: ac.signal,
      });
      if (!res.ok || !res.body) throw new Error('stream unavailable');
      const reader = res.body.getReader();
      const decoder = new TextDecoder();
      let buffer = '';
      let sawDone = false;
      const handle = (frame: string) => {
        let event = 'message';
        const dataLines: string[] = [];
        for (const line of frame.split('\n')) {
          if (line.startsWith('event:')) event = line.slice(6).trim();
          else if (line.startsWith('data:')) dataLines.push(line.slice(5).trim());
        }
        if (!dataLines.length) return;
        let ev: { [k: string]: unknown } | null = null;
        try { ev = JSON.parse(dataLines.join('\n')); } catch { return; }
        if (!ev) return;
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
      };
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });
        let idx: number;
        while ((idx = buffer.indexOf('\n\n')) >= 0) {
          handle(buffer.slice(0, idx));
          buffer = buffer.slice(idx + 2);
        }
      }
      if (!sawDone) {
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
      busyRef.current = false;
    }
  }, [busy, msgs, scope, toast]);

  const createSession = () => {
    const s = newSession();
    setSessions((prev) => [s, ...prev].slice(0, 20));
    setActiveId(s.id);
  };

  return (
    <>
      {!open && (
        <button onClick={() => setOpen(true)} aria-label="打开 AI 助手"
          className="fixed bottom-5 right-5 z-40 grid h-11 w-11 cursor-pointer place-items-center rounded-full border border-primary/30 bg-primary text-primary-foreground shadow-lg transition-transform hover:scale-105">
          <AssistantMark size={22} still />
        </button>
      )}
      {open && (
        <Card className="fixed bottom-5 right-5 z-40 flex h-[580px] w-[420px] flex-col overflow-hidden p-0 shadow-2xl">
          <div className="flex items-center gap-2 border-b border-border-soft px-3 py-2.5">
            <span className="grid shrink-0 place-items-center text-primary"><AssistantMark size={16} still /></span>
            <Select value={activeId} onChange={(e) => setActiveId(e.target.value)} aria-label="切换会话"
              className="h-7 max-w-[150px] flex-1 text-[11.5px]">
              {sessions.map((s) => <option key={s.id} value={s.id}>{s.name}</option>)}
            </Select>
            <button onClick={createSession} aria-label="新建会话" title="新建会话"
              className="cursor-pointer rounded p-1 text-faint hover:bg-secondary hover:text-foreground"><Plus size={14} /></button>
            <button onClick={() => { if (!busy && msgs.length) { updateActive((s) => ({ ...s, msgs: [] })); toast('会话已清空'); } }}
              disabled={busy || !msgs.length} aria-label="清空当前会话" title="清空当前会话"
              className="cursor-pointer rounded p-1 text-faint hover:bg-secondary hover:text-foreground disabled:opacity-40"><Eraser size={14} /></button>
            <Badge tone={lastEngine === 'llm' ? 'resolved' : 'info'}>
              {lastEngine === 'llm' ? '模型引擎' : '未配置模型'}
            </Badge>
            <button onClick={() => setOpen(false)} aria-label="关闭"
              className="cursor-pointer rounded p-1 text-faint hover:bg-secondary hover:text-foreground"><X size={14} /></button>
          </div>

          <div ref={listRef} className="flex-1 space-y-2.5 overflow-y-auto px-3.5 py-3">
            {msgs.length === 0 && (
              <div className="space-y-2">
                <div className="anim-pop grid place-items-center pb-0.5 pt-5 text-primary">
                  <AssistantMark size={52} />
                </div>
                <p className="text-[12px] leading-[1.7] text-faint">问平台里的事实（告警/事件/主机/情报/实时进程），需要时我会调用只读工具核实，每一步都实时可见。在告警或主机详情点「问 AI」会自动带上当前对象上下文。</p>
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
                  <div className="ml-10 rounded-lg rounded-br-sm bg-primary px-3 py-2 text-[12.5px] text-primary-foreground">
                    {m.content}
                    {m.scope && <div className="mt-1 text-[10px] opacity-70">（附带了当时页面的上下文）</div>}
                  </div>
                ) : (
                  <div className="mr-4 space-y-1.5">
                    {m.thinking && (
                      <details className="rounded-md border border-border-soft bg-secondary/50 px-2.5 py-1.5 text-[11px] text-faint">
                        <summary className="cursor-pointer select-none">思考过程</summary>
                        <div className="mt-1 max-h-32 overflow-y-auto whitespace-pre-wrap font-mono text-[10.5px] leading-[1.6]">{stripDSML(m.thinking)}</div>
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
              <div className="mr-4 flex items-center gap-2 rounded-md border border-border-soft bg-secondary/50 px-3 py-1.5 text-[11.5px] text-faint">
                <span className="grid shrink-0 place-items-center text-primary"><AssistantMark size={16} busy /></span>
                <span>思考中…</span>
              </div>
            )}
          </div>

          {/* 上下文 chip 行：发送前对"模型将看到什么"的审计面，可逐个摘除 */}
          {scope && (
            <div className="flex items-center gap-1.5 border-t border-border-soft px-3 py-1.5">
              <span className="rounded-full border border-primary/30 bg-brand-soft px-2 py-0.5 text-[11px] text-foreground">
                上下文：{scope.length > 26 ? scope.slice(0, 26) + '…' : scope}
                <button onClick={() => setScope('')} aria-label="移除上下文"
                  className="ml-1 cursor-pointer text-faint hover:text-destructive"><X size={10} className="inline" /></button>
              </span>
              <span className="text-[10px] text-faint">将随下一条消息发送</span>
            </div>
          )}

          {/* "/" 斜杠快捷命令（2026 对话标配：快捷动作的输入栏入口）：
              候选=快捷问题，选中整句填充而非宏替换，发送前仍可编辑 */}
          {slashOpen && slashCandidates.length > 0 && (
            <div className="border-t border-border-soft px-2.5 py-1.5">
              <div className="mb-1 text-[10px] font-semibold uppercase tracking-wide text-faint">快捷命令</div>
              <div className="grid gap-0.5">
                {slashCandidates.map((c) => (
                  <button key={c} type="button" onClick={() => { setInput(c); setSlashOpen(false); }}
                    className="cursor-pointer rounded px-2 py-1 text-left text-[12px] text-muted-foreground hover:bg-secondary hover:text-foreground">
                    {c}
                  </button>
                ))}
              </div>
            </div>
          )}

          <form onSubmit={(e) => { e.preventDefault(); ask(input); setSlashOpen(false); }}
            className="flex items-center gap-2 border-t border-border-soft p-2.5">
            <Input value={input} onChange={(e) => { setInput(e.target.value); setSlashOpen(e.target.value === '/' || e.target.value.startsWith('/ ')); }} maxLength={500}
              placeholder="问点什么…（输入 / 看快捷命令）" className="h-9 flex-1" disabled={busy} />
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
