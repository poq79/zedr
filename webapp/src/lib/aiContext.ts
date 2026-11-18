/* AI 作用域上下文的统一入口：告警/主机/简报/调查报告等页面把
   "当前正在看的对象"裁剪摘要经 window 事件喂给悬浮助手。
   chip 行是审计面（发送前可见、可摘除），见 components/AiAssistant.tsx。 */

export function dispatchAIContext(text: string, open = true) {
  window.dispatchEvent(new CustomEvent('zedr:ai-context', { detail: { text, open } }));
}

// stripDSML 剥离 DeepSeek v4.1 流式输出混入的工具调用标记块
// （2026-11-09 实测：answer 已在服务端净化，thinking/历史会话残留
// 由渲染层兜底清洗——思考链本质是推理过程，不该让用户看到标记）。
export function stripDSML(s: string): string {
  if (!s.includes('DSML')) return s;
  return s
    .replace(/^[ \t]*<\|DSML\|.*?\|>[ \t]*\\n?/gm, '')
    .replace(/<\|DSML\|.*?\|>/gs, '')
    .replace(/<\|\/?\s*\|?DSML\|?>/g, '')
    .trim();
}
