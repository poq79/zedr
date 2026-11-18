/* AI 作用域上下文的统一入口：告警/主机/简报/调查报告等页面把
   "当前正在看的对象"裁剪摘要经 window 事件喂给悬浮助手。
   chip 行是审计面（发送前可见、可摘除），见 components/AiAssistant.tsx。 */

export function dispatchAIContext(text: string, open = true) {
  window.dispatchEvent(new CustomEvent('zedr:ai-context', { detail: { text, open } }));
}

/* stripDSML 剥离泄漏进正文 content 的工具调用标记文本。
   形态实测（2026-11-19，方舟 deepseek-v4.1）：管道字符混用 ASCII | 与
   全角 ｜（同一回答内先后出现），任何单一"块正则"都会被非规整边界漏掉
   ——与服务端 sanitizeDSML（internal/ai/agent.go）同一行集合算法：
   收集含 DSML 的行、保留首行标记前正文前缀与末行之后的内容、中间行吸收。
   渲染层兜底清洗历史会话残留 + 流式期间的临时脏段。 */
export function stripDSML(s: string): string {
  if (!s.includes('DSML')) return s;
  const lines = s.split('\n');
  let first = -1;
  let last = -1;
  lines.forEach((ln, i) => {
    if (ln.includes('DSML')) {
      if (first < 0) first = i;
      last = i;
    }
  });
  if (first < 0) return s;
  const head = lines[first].split('<')[0];
  const out = lines.slice(0, first);
  if (head.trim() !== '') out.push(head);
  if (last + 1 < lines.length) out.push(...lines.slice(last + 1));
  return out.join('\n').trim();
}
