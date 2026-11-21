import { useEffect, useMemo, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Download, Rows3, Search, Sparkles, Sun, Keyboard, X, type LucideIcon } from 'lucide-react';
import { Kbd } from './ui/basics';
import { ROUTES } from './AppShell';
import { toggleDense, toggleTheme } from '../lib/theme';

interface Cmd { id: string; label: string; icon: LucideIcon; hint?: string; run: () => void }

export function CommandPalette({ open, setOpen, onExport, onShortcuts }: {
  open: boolean; setOpen: (v: boolean) => void; onExport: () => void; onShortcuts: () => void;
}) {
  const navigate = useNavigate();
  const [q, setQ] = useState('');
  const [sel, setSel] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);

  const commands: Cmd[] = useMemo(() => [
    // 导航命令直接复用侧边栏图标体系（宪法 §5：禁字符图标，一律 lucide）
    ...ROUTES.map((r) => ({ id: r.to, label: `前往${r.label}`, icon: r.icon, hint: r.label, run: () => navigate(r.to) })),
    { id: 'export', label: '导出当前视图 CSV', icon: Download, hint: '导出', run: () => onExport() },
    { id: 'dense', label: '切换紧凑视图', icon: Rows3, hint: '显示', run: () => toggleDense() },
    { id: 'theme', label: '切换亮 / 暗主题', icon: Sun, hint: '主题', run: () => toggleTheme() },
    { id: 'keys', label: '键盘快捷键帮助', icon: Keyboard, hint: '帮助', run: () => onShortcuts() },
    // 问 AI：经 zedr:ai-ask 事件打开助手并注入问题（助手自行走工具/流式管线）
    { id: 'ask-critical', label: '问 AI：现在最需要处理的告警是什么', icon: Sparkles, hint: 'AI', run: () => askAI('现在最需要处理的告警是什么？') },
    { id: 'ask-summary', label: '问 AI：总结今天的攻击面变化', icon: Sparkles, hint: 'AI', run: () => askAI('总结一下今天的攻击面变化') },
    { id: 'close', label: '关闭命令面板', icon: X, hint: 'Esc', run: () => setOpen(false) },
    { id: 'close', label: '关闭命令面板', icon: X, hint: 'Esc', run: () => setOpen(false) },
  ], [navigate, onExport, onShortcuts, setOpen]);

  const askAI = (text: string) => {
    setOpen(false);
    window.dispatchEvent(new CustomEvent('zedr:ai-ask', { detail: { text } }));
  };

  const filtered = useMemo(() => {
    const s = q.trim().toLowerCase();
    if (!s) return commands;
    return commands.filter((c) => c.label.toLowerCase().includes(s) || (c.hint || '').toLowerCase().includes(s));
  }, [q, commands]);

  useEffect(() => {
    if (open) {
      setQ(''); setSel(0);
      requestAnimationFrame(() => inputRef.current?.focus());
    }
  }, [open]);

  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') { e.preventDefault(); setOpen(false); }
      else if (e.key === 'ArrowDown') { e.preventDefault(); setSel((s) => Math.min(s + 1, filtered.length - 1)); }
      else if (e.key === 'ArrowUp') { e.preventDefault(); setSel((s) => Math.max(s - 1, 0)); }
      else if (e.key === 'Enter') {
        e.preventDefault();
        filtered[sel]?.run();
        setOpen(false);
      }
    };
    document.addEventListener('keydown', onKey);
    return () => document.removeEventListener('keydown', onKey);
  }, [open, filtered, sel, setOpen]);

  if (!open) return null;

  return (
    <div className="fixed inset-0 z-150 flex items-start justify-center bg-[#04070d]/65 pt-[14vh] backdrop-blur-[3px] light:bg-[#0f1a2e]/40" style={{ animation: 'mask-in 250ms cubic-bezier(.22,1,.36,1)' }} onClick={() => setOpen(false)}>
      <div
        className="w-[min(560px,92vw)] overflow-hidden rounded-lg border border-border-strong bg-card shadow-2xl"
        style={{ animation: 'pop-in 250ms cubic-bezier(.22,1,.36,1)' }}
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center gap-2.5 border-b border-border-soft px-4">
          <Search size={15} className="shrink-0 text-ghost" />
          <input
            ref={inputRef}
            value={q}
            onChange={(e) => { setQ(e.target.value); setSel(0); }}
            placeholder="跳转页面、执行操作…（支持：告警 / 主机 / 狩猎 / 矩阵 / 导出）"
            className="h-12 w-full border-0 bg-transparent text-[14.5px] text-foreground outline-none placeholder:text-ghost"
          />
        </div>
        <div className="max-h-[340px] overflow-y-auto p-1.5">
          {filtered.map((c, i) => (
            <button
              key={c.id}
              onClick={() => { c.run(); setOpen(false); }}
              onMouseEnter={() => setSel(i)}
              className={`flex w-full cursor-pointer items-center gap-2.5 rounded-[7px] border-0 px-3 py-2 text-left text-[13px] ${i === sel ? 'bg-brand-soft text-foreground' : 'bg-transparent text-foreground'}`}
            >
              <span className={`flex w-5 shrink-0 justify-center ${i === sel ? 'text-primary' : 'text-faint'}`}>
                <c.icon size={15} strokeWidth={1.7} />
              </span>
              <span>{c.label}</span>
              {c.hint && <span className="ml-auto rounded border border-border-soft px-1.5 py-px text-[11px] text-ghost">{c.hint}</span>}
            </button>
          ))}
          {!filtered.length && <div className="px-4 py-4 text-[13px] text-faint">没有匹配的命令，换个关键词试试</div>}
        </div>
        <div className="flex gap-3.5 border-t border-border-soft px-3.5 py-2 text-[11px] text-ghost">
          <span className="flex items-center gap-1"><Kbd>↑</Kbd><Kbd>↓</Kbd> 选择</span>
          <span className="flex items-center gap-1"><Kbd>Enter</Kbd> 执行</span>
          <span className="flex items-center gap-1"><Kbd>Esc</Kbd> 关闭</span>
        </div>
      </div>
    </div>
  );
}
