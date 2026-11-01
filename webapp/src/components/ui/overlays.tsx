import { createContext, useCallback, useContext, useEffect, useRef, useState, type ReactNode } from 'react';
import { X, Check, CircleAlert, TriangleAlert } from 'lucide-react';
import { cn } from '../../lib/utils';
import { Button } from './basics';

/* ================= Drawer（右侧抽屉，进慢出快） ================= */

export function Drawer({ open, onClose, title, sub, foot, children, width = 780 }: {
  open: boolean; onClose: () => void; title: ReactNode; sub?: ReactNode;
  foot?: ReactNode; children: ReactNode; width?: number;
}) {
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose(); };
    document.addEventListener('keydown', onKey);
    return () => document.removeEventListener('keydown', onKey);
  }, [open, onClose]);

  return (
    <div className={cn('fixed inset-0 z-60', !open && 'pointer-events-none')} aria-hidden={!open}>
      <div
        className={cn('absolute inset-0 bg-[#04080f]/60 backdrop-blur-[2px] transition-opacity', 'duration-[350ms] ease-[cubic-bezier(.22,1,.36,1)]', open ? 'opacity-100' : 'opacity-0')}
        onClick={onClose}
      />
      <aside
        className={cn(
          'absolute top-0 right-0 bottom-0 flex flex-col border-l border-border bg-card shadow-2xl',
          'transition-transform duration-[400ms] ease-[cubic-bezier(.22,1,.36,1)]',
          !open && 'duration-[250ms]',
          open ? 'translate-x-0' : 'translate-x-[102%]',
        )}
        style={{ width: `min(${width}px, 94vw)` }}
      >
        <header className="flex items-start gap-3 border-b border-border px-5 py-4">
          <div className="min-w-0 flex-1">
            <h2 className="m-0 text-[15px] font-semibold">{title}</h2>
            {sub && <div className="mt-1.5 text-xs text-faint">{sub}</div>}
          </div>
          <Button variant="ghost" size="icon" onClick={onClose} aria-label="关闭详情" title="关闭（Esc）">
            <X size={16} strokeWidth={1.8} />
          </Button>
        </header>
        <div className="flex-1 overflow-y-auto px-5 py-4">{children}</div>
        {foot && <footer className="flex flex-wrap items-center gap-2 border-t border-border px-5 py-3">{foot}</footer>}
      </aside>
    </div>
  );
}

/* ================= Toast ================= */

type ToastKind = 'ok' | 'err' | 'warn';
interface ToastItem { id: number; kind: ToastKind; msg: string; out?: boolean }

const ToastCtx = createContext<(msg: string, kind?: ToastKind) => void>(() => {});
export const useToast = () => useContext(ToastCtx);

const toastIcons: Record<ToastKind, ReactNode> = {
  ok: <Check size={15} strokeWidth={2.2} />,
  err: <CircleAlert size={15} strokeWidth={2} />,
  warn: <TriangleAlert size={15} strokeWidth={2} />,
};
const toastTones: Record<ToastKind, string> = {
  ok: 'border-l-ok [&_.t-ico]:text-ok',
  err: 'border-l-destructive [&_.t-ico]:text-destructive',
  warn: 'border-l-warn [&_.t-ico]:text-warn',
};

export function ToastProvider({ children }: { children: ReactNode }) {
  const [items, setItems] = useState<ToastItem[]>([]);
  const seq = useRef(0);

  const push = useCallback((msg: string, kind: ToastKind = 'ok') => {
    const id = ++seq.current;
    setItems((arr) => [...arr, { id, kind, msg }]);
    setTimeout(() => setItems((arr) => arr.map((t) => (t.id === id ? { ...t, out: true } : t))), 3200);
    setTimeout(() => setItems((arr) => arr.filter((t) => t.id !== id)), 3650);
  }, []);

  return (
    <ToastCtx.Provider value={push}>
      {children}
      <div className="fixed right-5 bottom-5 z-200 flex flex-col gap-2">
        {items.map((t) => (
          <div
            key={t.id}
            className={cn(
              'pointer-events-auto flex max-w-[380px] items-start gap-2.5 rounded-[9px] border border-border border-l-3 bg-popover px-3.5 py-2.5',
              'text-[12.5px] shadow-lg transition-[opacity,transform,filter] duration-[250ms] ease-[cubic-bezier(.22,1,.36,1)]',
              toastTones[t.kind],
              (t.out) && 'translate-y-2 opacity-0 blur-[2px]',
            )}
            style={{ animation: 'page-in 350ms cubic-bezier(.22,1,.36,1)' }}
          >
            <span className="t-ico mt-px shrink-0">{toastIcons[t.kind]}</span>
            <span>{t.msg}</span>
          </div>
        ))}
      </div>
    </ToastCtx.Provider>
  );
}

/* ================= Confirm（替代原生 confirm） ================= */

interface ConfirmOpts { title?: string; message: ReactNode; danger?: boolean; okText?: string; cancelText?: string }

const ConfirmCtx = createContext<(o: ConfirmOpts) => Promise<boolean>>(async () => false);
export const useConfirm = () => useContext(ConfirmCtx);

export function ConfirmProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<(ConfirmOpts & { resolve: (v: boolean) => void }) | null>(null);

  const confirm = useCallback((o: ConfirmOpts) => new Promise<boolean>((resolve) => setState({ ...o, resolve })), []);

  const done = (v: boolean) => { state?.resolve(v); setState(null); };

  useEffect(() => {
    if (!state) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') done(false);
      else if (e.key === 'Enter') { e.preventDefault(); done(true); }
    };
    document.addEventListener('keydown', onKey);
    return () => document.removeEventListener('keydown', onKey);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [state]);

  return (
    <ConfirmCtx.Provider value={confirm}>
      {children}
      {state && (
        <div className="fixed inset-0 z-170 flex items-center justify-center bg-[#04070d]/60 backdrop-blur-[3px] light:bg-[#0f1a2e]/40" style={{ animation: 'mask-in 250ms cubic-bezier(.22,1,.36,1)' }} onClick={() => done(false)}>
          <div
            className="w-[min(420px,92vw)] rounded-lg border border-border-strong bg-card p-5 pb-4 shadow-2xl"
            style={{ animation: 'pop-in 250ms cubic-bezier(.22,1,.36,1)' }}
            role="alertdialog" aria-modal="true" onClick={(e) => e.stopPropagation()}
          >
            <div className={cn('mb-2.5 flex items-center gap-2.5 text-sm font-bold', state.danger ? 'text-destructive' : 'text-warn')}>
              {state.danger ? <CircleAlert size={18} strokeWidth={2} /> : <TriangleAlert size={18} strokeWidth={2} />}
              {state.title || '确认操作'}
            </div>
            <div className="text-[12.5px] leading-[1.8] break-all whitespace-pre-wrap text-muted-foreground">{state.message}</div>
            <div className="mt-4.5 flex justify-end gap-2">
              <Button onClick={() => done(false)}>{state.cancelText || '取消'}</Button>
              <Button autoFocus variant={state.danger ? 'danger' : 'primary'} onClick={() => done(true)}>
                {state.okText || '确认'}
              </Button>
            </div>
          </div>
        </div>
      )}
    </ConfirmCtx.Provider>
  );
}
