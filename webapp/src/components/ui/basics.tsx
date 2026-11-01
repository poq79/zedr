import { forwardRef, type ButtonHTMLAttributes, type InputHTMLAttributes, type ReactNode, type SelectHTMLAttributes } from 'react';
import { cn } from '../../lib/utils';

/* ---------------- Button ---------------- */
type Variant = 'primary' | 'default' | 'ghost' | 'danger';
type Size = 'sm' | 'md' | 'icon';

const btnVariants: Record<Variant, string> = {
  primary: 'bg-primary text-primary-foreground font-semibold hover:brightness-110 border border-primary',
  default: 'bg-secondary text-foreground border border-border hover:bg-accent hover:border-border-strong',
  ghost: 'bg-transparent border border-transparent hover:bg-accent',
  danger: 'bg-destructive-soft text-destructive border border-destructive/30 hover:bg-destructive/20',
};
const btnSizes: Record<Size, string> = {
  sm: 'h-7 px-2.5 text-[11.5px] gap-1.5',
  md: 'h-8.5 px-3.5 text-[12.5px] gap-1.5',
  icon: 'h-8 w-8 justify-center',
};

export interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: Variant;
  size?: Size;
}

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, variant = 'default', size = 'md', ...props }, ref) => (
    <button
      ref={ref}
      className={cn(
        'inline-flex items-center justify-center rounded-[7px] transition-all duration-150 select-none',
        'active:translate-y-px disabled:opacity-50 disabled:pointer-events-none cursor-pointer',
        btnVariants[variant], btnSizes[size], className,
      )}
      {...props}
    />
  ),
);
Button.displayName = 'Button';

/* ---------------- Badge ---------------- */
const badgeTones: Record<string, string> = {
  critical: 'bg-crit-soft text-crit border-crit/30',
  high: 'bg-destructive-soft text-destructive border-destructive/25',
  medium: 'bg-warn-soft text-warn border-warn/25',
  low: 'bg-secondary text-muted-foreground border-border',
  info: 'bg-brand-soft text-primary border-primary/25',
  open: 'bg-brand-soft text-primary border-primary/25',
  acknowledged: 'bg-warn-soft text-warn border-warn/25',
  resolved: 'bg-ok-soft text-ok border-ok/25',
  false_positive: 'bg-secondary text-muted-foreground border-border',
  malicious: 'bg-crit-soft text-crit border-crit/30',
  suspicious: 'bg-warn-soft text-warn border-warn/25',
  safe: 'bg-ok-soft text-ok border-ok/25',
  online: 'bg-ok-soft text-ok border-ok/25',
  offline: 'bg-secondary text-muted-foreground border-border',
  neutral: 'bg-secondary text-muted-foreground border-border',
};

export function Badge({ tone = 'neutral', className, children, title }: { tone?: string; className?: string; children: ReactNode; title?: string }) {
  return (
    <span title={title} className={cn(
      'inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-[11.5px] font-semibold whitespace-nowrap',
      badgeTones[tone] || badgeTones.neutral, className,
    )}>
      {children}
    </span>
  );
}

/* ---------------- Card ---------------- */
export function Card({ className, children, style }: { className?: string; children: ReactNode; style?: React.CSSProperties }) {
  return (
    <div style={style} className={cn(
      // 纯平面板：发丝线定边界，不叠阴影/渐变层——层次靠面层色阶，不靠投影
      'rounded-md border border-border-soft bg-card',
      className,
    )}>
      {children}
    </div>
  );
}

export function CardTitle({ className, children }: { className?: string; children: ReactNode }) {
  return (
    <h3 className={cn('text-xs font-semibold uppercase tracking-[.05em] text-muted-foreground', className)}>
      {children}
    </h3>
  );
}

/* ---------------- Input / Select ---------------- */
export const Input = forwardRef<HTMLInputElement, InputHTMLAttributes<HTMLInputElement>>(
  ({ className, ...props }, ref) => (
    <input
      ref={ref}
      className={cn(
        'h-8.5 rounded-[7px] border border-input bg-card px-3 text-[13px] text-foreground',
        'outline-none transition-colors placeholder:text-ghost',
        'focus:border-primary focus:ring-3 focus:ring-brand-soft',
        className,
      )}
      {...props}
    />
  ),
);
Input.displayName = 'Input';

export const Select = forwardRef<HTMLSelectElement, SelectHTMLAttributes<HTMLSelectElement>>(
  ({ className, children, ...props }, ref) => (
    <select
      ref={ref}
      className={cn(
        'h-8.5 rounded-[7px] border border-input bg-card px-2.5 text-[13px] text-foreground',
        'outline-none transition-colors cursor-pointer focus:border-primary focus:ring-3 focus:ring-brand-soft',
        className,
      )}
      {...props}
    >
      {children}
    </select>
  ),
);
Select.displayName = 'Select';

/* ---------------- 空状态 ---------------- */
export function EmptyState({ icon, title, sub, tone = 'ok', action }: {
  icon: ReactNode; title: ReactNode; sub?: ReactNode; tone?: 'ok' | 'info' | 'warn'; action?: ReactNode;
}) {
  const tones = { ok: 'bg-ok-soft text-ok', info: 'bg-brand-soft text-primary', warn: 'bg-warn-soft text-warn' };
  return (
    <div className="px-5 py-11 text-center">
      <div className={cn('mx-auto mb-3.5 grid h-10 w-10 place-items-center rounded-xl', tones[tone])}>{icon}</div>
      <div className="mb-1.5 text-[13.5px] font-semibold text-muted-foreground">{title}</div>
      {sub && <div className="mx-auto max-w-[440px] text-xs leading-[1.8] text-faint">{sub}</div>}
      {action && <div className="mt-4">{action}</div>}
    </div>
  );
}

/* ---------------- 骨架 ---------------- */
export function Skeleton({ className, style }: { className?: string; style?: React.CSSProperties }) {
  return (
    <span
      className={cn('inline-block h-3 rounded-md bg-gradient-to-r from-secondary via-accent to-secondary bg-[length:200%_100%]', className)}
      style={{ animation: 'skel 1.3s ease infinite', ...style }}
    />
  );
}

export function SkeletonRows({ rows = 6 }: { rows?: number }) {
  const widths = [38, 92, 66, 50, 74, 58];
  return (
    <div className="py-1.5">
      {Array.from({ length: rows }, (_, i) => (
        <div key={i} className="flex items-center gap-3 px-3.5 py-2.5 [&+&]:border-t [&+&]:border-border-soft">
          <Skeleton style={{ width: `${widths[i % widths.length]}%` }} />
          <Skeleton style={{ width: `${widths[(i + 1) % widths.length]}%`, animationDelay: '.12s' }} />
          <Skeleton style={{ width: '14%', animationDelay: '.24s' }} />
        </div>
      ))}
    </div>
  );
}

/* ---------------- Kbd ---------------- */
export function Kbd({ children }: { children: ReactNode }) {
  return (
    <kbd className="inline-block min-w-5 border border-border bg-card px-1 py-0.5 text-center font-mono text-[11px] text-muted-foreground shadow-[0_2px_0_var(--border)] rounded-[5px]">
      {children}
    </kbd>
  );
}
