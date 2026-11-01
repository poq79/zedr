import { useCallback, useState } from 'react';
import { ApiError } from './api';
import { EmptyState, Button } from '../components/ui/basics';
import { Inbox } from 'lucide-react';

/* 统一错误处理：unauthenticated → 广播给根组件回登录页；其余渲染错误卡片 */
export function useError() {
  const [err, setErr] = useState<ApiError | null>(null);

  const capture = useCallback((e: unknown) => {
    const ae = e instanceof ApiError ? e : new ApiError('internal_error', e instanceof Error ? e.message : String(e), 0);
    if (ae.code === 'unauthenticated') {
      window.dispatchEvent(new CustomEvent('hg-unauth'));
      return;
    }
    setErr(ae);
  }, []);

  const reset = useCallback(() => setErr(null), []);

  const rendered = err ? (
    <div className="rounded-md border border-border-soft bg-card">
      <EmptyState
        tone="warn"
        icon={<Inbox size={20} />}
        title={err.message}
        sub={<>可以稍后重试；若持续出现，请联系管理员检查服务端状态。{err.requestId && <><br />请求 ID：<code className="font-mono text-[11px] text-primary">{err.requestId}</code></>}</>}
        action={<Button size="sm" onClick={() => window.location.reload()}>重新加载</Button>}
      />
    </div>
  ) : null;

  return { capture, reset, err, rendered };
}
