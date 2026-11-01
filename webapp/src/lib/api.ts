/* API 客户端：鉴权、401 刷新重放、5xx 退避重试、错误码中文化。
   从旧 vanilla 版移植，行为保持一致。 */

export class ApiError extends Error {
  code: string;
  status: number;
  requestId?: string;
  constructor(code: string, message: string, status: number, requestId?: string) {
    super(message);
    this.code = code;
    this.status = status;
    this.requestId = requestId;
  }
}

const CODE_TEXT: Record<string, string> = {
  invalid_argument: '提交的内容不合法',
  unauthenticated: '登录状态已失效，请重新登录',
  forbidden: '当前角色无权执行该操作',
  not_found: '目标对象不存在',
  conflict: '操作冲突，请刷新后重试',
  too_many_requests: '操作过于频繁，请稍后再试',
  unavailable: '服务暂不可用，请稍后重试',
  internal_error: '服务内部错误，请稍后重试或联系管理员',
};

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

interface TokenPair { token: string | null; exp: number }

const auth: TokenPair = { token: null, exp: 0 };

let refreshing: Promise<boolean> | null = null;

async function tryRefresh(): Promise<boolean> {
  if (refreshing) return refreshing;
  refreshing = (async () => {
    try {
      const res = await fetch('/api/v1/auth/refresh', { method: 'POST', credentials: 'same-origin' });
      if (!res.ok) return false;
      const data = await res.json();
      auth.token = data.access_token ?? null;
      auth.exp = Date.parse(data.expires_at) || 0;
      return !!auth.token;
    } catch {
      return false;
    } finally {
      setTimeout(() => { refreshing = null; }, 0);
    }
  })();
  return refreshing;
}

async function request<T>(path: string, opts: { method?: string; body?: unknown; retried?: boolean } = {}): Promise<T> {
  const method = opts.method || 'GET';
  const maxAttempts = method === 'GET' ? 4 : 1;
  let attempt = 0;

  while (true) {
    const headers: Record<string, string> = { Accept: 'application/json' };
    if (opts.body !== undefined) headers['Content-Type'] = 'application/json';
    if (auth.token) headers.Authorization = `Bearer ${auth.token}`;

    let res: Response;
    try {
      res = await fetch(path, {
        method, headers, credentials: 'same-origin',
        body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
      });
    } catch {
      if (attempt < maxAttempts - 1) { attempt++; await sleep(400 * attempt); continue; }
      throw new ApiError('offline', '无法连接服务端，请检查网络或服务进程是否运行', 0);
    }

    if (res.status === 401 && !opts.retried && !path.startsWith('/api/v1/auth/')) {
      const ok = await tryRefresh();
      if (ok) return request<T>(path, { ...opts, retried: true });
      throw new ApiError('unauthenticated', CODE_TEXT.unauthenticated, 401);
    }

    if (res.status >= 500 && attempt < maxAttempts - 1) {
      attempt++; await sleep(300 * attempt); continue;
    }

    if (res.status === 204) return undefined as T;

    const data = await res.json().catch(() => null);
    if (!res.ok) {
      const err = (data && (data.error ?? data)) || {};
      const code = typeof err === 'object' ? (err.code as string) || `http_${res.status}` : `http_${res.status}`;
      const msg = typeof err === 'object' ? (err.message as string) || CODE_TEXT[code] || `请求失败 (${res.status})` : String(err);
      throw new ApiError(code, msg, res.status, typeof err === 'object' ? err.request_id : undefined);
    }
    return (data && Object.prototype.hasOwnProperty.call(data, 'data') ? data.data : data) as T;
  }
}

async function login(username: string, password: string) {
  const res = await request<{ access_token: string; expires_at: string; user: import('./types').User }>(
    '/api/v1/auth/login', { method: 'POST', body: { username, password } },
  );
  auth.token = res.access_token;
  auth.exp = Date.parse(res.expires_at) || 0;
  return res.user;
}

async function logout() {
  try { await request('/api/v1/auth/logout', { method: 'POST', body: {} }); } catch { /* 尽力而为 */ }
  auth.token = null;
}

export const api = {
  get: <T>(p: string) => request<T>(p),
  post: <T>(p: string, body?: unknown) => request<T>(p, { method: 'POST', body }),
  put: <T>(p: string, body?: unknown) => request<T>(p, { method: 'PUT', body }),
  del: <T>(p: string) => request<T>(p, { method: 'DELETE' }),
  login, logout, tryRefresh,
  me: () => request<import('./types').User>('/api/v1/me'),
};

export function sseConnect(onEvent: (a: import('./types').Alert) => void): EventSource {
  const es = new EventSource('/api/v1/stream');
  es.addEventListener('alert', (ev) => {
    try { onEvent(JSON.parse((ev as MessageEvent).data)); } catch { /* 忽略坏帧 */ }
  });
  return es;
}
