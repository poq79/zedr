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

/* ================= 实时隧道（docs/LIVE-TUNNEL.md §5.1） =================
   与上面 request() 的差异：隧道 503 tunnel_not_connected / 429 探针忙是
   即时确定性状态，5xx 退避重试只会把"未连接"的呈现拖慢近 2 秒，故不复用
   GET 重试循环；401 刷新重放语义保留。fs/read 为字节流直通（响应不包
   {data}，元数据在 X-HG-File-Size / X-HG-Truncated 头），用带 Authorization
   的 fetch 取 blob——不做下载，消费面只有文本预览。 */

/** 规范错误解析（与 request 内部逻辑一致；单独成函数避免动既有代码路径） */
async function liveError(res: Response): Promise<ApiError> {
  const data = await res.json().catch(() => null);
  const err = (data && (data.error ?? data)) || {};
  const code = typeof err === 'object' ? (err.code as string) || `http_${res.status}` : `http_${res.status}`;
  const msg = typeof err === 'object' ? (err.message as string) || CODE_TEXT[code] || `请求失败 (${res.status})` : String(err);
  return new ApiError(code, msg, res.status, typeof err === 'object' ? err.request_id : undefined);
}

async function liveJSON<T>(path: string, retried = false): Promise<T> {
  const headers: Record<string, string> = { Accept: 'application/json' };
  if (auth.token) headers.Authorization = `Bearer ${auth.token}`;
  let res: Response;
  try {
    res = await fetch(path, { headers, credentials: 'same-origin' });
  } catch {
    throw new ApiError('offline', '无法连接服务端，请检查网络或服务进程是否运行', 0);
  }
  if (res.status === 401 && !retried) {
    if (await tryRefresh()) return liveJSON<T>(path, true);
    throw new ApiError('unauthenticated', CODE_TEXT.unauthenticated, 401);
  }
  if (!res.ok) throw await liveError(res);
  const data = await res.json().catch(() => null);
  return (data && Object.prototype.hasOwnProperty.call(data, 'data') ? data.data : data) as T;
}

export interface LiveReadResult { blob: Blob; contentType: string; size: number; truncated: boolean }

/** fs/read：字节流直通，按 Content-Type 判文本由调用方决定 */
async function liveRead(path: string): Promise<LiveReadResult> {
  const headers: Record<string, string> = {};
  if (auth.token) headers.Authorization = `Bearer ${auth.token}`;
  let res: Response;
  try {
    res = await fetch(path, { headers, credentials: 'same-origin' });
  } catch {
    throw new ApiError('offline', '无法连接服务端，请检查网络或服务进程是否运行', 0);
  }
  if (res.status === 401) {
    if (await tryRefresh()) {
      const retryHeaders: Record<string, string> = {};
      if (auth.token) retryHeaders.Authorization = `Bearer ${auth.token}`;
      res = await fetch(path, { headers: retryHeaders, credentials: 'same-origin' });
    } else {
      throw new ApiError('unauthenticated', CODE_TEXT.unauthenticated, 401);
    }
  }
  if (!res.ok) throw await liveError(res);
  return {
    blob: await res.blob(),
    contentType: res.headers.get('Content-Type') || '',
    size: Number(res.headers.get('X-HG-File-Size')) || 0,
    // 探针侧发 "1"/"0"（liveapi/fs.go），契约文本为布尔——两种形态都认
    truncated: ['1', 'true'].includes((res.headers.get('X-HG-Truncated') || '').toLowerCase()),
  };
}

/** 实时查询系列：路径与错误码以 LIVE-TUNNEL.md §5.1 为准 */
export const live = {
  /** 目录列表；cursor 缺省 = 第一页，next_cursor 为空 = 结尾 */
  fs: (agentId: string, path: string, cursor?: string) =>
    liveJSON<import('./types').LiveFsList>(
      `/api/v1/hosts/${encodeURIComponent(agentId)}/live/fs?path=${encodeURIComponent(path)}${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ''}`,
    ),
  /** 文件内容读取（默认 64KB 预览预算，服务端/探针双侧钳制 ≤512KB） */
  read: (agentId: string, path: string, limit = 64 * 1024) =>
    liveRead(`/api/v1/hosts/${encodeURIComponent(agentId)}/live/fs/read?path=${encodeURIComponent(path)}&limit=${limit}`),
  /** SHA256 + Authenticode 现场计算 */
  hash: (agentId: string, path: string) =>
    liveJSON<import('./types').LiveHash>(`/api/v1/hosts/${encodeURIComponent(agentId)}/live/fs/hash?path=${encodeURIComponent(path)}`),
};

/** 隧道错误分类：供 UI 层映射专用状态（状态条/Toast/内联说明） */
export function liveErrorKind(e: unknown): 'tunnel' | 'busy' | 'off' | 'unsupported' | null {
  if (!(e instanceof ApiError)) return null;
  if (e.status === 503 && e.code === 'tunnel_not_connected') return 'tunnel';
  if (e.status === 429) return 'busy';
  if (e.status === 403) return 'off';
  if (e.status === 501) return 'unsupported';
  return null;
}
