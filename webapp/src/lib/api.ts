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
  /** 带鉴权的二进制下载（部署包等 attachment 端点）：走 liveRead 同款
      401 刷新重放，返回 blob 由调用方触发浏览器保存。 */
  download: (p: string) => liveRead(p).then((r) => r.blob),
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
   {data}，元数据在 X-ZEDR-File-Size / X-ZEDR-Truncated 头），用带 Authorization
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
    size: Number(res.headers.get('X-ZEDR-File-Size')) || 0,
    // 探针侧发 "1"/"0"（liveapi/fs.go），契约文本为布尔——两种形态都认
    truncated: ['1', 'true'].includes((res.headers.get('X-ZEDR-Truncated') || '').toLowerCase()),
  };
}

/** 实时查询系列：路径与错误码以 LIVE-TUNNEL.md §5.1 / §11.3 为准 */
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

  /* ---- v2 增量（LIVE-TUNNEL.md §11）---- */
  /** 文件元数据（跨 Tab 以路径打开抽屉前先取） */
  stat: (agentId: string, path: string) =>
    liveJSON<import('./types').LiveStat>(`/api/v1/hosts/${encodeURIComponent(agentId)}/live/fs/stat?path=${encodeURIComponent(path)}`),
  /** 实时进程表（state.ProcRow） */
  processes: (agentId: string, limit = 2000) =>
    liveJSON<import('./types').LiveProcList>(`/api/v1/hosts/${encodeURIComponent(agentId)}/live/processes?limit=${limit}`),
  /** 实时连接表（v2 富化行：归属进程 + 内外网分类 + exited 信号） */
  netstat: (agentId: string) =>
    liveJSON<import('./types').LiveNetList>(`/api/v1/hosts/${encodeURIComponent(agentId)}/live/netstat`),
  /** 进程详情：模块/未签名计数/可执行速览/该 PID 连接（交叉动线中枢） */
  procinfo: (agentId: string, pid: number) =>
    liveJSON<import('./types').LiveProcInfo>(`/api/v1/hosts/${encodeURIComponent(agentId)}/live/procinfo?pid=${pid}`),
  /** 目录限深搜索（depth ≤4 默认 2，limit ≤200 默认 100，通配 *?） */
  search: (agentId: string, path: string, pattern: string, depth = 2, limit = 100) =>
    liveJSON<import('./types').LiveSearchResult>(
      `/api/v1/hosts/${encodeURIComponent(agentId)}/live/fs/search?path=${encodeURIComponent(path)}&pattern=${encodeURIComponent(pattern)}&depth=${depth}&limit=${limit}`,
    ),
  /** 二进制深度分析（≤64MB，PE 解析有成本——按需调用） */
  analyze: (agentId: string, path: string) =>
    liveJSON<import('./types').LiveAnalyze>(`/api/v1/hosts/${encodeURIComponent(agentId)}/live/analyze?path=${encodeURIComponent(path)}`),
  /** NTFS 备用数据流 + MotW 下载来源 */
  ads: (agentId: string, path: string) =>
    liveJSON<import('./types').LiveAds>(`/api/v1/hosts/${encodeURIComponent(agentId)}/live/ads?path=${encodeURIComponent(path)}`),
  /** 探针实时运行时（主机详情探针状态行轮询用） */
  info: (agentId: string) =>
    liveJSON<import('./types').LiveInfo>(`/api/v1/hosts/${encodeURIComponent(agentId)}/live/info`),
  /** 资产侦查（LIVE-TUNNEL §12）：六类资产 + 暴露面；probe=false 仅被动采集 */
  recon: (agentId: string, opts: { categories?: string[]; probe?: boolean } = {}) => {
    const q: string[] = [];
    // categories 来自固定白名单（web/ai/db/remote/dev/virt），无需额外编码
    if (opts.categories && opts.categories.length) q.push(`categories=${opts.categories.join(',')}`);
    if (opts.probe !== undefined) q.push(`probe=${opts.probe ? '1' : '0'}`);
    return liveJSON<import('./types').ReconResult>(
      `/api/v1/hosts/${encodeURIComponent(agentId)}/live/recon${q.length ? `?${q.join('&')}` : ''}`,
    );
  },

  /* ---- 主机详情深化 v1（LIVE-TUNNEL.md §13，F5）---- */
  /** 安全基线：10 项注册表/系统状态只读检查（analyst+） */
  baseline: (agentId: string) =>
    liveJSON<import('./types').LiveBaseline>(
      `/api/v1/hosts/${encodeURIComponent(agentId)}/live/baseline`,
    ),
  /** 账户与会话：本地账户表 + 密码策略（analyst+） */
  accounts: (agentId: string) =>
    liveJSON<import('./types').LiveAccounts>(
      `/api/v1/hosts/${encodeURIComponent(agentId)}/live/accounts`,
    ),

  /* ---- 进程取证 v1（LIVE-TUNNEL.md §15，F8）----
     句柄/线程/内存枚举在探针侧有真实成本（全系统句柄表 + VirtualQueryEx
     循环），全部按需调用，不做打开抽屉即拉取。 */
  /** 句柄表：type 大小写不敏感（服务端过滤），limit 默认 1000 ≤5000 */
  handles: (agentId: string, pid: number, opts: { type?: string; limit?: number } = {}) => {
    const q = [`pid=${pid}`];
    if (opts.type) q.push(`type=${encodeURIComponent(opts.type)}`);
    if (opts.limit) q.push(`limit=${opts.limit}`);
    return liveJSON<import('./types').LiveHandleList>(
      `/api/v1/hosts/${encodeURIComponent(agentId)}/live/handles?${q.join('&')}`,
    );
  },
  /** 谁打开了这个文件：全系统 File 句柄扫描（部分覆盖，note 诚实标注） */
  handleowners: (agentId: string, path: string) =>
    liveJSON<import('./types').LiveHandleOwners>(
      `/api/v1/hosts/${encodeURIComponent(agentId)}/live/handleowners?path=${encodeURIComponent(path)}`,
    ),
  /** 线程枚举：in_anonymous_exec=true 为注入线索 */
  threads: (agentId: string, pid: number) =>
    liveJSON<import('./types').LiveThreads>(
      `/api/v1/hosts/${encodeURIComponent(agentId)}/live/threads?pid=${pid}`,
    ),
  /** 内存区域扫描：只出摘要（探针绝不回传内容；pid 0/4 由探针拒绝） */
  memscan: (agentId: string, pid: number) =>
    liveJSON<import('./types').LiveMemScan>(
      `/api/v1/hosts/${encodeURIComponent(agentId)}/live/memscan?pid=${pid}`,
    ),

  /* ---- 非进程域（LIVE-TUNNEL.md §16，F9）----
     均为探针侧只读聚合：persistence 复用服务/任务/启动项枚举，peers 聚合
     Netstat；老探针 501、老服务端预算表未收录 404，UI 统一提示版本不支持。 */
  /** 持久化总览：服务（auto/delayed-auto）+ 已启用任务 + 启动项（上限 2000） */
  persistence: (agentId: string) =>
    liveJSON<import('./types').LivePersistence>(
      `/api/v1/hosts/${encodeURIComponent(agentId)}/live/persistence`,
    ),
  /** 外联对端聚合：仅 ESTABLISHED，按远端 IP / 进程两种视角 */
  peers: (agentId: string) =>
    liveJSON<import('./types').LivePeers>(
      `/api/v1/hosts/${encodeURIComponent(agentId)}/live/peers`,
    ),
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
