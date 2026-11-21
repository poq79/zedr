/* 与 Go 端 domain 模型对齐的最小类型集 */

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type AlertStatus = 'open' | 'acknowledged' | 'resolved' | 'false_positive';
export type Verdict = 'malicious' | 'suspicious' | 'safe';
export type Role = 'admin' | 'analyst' | 'viewer';

export interface User { id: number; username: string; role: Role }

export interface Alert {
  id: string; /* 服务端生成的十六进制 ID（不是数字） */
  agent_id?: string;
  hostname: string;
  fingerprint?: string;
  pid: number;
  ppid?: number;
  process_name: string;
  image_path?: string;
  cmdline?: string;
  proc_user?: string;
  signer?: string;
  signed?: boolean;
  title: string;
  severity: Severity;
  status: AlertStatus;
  score: number;
  verdict?: Verdict;
  rule_ids?: string[];
  mitre?: string[];
  duplicate?: number;
  created_at: string;
  occurred_at?: string;
  hash_sha256?: string;
  summary?: string;
  evidence?: Evidence;
  handled_by?: string;
  handled_at?: string | null;
  note?: string;
  host_count?: number;
}

export interface Evidence {
  process?: { name?: string; pid?: number; ppid?: number; path?: string; user?: string; hash_sha256?: string; signature_ok?: boolean; signed?: boolean; signer?: string; elevated?: boolean; start_time?: string; cmdline?: string };
  static_score?: number; keyword_score?: number; rule_score?: number; lineage_score?: number;
  signals?: { layer: string; name: string; note?: string; score: number }[];
  ancestry?: { name: string; pid: number; path?: string }[];
  network?: { proto: string; local_ip: string; local_port: number; remote_ip: string; remote_port: number; state: string }[];
  notes?: string[];
}

export interface Host {
  id: string; hostname: string; os_version?: string; arch?: string; version?: string;
  username?: string; status: 'online' | 'offline';
  proc_count?: number; cpu_percent?: number; mem_mb?: number;
  open_alerts?: number; last_seen_at: string; clock_skew_ms?: number;
  /** 主机网络隔离状态（R+3，探针心跳为事实源） */
  isolated?: boolean;
  /* 以下为契约对拍补齐（2026-11-21，服务端 domain.Agent 实际下发面） */
  ip?: string; tags?: string[]; machine_id?: string;
  enrolled_at?: string; rule_version?: number; queue_dropped?: number;
}

export interface AllowEntry { id: number; type: string; value: string; note?: string; created_at?: string; created_by?: string; hits?: number }

export interface Rule {
  id: string; name: string; description: string;
  severity: Severity; score: number; mitre?: string[];
  enabled: boolean; builtin: boolean;
  mode?: '' | 'active' | 'observe';
  definition: string; version: number; updated_at: string;
  observed_hits?: number;
}

export interface RuleCondition { field: string; op: string; value: unknown }

export interface RuleFieldDoc { field: string; kind: string; desc: string; group: string; example?: string }

export interface RuleOpDoc { op: string; desc: string; kinds?: string[] }

export interface RuleTemplate {
  id: string; name: string; description: string;
  severity: Severity; score: number; mitre?: string[];
  definition: { all?: RuleCondition[]; any?: RuleCondition[]; none?: RuleCondition[] };
}

export interface RuleSchema { fields: RuleFieldDoc[]; ops: RuleOpDoc[]; templates: RuleTemplate[] }

export interface AuditRow { id: number; at: string; actor: string; action: string; detail?: string; request_id?: string }

export interface UserRow { id: number; username: string; role: Role; created_at?: string; last_login_at?: string }

export interface Incident {
  id: string;
  agent_id: string;
  hostname: string;
  title: string;
  peak_severity: Severity;
  max_score: number;
  alert_count: number;
  open_count: number;
  status: 'open' | 'investigating' | 'contained' | 'resolved';
  processes?: string[];
  rule_ids?: string[];
  mitre?: string[];
  first_seen: string;
  last_seen: string;
  first_action_at?: string | null;
  resolved_at?: string | null;
  note?: string;
  updated_at?: string;
}

/** 跨主机爆发聚类（同一载荷在多台主机出现） */
export interface Burst {
  hash: string;
  host_count: number;
  alert_count: number;
  peak_severity: Severity;
  hosts: string[];
  title_sample?: string;
}

export interface AiTriage { verdict: Verdict; confidence: number; summary: string; cites?: { id: string; note?: string }[]; notes?: string[] }

export interface Paged<T> { items: T[]; total?: number }

export interface AiStats { total: number; blocked: number; degraded: number; avg_ms?: number }

/* ---- v0.9 新接口（[FE-WANTED] 跟进） ---- */

/** 威胁指标（当前仅 SHA256），随签名包下发到终端 */
export interface IOC { id: string; hash: string; note?: string; created_by?: string; created_at: string; hits?: number }

export interface IntelItem {
  id: string; type: 'ip' | 'path' | 'keyword'; value: string;
  score?: number; name?: string; note?: string; mitre?: string;
  hits?: number; created_by?: string; created_at: string;
}

/** 远程指令：terminate/quarantine_file/quarantine_restore/rescan/sync_rules/collect */
export interface AgentCommand {
  id: string; agent_id: string; type: string; payload?: string;
  status: 'pending' | 'delivered' | 'done' | 'failed' | string;
  result?: string; created_by?: string; created_at: string;
  delivered_at?: string | null; finished_at?: string | null;
}

/** 主机资产清单节（探针分节上报，payload 是 JSON 字符串，服务端不解析） */
export interface HostInventorySection { name: string; hash: string; payload: string; updated_at: string }

/** ATT&CK 战术×技术矩阵（GET /api/v1/attack/matrix） */
export interface AttackMatrix {
  tactics: AttackTactic[];
  window_days: number;
  generated_at: string;
  summary: { techniques_hit: number; techniques_covered: number; total_alerts: number; unmapped: number };
}
export interface AttackTactic { id: string; name: string; name_zh: string; techniques: AttackTechStat[] }
export interface AttackTechStat {
  id: string; name: string; name_zh: string;
  alert_count: number; open_count: number; critical_count: number;
  rule_count: number; last_seen?: string;
}

/** 告警完整性链逐日校验 */
export interface IntegrityReport {
  days: { day: string; status: 'ok' | 'purged' | 'tampered' | string; alerts?: number }[];
  ok: number; purged: number; tampered: number;
}

/** 自然语言狩猎（POST /api/v1/ai/hunt）：AI 把自然语言翻译成受控过滤条件 */
export interface HuntFilter { field: string; op: string; value: string; values?: string[] }export interface HuntQuery {
  target: string; filters: HuntFilter[]; since_sec: number;
  order_by: string; desc: boolean; limit: number;
  explain: string; /* 模型对查询的自然语言解释，供分析师确认意图 */
}
export interface HuntResult {
  query: HuntQuery;
  total: number;
  alerts: Alert[];
  elapsed: string;
}

/** Agentic 自动调查（POST /api/v1/alerts/{id}/investigate）：五步确定性编排 */
export interface InvestigationStep { name: string; finding: string; citations?: string[] }
export interface RecommendedAction { action: string; target: string; available: boolean; reason?: string }
export interface Investigation {
  alert_id: string;
  verdict_suggestion: string;
  confidence: number;
  steps: InvestigationStep[];
  recommended_actions: RecommendedAction[];
  created_at: string;
}

/* ---- 实时隧道（docs/LIVE-TUNNEL.md §5.2 契约的前端镜像） ---- */

/** 隧道目录条目：服务端只给 name，全路径由前端用 path + name 拼接 */
export interface LiveFsEntry {
  name: string;
  size: number;
  is_dir: boolean;
  hidden: boolean;
  system: boolean;
  readonly: boolean;
  reparse: boolean;
  mtime_unix: number; /* 秒级时间戳 */
}

/** GET /hosts/{id}/live/fs —— next_cursor 非空表示还有下一页（游标 o<offset>） */
export interface LiveFsList { path: string; entries: LiveFsEntry[]; next_cursor: string }

/** GET /hosts/{id}/live/fs/hash —— state: valid|unsigned|distrusted|bad_digest|expired|untrusted|error… */
export interface LiveHash {
  path: string;
  sha256: string;
  size: number;
  authenticode: { state: string; subject?: string; issuer?: string };
}

/** GET /hosts/{id}/live/fs/stat —— 跨 Tab 以路径打开抽屉时先取元数据 */
export interface LiveStat {
  path: string;
  exists: boolean;
  size: number;
  is_dir: boolean;
  hidden: boolean;
  system: boolean;
  readonly: boolean;
  reparse: boolean;
  mtime_unix: number;
}

/* ---- v2 增量（docs/LIVE-TUNNEL.md §11，排查级深化）----
   字段名与契约逐字对齐；老探针对 v2 字段可能缺省，因此新增字段一律可空。 */

/** /live/netstat 富化行：连接五元组 + 归属进程 + 内外网分类。
   exited=true = 连接还在而进程已没了（排查高价值信号）。 */
export interface LiveNetConn {
  proto: string;
  local_ip: string;
  local_port: number;
  remote_ip: string;
  remote_port: number;
  state: string;
  pid: number;
  proc_name?: string;
  proc_path?: string;
  proc_user?: string;
  /** 进程真实启动时刻，unix 秒（探针 int64；不是 ISO 字符串） */
  proc_started_at?: number;
  proc_cmdline?: string;
  proc_elevated?: boolean;
  exited?: boolean;
  /** loopback | private | public | multicast | reserved（Go net 标准库划分） */
  remote_class?: 'loopback' | 'private' | 'public' | 'multicast' | 'reserved' | string;
}

export interface LiveNetList { items: LiveNetConn[] }

/** /live/processes 行 = 探针 state.ProcRow 镜像。
   注意：ProcRow 没有 cpu_percent/mem_mb 字段——不要凭空渲染这两列。 */
export interface LiveProcRow {
  pid: number;
  ppid: number;
  name: string;
  path: string;
  cmdline: string;
  user: string;
  score: number;
  verdict: string;
  severity: string;
  title: string;
  /** 探针首次发现时间（不是进程启动时间） */
  first_seen: string;
  conn_count: number;
  modules: number;
  suppressed?: string;
}

export interface LiveProcList { items: LiveProcRow[] }

export interface LiveModule { name: string; path: string }

/** /live/procinfo —— 交叉动线中枢；modules 等字段可能缺省（可选渲染） */
export interface LiveProcInfo {
  pid: number;
  exists: boolean;
  name?: string;
  path?: string;
  cmdline?: string;
  user?: string;
  session_id?: number;
  elevated?: boolean;
  started_at?: string;
  cpu_percent?: number;
  mem_mb?: number;
  connections?: LiveNetConn[];
  modules?: LiveModule[];
  unsigned_module_count?: number;
  /** 模块列表是否因预算截断 */
  truncated?: boolean;
  exec_info?: { exists: boolean; signed_state?: string; ads_zone_id?: number | null };
}

/** fs/search 条目 = 常规条目 + quick 速览旗标（仅搜索结果携带）。
   dir 为探针可选提供的命中目录：缺省时按搜索根拼接（depth=1 命中恒正确）。 */
export interface LiveSearchEntry extends LiveFsEntry {
  quick?: { pe: boolean; ads: boolean; hidden: boolean; system: boolean };
  dir?: string;
}

export interface LiveSearchResult {
  path: string;
  pattern: string;
  entries: LiveSearchEntry[];
  /** 探针 30s 预算用尽：返回已收集部分 + truncated */
  truncated: boolean;
}

/** /live/analyze PE 节区（熵 >7.2 前端按加壳信号渲染） */
export interface LiveSection { name: string; size: number; entropy: number; flags?: string }

export interface LivePeInfo {
  machine: string;
  subsystem: string;
  is_dll: boolean;
  compile_ts_unix: number;
  entry_point: number;
  sections: LiveSection[];
  max_section_entropy: number;
  /** VT 口径 imphash（小写 dll!func 排序拼接取 MD5） */
  imphash?: string;
  imports?: {
    total: number;
    categories: {
      network: number; process_injection: number; persistence: number;
      keyboard_hook: number; anti_debug: number; exec: number; fs: number;
    };
    notable: string[];
  };
}

/** OriginalFilename 与实际文件名不符 = 伪装信号（mismatch） */
export interface LiveVersionResource {
  company?: string;
  product?: string;
  description?: string;
  original_filename?: string;
  mismatch?: boolean;
}

/** 采样前 64KB + 尾 64KB 的可打印串，每类 ≤10 */
export interface LiveStrings {
  urls?: string[];
  ips?: string[];
  registry_paths?: string[];
  file_paths?: string[];
  mutex?: string[];
}

export interface LiveAnalyze {
  md5: string;
  sha1: string;
  sha256: string;
  size: number;
  /** 非 PE 文件为 null/缺省 */
  pe?: LivePeInfo | null;
  /** 加壳/高熵节提示（节名特征 + 节熵 >7.2），与 pe 平级——非 PE 文件也可能给出 */
  packer_hints?: string[];
  version_resource?: LiveVersionResource | null;
  strings?: LiveStrings | null;
}

/** /live/ads —— NTFS 备用数据流 + MotW（Zone.Identifier） */
export interface LiveAds {
  streams: { name: string; size: number }[];
  zone?: {
    zone_id: number;
    zone_name: string;
    referrer_url?: string;
    host_url?: string;
    download_time?: string;
  } | null;
}

/** /live/info —— 探针实时运行时（部分字段可能缺省） */
export interface LiveInfo {
  version?: string;
  hostname?: string;
  uptime_sec?: number;
  proc_count?: number;
  cpu_percent?: number;
  mem_mb?: number;
  scan_interval?: number;
  collector?: string;
}

/* ---- 资产侦查（docs/LIVE-TUNNEL.md §12.2 契约镜像，第三轮 F4）----
   后端 recon 并行实现中：Finding 的对象字段按契约全部可空，且允许
   `findings: ["人话描述 + 建议"]` 的纯字符串形态——前端两种都要渲染。 */

export type ReconExposureLevel = 'critical' | 'high' | 'medium' | 'low' | 'info';

/** 监听端点（addr 可能是 0.0.0.0 / :: / 127.0.0.1） */
export interface ReconListen {
  proto?: string;
  addr?: string;
  port?: number;
}

/** 有进程归属时的进程上下文（字段可能缺省） */
export interface ReconProcess {
  pid?: number;
  name?: string;
  path?: string;
  user?: string;
  cmdline?: string;
  started_at?: string;
}

/** 暴露面判定：level + 证据（证据前端折叠展示，不丢判定依据） */
export interface ReconExposure {
  level?: ReconExposureLevel | string;
  evidence?: string[];
}

/** Finding 的对象形态：字段名以最终实现为准，这里只列常见键并保留索引签名 */
export interface ReconFinding {
  id?: string;
  severity?: ReconExposureLevel | string;
  title?: string;
  message?: string;
  description?: string;
  detail?: string;
  advice?: string;
  recommendation?: string;
  suggestion?: string;
  solution?: string;
  asset_id?: string;
  category?: string;
  evidence?: string[];
  [key: string]: unknown;
}

export type ReconFindingLike = string | ReconFinding;

/** 单个资产（应用 / 服务 / 监听面） */
export interface ReconAssetItem {
  id?: string;
  category?: string;
  /** iis/ollama/redis/rdp/jupyter/wsl…（前端渲染为中性 kind 徽标） */
  kind?: string;
  title?: string;
  process?: ReconProcess;
  listens?: ReconListen[];
  /** 可 HTTP 访问时的地址（如 http://127.0.0.1:11434） */
  endpoint?: string;
  exposure?: ReconExposure;
  /** 类目特有键值；前端按 category/kind 定制渲染，禁止裸 JSON */
  details?: Record<string, unknown>;
  findings?: ReconFindingLike[];
}

export interface ReconCategory {
  key?: string;
  title?: string;
  items?: ReconAssetItem[];
  findings?: ReconFindingLike[];
  /** 单类失败不影响其他类 */
  error?: string;
}

/** GET /hosts/{id}/live/recon 的统一结果（§12.2） */
export interface ReconResult {
  generated_at?: string;
  duration_ms?: number;
  /** false = 仅被动采集（未做主动探测） */
  probed?: boolean;
  /** true = 入口预算用尽，结果不完整 */
  truncated?: boolean;
  categories?: ReconCategory[];
}

/* ---- 主机详情深化 v1（docs/LIVE-TUNNEL.md §13，第四轮 F5）----
   两个新 Tab 的契约镜像；字段名逐字对齐，状态枚举只认四档。 */

export type BaselineStatus = 'pass' | 'warn' | 'fail' | 'info';

/** 单个基线检查项：status=info 表示读取失败/无法判断（不猜测） */
export interface BaselineItem {
  key: string;
  title: string;
  status: BaselineStatus;
  current: string;
  recommended: string;
  evidence: string;
}

/** info 不进入 pass/warn/fail，但 total 恒等于 items 长度 */
export interface BaselineScore {
  pass: number;
  warn: number;
  fail: number;
  total: number;
}

/** GET /hosts/{id}/live/baseline —— 10 项只读安全检查（§13.2） */
export interface LiveBaseline {
  generated_at?: string;
  score: BaselineScore;
  items: BaselineItem[];
}

/** 本地账户行；last_logon_unix=0 表示从未登录/无记录 */
export interface AccountUser {
  name: string;
  sid: string;
  disabled: boolean;
  password_never_expires: boolean;
  password_age_days: number;
  last_logon_unix: number;
  comment: string;
  is_admin: boolean;
}

/** 本地密码策略；0 值表示未配置/不限制（前端显示为 —） */
export interface AccountPolicy {
  min_password_length: number;
  max_age_days: number;
  lockout_threshold: number;
}

/** GET /hosts/{id}/live/accounts —— 账户与会话（§13.3） */
export interface LiveAccounts {
  generated_at?: string;
  users: AccountUser[];
  administrators: string[];
  policy: AccountPolicy;
}

/* ---- 进程取证 v1（docs/LIVE-TUNNEL.md §15，第六轮 F8）----
   四端点全部只读、限预算；字段名与 §15.1-15.4 契约逐字对齐。
   老探针未挂 handler → 501，老服务端代理预算表未收录 → 404，前端同口径
   提示"该探针版本不支持此能力"。 */

/** 单条句柄：value 为原生句柄值；name 仅对安全类型解析（其余为空） */
export interface LiveHandle {
  value: number;
  type: string;
  name?: string;
}

/** GET /hosts/{id}/live/handles —— types 是类型直方图（键=类型名，值=条数） */
export interface LiveHandleList {
  pid: number;
  total: number;
  /** 预算内未枚举完（条目本身可能被 limit 截断） */
  truncated: boolean;
  types: Record<string, number>;
  items: LiveHandle[];
  note?: string;
}

/** 占用文件的进程；path 为该进程的镜像路径（来自快照，可能为空） */
export interface LiveHandleOwner { pid: number; name: string; path: string }

/** GET /hosts/{id}/live/handleowners —— 语义是"部分覆盖"：
    scanned=已解析的文件句柄数，resolved=成功拿到对象名的数量 */
export interface LiveHandleOwners {
  path: string;
  scanned: number;
  resolved: number;
  owners: LiveHandleOwner[];
  truncated: boolean;
  note?: string;
}

/** 线程；module 为空表示起始地址不在本进程任何模块区间内 */
export interface LiveThread {
  tid: number;
  start_address: number;
  module?: string;
  /** true = 起始页为 MEM_PRIVATE + 可执行（注入线索） */
  in_anonymous_exec: boolean;
}

/** GET /hosts/{id}/live/threads —— 受保护进程打不开时 note 说明覆盖度 */
export interface LiveThreads {
  pid: number;
  items: LiveThread[];
  note?: string;
}

/** 一条内存区域；mapped_file 为空 = 无文件映射（匿名内存） */
export interface LiveMemRegion {
  base: number;
  size: number;
  protect: string;
  type?: string;
  mapped_file?: string;
}

/** 可疑区域：私有 + 可执行 + 无映射文件；pe_header=null 表示读取失败（无法判断） */
export interface LiveMemSuspicious {
  base: number;
  size: number;
  protect: string;
  pe_header?: boolean | null;
}

/** GET /hosts/{id}/live/memscan —— 只出摘要，探针绝不回传内存内容 */
export interface LiveMemScan {
  pid: number;
  counts: { regions: number; private_exec: number; suspicious: number };
  regions: LiveMemRegion[];
  suspicious: LiveMemSuspicious[];
  truncated: boolean;
  note?: string;
}

/* ---- 非进程域三个模块（docs/LIVE-TUNNEL.md §16，第七轮 F9）----
   persistence / peers 为探针侧聚合端点，字段名逐字对齐 §16.1/§16.2；
   老探针未挂 handler → 501、老服务端预算表未收录 → 404，前端同口径降级。 */

/** 持久化项来源：服务（auto/delayed-auto）/ 计划任务 / 启动项 */
export type PersistenceSource = 'service' | 'task' | 'startup';

/** 单条持久化项；exe_path 由探针从 command 基础提取，可能为空（无绝对路径） */
export interface PersistenceItem {
  source: PersistenceSource | string;
  name: string;
  command: string;
  exe_path: string;
  user: string;
  /** task enabled=false 表示任务已禁用（仍列出便于审视） */
  enabled: boolean;
  /** service=服务名路径；task=任务路径；startup=注册表/目录位置 */
  location: string;
}

/** GET /hosts/{id}/live/persistence —— 三来源聚合，上限 2000 条 / 10s 预算 */
export interface LivePersistence {
  generated_at?: string;
  truncated?: boolean;
  counts?: { service: number; task: number; startup: number };
  items?: PersistenceItem[];
}

/** 对端端口聚合：conns 为该端口上的连接数 */
export interface PeerPort {
  port: number;
  conns: number;
}

/** 单个远端 IP 的聚合行；procs 是 "name(pid)" 字符串（探针侧已格式化） */
export interface PeerRow {
  ip: string;
  /** public | private | loopback | reserved（探针 net 标准库划分，可能扩展） */
  class: string;
  ports: PeerPort[];
  conns: number;
  procs: string[];
}

/** 按进程视角：谁在跟最多对端说话（C2 心跳往往集中少量对端） */
export interface PeerByProcess {
  pid: number;
  name: string;
  conns: number;
  peer_count: number;
}

/** GET /hosts/{id}/live/peers —— 仅 ESTABLISHED，peers ≤200 / by_process ≤50 */
export interface LivePeers {
  generated_at?: string;
  counts?: { established: number; public: number; private: number };
  peers?: PeerRow[];
  by_process?: PeerByProcess[];
  truncated?: boolean;
}

/* ================= 探针自升级（单机指令 + 批量编排，2026-11-19） ================= */

/** GET /api/v1/upgrade/available —— 服务端升级物料元信息；enabled=false 时前端静默隐藏升级入口 */
export interface UpgradeAvail { enabled: boolean; version: string; size: number }

/** 批量批次里的单主机结局：pending=在途（含排队），其余为终态 */
export interface FleetEntry {
  agent_id: string;
  status: 'pending' | 'success' | 'already_latest' | 'failed' | 'timed_out'
    | 'skipped_offline' | 'skipped_linux' | 'skipped_newer' | string;
  command_id?: string;
  detail?: string;
}

/** GET /api/v1/upgrade/fleet —— 批次快照；无批次时响应体为 null */
export interface FleetStatus {
  id: string;
  target_version: string;
  state: 'running' | 'paused' | 'done' | 'aborted' | string;
  created_by: string;
  created_at: string;
  total: number;
  queue_remain: number;
  waves: { index: number; hosts: FleetEntry[] }[];
  summary: Record<string, number>;
  hosts: Record<string, FleetEntry>;
}
