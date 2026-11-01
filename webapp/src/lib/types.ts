/* 与 Go 端 domain 模型对齐的最小类型集 */

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type AlertStatus = 'open' | 'acknowledged' | 'resolved' | 'false_positive';
export type Verdict = 'malicious' | 'suspicious' | 'safe';
export type Role = 'admin' | 'analyst' | 'viewer';

export interface User { id: number; username: string; role: Role }

export interface Alert {
  id: string; /* 服务端生成的十六进制 ID（不是数字） */
  hostname: string;
  pid: number;
  process_name: string;
  image_path?: string;
  cmdline?: string;
  title: string;
  severity: Severity;
  status: AlertStatus;
  score: number;
  verdict?: Verdict;
  rule_ids?: string[];
  duplicate?: number;
  created_at: string;
  hash_sha256?: string;
  summary?: string;
  evidence?: Evidence;
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
}

export interface AllowEntry { id: number; type: string; value: string; note?: string; created_at?: string; created_by?: string }

export interface AuditRow { id: number; at: string; actor: string; action: string; detail?: string; request_id?: string }

export interface UserRow { id: number; username: string; role: Role; created_at?: string; last_login_at?: string }

export interface Incident {
  id: string; title: string; severity: Severity; hostnames: string[];
  alert_count: number; first_seen: string; last_seen: string;
}

export interface AiTriage { verdict: Verdict; confidence: number; summary: string; cites?: { id: string; note?: string }[]; notes?: string[] }

export interface Paged<T> { items: T[]; total?: number }

export interface AiStats { total: number; blocked: number; degraded: number; avg_ms?: number }

/* ---- v0.9 新接口（[FE-WANTED] 跟进） ---- */

/** 威胁指标（当前仅 SHA256），随签名包下发到终端 */
export interface IOC { id: string; hash: string; note?: string; created_by?: string; created_at: string }

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
export interface HuntFilter { field: string; op: string; value: string; values?: string[] }
export interface HuntQuery {
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
