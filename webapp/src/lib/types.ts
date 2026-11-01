/* 与 Go 端 domain 模型对齐的最小类型集 */

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type AlertStatus = 'open' | 'acknowledged' | 'resolved' | 'false_positive';
export type Verdict = 'malicious' | 'suspicious' | 'safe';
export type Role = 'admin' | 'analyst' | 'viewer';

export interface User { id: number; username: string; role: Role }

export interface Alert {
  id: number;
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
