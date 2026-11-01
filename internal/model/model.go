// Package model 是探针与服务端共享的领域模型与线协议定义。
//
// 之所以独立成包：agent 与 server 是两个独立二进制，但必须对"什么是一条告警"
// 保持完全一致的理解。把共享类型放这里，可以避免两侧结构体漂移，
// 同时让服务端 domain 包通过类型别名复用，不产生重复定义。
package model

import "time"

// ---------------------------------------------------------------- 枚举

// Severity 是告警严重度。
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// Rank 用于排序，数值越大越严重。
func (s Severity) Rank() int {
	switch s {
	case SeverityCritical:
		return 5
	case SeverityHigh:
		return 4
	case SeverityMedium:
		return 3
	case SeverityLow:
		return 2
	case SeverityInfo:
		return 1
	}
	return 0
}

// Valid 判断严重度是否合法。
func (s Severity) Valid() bool { return s.Rank() > 0 }

// Verdict 是检测结论。
type Verdict string

const (
	VerdictMalicious  Verdict = "malicious"
	VerdictSuspicious Verdict = "suspicious"
	VerdictSafe       Verdict = "safe"
)

// Valid 判断结论是否合法。
func (v Verdict) Valid() bool {
	return v == VerdictMalicious || v == VerdictSuspicious || v == VerdictSafe
}

// AlertStatus 是告警处置状态。
type AlertStatus string

const (
	StatusOpen          AlertStatus = "open"
	StatusAcknowledged  AlertStatus = "acknowledged"
	StatusResolved      AlertStatus = "resolved"
	StatusFalsePositive AlertStatus = "false_positive"
)

// Valid 判断状态是否合法。
func (s AlertStatus) Valid() bool {
	switch s {
	case StatusOpen, StatusAcknowledged, StatusResolved, StatusFalsePositive:
		return true
	}
	return false
}

// Role 是后台账号角色。
type Role string

const (
	RoleAdmin   Role = "admin"
	RoleAnalyst Role = "analyst"
	RoleViewer  Role = "viewer"
)

// Valid 判断角色合法。
func (r Role) Valid() bool {
	return r == RoleAdmin || r == RoleAnalyst || r == RoleViewer
}

// CanWrite 是否具备写权限。
func (r Role) CanWrite() bool { return r == RoleAdmin || r == RoleAnalyst }

// AgentStatus 是终端在线状态。
type AgentStatus string

const (
	AgentOnline  AgentStatus = "online"
	AgentOffline AgentStatus = "offline"
	AgentPending AgentStatus = "pending"
)

// ---------------------------------------------------------------- 证据

// Evidence 是一条告警的完整可解释证据链。
type Evidence struct {
	Process      ProcEvidence   `json:"process"`
	Ancestry     []AncestorLink `json:"ancestry"`
	Signals      []Signal       `json:"signals"`
	RuleHits     []RuleHit      `json:"rule_hits"`
	Network      []NetConn      `json:"network"`
	Modules      []ModuleInfo   `json:"modules"`
	LineageScore float64        `json:"lineage_score"`
	StaticScore  float64        `json:"static_score"`
	KeywordScore float64        `json:"keyword_score"`
	RuleScore    float64        `json:"rule_score"`
	// DropScore 是"文件落地即执行"关联层的得分，单独列出便于事后审计
	DropScore    float64        `json:"drop_score"`
	Notes        []string       `json:"notes"`
}

// ProcEvidence 是进程本体字段。
type ProcEvidence struct {
	PID         uint32    `json:"pid"`
	PPID        uint32    `json:"ppid"`
	Name        string    `json:"name"`
	Path        string    `json:"path"`
	CmdLine     string    `json:"cmdline"`
	User        string    `json:"user"`
	SessionID   uint32    `json:"session_id"`
	Elevated    bool      `json:"elevated"`
	StartTime   time.Time `json:"start_time"`
	HashSHA256  string    `json:"hash_sha256"`
	FileSize    int64     `json:"file_size"`
	Signer      string    `json:"signer"`
	Signed      bool      `json:"signed"`
	SignatureOK bool      `json:"signature_ok"`
	CompanyName string    `json:"company_name"`
	IsWow64     bool      `json:"is_wow64"`
}

// AncestorLink 是进程树中的一条父子边。
type AncestorLink struct {
	PID  uint32 `json:"pid"`
	PPID uint32 `json:"ppid"`
	Name string `json:"name"`
	Path string `json:"path"`
	Cmd  string `json:"cmd,omitempty"`
}

// Signal 是某个检测引擎给出的证据点。
type Signal struct {
	Layer string `json:"layer"` // static | keyword | rule | lineage | behavior
	ID    string `json:"id"`
	Name  string `json:"name"`
	Score int    `json:"score"`
	Note  string `json:"note,omitempty"`
	MITRE string `json:"mitre,omitempty"`
}

// RuleHit 是命中的行为规则。
type RuleHit struct {
	RuleID   string   `json:"rule_id"`
	Name     string   `json:"name"`
	Severity Severity `json:"severity"`
	Score    int      `json:"score"`
	MITRE    []string `json:"mitre"`
	Matched  []string `json:"matched"`
}

// NetConn 是进程持有的网络连接。
type NetConn struct {
	Proto      string `json:"proto"`
	LocalIP    string `json:"local_ip"`
	LocalPort  uint32 `json:"local_port"`
	RemoteIP   string `json:"remote_ip"`
	RemotePort uint32 `json:"remote_port"`
	State      string `json:"state"`
}

// ModuleInfo 是进程加载的模块（用于注入线索）。
type ModuleInfo struct {
	Name     string `json:"name"`
	Path     string `json:"path"`
	BaseAddr uint64 `json:"base_addr"`
	Size     uint32 `json:"size"`
}

// ---------------------------------------------------------------- 线协议

// EnrollRequest 是终端首次注册请求。
type EnrollRequest struct {
	EnrollToken string   `json:"enroll_token"`
	MachineID   string   `json:"machine_id"`
	Hostname    string   `json:"hostname"`
	OSVersion   string   `json:"os_version"`
	Arch        string   `json:"arch"`
	Username    string   `json:"username"`
	Version     string   `json:"version"`
	Tags        []string `json:"tags,omitempty"`
}

// EnrollResponse 是注册响应，包含后续请求所需的凭证。
type EnrollResponse struct {
	AgentID              string `json:"agent_id"`
	AgentSecret          string `json:"agent_secret"`
	ServerTime           int64  `json:"server_time"`
	HeartbeatIntervalSec int    `json:"heartbeat_interval_sec"`
	RuleVersion          int    `json:"rule_version"`
	ScanIntervalSec      int    `json:"scan_interval_sec"`
	KillEnabled          bool   `json:"kill_enabled"`
}

// HeartbeatRequest 是心跳（同时携带运行指标）。
type HeartbeatRequest struct {
	Hostname     string          `json:"hostname"`
	Version      string          `json:"version"`
	ProcCount    int             `json:"proc_count"`
	CPUPercent   float64         `json:"cpu_percent"`
	MemMB        float64         `json:"mem_mb"`
	UptimeSec    int64           `json:"uptime_sec"`
	RuleVersion  int             `json:"rule_version"`
	Detector     DetectorStats   `json:"detector"`
	Samples      int64           `json:"samples"`
}

// DetectorStats 是本地检测器计数，便于观察去噪效果。
type DetectorStats struct {
	EventsScanned int64 `json:"events_scanned"`
	AlertsFired   int64 `json:"alerts_fired"`
	Suppressed    int64 `json:"suppressed"`
	Whitelisted   int64 `json:"whitelisted"`
	AvgLatencyMs  int64 `json:"avg_latency_ms"`
}

// HeartbeatResponse 返回服务端指令与规则版本。
type HeartbeatResponse struct {
	ServerTime  int64           `json:"server_time"`
	RuleVersion int             `json:"rule_version"`
	AckCommand  []string        `json:"ack_command"` // 已投递的指令 ID
	Commands    []Command       `json:"commands"`
	ScanSeconds int             `json:"scan_seconds"`
}

// Command 是服务端下发到终端的指令。
type Command struct {
	ID      string `json:"id"`
	Type    string `json:"type"`
	Payload string `json:"payload"`
}

// AlertEnvelope 是上报的单条告警（终端侧结构）。
type AlertEnvelope struct {
	Fingerprint string    `json:"fingerprint"`
	Title       string    `json:"title"`
	Summary     string    `json:"summary"`
	Verdict     Verdict   `json:"verdict"`
	Severity    Severity  `json:"severity"`
	Score       int       `json:"score"`
	PID         uint32    `json:"pid"`
	PPID        uint32    `json:"ppid"`
	ProcessName string    `json:"process_name"`
	ImagePath   string    `json:"image_path"`
	CmdLine     string    `json:"cmdline"`
	ProcUser    string    `json:"proc_user"`
	HashSHA256  string    `json:"hash_sha256"`
	Signer      string    `json:"signer"`
	Signed      bool      `json:"signed"`
	RuleIDs     []string  `json:"rule_ids"`
	MITRE       []string  `json:"mitre"`
	Evidence    Evidence  `json:"evidence"`
	OccurredAt  time.Time `json:"occurred_at"`
}

// AlertBatchRequest 是批量上报。
type AlertBatchRequest struct {
	Alerts []AlertEnvelope `json:"alerts"`
}

// AlertBatchResponse 上报结果。
type AlertBatchResponse struct {
	Accepted   int `json:"accepted"`
	Duplicates int `json:"duplicates"`
	Rejected   int `json:"rejected"`
}

// RuleDTO 是下发到终端的规则。
type RuleDTO struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Severity    Severity `json:"severity"`
	MITRE       []string `json:"mitre"`
	Score       int      `json:"score"`
	Enabled     bool     `json:"enabled"`
	Definition  string   `json:"definition"`
	Version     int      `json:"version"`
}

// AllowDTO 是下发到终端的白名单项。
type AllowDTO struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

// RuleBundle 是规则+白名单整包下发。
type RuleBundle struct {
	Version     int       `json:"version"`
	GeneratedAt time.Time `json:"generated_at"`
	Rules       []RuleDTO `json:"rules"`
	Allowlist   []AllowDTO `json:"allowlist"`
	// Signature 是整包内容的 HMAC-SHA256（hex）。
	// 终端验签通过才应用，防止下发链路被篡改导致检测被悄悄关掉。
	Signature string `json:"signature,omitempty"`
}

// CommandResult 是终端回执。
type CommandResult struct {
	CommandID string `json:"command_id"`
	Status    string `json:"status"` // done | failed
	Result    string `json:"result"`
}

// ErrorBody 是服务端标准错误结构（终端侧需要解析）。
type ErrorBody struct {
	Error struct {
		Code      string `json:"code"`
		Message   string `json:"message"`
		RequestID string `json:"request_id"`
	} `json:"error"`
}
