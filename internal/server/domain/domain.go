// Package domain 定义服务端核心实体。
//
// 枚举与证据结构复用 internal/model（与探针共享），本包只新增
// 「只在服务端存在」的实体：账号、终端、规则、白名单、审计、指令、统计。
// 该层不依赖数据库、不依赖 HTTP。
package domain

import (
	"strings"
	"time"

	"hostguard/internal/model"
)

// 共享枚举别名：保证服务端内部书写简短，同时与线协议完全同源。
type (
	Severity     = model.Severity
	Verdict      = model.Verdict
	AlertStatus  = model.AlertStatus
	Role         = model.Role
	AgentStatus  = model.AgentStatus
	Evidence     = model.Evidence
	ProcEvidence = model.ProcEvidence
	AncestorLink = model.AncestorLink
	Signal       = model.Signal
	RuleHit      = model.RuleHit
	NetConn      = model.NetConn
	ModuleInfo   = model.ModuleInfo
)

const (
	SeverityCritical = model.SeverityCritical
	SeverityHigh     = model.SeverityHigh
	SeverityMedium   = model.SeverityMedium
	SeverityLow      = model.SeverityLow
	SeverityInfo     = model.SeverityInfo

	VerdictMalicious  = model.VerdictMalicious
	VerdictSuspicious = model.VerdictSuspicious
	VerdictSafe       = model.VerdictSafe

	StatusOpen          = model.StatusOpen
	StatusAcknowledged  = model.StatusAcknowledged
	StatusResolved      = model.StatusResolved
	StatusFalsePositive = model.StatusFalsePositive

	RoleAdmin   = model.RoleAdmin
	RoleAnalyst = model.RoleAnalyst
	RoleViewer  = model.RoleViewer

	AgentOnline  = model.AgentOnline
	AgentOffline = model.AgentOffline
	AgentPending = model.AgentPending
)

// ---------------------------------------------------------------- 实体

// User 是后台运维账号。
type User struct {
	ID           string     `json:"id"`
	Username     string     `json:"username"`
	DisplayName  string     `json:"display_name"`
	PasswordHash string     `json:"-"`
	Role         Role       `json:"role"`
	Disabled     bool       `json:"disabled"`
	CreatedAt    time.Time  `json:"created_at"`
	LastLoginAt  *time.Time `json:"last_login_at,omitempty"`
}

// RefreshToken 记录服务端持有的刷新令牌（仅存哈希）。
type RefreshToken struct {
	ID        string
	UserID    string
	TokenHash string
	ExpiresAt time.Time
	Revoked   bool
	CreatedAt time.Time
	UserAgent string
	IP        string
}

// Agent 是被管控终端。
type Agent struct {
	ID          string      `json:"id"`
	Hostname    string      `json:"hostname"`
	OSVersion   string      `json:"os_version"`
	Arch        string      `json:"arch"`
	Username    string      `json:"username"`
	IP          string      `json:"ip"`
	Tags        []string    `json:"tags"`
	Version     string      `json:"version"`
	MachineID   string      `json:"machine_id"`
	SecretHash  string      `json:"-"`
	Status      AgentStatus `json:"status"`
	EnrolledAt  time.Time   `json:"enrolled_at"`
	LastSeenAt  time.Time   `json:"last_seen_at"`
	ProcCount   int         `json:"proc_count"`
	CPUPercent  float64     `json:"cpu_percent"`
	MemMB       float64     `json:"mem_mb"`
	RuleVersion int         `json:"rule_version"`
	OpenAlerts  int         `json:"open_alerts"`
}

// Alert 是一条进程级告警（含完整证据链）。
type Alert struct {
	ID          string      `json:"id"`
	AgentID     string      `json:"agent_id"`
	Hostname    string      `json:"hostname"`
	Fingerprint string      `json:"fingerprint"`
	Title       string      `json:"title"`
	Summary     string      `json:"summary"`
	Verdict     Verdict     `json:"verdict"`
	Severity    Severity    `json:"severity"`
	Score       int         `json:"score"`
	PID         uint32      `json:"pid"`
	PPID        uint32      `json:"ppid"`
	ProcessName string      `json:"process_name"`
	ImagePath   string      `json:"image_path"`
	CmdLine     string      `json:"cmdline"`
	ProcUser    string      `json:"proc_user"`
	HashSHA256  string      `json:"hash_sha256"`
	Signer      string      `json:"signer"`
	Signed      bool        `json:"signed"`
	RuleIDs     []string    `json:"rule_ids"`
	MITRE       []string    `json:"mitre"`
	Evidence    Evidence    `json:"evidence"`
	Status      AlertStatus `json:"status"`
	HandledBy   string      `json:"handled_by,omitempty"`
	HandledAt   *time.Time  `json:"handled_at,omitempty"`
	Note        string      `json:"note,omitempty"`
	OccurredAt  time.Time   `json:"occurred_at"`
	CreatedAt   time.Time   `json:"created_at"`
	HostCount   int         `json:"host_count"`
	Duplicate   int         `json:"duplicate"`
}

// Rule 是行为规则（可下发到终端）。
type Rule struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Severity    Severity  `json:"severity"`
	MITRE       []string  `json:"mitre"`
	Score       int       `json:"score"`
	Enabled     bool      `json:"enabled"`
	Builtin     bool      `json:"builtin"`
	Definition  string    `json:"definition"`
	Version     int       `json:"version"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// AllowlistEntry 是降噪白名单。
type AllowlistEntry struct {
	ID        string    `json:"id"`
	Type      string    `json:"type"`
	Value     string    `json:"value"`
	Note      string    `json:"note"`
	CreatedBy string    `json:"created_by"`
	CreatedAt time.Time `json:"created_at"`
	Hits      int       `json:"hits"`
}

// AuditLog 是后台操作审计。
type AuditLog struct {
	ID        int64     `json:"id"`
	UserID    string    `json:"user_id"`
	Username  string    `json:"username"`
	Action    string    `json:"action"`
	Target    string    `json:"target"`
	Detail    string    `json:"detail"`
	IP        string    `json:"ip"`
	CreatedAt time.Time `json:"created_at"`
}

// AgentCommand 是下发给终端的指令。
type AgentCommand struct {
	ID          string     `json:"id"`
	AgentID     string     `json:"agent_id"`
	Type        string     `json:"type"`
	Payload     string     `json:"payload"`
	Status      string     `json:"status"`
	Result      string     `json:"result"`
	CreatedBy   string     `json:"created_by"`
	CreatedAt   time.Time  `json:"created_at"`
	DeliveredAt *time.Time `json:"delivered_at,omitempty"`
	FinishedAt  *time.Time `json:"finished_at,omitempty"`
}

// ---------------------------------------------------------------- 统计

// DashboardSummary 是后台首页聚合数据。
type DashboardSummary struct {
	TotalHosts     int              `json:"total_hosts"`
	OnlineHosts    int              `json:"online_hosts"`
	Alerts24h      int              `json:"alerts_24h"`
	OpenAlerts     int              `json:"open_alerts"`
	CriticalOpen   int              `json:"critical_open"`
	MaliciousCount int              `json:"malicious_count"`
	FalsePositive  int              `json:"false_positive"`
	TopHosts       []HostAlertStat  `json:"top_hosts"`
	SeverityDist   map[string]int   `json:"severity_dist"`
	Timeline       []TimelinePoint  `json:"timeline"`
	TopRules       []RuleStat       `json:"top_rules"`
	TopMITRE       []MITREStat      `json:"top_mitre"`
	AvgScore       float64          `json:"avg_score"`
}

// HostAlertStat 是主机告警排行项。
type HostAlertStat struct {
	AgentID  string `json:"agent_id"`
	Hostname string `json:"hostname"`
	Count    int    `json:"count"`
	Critical int    `json:"critical"`
}

// TimelinePoint 是时间轴上的一个点。
type TimelinePoint struct {
	Bucket   string `json:"bucket"`
	Total    int    `json:"total"`
	Critical int    `json:"critical"`
}

// RuleStat 是规则命中排行项。
type RuleStat struct {
	RuleID string `json:"rule_id"`
	Name   string `json:"name"`
	Count  int    `json:"count"`
}

// MITREStat 是 ATT&CK 技术命中排行项。
type MITREStat struct {
	Tech  string `json:"tech"`
	Count int    `json:"count"`
}

// AlertFilter 是告警查询条件。
type AlertFilter struct {
	Status   []AlertStatus
	Severity []Severity
	AgentID  string
	Verdict  []Verdict
	Query    string
	Page     int
	PageSize int
	Sort     string
}

// Normalize 补全默认分页参数并限制上限。
func (f *AlertFilter) Normalize() {
	if f.Page <= 0 {
		f.Page = 1
	}
	if f.PageSize <= 0 {
		f.PageSize = 20
	}
	if f.PageSize > 200 {
		f.PageSize = 200
	}
	f.Query = strings.TrimSpace(f.Query)
}
