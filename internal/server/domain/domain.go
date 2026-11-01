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

	// ClockSkewMS 是终端与服务端的时钟偏移（毫秒，进程内存值不落库）。
	// >10s 时告警时间线与事件窗口判定会失真，管理台据此提示检查 NTP。
	ClockSkewMS int64 `json:"clock_skew_ms,omitempty"`

	// QueueDropped 是终端告警队列的丢弃计数（运行时值，不落库）。
	// >0 说明该终端存在"告警黑洞"，需要在容量或网络上排查。
	QueueDropped int64 `json:"queue_dropped,omitempty"`
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

// IOC 是一条威胁指标（当前仅 SHA256 哈希），随签名包下发到终端。
type IOC struct {
	ID        string    `json:"id"`
	Hash      string    `json:"hash"`
	Note      string    `json:"note"`
	CreatedBy string    `json:"created_by"`
	CreatedAt time.Time `json:"created_at"`
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

// HostInventorySection 是主机资产清单的一个节（探针分节上报）。
// 服务端不解析 payload 内容（JSON 进 JSON 出），hash 是 payload 的
// SHA-256 十六进制摘要，用于幂等去重：内容没变就不重复落库。
type HostInventorySection struct {
	Name      string    `json:"name"`
	Hash      string    `json:"hash"`
	Payload   string    `json:"payload"`
	UpdatedAt time.Time `json:"updated_at"`
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

	// AvgResponseMin 是过去 7 天已处置告警的"创建→处置"平均时长（分钟）。
	// MTTR 是安全运营最核心的效率指标：没有它，"响应变快了还是变慢了"
	// 只能靠感觉。0 表示窗口内没有已处置告警。
	AvgResponseMin float64 `json:"avg_response_min"`
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

// AttackMatrix 是战术×技术覆盖矩阵（GET /api/v1/attack/matrix）。
// 与 Dashboard 的 TopMITRE 不同：矩阵按战术组织全部技术，同时给出
// "告警命中"与"规则覆盖"两个维度——只有命中没有覆盖 = 检出靠运气；
// 只有覆盖没有命中 = 安静态（是好事）。
type AttackMatrix struct {
	Tactics     []AttackTactic `json:"tactics"`
	WindowDays  int            `json:"window_days"`
	GeneratedAt time.Time      `json:"generated_at"`
	Summary     AttackSummary  `json:"summary"`
}

// AttackTactic 是矩阵中的一列（一个战术）。
type AttackTactic struct {
	ID         string           `json:"id"`
	Name       string           `json:"name"`
	NameZh     string           `json:"name_zh"`
	Techniques []AttackTechStat `json:"techniques"`
}

// AttackTechStat 是矩阵中的一个格子（一项技术的聚合状态）。
type AttackTechStat struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	NameZh        string `json:"name_zh"`
	AlertCount    int    `json:"alert_count"`
	OpenCount     int    `json:"open_count"`
	CriticalCount int    `json:"critical_count"`
	RuleCount     int    `json:"rule_count"`
	LastSeen      string `json:"last_seen,omitempty"`
}

// AttackSummary 是矩阵的全局摘要。
type AttackSummary struct {
	TechniquesHit     int `json:"techniques_hit"`
	TechniquesCovered int `json:"techniques_covered"`
	TotalAlerts       int `json:"total_alerts"`
	// Unmapped 是目录外技术编号数（聚合层归入未分类战术）。
	Unmapped int `json:"unmapped"`
}

// MitreAgg 是单个技术编号在时间窗内的告警聚合值。
type MitreAgg struct {
	Count    int
	Open     int
	Critical int
	LastSeen time.Time
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

	// 以下字段由 AI 查询 DSL 映射而来（见 service.AIService.Hunt）。
	// 每个字段都对应固定的 SQL 片段，值一律走参数绑定——
	// 这是"模型无法触及 SQL"的落地点。
	ProcessLike string
	PathLike    string
	CmdLike     string
	UserLike    string
	HostLike    string
	RuleLike    string
	Hash        string
	// Mitre 是 ATT&CK 技术编号的精确匹配（供矩阵格子下钻）。
	// 存储侧是 CSV 列，SQL 用逗号定界匹配，避免 T1059 误匹配 T1059.001。
	Mitre string
	MinScore    int
	// Unsigned 为 true 时只要未签名；false 时只要已签名；nil 表示不限。
	Unsigned *bool
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
