// Package repository 定义数据访问契约（仓储层接口）。
//
// 服务层只依赖这些接口，从而可以在单测里用内存实现替换真实数据库，
// 也可以在集成测试里直接连真实 SQLite。
package repository

import (
	"context"
	"time"

	"zedr/internal/server/domain"
)

// Repos 汇总所有仓储。
type Repos struct {
	Users        UserRepo
	Tokens       TokenRepo
	Agents       AgentRepo
	Alerts       AlertRepo
	Rules        RuleRepo
	RuleObserve  ObserveRepo
	IocObserve   ObserveRepo
	AllowObserve ObserveRepo
	Intel        IntelRepo
	Allowlist    AllowlistRepo
	IOCs         IocRepo
	Audit        AuditRepo
	Commands     CommandRepo
	Stats        StatsRepo
	Inventory    InventoryRepo
	Incidents    IncidentRepo
	AIConfig     AIConfigRepo
	ATriage      AITriageRepo
}

// AITriageRepo AI 判定台账：AI/确定性调查结论的按告警快照。
// 研判质量对账（AI 结论 × 分析师处置）的数据来源。
type AITriageRepo interface {
	// Upsert 写入/覆盖某告警某来源的最新结论。
	Upsert(ctx context.Context, log *domain.AITriageLog) error
	// List 按时间倒序取最近 n 条台账（服务层自行按 alert 去重）。
	List(ctx context.Context, limit int) ([]domain.AITriageLog, error)
}

// AIConfigRepo AI 配置中心数据访问：模型槽位配置（settings KV）、
// 提示词模板（版本化历史）与技能包。
type AIConfigRepo interface {
	// GetSetting 读 settings 表通用 KV（found=false 表示键不存在）。
	GetSetting(ctx context.Context, key string) (string, bool, error)
	// SetSetting 写 settings 表通用 KV（UPSERT）。
	SetSetting(ctx context.Context, key, value string) error

	// Prompt 读某任务域的提示词模板（含历史版本，降序，上限 20）。
	Prompt(ctx context.Context, task string) (*domain.AIPrompt, error)
	// SavePrompt 保存新版本：当前内容（若有）压入历史，content 成为新版。
	// 返回新版本号。历史超过 20 条时丢弃最老的。
	SavePrompt(ctx context.Context, task, content, by string, at time.Time) (int, error)
	// RollbackPrompt 把指定历史版本的内容复制为新版本（追加式回滚，
	// 不删除任何历史——回滚本身也要可审计、可再回滚）。
	RollbackPrompt(ctx context.Context, task string, version int, by string, at time.Time) (int, error)

	// Skills 技能包清单（按 sort, name 排序）。
	Skills(ctx context.Context) ([]domain.AISkill, error)
	Skill(ctx context.Context, id string) (*domain.AISkill, error)
	UpsertSkill(ctx context.Context, s *domain.AISkill) error
	DeleteSkill(ctx context.Context, id string) error
}

// UserRepo 账号数据访问。
type UserRepo interface {
	Create(ctx context.Context, u *domain.User) error
	ByUsername(ctx context.Context, username string) (*domain.User, error)
	ByID(ctx context.Context, id string) (*domain.User, error)
	TouchLogin(ctx context.Context, id string, at time.Time) error
	Count(ctx context.Context) (int, error)
	List(ctx context.Context) ([]domain.User, error)
	UpdatePassword(ctx context.Context, id, hash string) error
	SetDisabled(ctx context.Context, id string, disabled bool) error
}

// TokenRepo 刷新令牌数据访问（只存哈希）。
type TokenRepo interface {
	Create(ctx context.Context, t *domain.RefreshToken) error
	ByHash(ctx context.Context, hash string) (*domain.RefreshToken, error)
	Revoke(ctx context.Context, id string) error
	RevokeAllForUser(ctx context.Context, userID string) error
	DeleteExpired(ctx context.Context, before time.Time) (int64, error)
}

// AgentRepo 终端数据访问。
type AgentRepo interface {
	Upsert(ctx context.Context, a *domain.Agent) error
	ByID(ctx context.Context, id string) (*domain.Agent, error)
	ByMachineID(ctx context.Context, machineID string) (*domain.Agent, error)
	List(ctx context.Context) ([]domain.Agent, error)
	UpdateHeartbeat(ctx context.Context, id string, at time.Time, procCount int, cpu, mem float64, ruleVersion int, ip, version string) error
	MarkOfflineBefore(ctx context.Context, threshold time.Time) (int64, error)
	Delete(ctx context.Context, id string) error
	Count(ctx context.Context) (int, error)
}

// AlertRepo 告警数据访问。
type AlertRepo interface {
	Create(ctx context.Context, a *domain.Alert) error
	FindDuplicate(ctx context.Context, fingerprint, agentID string, since time.Time) (*domain.Alert, error)
	// FindDuplicates 批量查重（上报路径优化，见 sqlite/alerts.go 注释）。
	FindDuplicates(ctx context.Context, agentID string, since time.Time, fingerprints []string) (map[string]string, error)
	BumpDuplicate(ctx context.Context, id string, at time.Time) error
	ByID(ctx context.Context, id string) (*domain.Alert, error)
	List(ctx context.Context, f domain.AlertFilter) ([]domain.Alert, int, error)
	UpdateStatus(ctx context.Context, id string, status domain.AlertStatus, by, note string, at time.Time) error
	CountOpenByAgent(ctx context.Context) (map[string]int, error)
	// RecycleForAllow 把命中某条白名单的未处置告警批量标记为误报（加白闭环）。
	RecycleForAllow(ctx context.Context, typ, value, by string, at time.Time) (int64, error)
	PurgeBefore(ctx context.Context, before time.Time) (int64, error)
	// IntegrityDigest 计算某时间区间内告警的完整性摘要（按 id 排序拼接后哈希）。
	// n 为参与计算的告警数；供"告警防篡改链"每日归档与校验使用。
	IntegrityDigest(ctx context.Context, start, end time.Time) (digest string, n int, err error)
	// IntegrityDays 返回完整性链中已归档的日期列表（升序）。
	IntegrityDays(ctx context.Context) ([]string, error)
	// IntegrityGet 读取某日归档；exists=false 表示未归档。
	IntegrityGet(ctx context.Context, day string) (digest string, n int, exists bool, err error)
	// IntegrityPut 归档某日摘要（幂等：已存在则跳过）。
	IntegrityPut(ctx context.Context, day, digest string, n int) error
	// ListInventoryChanges 返回某终端的资产变更事件（inventory 层信号告警）。
	// 证据列是 JSON，按层标记做 LIKE 定位——主机内事件量小，可接受。
	ListInventoryChanges(ctx context.Context, agentID string, limit int) ([]domain.Alert, error)
}

// IncidentRepo 事件（告警聚类 + 处置状态机）数据访问。
type IncidentRepo interface {
	// UpsertBatch 同步聚类结果：不存在或仍处 open 的事件整体覆盖，
	// 已被人工处置的只刷新观测字段（状态/时间戳/备注保留）。
	UpsertBatch(ctx context.Context, items []domain.Incident) error
	List(ctx context.Context, status string, page, pageSize int) ([]domain.Incident, int, error)
	ByID(ctx context.Context, id string) (*domain.Incident, error)
	// UpdateStatus 推进状态机：首次离开 open 记 first_action_at（MTTA），
	// 进入 resolved 记 resolved_at。
	UpdateStatus(ctx context.Context, id string, status domain.IncidentStatus, note string, at time.Time) error
	CountByStatus(ctx context.Context) (map[string]int, error)
	// AvgFirstActionMinutes 事件创建→首次人工动作的平均分钟数（MTTA）。
	AvgFirstActionMinutes(ctx context.Context, since time.Time) (float64, error)
}

// RuleRepo 规则数据访问。
type RuleRepo interface {
	List(ctx context.Context) ([]domain.Rule, error)
	ListEnabled(ctx context.Context) ([]domain.Rule, error)
	ByID(ctx context.Context, id string) (*domain.Rule, error)
	Upsert(ctx context.Context, r *domain.Rule) error
	Delete(ctx context.Context, id string) error
	MaxVersion(ctx context.Context) (int, error)
}

// ObserveRepo 命中计数快照数据访问（rule/ioc/allow 三张同构表共用）。
// 计数是探针运行期快照（重启清零），按心跳整包替换——它回答的是
// "此刻在现网会命中多少"，不是历史总量（历史总量交给告警表）。
type ObserveRepo interface {
	// ReplaceForAgent 用探针上报的快照整体替换该终端的计数行：
	// 上报里没有的 key（已转正/已删除）对应行会被删除，
	// 防止残留计数虚高汇总。
	ReplaceForAgent(ctx context.Context, agentID string, stats map[string]int64, at time.Time) error
	// SumByKey 跨终端汇总：key → 全部终端当前命中之和。
	SumByKey(ctx context.Context) (map[string]int64, error)
}

// IntelRepo 非哈希威胁情报（ip/path/keyword）数据访问。
type IntelRepo interface {
	List(ctx context.Context, typ string) ([]domain.IntelItem, error)
	ByID(ctx context.Context, id string) (*domain.IntelItem, error)
	ByValue(ctx context.Context, typ, value string) (*domain.IntelItem, error)
	Add(ctx context.Context, e *domain.IntelItem) error
	Delete(ctx context.Context, id string) error
	Count(ctx context.Context) (int, error)
	// Version 读取情报版本（settings.intel_version，随内容变更递增）。
	// 规则包版本取 max(rules.MaxVersion, intel.Version)——情报随规则包
	// 下发，情报变更必须能推动探针重拉。
	Version(ctx context.Context) (int, error)
	// BumpVersion 递增情报版本，floor 是版本下限（调用方传当前规则
	// MaxVersion）：情报版本低于规则版本时，max() 口径会让 ETag 不变、
	// 探针永远拉不到新情报（实测踩过）——因此 bump 必须越过下限。
	BumpVersion(ctx context.Context, floor int) (int, error)
}

// AllowlistRepo 白名单数据访问。
type AllowlistRepo interface {
	List(ctx context.Context) ([]domain.AllowlistEntry, error)
	Add(ctx context.Context, e *domain.AllowlistEntry) error
	Delete(ctx context.Context, id string) error
	Exists(ctx context.Context, typ, value string) (bool, error)
	BumpHit(ctx context.Context, typ, value string) error
}

// IocRepo 威胁指标数据访问。
type IocRepo interface {
	List(ctx context.Context) ([]domain.IOC, error)
	ByHash(ctx context.Context, hash string) (*domain.IOC, error)
	Add(ctx context.Context, e *domain.IOC) error
	Delete(ctx context.Context, id string) error
	Count(ctx context.Context) (int, error)
	// Version 读取 IOC 库版本（settings 单调计数，随内容变更递增）。
	Version(ctx context.Context) (int, error)
	// BumpVersion 版本 +1 并返回新值（下发端据此判断终端是否需要重拉）。
	BumpVersion(ctx context.Context) (int, error)
}

// AuditRepo 审计日志。
type AuditRepo interface {
	Add(ctx context.Context, l *domain.AuditLog) error
	List(ctx context.Context, limit int) ([]domain.AuditLog, error)
	// EnableSeal 注入防篡改链密钥并回填未封印的历史行（返回回填条数）。
	// 幂等：重复调用只更新密钥，已封印行不动。
	EnableSeal(ctx context.Context, key []byte) (int, error)
	// VerifyChain 全链校验：逐行重算 HMAC、检查序号连续性与锚点一致性。
	VerifyChain(ctx context.Context) (domain.AuditChainReport, error)
}

// CommandRepo 终端指令。
type CommandRepo interface {
	Create(ctx context.Context, c *domain.AgentCommand) error
	PendingForAgent(ctx context.Context, agentID string, limit int) ([]domain.AgentCommand, error)
	MarkDelivered(ctx context.Context, ids []string, at time.Time) error
	Complete(ctx context.Context, id, status, result string, at time.Time) error
	ListRecent(ctx context.Context, limit int) ([]domain.AgentCommand, error)
	// ListByAgentType 按终端+类型分页查询（检测演练报告从 type=drill 的
	// 指令回执里投影，复用同一张表，不建新表）；返回该过滤条件下的总数。
	ListByAgentType(ctx context.Context, agentID, typ string, offset, limit int) ([]domain.AgentCommand, int, error)
}

// InventoryRepo 主机资产清单数据访问。
// 探针按节上报（节名白名单见服务层），服务端不解析 payload 内容；
// hash 幂等去重在服务层做（读现值比对），仓储只负责存取。
type InventoryRepo interface {
	Upsert(ctx context.Context, agentID string, s domain.HostInventorySection) error
	ListByAgent(ctx context.Context, agentID string) ([]domain.HostInventorySection, error)
	DeleteByAgent(ctx context.Context, agentID string) error
}

// StatsRepo 聚合统计。
type StatsRepo interface {
	Dashboard(ctx context.Context, since time.Time, bucketMinutes int) (*domain.DashboardSummary, error)
	VersionDist(ctx context.Context) (map[string]int, error)
	// MitreAgg 按技术编号聚合时间窗内的告警计数（供 ATT&CK 矩阵）。
	// 存储侧 mitre 是 CSV 列，本方法在应用层拆分合并。
	// 第二个返回值是窗口内"带 MITRE 编号的告警条数"（一条告警可命中
	// 多个技术，按技术求和会重复计数，告警数必须单独统计）。
	MitreAgg(ctx context.Context, since time.Time) (agg map[string]domain.MitreAgg, alertTotal int, err error)
}
