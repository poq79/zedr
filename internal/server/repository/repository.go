// Package repository 定义数据访问契约（仓储层接口）。
//
// 服务层只依赖这些接口，从而可以在单测里用内存实现替换真实数据库，
// 也可以在集成测试里直接连真实 SQLite。
package repository

import (
	"context"
	"time"

	"hostguard/internal/server/domain"
)

// Repos 汇总所有仓储。
type Repos struct {
	Users     UserRepo
	Tokens    TokenRepo
	Agents    AgentRepo
	Alerts    AlertRepo
	Rules     RuleRepo
	Allowlist AllowlistRepo
	IOCs      IocRepo
	Audit     AuditRepo
	Commands  CommandRepo
	Stats     StatsRepo
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
}

// CommandRepo 终端指令。
type CommandRepo interface {
	Create(ctx context.Context, c *domain.AgentCommand) error
	PendingForAgent(ctx context.Context, agentID string, limit int) ([]domain.AgentCommand, error)
	MarkDelivered(ctx context.Context, ids []string, at time.Time) error
	Complete(ctx context.Context, id, status, result string, at time.Time) error
	ListRecent(ctx context.Context, limit int) ([]domain.AgentCommand, error)
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
