// Package service 承载服务端业务逻辑。
//
// 约束：本层不依赖 net/http，不感知请求/响应对象，只接收普通参数并返回领域对象；
// 这样服务层可以被单元测试直接驱动，也可以在 CLI 或定时任务中复用。
package service

import (
	"log/slog"
	"time"

	"hostguard/internal/server/auth"
	"hostguard/internal/ai"
	"hostguard/internal/server/repository"
)

// Config 是服务层可调参数。
type Config struct {
	EnrollToken       string        // 终端注册预共享令牌
	KillEnabled       bool          // 是否允许下发终止进程指令
	QuarantineEnabled bool          // 是否允许下发文件隔离/恢复指令
	HeartbeatInterval time.Duration // 心跳间隔（下发给终端）
	ScanInterval      time.Duration // 采集间隔（下发给终端）
	DupWindow         time.Duration // 同指纹告警聚合窗口
	RetentionDays     int           // 处置完成告警的保留天数
}

// Services 汇总所有业务服务。
type Services struct {
	Auth  *AuthService
	Agent *AgentService
	Alert *AlertService
	Rule  *RuleService
	Audit *AuditService
	Stats *StatsService
	Bus   *AlertBus
	AI    *AIService
}

// New 组装服务集合（依赖注入：仓储 + 令牌管理器 + 配置 + 日志）。
func New(repos repository.Repos, tokens *auth.Manager, cfg Config, log *slog.Logger, aiEngine *ai.Engine) *Services {
	if cfg.DupWindow <= 0 {
		cfg.DupWindow = 5 * time.Minute
	}
	bus := NewAlertBus()

	return &Services{
		Auth:  &AuthService{repos: repos, tokens: tokens, log: log},
		Agent: &AgentService{repos: repos, cfg: cfg, log: log},
		Alert: &AlertService{repos: repos, cfg: cfg, log: log, bus: bus},
		Rule:  &RuleService{repos: repos, log: log},
		Audit: &AuditService{repos: repos},
		Stats: &StatsService{repos: repos},
		Bus:   bus,
		AI:    &AIService{repos: repos, eng: aiEngine, log: log},
	}
}
