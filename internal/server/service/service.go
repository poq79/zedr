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
	// OpenAlertTTL 是超期 open 告警自动归档为 acknowledged 的时限。
	// 0 = 禁用（默认）：自动替值班人员做"不重要"的决定必须显式打开。
	OpenAlertTTL time.Duration

	// AIBootstrap 是环境变量引导的 AI 引擎配置：后台未保存过配置时它是
	// 生效配置，保存过则以配置中心为准。传进来只为展示与回退，不改写。
	AIBootstrap ai.Config

	// SettingEncKey 是后台配置敏感字段的静态加密密钥（AES-256-GCM）。
	// 为 nil 时后台无法保存含密钥的配置（Get/Save 返回明确错误）。
	SettingEncKey []byte
}

// Services 汇总所有业务服务。
type Services struct {
	Auth     *AuthService
	Agent    *AgentService
	Alert    *AlertService
	Rule     *RuleService
	Audit    *AuditService
	Stats    *StatsService
	Incident *IncidentService
	Bus      *AlertBus
	AI       *AIService
}

// New 组装服务集合（依赖注入：仓储 + 令牌管理器 + 配置 + 日志）。
func New(repos repository.Repos, tokens *auth.Manager, cfg Config, log *slog.Logger, aiEngine *ai.Engine) *Services {
	if cfg.DupWindow <= 0 {
		cfg.DupWindow = 5 * time.Minute
	}
	bus := NewAlertBus()

	return &Services{
		Auth:     &AuthService{repos: repos, tokens: tokens, log: log},
		Agent:    &AgentService{repos: repos, cfg: cfg, log: log},
		Alert:    &AlertService{repos: repos, cfg: cfg, log: log, bus: bus},
		Rule:     &RuleService{repos: repos, log: log},
		Audit:    &AuditService{repos: repos},
		Stats:    &StatsService{repos: repos},
		Incident: &IncidentService{repos: repos, cfg: cfg, log: log},
		Bus:      bus,
		AI:       &AIService{repos: repos, eng: aiEngine, log: log, cfg: cfg, bootstrap: cfg.AIBootstrap, encKey: cfg.SettingEncKey},
	}
}
