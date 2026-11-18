// Package service 承载服务端业务逻辑。
//
// 约束：本层不依赖 net/http，不感知请求/响应对象，只接收普通参数并返回领域对象；
// 这样服务层可以被单元测试直接驱动，也可以在 CLI 或定时任务中复用。
package service

import (
	"log/slog"
	"time"

	"zedr/internal/ai"
	"zedr/internal/server/auth"
	"zedr/internal/server/repository"
)

// Config 是服务层可调参数。
type Config struct {
	EnrollToken       string // 终端注册预共享令牌
	KillEnabled       bool   // 是否允许下发终止进程指令
	QuarantineEnabled bool   // 是否允许下发文件隔离/恢复指令
	// DrillEnabled 是检测演练指令（type=drill）的服务端闸门：演练会让
	// 探针在目标机器上执行受控自测（自造样本、零真实恶意内容），只在
	// 交付验收/升级回归场景显式打开。终端侧还有 HG_AGENT_DRILL_ENABLED
	// 第二道闸，单侧误开不会真的跑起来。
	DrillEnabled bool // 是否允许下发检测演练指令
	// UpgradeEnabled 是探针自升级指令（type=self_upgrade）的服务端闸门：
	// 升级会让探针进程退出重启（服务模式由 SCM 拉起新版本），且版本只升不降、
	// 方向不可逆。与 drill 同纪律：服务端总开关 + 终端侧 HG_AGENT_UPGRADE_ENABLED
	// 第二道闸，单侧误开不会真的换装。物料（升级包路径/版本）另行配置。
	UpgradeEnabled bool
	// UpgradeWaveSize/WaveTimeout 是批量升级编排的波次参数（0=服务内默认
	// 10 台 / 10min）：波次越小爆炸半径越小，但批次拖得越长——按舰队规模
	// 与维护窗口权衡。
	UpgradeWaveSize    int
	UpgradeWaveTimeout time.Duration
	// SensorOfflineAlerts/Severity 是传感器失联告警（SEN-OFFLINE）的开关
	// 与严重度，语义见 app.Config 同名字段注释。
	SensorOfflineAlerts   bool
	SensorOfflineSeverity string
	HeartbeatInterval     time.Duration // 心跳间隔（下发给终端）
	ScanInterval          time.Duration // 采集间隔（下发给终端）
	DupWindow             time.Duration // 同指纹告警聚合窗口
	RetentionDays         int           // 处置完成告警的保留天数
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
	Sensor   *SensorWatchService
	Upgrade  *UpgradeService
	Bus      *AlertBus
	AI       *AIService
}

// New 组装服务集合（依赖注入：仓储 + 令牌管理器 + 配置 + 日志）。
func New(repos repository.Repos, tokens *auth.Manager, cfg Config, log *slog.Logger, aiEngine *ai.Engine) *Services {
	if cfg.DupWindow <= 0 {
		cfg.DupWindow = 5 * time.Minute
	}
	bus := NewAlertBus()
	sensor := &SensorWatchService{repos: repos, bus: bus, cfg: cfg, log: log}
	agent := &AgentService{repos: repos, cfg: cfg, log: log, sensor: sensor}

	return &Services{
		Auth:     &AuthService{repos: repos, tokens: tokens, log: log},
		Agent:    agent,
		Alert:    &AlertService{repos: repos, cfg: cfg, log: log, bus: bus},
		Rule:     &RuleService{repos: repos, log: log},
		Audit:    &AuditService{repos: repos},
		Stats:    &StatsService{repos: repos},
		Incident: &IncidentService{repos: repos, cfg: cfg, log: log},
		Sensor:   sensor,
		Upgrade:  NewUpgradeService(repos, cfg, agent, log),
		Bus:      bus,
		AI:       &AIService{repos: repos, eng: aiEngine, log: log, cfg: cfg, bootstrap: cfg.AIBootstrap, encKey: cfg.SettingEncKey},
	}
}
