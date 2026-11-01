// Package app 组装服务端运行时：配置 → 存储 → 服务 → 路由 → 后台任务。
package app

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"hostguard/internal/platform/config"
)

// Config 是服务端全部运行时配置（只来自环境变量）。
type Config struct {
	Env       string
	LogLevel  string
	LogFormat string

	Addr            string
	DBPath          string
	CORSOrigins     []string
	RuleSignKey  string // 规则包签名密钥；空则从 JWTSecret 派生

	// Webhook 告警推送：URL 为空表示不启用。
	WebhookURL        string
	WebhookSecret     string        // HMAC-SHA256 签名密钥（X-HG-Signature 头）
	WebhookTimeout    time.Duration
	WebhookMinSeverity string       // 只推送不低于该严重度的告警（治理通知风暴）
	SyslogAddr         string       // CEF over UDP；空则不启用

	// 下发给所有终端的运行策略（随规则包走，零值=不干预终端本地配置）
	AgentPolicyScanInterval time.Duration
	AgentPolicyCollector    string

	// AI 推理后端配置。Provider=none 时只用确定性启发式分析。
	AIProvider    string
	AIBaseURL     string
	AIAPIKey      string
	AIModel       string
	AITimeout     time.Duration
	AITokenBudget int
	JWTSecret       string
	AccessTTL       time.Duration
	RefreshTTL      time.Duration
	CookieSecure    bool
	BootstrapUser   string
	BootstrapPass   string
	EnrollToken     string
	RateRPS         float64
	LoginRPS    float64
	LoginBurst  float64
	RateBurst       float64
	KillEnabled     bool
	RetentionDays   int
	DupWindow       time.Duration // 同指纹告警聚合窗口
	HeartbeatSec    int
	ScanSec         int
	ShutdownTimeout time.Duration
}

// LoadConfig 读取并集中校验配置；任何非法项都会让进程启动即失败。
func LoadConfig() (*Config, error) {
	var l config.Loader
	c := &Config{}

	c.Env = l.Env("HG_ENV", "development")
	c.LogLevel = l.Env("HG_LOG_LEVEL", "info")
	c.LogFormat = l.Env("HG_LOG_FORMAT", "json")

	c.Addr = l.Env("HG_SERVER_ADDR", "0.0.0.0:8080")
	c.DBPath = l.Env("HG_SERVER_DB_PATH", "./data/secserver.db")
	c.CORSOrigins = l.CSV("HG_SERVER_CORS_ORIGINS", []string{"http://localhost:8080", "http://127.0.0.1:8080"})
	c.JWTSecret = l.Required("HG_SERVER_JWT_SECRET")
	c.RuleSignKey = l.Env("HG_SERVER_RULE_SIGN_KEY", "")

	c.WebhookURL = l.Env("HG_SERVER_WEBHOOK_URL", "")
	c.WebhookSecret = l.Env("HG_SERVER_WEBHOOK_SECRET", "")
	c.WebhookTimeout = l.Duration("HG_SERVER_WEBHOOK_TIMEOUT", 10*time.Second)
	c.WebhookMinSeverity = l.Env("HG_SERVER_WEBHOOK_MIN_SEVERITY", "high")
	c.SyslogAddr = l.Env("HG_SERVER_SYSLOG_ADDR", "")

	c.AgentPolicyScanInterval = l.Duration("HG_AGENT_POLICY_SCAN_INTERVAL", 0)
	c.AgentPolicyCollector = l.Env("HG_AGENT_POLICY_COLLECTOR", "")
	l.Check(c.AgentPolicyCollector == "" || c.AgentPolicyCollector == "auto" ||
		c.AgentPolicyCollector == "ntquery" || c.AgentPolicyCollector == "toolhelp",
		"HG_AGENT_POLICY_COLLECTOR 只能是 auto/ntquery/toolhelp")

	c.AIProvider = l.Env("HG_AI_PROVIDER", "none")
	c.AIBaseURL = l.Env("HG_AI_BASE_URL", "")
	c.AIAPIKey = l.Env("HG_AI_API_KEY", "")
	c.AIModel = l.Env("HG_AI_MODEL", "")
	c.AITimeout = l.Duration("HG_AI_TIMEOUT", 45*time.Second)
	c.AITokenBudget = l.Int("HG_AI_HOURLY_TOKEN_BUDGET", 200000)
	c.AccessTTL = l.Duration("HG_SERVER_ACCESS_TTL", 15*time.Minute)
	c.RefreshTTL = l.Duration("HG_SERVER_REFRESH_TTL", 168*time.Hour)
	c.CookieSecure = l.Bool("HG_SERVER_COOKIE_SECURE", false)
	c.BootstrapUser = l.Env("HG_SERVER_BOOTSTRAP_USER", "admin")
	c.BootstrapPass = l.Env("HG_SERVER_BOOTSTRAP_PASSWORD", "")
	c.EnrollToken = l.Env("HG_SERVER_ENROLL_TOKEN", "")
	c.RateRPS = l.Float("HG_SERVER_RATE_LIMIT_RPS", 20)
	c.RateBurst = l.Float("HG_SERVER_RATE_LIMIT_BURST", 60)
	c.LoginRPS = l.Float("HG_SERVER_LOGIN_RPS", 0.5)   // 登录：约每 2 秒 1 次
	c.LoginBurst = float64(l.Int("HG_SERVER_LOGIN_BURST", 5))
	c.KillEnabled = l.Bool("HG_SERVER_KILL_ENABLED", false)
	c.RetentionDays = l.Int("HG_SERVER_RETENTION_DAYS", 30)
	c.DupWindow = l.Duration("HG_SERVER_DUP_WINDOW", 5*time.Minute) // 同指纹告警聚合窗口
	c.HeartbeatSec = l.Int("HG_SERVER_HEARTBEAT_SEC", 30)
	c.ScanSec = l.Int("HG_SERVER_SCAN_SEC", 2)
	c.ShutdownTimeout = l.Duration("HG_SERVER_SHUTDOWN_TIMEOUT", 20*time.Second)

	// 校验
	l.Check(c.WebhookMinSeverity == "low" || c.WebhookMinSeverity == "medium" ||
		c.WebhookMinSeverity == "high" || c.WebhookMinSeverity == "critical",
		"HG_SERVER_WEBHOOK_MIN_SEVERITY 只能是 low/medium/high/critical")
	l.Check(c.AIProvider == "none" || c.AIProvider == "openai",
		"HG_AI_PROVIDER 只能是 none 或 openai")
	l.Check(c.AITokenBudget >= 1000, "HG_AI_HOURLY_TOKEN_BUDGET 至少 1000")
	l.Check(len(c.JWTSecret) >= 32, "HG_SERVER_JWT_SECRET 长度必须 >= 32 字节（可用 openssl rand -hex 32 生成）")
	l.Check(c.RefreshTTL > c.AccessTTL, "HG_SERVER_REFRESH_TTL 必须大于 HG_SERVER_ACCESS_TTL")
	l.Check(c.AccessTTL <= 30*time.Minute, "HG_SERVER_ACCESS_TTL 建议不超过 30 分钟（短时效访问令牌）")
	l.Check(c.HeartbeatSec >= 5 && c.HeartbeatSec <= 600, "HG_SERVER_HEARTBEAT_SEC 需在 5-600 之间")
	l.Check(c.ScanSec >= 1 && c.ScanSec <= 300, "HG_SERVER_SCAN_SEC 需在 1-300 之间")
	l.Check(c.RetentionDays >= 1, "HG_SERVER_RETENTION_DAYS 至少为 1")
	l.Check(c.Addr != "", "HG_SERVER_ADDR 不能为空")

	isProd := strings.EqualFold(c.Env, "production")
	if isProd {
		l.Check(c.CookieSecure, "生产环境必须开启 HG_SERVER_COOKIE_SECURE=true（需配合 HTTPS）")
		l.Check(len(c.CORSOrigins) > 0 && !containsWildcard(c.CORSOrigins),
			"生产环境 CORS 必须使用显式来源，禁止通配符 *")
		l.SecurityWarning(c.JWTSecret != "change-me-to-a-long-random-secret-at-least-32-bytes",
			"JWT 密钥仍是示例默认值，请更换为随机密钥")
		l.SecurityWarning(c.EnrollToken != "" && c.EnrollToken != "change-me-enroll-token",
			"终端注册令牌仍是示例默认值，请更换")
	}

	if err := l.Err(); err != nil {
		return nil, err
	}

	// 数据目录准备
	if dir := filepath.Dir(c.DBPath); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return nil, fmt.Errorf("创建数据目录 %s 失败: %w", dir, err)
		}
	}
	return c, nil
}

func containsWildcard(list []string) bool {
	for _, s := range list {
		if strings.TrimSpace(s) == "*" {
			return true
		}
	}
	return false
}
