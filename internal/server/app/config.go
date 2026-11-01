// Package app 组装服务端运行时：配置 → 存储 → 服务 → 路由 → 后台任务。
package app

import (
	"encoding/hex"
	"fmt"
	"net/mail"
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
	WebhookURL     string
	WebhookSecret  string // HMAC-SHA256 签名密钥（X-HG-Signature 头）
	WebhookTimeout time.Duration
	// WebhookMinSeverity 是全部通知渠道（webhook/syslog/飞书/钉钉/Slack/邮件）
	// 的统一严重度门槛：只推送不低于该严重度的告警（治理通知风暴）。
	// 刻意不设每渠道阈值——多套阈值会让"这台为什么没收通知"无法排查，
	// 也会让渠道之间的噪音治理口径漂移。
	WebhookMinSeverity string
	SyslogAddr         string // CEF over UDP；空则不启用

	// IM 卡片渠道与邮件通知：全部可选，对应 URL/Host 为空即禁用。
	FeishuWebhookURL   string // 飞书自定义机器人 webhook
	DingTalkWebhookURL string // 钉钉自定义机器人 webhook
	DingTalkSecret     string // 钉钉"加签"安全设置密钥；空=不加签
	SlackWebhookURL    string // Slack incoming webhook
	ConsoleURL         string // 管理台对外地址（卡片"前往处理"链接）；空=卡片只带告警 ID 占位
	SMTPHost           string
	SMTPPort           int // 默认 25
	SMTPUser           string
	SMTPPass           string
	SMTPFrom           string // 信封发件人（纯邮箱地址或 "Name <addr>"）
	AlertEmailTo       []string
	// OpenAlertTTL 超期 open 告警自动归档时限；0=禁用（默认）
	OpenAlertTTL time.Duration
	// UpgradeFile/UpgradeVersion 探针自升级包路径与版本；空=升级端点不可用
	UpgradeFile    string
	UpgradeVersion string

	// 实时隧道/实时查询（只读调查面，docs/LIVE-TUNNEL.md）。
	// LiveQueryEnabled 默认开：只读 + JWT + 全程审计，风险面低于处置类，
	// 默认关会让"开箱可分析"落空；LiveQueryFileRead 默认关——文件内容预览
	// 是该体系里信息暴露面最大的端点，与处置类同纪律，现场显式开启。
	LiveQueryEnabled  bool
	LiveQueryFileRead bool

	// 下发给所有终端的运行策略（随规则包走，零值=不干预终端本地配置）
	AgentPolicyScanInterval time.Duration
	AgentPolicyCollector    string

	// AI 推理后端配置。Provider=none 时只用确定性启发式分析。
	// 后台配置中心保存过配置后，DB 配置优先于这里的引导值。
	AIProvider    string
	AIBaseURL     string
	AIAPIKey      string
	AIModel       string
	AITimeout     time.Duration
	AITokenBudget int
	// SettingEncKey 是后台配置敏感字段（模型 API Key）的静态加密密钥，
	// 64 位 hex（32 字节）。空则从 JWTSecret 派生子密钥（与规则签名同策略）。
	SettingEncKey string
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
	QuarantineEnabled bool
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

	// IM 卡片渠道与邮件通知（全部可选；空=禁用）
	c.FeishuWebhookURL = l.Env("HG_SERVER_FEISHU_WEBHOOK_URL", "")
	c.DingTalkWebhookURL = l.Env("HG_SERVER_DINGTALK_WEBHOOK_URL", "")
	c.DingTalkSecret = l.Env("HG_SERVER_DINGTALK_SECRET", "")
	c.SlackWebhookURL = l.Env("HG_SERVER_SLACK_WEBHOOK_URL", "")
	c.ConsoleURL = l.Env("HG_SERVER_CONSOLE_URL", "")
	c.SMTPHost = l.Env("HG_SERVER_SMTP_HOST", "")
	c.SMTPPort = l.Int("HG_SERVER_SMTP_PORT", 25)
	c.SMTPUser = l.Env("HG_SERVER_SMTP_USER", "")
	c.SMTPPass = l.Env("HG_SERVER_SMTP_PASS", "")
	c.SMTPFrom = l.Env("HG_SERVER_SMTP_FROM", "")
	c.AlertEmailTo = l.CSV("HG_SERVER_ALERT_EMAIL_TO", nil)
	c.OpenAlertTTL = l.Duration("HG_SERVER_OPEN_ALERT_TTL", 0)
	c.UpgradeFile = l.Env("HG_SERVER_UPGRADE_FILE", "")
	c.UpgradeVersion = l.Env("HG_SERVER_UPGRADE_VERSION", "")
	c.LiveQueryEnabled = l.Bool("HG_SERVER_LIVEQUERY_ENABLED", true)
	c.LiveQueryFileRead = l.Bool("HG_SERVER_LIVEQUERY_FILEREAD", false)

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
	c.SettingEncKey = l.Env("HG_SERVER_SETTING_ENC_KEY", "")
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
	c.QuarantineEnabled = l.Bool("HG_SERVER_QUARANTINE_ENABLED", false)
	c.RetentionDays = l.Int("HG_SERVER_RETENTION_DAYS", 30)
	c.DupWindow = l.Duration("HG_SERVER_DUP_WINDOW", 5*time.Minute) // 同指纹告警聚合窗口
	c.HeartbeatSec = l.Int("HG_SERVER_HEARTBEAT_SEC", 30)
	c.ScanSec = l.Int("HG_SERVER_SCAN_SEC", 2)
	c.ShutdownTimeout = l.Duration("HG_SERVER_SHUTDOWN_TIMEOUT", 20*time.Second)

	// 校验
	l.Check(c.WebhookMinSeverity == "low" || c.WebhookMinSeverity == "medium" ||
		c.WebhookMinSeverity == "high" || c.WebhookMinSeverity == "critical",
		"HG_SERVER_WEBHOOK_MIN_SEVERITY 只能是 low/medium/high/critical")

	// 后台配置加密密钥：显式配置必须是 64 位 hex；空值合法（从 JWTSecret 派生）
	if ek := strings.TrimSpace(c.SettingEncKey); ek != "" {
		_, err := hex.DecodeString(ek)
		l.Check(err == nil && len(ek) == 64,
			"HG_SERVER_SETTING_ENC_KEY 必须是 64 个 hex 字符（32 字节）")
	}

	// IM 卡片与邮件渠道校验
	l.Check(c.DingTalkSecret == "" || c.DingTalkWebhookURL != "",
		"HG_SERVER_DINGTALK_SECRET 需与 HG_SERVER_DINGTALK_WEBHOOK_URL 同时配置")
	l.Check(c.ConsoleURL == "" || strings.HasPrefix(c.ConsoleURL, "http://") ||
		strings.HasPrefix(c.ConsoleURL, "https://"),
		"HG_SERVER_CONSOLE_URL 必须以 http:// 或 https:// 开头")
	l.Check(c.SMTPPort >= 1 && c.SMTPPort <= 65535, "HG_SERVER_SMTP_PORT 需在 1-65535 之间")
	l.Check((c.SMTPUser == "") == (c.SMTPPass == ""),
		"HG_SERVER_SMTP_USER 与 HG_SERVER_SMTP_PASS 必须成对配置")
	l.Check(c.SMTPHost == "" || (len(c.AlertEmailTo) > 0 && c.SMTPFrom != ""),
		"启用邮件通知需同时配置 HG_SERVER_ALERT_EMAIL_TO 与 HG_SERVER_SMTP_FROM")
	fromOK := c.SMTPFrom == ""
	if !fromOK {
		if addr, perr := mail.ParseAddress(c.SMTPFrom); perr == nil && addr != nil {
			fromOK = true
		}
	}
	l.Check(fromOK, "HG_SERVER_SMTP_FROM 不是合法邮箱地址")
	badRcpt := ""
	for _, rcpt := range c.AlertEmailTo {
		if badRcpt != "" {
			continue
		}
		if _, err := mail.ParseAddress(rcpt); err != nil {
			badRcpt = rcpt
		}
	}
	l.Check(badRcpt == "", "HG_SERVER_ALERT_EMAIL_TO 含非法邮箱地址: "+badRcpt)
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
		l.SecurityWarning(!c.LiveQueryFileRead,
			"已启用实时文件内容预览（HG_SERVER_LIVEQUERY_FILEREAD），管理端可读取终端文件内容，请确认这是预期行为")
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
