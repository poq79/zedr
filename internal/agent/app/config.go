package agentapp

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"hostguard/internal/platform/config"
)

// Config 是探针全部运行时配置（只来自环境变量）。
type Config struct {
	Env       string
	LogLevel  string
	LogFormat string

	ServerURL   string
	EnrollToken string
	DataDir     string
	LocalAddr   string
	Tags        []string
	Version     string

	ScanInterval  time.Duration
	FullRescan    time.Duration
	MaxHashMB     int64
	OfflineQueue  int
	KillEnabled   bool
	BaselineLearn bool
	Warmup        time.Duration
	HeartbeatSec  int
}

// LoadConfig 读取并校验配置。
func LoadConfig(version string) (*Config, error) {
	var l config.Loader
	c := &Config{Version: version}

	c.Env = l.Env("HG_ENV", "development")
	c.LogLevel = l.Env("HG_LOG_LEVEL", "info")
	c.LogFormat = l.Env("HG_LOG_FORMAT", "json")

	c.ServerURL = l.Env("HG_AGENT_SERVER_URL", "http://127.0.0.1:8080")
	c.EnrollToken = l.Env("HG_AGENT_ENROLL_TOKEN", "")
	c.DataDir = l.Env("HG_AGENT_DATA_DIR", defaultDataDir())
	c.LocalAddr = l.Env("HG_AGENT_LOCAL_ADDR", "127.0.0.1:8843")
	c.Tags = l.CSV("HG_AGENT_TAGS", nil)

	c.ScanInterval = l.Duration("HG_AGENT_SCAN_INTERVAL", 2*time.Second)
	c.FullRescan = l.Duration("HG_AGENT_FULL_RESCAN", 15*time.Minute)
	c.MaxHashMB = int64(l.Int("HG_AGENT_MAX_HASH_MB", 64))
	c.OfflineQueue = l.Int("HG_AGENT_OFFLINE_QUEUE", 5000)
	c.KillEnabled = l.Bool("HG_AGENT_KILL_ENABLED", false)
	c.BaselineLearn = l.Bool("HG_AGENT_BASELINE_LEARN", true)
	c.Warmup = l.DurationZeroOK("HG_AGENT_WARMUP", 5*time.Minute) // 允许 0 = 关闭静默期
	c.HeartbeatSec = l.Int("HG_AGENT_HEARTBEAT_SEC", 30)

	// 校验
	l.Check(c.ServerURL != "", "HG_AGENT_SERVER_URL 不能为空")
	l.Check(strings.HasPrefix(c.ServerURL, "http://") || strings.HasPrefix(c.ServerURL, "https://"),
		"HG_AGENT_SERVER_URL 必须以 http:// 或 https:// 开头")
	l.Check(c.ScanInterval >= 500*time.Millisecond, "HG_AGENT_SCAN_INTERVAL 不能小于 500ms（避免采集拖垮主机）")
	l.Check(c.ScanInterval <= 60*time.Second, "HG_AGENT_SCAN_INTERVAL 不建议大于 60s（会漏掉短命进程）")
	l.Check(c.FullRescan >= 1*time.Minute, "HG_AGENT_FULL_RESCAN 建议 >= 1m")
	l.Check(c.OfflineQueue >= 100, "HG_AGENT_OFFLINE_QUEUE 至少 100")
	l.Check(c.HeartbeatSec >= 5, "HG_AGENT_HEARTBEAT_SEC 至少 5 秒")

	if strings.EqualFold(c.Env, "production") && c.KillEnabled {
		l.SecurityWarning(false, "已启用主动终止进程能力（HG_AGENT_KILL_ENABLED），请确认这是预期行为")
	}

	if err := l.Err(); err != nil {
		return nil, err
	}

	if err := os.MkdirAll(c.DataDir, 0o750); err != nil {
		return nil, fmt.Errorf("创建数据目录 %s 失败: %w", c.DataDir, err)
	}
	return c, nil
}

// defaultDataDir 默认落在 %LOCALAPPDATA%\HostGuard，避免污染用户目录。
func defaultDataDir() string {
	if v := os.Getenv("LOCALAPPDATA"); v != "" {
		return filepath.Join(v, "HostGuard")
	}
	return `C:\ProgramData\HostGuard`
}

// Path 返回数据目录下的文件路径。
func (c *Config) Path(name string) string { return filepath.Join(c.DataDir, name) }
