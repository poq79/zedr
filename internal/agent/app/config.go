package agentapp

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"zedr/internal/platform/config"
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

	// Collector 选择进程采集引擎：auto / ntquery / toolhelp
	Collector     string
	ScanInterval  time.Duration
	FullRescan    time.Duration
	MaxHashMB     int64
	OfflineQueue  int
	KillEnabled   bool
	// QuarantineEnabled 控制是否执行文件隔离指令。
	// 与 KillEnabled 同一套双层开关先例：服务端、终端都要显式打开，
	// 隔离动作才会真正执行——现场排障时可以只关终端侧。
	QuarantineEnabled bool
	BaselineLearn bool
	Warmup        time.Duration
	HeartbeatSec  int

	// PersistCheck 是自启动项（持久化）扫描间隔。
	// 比进程扫描慢一个数量级即可——自启动项的变化频率远低于进程创建。
	PersistCheck time.Duration
	// FileWatch 控制是否启用文件落地监控（落地即执行关联检测的依据）。
	FileWatch bool
	// USNCatchup 开启后，启动时用 NTFS USN Journal 补采探针停机期间的
	// 文件落地事件（升级/重启/崩溃窗口）。需要管理员权限与 NTFS；
	// 任一条件不满足时只记 warn，不影响 ReadDirectoryChangesW 主路径。
	USNCatchup bool
	// AdaptiveScan 开启后，空闲时段自动降低扫描频率以节省 CPU。
	// 代价是空闲时段漏检短命进程的概率上升；活跃时会立刻回到基础间隔。
	AdaptiveScan bool
	// LocalToken 是本地接口（桌面 UI 对接）的访问令牌，启动时自动生成。
	LocalToken string
	// RuleSignKey 非空时强制校验下发规则包的 HMAC 签名。
	// 需与服务端 HG_SERVER_RULE_SIGN_KEY 一致；留空则不校验（仅记录告警）。
	RuleSignKey string
	// InventoryEnabled 控制资产清单快照循环（system/adapters/listeners/
	// services/tasks/startup/agent 及 defender/firewall/accounts 三节，差量上报）。
	// 清单采集（服务/任务/网卡枚举）本身有成本，且老服务端没有对应端点
	// 时上报只会持续报错——现场可整体关闭。
	InventoryEnabled bool
	// UpgradeEnabled 控制是否接受服务端下发的自升级指令（self_upgrade）。
	// 升级包走"清单 HMAC 签名（upgv1 域，密钥同 HG_AGENT_RULE_SIGN_KEY）
	// + 下载后 sha256 校验"双重把关，换装在进程退出后的重启中完成。
	// 默认 false：替换自身二进制是探针所有能力里信任要求最高的一类，
	// 必须现场显式开启，且与 terminate/quarantine 同一套双层开关纪律。
	UpgradeEnabled bool
	// TunnelEnabled 控制是否维持到服务端的实时隧道（docs/LIVE-TUNNEL.md）：
	// 只读调查通道（文件浏览/进程/连接实时查询）。零监听、纯出站长连接，
	// 服务端经隧道发起请求、探针只读应答；关闭后实时查询退化为
	// "隧道未连接"，心跳/上报等既有链路不受影响。
	TunnelEnabled bool
	// ReconProbe 控制资产侦查（/recon）是否做主动探测：对回环监听端口
	// 发只读 GET/PING 以判定产品与认证状态（仅 127.0.0.1/::1，无凭据、
	// 2s 超时、≤64KB 读取）。false = 纯被动模式（仅进程/端口/配置推断），
	// 用于对"零主动探测"有硬要求的现场。
	ReconProbe bool
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

	c.Collector = l.Env("HG_AGENT_COLLECTOR", "auto")
	c.ScanInterval = l.Duration("HG_AGENT_SCAN_INTERVAL", 2*time.Second)
	c.FullRescan = l.Duration("HG_AGENT_FULL_RESCAN", 15*time.Minute)
	c.MaxHashMB = int64(l.Int("HG_AGENT_MAX_HASH_MB", 64))
	c.OfflineQueue = l.Int("HG_AGENT_OFFLINE_QUEUE", 5000)
	c.KillEnabled = l.Bool("HG_AGENT_KILL_ENABLED", false)
	c.QuarantineEnabled = l.Bool("HG_AGENT_QUARANTINE_ENABLED", false)
	c.BaselineLearn = l.Bool("HG_AGENT_BASELINE_LEARN", true)
	c.Warmup = l.DurationZeroOK("HG_AGENT_WARMUP", 5*time.Minute) // 允许 0 = 关闭静默期
	c.HeartbeatSec = l.Int("HG_AGENT_HEARTBEAT_SEC", 30)
	c.PersistCheck = l.Duration("HG_AGENT_PERSIST_INTERVAL", 5*time.Minute)
	c.FileWatch = l.Bool("HG_AGENT_FILEWATCH", true)
	c.USNCatchup = l.Bool("HG_AGENT_USN_CATCHUP", true)
	c.AdaptiveScan = l.Bool("HG_AGENT_ADAPTIVE_SCAN", true)
	c.RuleSignKey = l.Env("HG_AGENT_RULE_SIGN_KEY", "")
	c.InventoryEnabled = l.Bool("HG_AGENT_INVENTORY", true)
	c.UpgradeEnabled = l.Bool("HG_AGENT_UPGRADE_ENABLED", false)
	c.TunnelEnabled = l.Bool("HG_AGENT_TUNNEL_ENABLED", true)
	c.ReconProbe = l.Bool("HG_AGENT_RECON_PROBE", true)

	// 校验
	l.Check(c.ServerURL != "", "HG_AGENT_SERVER_URL 不能为空")
	l.Check(strings.HasPrefix(c.ServerURL, "http://") || strings.HasPrefix(c.ServerURL, "https://"),
		"HG_AGENT_SERVER_URL 必须以 http:// 或 https:// 开头")
	l.Check(c.Collector == "auto" || c.Collector == "ntquery" || c.Collector == "toolhelp",
		"HG_AGENT_COLLECTOR 只能是 auto / ntquery / toolhelp")
	l.Check(c.ScanInterval >= 500*time.Millisecond, "HG_AGENT_SCAN_INTERVAL 不能小于 500ms（避免采集拖垮主机）")
	l.Check(c.ScanInterval <= 60*time.Second, "HG_AGENT_SCAN_INTERVAL 不建议大于 60s（会漏掉短命进程）")
	l.Check(c.FullRescan >= 1*time.Minute, "HG_AGENT_FULL_RESCAN 建议 >= 1m")
	l.Check(c.OfflineQueue >= 100, "HG_AGENT_OFFLINE_QUEUE 至少 100")
	l.Check(c.HeartbeatSec >= 5, "HG_AGENT_HEARTBEAT_SEC 至少 5 秒")
	l.Check(c.PersistCheck >= 30*time.Second, "HG_AGENT_PERSIST_INTERVAL 至少 30s（枚举注册表本身有成本）")

	if strings.EqualFold(c.Env, "production") && c.KillEnabled {
		l.SecurityWarning(false, "已启用主动终止进程能力（HG_AGENT_KILL_ENABLED），请确认这是预期行为")
	}
	if strings.EqualFold(c.Env, "production") && c.QuarantineEnabled {
		l.SecurityWarning(false, "已启用文件隔离能力（HG_AGENT_QUARANTINE_ENABLED），请确认这是预期行为")
	}
	if strings.EqualFold(c.Env, "production") && c.UpgradeEnabled {
		l.SecurityWarning(false, "已启用探针自升级（HG_AGENT_UPGRADE_ENABLED），探针将接受服务端推送的二进制并自动换装，请确认这是预期行为")
	}

	if err := l.Err(); err != nil {
		return nil, err
	}

	if err := os.MkdirAll(c.DataDir, 0o750); err != nil {
		return nil, fmt.Errorf("创建数据目录 %s 失败: %w", c.DataDir, err)
	}
	return c, nil
}

// defaultDataDir 默认落在 %LOCALAPPDATA%\zedr，避免污染用户目录。
func defaultDataDir() string {
	if v := os.Getenv("LOCALAPPDATA"); v != "" {
		return filepath.Join(v, "zedr")
	}
	return `C:\ProgramData\zedr`
}

// Path 返回数据目录下的文件路径。
func (c *Config) Path(name string) string { return filepath.Join(c.DataDir, name) }
