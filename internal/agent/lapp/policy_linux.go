//go:build linux

// 服务端策略与 CPU 采样（Linux 口径），与 Windows 版 app.go 的对应实现
// 逐行同构。未在 Linux 实机验证。
package lapp

import (
	"encoding/json"
	"os"
	"runtime"
	"time"

	"zedr/internal/model"
)

// policyFile 是 policy.json 的落盘形态（采集器冷生效策略）。
type policyFile struct {
	Collector string `json:"collector"`
}

// applyServerPolicy 应用服务端统一下发的探针运行策略。
// 环境变量显式配置优先：服务端不能覆盖现场排障时手工改的值，
// 否则现场排障时想临时改个参数都会被服务端悄悄改回去。
// scan interval 热生效；collector 需要重建采集器，缓存后冷生效。
func (a *Agent) applyServerPolicy(p *model.AgentPolicy) {
	if p == nil {
		return
	}
	if p.ScanIntervalSec >= 2 {
		if _, explicit := os.LookupEnv("HG_AGENT_SCAN_INTERVAL"); !explicit {
			a.policyInterval.Store(int64(time.Duration(p.ScanIntervalSec) * time.Second))
			a.log.Info("policy_scan_interval_applied", "sec", p.ScanIntervalSec)
		}
	}
	if p.Collector != "" && p.Collector != a.coll.SourceName() {
		if _, explicit := os.LookupEnv("HG_AGENT_COLLECTOR"); !explicit {
			switch p.Collector {
			case "auto", "procfs":
				if err := saveCollectorPolicy(a.cfg.Path("policy.json"), p.Collector); err != nil {
					a.log.Warn("policy_collector_save_failed", "err", err)
				} else {
					a.log.Warn("policy_collector_pending_restart", "collector", p.Collector,
						"hint", "采集引擎需重启探针后切换")
				}
			default:
				a.log.Warn("policy_collector_invalid", "collector", p.Collector)
			}
		}
	}
}

// readCollectorPolicy 读采集器冷生效策略（policy.json）。
func readCollectorPolicy(path string) string {
	raw, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	var pf policyFile
	if json.Unmarshal(raw, &pf) != nil {
		return ""
	}
	return pf.Collector
}

func saveCollectorPolicy(path, collector string) error {
	raw, err := json.Marshal(policyFile{Collector: collector})
	if err != nil {
		return err
	}
	return os.WriteFile(path, raw, 0o600)
}

// baseInterval 返回当前应使用的扫描基础间隔：服务端策略（热生效）>
// 本地配置。自适应退避在 Linux v1 未启用（诚实边界，Windows 有）。
func (a *Agent) baseInterval() time.Duration {
	if v := a.policyInterval.Load(); v > 0 {
		return time.Duration(v)
	}
	return a.cfg.ScanInterval
}

// cpuSample 从 /proc/stat 两次采样计算本进程的 CPU 占用（百分比，
// 相对全部核心）。Windows 用 winapi.CPUSampler（GetProcessTimes 差分），
// Linux 用 /proc/self/stat 的 utime+stime tick 差分（USER_HZ=100）。
// 采样间隔由 scanLoop 的调用节奏决定（每轮一次）。
type cpuSampler struct {
	lastJiffies uint64
	lastWall    time.Time
}

// sample 返回自上次调用以来的进程 CPU 占用百分比（0..100*N 无归一——
// 与 Windows 版同口径：占用相对单核，多核满载可超 100）。
func (c *cpuSampler) sample() float64 {
	data, err := os.ReadFile("/proc/self/stat")
	if err != nil {
		return 0
	}
	// stat 的 utime(14)/stime(15) 在 comm 之后（同 collect 解析口径：
	// 最后一个 ')' 之后切字段），utime=rest[11]、stime=rest[12]
	s := string(data)
	l := lastIndexByte(s, ')')
	if l < 0 || l+2 > len(s) {
		return 0
	}
	fields := splitFields(s[l+2:])
	if len(fields) < 13 {
		return 0
	}
	ut := parseU64(fields[11])
	st := parseU64(fields[12])
	now := time.Now()
	jiffies := ut + st
	defer func() {
		c.lastJiffies = jiffies
		c.lastWall = now
	}()
	if c.lastWall.IsZero() || jiffies < c.lastJiffies {
		return 0 // 首轮无基线（或时钟回拨），诚实 0
	}
	elapsed := now.Sub(c.lastWall).Seconds()
	if elapsed <= 0 {
		return 0
	}
	const userHZ = 100 // userspace ABI 冻结值
	return float64(jiffies-c.lastJiffies) / userHZ / elapsed * 100
}

// lastIndexByte/splitFields/parseU64 是小工具（collect 包的解析是私有
// 的，这里只需要极简形态，不为此引依赖）。
func lastIndexByte(s string, b byte) int {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == b {
			return i
		}
	}
	return -1
}

func splitFields(s string) []string {
	out := make([]string, 0, 32)
	start := -1
	for i := 0; i < len(s); i++ {
		if s[i] == ' ' || s[i] == '\t' || s[i] == '\n' {
			if start >= 0 {
				out = append(out, s[start:i])
				start = -1
			}
			continue
		}
		if start < 0 {
			start = i
		}
	}
	if start >= 0 {
		out = append(out, s[start:])
	}
	return out
}

func parseU64(s string) uint64 {
	var n uint64
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return n
		}
		n = n*10 + uint64(s[i]-'0')
	}
	return n
}

// 确认 runtime 引用不悬空（mem 统计在 scan 里用）。
var _ = runtime.NumCPU
