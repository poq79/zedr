// Command zedr-agent 是 Z-EDR 终端探针。
//
// 用法：
//
//	zedr-agent                 前台运行（适合调试，Ctrl+C 退出）
//	zedr-agent -service        作为 Windows 服务运行（由 SCM 启动时使用）
//	zedr-agent -install        安装为开机自启的 Windows 服务（需管理员）
//	zedr-agent -uninstall      卸载服务（需管理员）
//	zedr-agent -version        打印版本
package main

import (
	"path/filepath"
	"strings"
	"encoding/json"
	"net/http"
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"runtime/debug"
	"strconv"
	"syscall"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"

	agentapp "zedr/internal/agent/app"
	"zedr/internal/platform/config"
)

const serviceName = "ZEDRAgent"

// version 由构建脚本通过 -ldflags -X main.version 注入。
var version = "dev"

func main() {
	var (
		flagService   = flag.Bool("service", false, "以 Windows 服务方式运行")
		flagInstall   = flag.Bool("install", false, "安装为 Windows 服务")
		flagUninstall = flag.Bool("uninstall", false, "卸载 Windows 服务")
		flagPurge     = flag.Bool("purge", false, "配合 -uninstall：同时删除数据目录（基线/队列/本地令牌）")
		flagVersion   = flag.Bool("version", false, "打印版本")
		flagStatus    = flag.Bool("status", false, "查看本机探针运行状态（服务器/SSH 场景无需打开界面）")
	)
	flag.Parse()

	if *flagVersion {
		fmt.Printf("zedr-agent %s\n", version)
		return
	}

	// -status：服务器与 SSH 场景的"看一眼"。桌面 UI 在 Server Core/无
	// WebView2 的机器上没有意义，而运维排查恰恰最常发生在那里。
	if *flagStatus {
		if err := printStatus(); err != nil {
			fmt.Fprintf(os.Stderr, "获取状态失败: %v\n（提示：探针必须在本机运行，本地接口 127.0.0.1:8843）\n", err)
			os.Exit(1)
		}
		return
	}

	// .env 仅用于开发调试；安装成服务后应改为系统环境变量
	if _, err := config.LoadDotEnv(); err != nil {
		fmt.Fprintf(os.Stderr, "读取 .env 失败: %v\n", err)
	}

	// 软内存上限必须在 app.New 之前生效：启动阶段（规则/IOC 加载、
	// 基线读取、离线队列恢复）同样在保护范围内。
	applyMemoryLimit()

	switch {
	case *flagInstall:
		if err := installService(); err != nil {
			fmt.Fprintf(os.Stderr, "安装服务失败: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("服务 %s 已安装并设为自动启动\n", serviceName)
		return
	case *flagUninstall:
		if err := uninstallService(); err != nil {
			fmt.Fprintf(os.Stderr, "卸载服务失败: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("服务 %s 已卸载\n", serviceName)
		if *flagPurge {
			dir := agentDataDir()
			if dir != "" {
				if err := os.RemoveAll(dir); err != nil {
					fmt.Fprintf(os.Stderr, "清理数据目录失败（%s）: %v\n", dir, err)
				} else {
					fmt.Printf("数据目录已清理: %s\n", dir)
				}
			}
		} else {
			fmt.Println("提示：数据目录（基线/离线队列）仍保留在 %LOCALAPPDATA%\\Z-EDR；确认无需取证时可用 -uninstall -purge 一并清除。")
		}
		return
	case *flagService:
		if err := svc.Run(serviceName, &serviceHandler{}); err != nil {
			fmt.Fprintf(os.Stderr, "服务运行失败: %v\n", err)
			os.Exit(1)
		}
		return
	}

	// 前台模式
	a, err := agentapp.New(version)
	if err != nil {
		fmt.Fprintf(os.Stderr, "启动失败: %v\n", err)
		os.Exit(1)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := a.Run(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "运行异常退出: %v\n", err)
		os.Exit(1)
	}
}

// applyMemoryLimit 按 HG_AGENT_MEM_LIMIT_MB 设置 Go 软内存上限（默认 256MB）。
//
// 为什么需要：Go 运行时的堆目标默认随分配增长，探针在资产盘点/哈希/
// 上报峰值叠加时会把进程提交量推高，系统级 OOM 会直接杀进程——fatal
// "out of memory" 不可捕获，也没有机会 flush 上报队列。软上限让 GC 在
// 接近该值时更激进回收，把长期驻留量收敛在量级内（单次大分配仍可能
// 突破，这是软限制的固有边界，不做夸大）。
//
// 0 表示不设置（保留 Go 默认）；非法值告警后回退默认值，绝不阻断启动。
func applyMemoryLimit() {
	const defaultMB = 256

	mb := defaultMB
	if raw := strings.TrimSpace(os.Getenv("HG_AGENT_MEM_LIMIT_MB")); raw != "" {
		n, err := strconv.Atoi(raw)
		switch {
		case err != nil:
			fmt.Fprintf(os.Stderr, "警告: HG_AGENT_MEM_LIMIT_MB=%q 不是整数，使用默认 %dMB\n", raw, defaultMB)
		case n < 0:
			fmt.Fprintf(os.Stderr, "警告: HG_AGENT_MEM_LIMIT_MB=%d 为负数，使用默认 %dMB\n", n, defaultMB)
		default:
			mb = n
		}
	}

	if mb == 0 {
		fmt.Fprintln(os.Stderr, "mem_limit_mb=0（未启用软内存上限，使用 Go 运行时默认）")
		return
	}
	debug.SetMemoryLimit(int64(mb) << 20)
	fmt.Fprintf(os.Stderr, "mem_limit_mb=%d\n", mb)
}

type serviceHandler struct{}

// Execute 实现 svc.Handler。
func (h *serviceHandler) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	const accepted = svc.AcceptStop | svc.AcceptShutdown
	changes <- svc.Status{State: svc.StartPending}

	a, err := agentapp.New(version)
	if err != nil {
		changes <- svc.Status{State: svc.Stopped}
		return false, 1
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := a.Run(ctx); err != nil {
			fmt.Fprintf(os.Stderr, "agent run failed: %v\n", err)
		}
	}()

	changes <- svc.Status{State: svc.Running, Accepts: accepted}

	for c := range r {
		switch c.Cmd {
		case svc.Interrogate:
			changes <- c.CurrentStatus
		case svc.Stop, svc.Shutdown:
			changes <- svc.Status{State: svc.StopPending}
			cancel()
			<-done
			return false, 0
		}
	}
	cancel()
	<-done
	return false, 0
}

func installService() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()

	if s, err := m.OpenService(serviceName); err == nil {
		s.Close()
		return fmt.Errorf("服务已存在，请先执行 -uninstall")
	}

	s, err := m.CreateService(serviceName, exe, mgr.Config{
		DisplayName:  "Z-EDR 主机安全探针",
		Description:  "采集进程与血缘信息，执行多引擎恶意进程检测并上报总控服务端。",
		StartType:    mgr.StartAutomatic,
		ErrorControl: mgr.ErrorNormal,
	}, "-service")
	if err != nil {
		return err
	}
	defer s.Close()

	// 延迟自启动：不与开机关键路径抢资源（办公机开机速度是用户对
	// 安全软件最直观的体感之一）。失败不阻断安装。
	_ = setDelayedAutostart(s.Handle)

	// 恢复策略：异常终止后自动重启。
	// 没有这一步，一次 taskkill /f 就能让防护永久失效，而系统看起来一切正常。
	if err := setServiceRecovery(s.Handle); err != nil {
		fmt.Fprintf(os.Stderr,
			"警告: %v\n  服务已安装，但异常终止后不会自动重启；\n"+
				"  可手动设置: sc failure %s reset= 86400 actions= restart/5000/restart/10000/restart/30000\n",
			err, serviceName)
	}

	// 配置来源提示：服务的工作目录是 System32，因此配置必须放在
	// 可执行文件同目录（或系统环境变量）里，否则会静默使用默认值。
	if _, err := config.LoadDotEnv(); err != nil {
		fmt.Fprintf(os.Stderr, "警告: 读取 .env 失败: %v\n", err)
	}

	return s.Start()
}

func uninstallService() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()

	s, err := m.OpenService(serviceName)
	if err != nil {
		return fmt.Errorf("服务不存在: %w", err)
	}
	defer s.Close()

	_, _ = s.Control(svc.Stop)
	return s.Delete()
}


// agentDataDir 返回探针数据目录（与运行时 cfg.Path 的来源一致）。
func agentDataDir() string {
	if v := os.Getenv("HG_AGENT_DATA_DIR"); v != "" {
		return v
	}
	if v := os.Getenv("LOCALAPPDATA"); v != "" {
		return filepath.Join(v, "zedr")
	}
	return ""
}


// printStatus 输出人话版本机状态（不依赖任何前端）。
func printStatus() error {
	tok := ""
	if raw, err := os.ReadFile(filepath.Join(agentDataDir(), "local.token")); err == nil {
		tok = strings.TrimSpace(string(raw))
	}
	req, _ := http.NewRequest(http.MethodGet, "http://127.0.0.1:8843/api/local/status", nil)
	req.Header.Set("X-ZEDR-Token", tok)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return fmt.Errorf("本地接口返回 %d", res.StatusCode)
	}

	var wrap struct {
		Data struct {
			AgentVersion  string `json:"agent_version"`
			ProcCount     int    `json:"proc_count"`
			CPUPercent    float64 `json:"cpu_percent"`
			MemMB         float64 `json:"mem_mb"`
			RuleCount     int    `json:"rule_count"`
			IOCCount      int    `json:"ioc_count"`
			InventorySections int `json:"inventory_sections"`
			BaselineSize  int    `json:"baseline_size"`
			FileWatch     bool   `json:"file_watch"`
			PersistCount  int    `json:"persist_count"`
			UptimeSec     int64  `json:"uptime_sec"`
			ScanInterval  string `json:"scan_interval"`
			Online        bool   `json:"online"`
			Stats         struct {
				Scanned   int64 `json:"scanned"`
				Fired     int64 `json:"fired"`
				Suppressed int64 `json:"suppressed"`
			} `json:"stats"`
		} `json:"data"`
	}
	if err := json.NewDecoder(res.Body).Decode(&wrap); err != nil {
		return err
	}
	d := wrap.Data

	online := "未连接总控"
	if d.Online {
		online = "已连接总控"
	}
	fmt.Printf("Z-EDR 探针 %s · 运行 %d 分钟 · %s\n", d.AgentVersion, d.UptimeSec/60, online)
	fmt.Printf("  监控进程   : %d（扫描间隔 %s）\n", d.ProcCount, d.ScanInterval)
	fmt.Printf("  检测规则   : %d 条 · IOC %d 条 · 资产清单 %d 节\n", d.RuleCount, d.IOCCount, d.InventorySections)
	fmt.Printf("  资源占用   : CPU %.2f%% · 内存 %.1f MB\n", d.CPUPercent, d.MemMB)
	fmt.Printf("  行为监控   : 文件落地监控 %s · 自启动基线 %d 项\n", map[bool]string{true: "开", false: "关"}[d.FileWatch], d.PersistCount)
	fmt.Printf("  累计检测   : 扫描 %d 次 · 告警 %d · 抑制 %d\n", d.Stats.Scanned, d.Stats.Fired, d.Stats.Suppressed)
	return nil
}
