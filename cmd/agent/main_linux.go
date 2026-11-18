//go:build linux

// Command zedr-agent 是 Z-EDR Linux 探针入口。
//
// 启动：zedr-agent（配置全部来自环境变量 / .env）
// 服务化：zedr-agent -install（写 systemd unit + daemon-reload + enable）
// 自检：zedr-agent -status -json
//
// Windows 专属旗子（-collector 等）在本入口不存在；配置一律走 HG_*
// 环境变量（与 Windows 服务化形态同一来源，见 agentapp.LoadConfig）。
// 2026-11-14 已在 Kali 实机验收（RESEARCH-LINUX-AGENT §7/§8）；
// -install 的 systemd 语义见同文档 §3。
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"syscall"

	agentapp "zedr/internal/agent/app"
	"zedr/internal/agent/lapp"
	"zedr/internal/platform/config"
)

// version 由构建脚本通过 -ldflags -X main.version 注入。
var version = "dev"

const serviceName = "zedr-agent"

func main() {
	var (
		flagInstall   = flag.Bool("install", false, "安装为 systemd 服务（写 unit + enable --now，需 root）")
		flagUninstall = flag.Bool("uninstall", false, "卸载 systemd 服务")
		flagStatus    = flag.Bool("status", false, "查询本机探针状态（配合 -json 机器可读）")
		flagJSON      = flag.Bool("json", false, "配合 -status：输出 JSON")
		flagVersion   = flag.Bool("version", false, "打印版本")
	)
	flag.Parse()

	if *flagVersion {
		fmt.Printf("zedr-agent %s (linux/%s)\n", version, runtime.GOARCH)
		return
	}
	if *flagStatus {
		runStatus(*flagJSON)
		return
	}
	if *flagInstall {
		if err := installService(); err != nil {
			fmt.Fprintf(os.Stderr, "安装服务失败: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("服务 %s 已安装并启动（systemd 托管：开机自启 + 崩溃自动重启）\n", serviceName)
		return
	}
	if *flagUninstall {
		if err := uninstallService(); err != nil {
			fmt.Fprintf(os.Stderr, "卸载服务失败: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("服务 %s 已卸载\n", serviceName)
		return
	}

	// .env 仅用于开发调试；systemd 模式应改为 unit 内 EnvironmentFile
	if _, err := config.LoadDotEnv(); err != nil {
		fmt.Fprintf(os.Stderr, "读取 .env 失败: %v\n", err)
	}
	applyMemoryLimit()

	a, err := lapp.New(version)
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

// runStatus 查询本地接口状态（127.0.0.1:8843，令牌在数据目录 local.token）。
// 本地 API 已在 lapp 组合根接线（本地面板/桌面端同源），与 Windows 版
// printStatus 同口径：json=true 输出机器可读 JSON（脚本按 online 字段
// 闭环判断），否则人话。实现复制而非共享：cmd/ 下 main 包相互独立，
// Windows 侧 fetchLocalStatus 依赖 Windows 目录候选，复制最小实现是
// 既定取舍（见 applyMemoryLimit 注释）。
func runStatus(asJSON bool) {
	cfg, _ := agentapp.LoadConfig(version)

	res := fetchLocalStatusLinux(cfg.DataDir)
	if res == nil {
		if asJSON {
			b, _ := json.MarshalIndent(map[string]any{
				"platform": "linux", "version": version,
				"data_dir": cfg.DataDir, "online": false,
				"note": "本地接口 127.0.0.1:8843 不可达（探针未运行？）",
			}, "", "  ")
			fmt.Println(string(b))
			return
		}
		fmt.Println("本地接口 127.0.0.1:8843 不可达（探针未运行？）")
		fmt.Printf("版本: zedr-agent %s (linux)\n数据目录: %s\n", version, cfg.DataDir)
		return
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		fmt.Printf("本地接口返回 %d（令牌不匹配或探针异常）\n", res.StatusCode)
		return
	}

	var wrap struct {
		Data struct {
			AgentVersion string  `json:"agent_version"`
			ProcCount    int     `json:"proc_count"`
			CPUPercent   float64 `json:"cpu_percent"`
			MemMB        float64 `json:"mem_mb"`
			RuleCount    int     `json:"rule_count"`
			IOCCount     int     `json:"ioc_count"`
			UptimeSec    int64   `json:"uptime_sec"`
			Online       bool    `json:"online"`
		} `json:"data"`
	}
	if err := json.NewDecoder(res.Body).Decode(&wrap); err != nil {
		fmt.Printf("本地接口响应解析失败: %v\n", err)
		return
	}
	d := wrap.Data
	if asJSON {
		b, _ := json.MarshalIndent(map[string]any{
			"platform":      "linux",
			"online":        true,
			"data_dir":      cfg.DataDir,
			"agent_version": d.AgentVersion,
			"proc_count":    d.ProcCount,
			"cpu_percent":   d.CPUPercent,
			"mem_mb":        d.MemMB,
			"rule_count":    d.RuleCount,
			"ioc_count":     d.IOCCount,
			"uptime_sec":    d.UptimeSec,
			"server_online": d.Online,
		}, "", "  ")
		fmt.Println(string(b))
		return
	}
	fmt.Printf("探针在线: zedr-agent %s (linux)\n", d.AgentVersion)
	fmt.Printf("进程: %d  CPU: %.1f%%  内存: %.1fMB\n", d.ProcCount, d.CPUPercent, d.MemMB)
	fmt.Printf("规则: %d 条  IOC: %d 条  运行时长: %ds\n", d.RuleCount, d.IOCCount, d.UptimeSec)
	fmt.Printf("服务端连接: %v\n", d.Online)
}

// fetchLocalStatusLinux 依次尝试候选令牌读取本地状态；全部失败返回 nil。
// Linux 数据目录候选与 Windows 的 localTokenCandidates 同构：
// 显式 HG_AGENT_DATA_DIR 优先，其次默认 /var/lib/zedr（服务化 root）。
func fetchLocalStatusLinux(dataDir string) *http.Response {
	for _, dir := range []string{dataDir, "/var/lib/zedr"} {
		if dir == "" {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, "local.token"))
		if err != nil {
			continue
		}
		req, _ := http.NewRequest(http.MethodGet, "http://127.0.0.1:8843/api/local/status", nil)
		req.Header.Set("X-ZEDR-Token", strings.TrimSpace(string(raw)))
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			// 接口不可达：换令牌也没用，直接结束（探针没在跑）。
			return nil
		}
		if res.StatusCode == 200 {
			return res
		}
		res.Body.Close()
		if res.StatusCode != 401 {
			return res
		}
		// 401：令牌不匹配，试下一个候选目录。
	}
	return nil
}

// applyMemoryLimit 软内存上限（与 Windows main.go 同逻辑；独立成函数是因为
// cmd/ 下 main 包相互独立，复制最小实现是可接受的取舍）。
func applyMemoryLimit() {
	const defaultMB = 256
	mb := defaultMB
	if raw := strings.TrimSpace(os.Getenv("HG_AGENT_MEM_LIMIT_MB")); raw != "" {
		var n int
		if _, err := fmt.Sscanf(raw, "%d", &n); err == nil && n >= 0 {
			mb = n
		}
	}
	if mb == 0 {
		return
	}
	debug.SetMemoryLimit(int64(mb) * 1024 * 1024)
}

// ---------------------------------------------------------------- systemd 安装

// unitText 是 systemd 单元模板。崩溃自动重启对齐 Windows SCM 恢复策略
// 的精神（Restart=on-failure + 5s 起步）；EnvironmentFile 指向 exe 同目录
// .env，与 -install 的配置落盘语义一致（Windows 版 persistInstallConfig）。
func unitText(exe string) string {
	return fmt.Sprintf(`[Unit]
Description=Z-EDR Linux Agent (zedr)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=%s
EnvironmentFile=-%s
Restart=on-failure
RestartSec=5s
# 探针是用户态只读采集器，不放大系统权限面
NoNewPrivileges=true
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
`, exe, filepath.Join(filepath.Dir(exe), ".env"))
}

func installService() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	unit := unitText(exe)
	path := "/etc/systemd/system/" + serviceName + ".service"
	if err := os.WriteFile(path, []byte(unit), 0o644); err != nil {
		return fmt.Errorf("写单元文件失败（需要 root）: %w", err)
	}
	if out, err := runCmd("systemctl", "daemon-reload"); err != nil {
		return fmt.Errorf("daemon-reload 失败: %v\n%s", err, out)
	}
	if out, err := runCmd("systemctl", "enable", "--now", serviceName); err != nil {
		return fmt.Errorf("enable --now 失败: %v\n%s", err, out)
	}
	return nil
}

func uninstallService() error {
	_, _ = runCmd("systemctl", "disable", "--now", serviceName)
	_ = os.Remove("/etc/systemd/system/" + serviceName + ".service")
	if out, err := runCmd("systemctl", "daemon-reload"); err != nil {
		return fmt.Errorf("daemon-reload 失败: %v\n%s", err, out)
	}
	return nil
}

func runCmd(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}
