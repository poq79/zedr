//go:build linux

// Command zedr-agent 是 Z-EDR Linux 探针入口。
//
// 启动：zedr-agent（配置全部来自环境变量 / .env）
// 服务化：zedr-agent -install（写 systemd unit + daemon-reload + enable）
// 自检：zedr-agent -status -json
//
// Windows 专属旗子（-collector 等）在本入口不存在；配置一律走 HG_*
// 环境变量（与 Windows 服务化形态同一来源，见 agentapp.LoadConfig）。
// 未在 Linux 实机验证；-install 的 systemd 语义见 RESEARCH-LINUX-AGENT §3。
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
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
// Linux v1 的本地接口尚未接线（TODO(integration)），此时给出明确的
// "探针未运行/本地接口不可用"提示而不是报错堆栈。
func runStatus(asJSON bool) {
	cfg, _ := agentapp.LoadConfig(version)
	out := map[string]any{
		"platform": "linux",
		"version":  version,
		"data_dir": cfg.DataDir,
		"online":   false,
		"note":     "Linux v1 本地接口未接线；状态以服务端主机列表为准",
	}
	b, _ := json.MarshalIndent(out, "", "  ")
	fmt.Println(string(b))
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
