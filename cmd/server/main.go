// Command zedr-server 是 Z-EDR 总控服务端。
//
// 启动：zedr-server（配置全部来自环境变量 / .env）
// 服务化：zedr-server -install（Windows: SCM 服务；Linux: systemd，见
// scripts/deploy；本文件经 serviceFlags()/runIfServiceMode() 与平台解耦）
// 端点：GET /health  GET /ready  GET /（管理台）
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"zedr/internal/platform/config"
	"zedr/internal/server/app"
)

// version 由构建脚本通过 -ldflags -X main.version 注入。
var version = "dev"

func main() {
	var (
		flagVersion = flag.Bool("version", false, "打印版本")
	)
	// 服务化三旗（install/uninstall/service）按 OS 各自注册：Windows 走
	// SCM，Linux 由 systemd 接管进程生命周期、不注册这些旗子。
	serviceFlags()

	flag.Parse()

	if *flagVersion {
		fmt.Printf("zedr-server %s\n", version)
		return
	}
	if handled := serviceFlagsHandled(); handled {
		return
	}

	if _, err := config.LoadDotEnv(); err != nil {
		fmt.Fprintf(os.Stderr, "读取 .env 失败: %v\n", err)
	}

	app.Version = version // 注入到 app 包，供 /health 与日志使用

	// SCM 拉起时走服务处理器，不占信号处理路径（Windows 专属；
	// runIfServiceMode 在 Linux 恒返回 false）
	if runIfServiceMode() {
		return
	}

	a, err := app.New()
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
