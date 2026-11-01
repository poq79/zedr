// Command zedr-server 是 Z-EDR 总控服务端。
//
// 启动：zedr-server（配置全部来自环境变量 / .env）
// 服务化：zedr-server -install（管理员，开机自启+崩溃自动重启）
// 端点：GET /health  GET /ready  GET /（管理台）
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"golang.org/x/sys/windows/svc"

	"zedr/internal/platform/config"
	"zedr/internal/server/app"
)

// version 由构建脚本通过 -ldflags -X main.version 注入。
var version = "dev"

func main() {
	var (
		flagInstall   = flag.Bool("install", false, "安装为 Windows 服务（开机自启+崩溃自动重启，需管理员）")
		flagUninstall = flag.Bool("uninstall", false, "卸载 Windows 服务")
		flagService   = flag.Bool("service", false, "以 Windows 服务方式运行（SCM 调用）")
		flagVersion   = flag.Bool("version", false, "打印版本")
	)
	flag.Parse()

	if *flagVersion {
		fmt.Printf("zedr-server %s\n", version)
		return
	}
	if *flagInstall {
		if err := installServerService(); err != nil {
			fmt.Fprintf(os.Stderr, "安装服务失败: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("服务 %s 已安装并设为自动启动（崩溃自动重启已启用）\n", serviceName)
		return
	}
	if *flagUninstall {
		if err := uninstallServerService(); err != nil {
			fmt.Fprintf(os.Stderr, "卸载服务失败: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("服务 %s 已卸载\n", serviceName)
		return
	}

	if _, err := config.LoadDotEnv(); err != nil {
		fmt.Fprintf(os.Stderr, "读取 .env 失败: %v\n", err)
	}

	app.Version = version // 注入到 app 包，供 /health 与日志使用

	// -service：SCM 拉起时走服务处理器，不占信号处理路径
	if *flagService {
		if err := svc.Run(serviceName, &serverServiceHandler{}); err != nil {
			fmt.Fprintf(os.Stderr, "服务运行失败: %v\n", err)
			os.Exit(1)
		}
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
