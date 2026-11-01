// Command secserver 是 HostGuard 总控服务端。
//
// 启动：secserver（配置全部来自环境变量 / .env）
// 端点：GET /health  GET /ready  GET /（管理台）
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"hostguard/internal/platform/config"
	"hostguard/internal/server/app"
)

func main() {
	if _, err := config.LoadDotEnv(); err != nil {
		fmt.Fprintf(os.Stderr, "读取 .env 失败: %v\n", err)
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
