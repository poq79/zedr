// Command secagent 是 HostGuard 终端探针。
//
// 用法：
//
//	secagent                 前台运行（适合调试，Ctrl+C 退出）
//	secagent -service        作为 Windows 服务运行（由 SCM 启动时使用）
//	secagent -install        安装为开机自启的 Windows 服务（需管理员）
//	secagent -uninstall      卸载服务（需管理员）
//	secagent -version        打印版本
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"

	agentapp "hostguard/internal/agent/app"
	"hostguard/internal/platform/config"
)

const serviceName = "HostGuardAgent"

// version 由构建脚本通过 -ldflags -X main.version 注入。
var version = "dev"

func main() {
	var (
		flagService   = flag.Bool("service", false, "以 Windows 服务方式运行")
		flagInstall   = flag.Bool("install", false, "安装为 Windows 服务")
		flagUninstall = flag.Bool("uninstall", false, "卸载 Windows 服务")
		flagVersion   = flag.Bool("version", false, "打印版本")
	)
	flag.Parse()

	if *flagVersion {
		fmt.Printf("secagent %s\n", version)
		return
	}

	// .env 仅用于开发调试；安装成服务后应改为系统环境变量
	if _, err := config.LoadDotEnv(); err != nil {
		fmt.Fprintf(os.Stderr, "读取 .env 失败: %v\n", err)
	}

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
		DisplayName:  "HostGuard 主机安全探针",
		Description:  "采集进程与血缘信息，执行多引擎恶意进程检测并上报总控服务端。",
		StartType:    mgr.StartAutomatic,
		ErrorControl: mgr.ErrorNormal,
	}, "-service")
	if err != nil {
		return err
	}
	defer s.Close()
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
