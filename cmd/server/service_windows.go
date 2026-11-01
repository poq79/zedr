//go:build windows

package main

// zedr-server 的 Windows 服务化支持（与 cmd/agent 的实现同构）：
//
// 为什么必须服务化：开发会话沙箱会静默回收"后台命令拉起的子进程"
// （本轮实测 server 被回收 3 次），而生产部署里裸进程也没有自愈能力。
// 注册为 Windows 服务后由 SCM 统一管理生命周期：开机自启、崩溃自动
// 重启（恢复策略 5s/10s/30s 三级）、退出有 Stop 通知可优雅收尾。
//
// 用法：zedr-server -install（管理员）/ -uninstall / -service（SCM 调用）

import (
	"context"
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"

	"zedr/internal/platform/config"
	"zedr/internal/server/app"
)

const serviceName = "ZEDRServer"

type serverServiceHandler struct{}

// Execute 实现 svc.Handler。
func (h *serverServiceHandler) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	const accepted = svc.AcceptStop | svc.AcceptShutdown
	changes <- svc.Status{State: svc.StartPending}

	if _, err := config.LoadDotEnv(); err != nil {
		fmt.Fprintf(os.Stderr, "警告: 读取 .env 失败: %v\n", err)
	}
	a, err := app.New()
	if err != nil {
		changes <- svc.Status{State: svc.Stopped}
		return false, 1
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := a.Run(ctx); err != nil {
			fmt.Fprintf(os.Stderr, "server run failed: %v\n", err)
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

func installServerService() error {
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
		DisplayName: "Z-EDR 总控服务端",
		Description: "接收终端探针告警上报，执行事件聚合、规则下发与处置指令。",
		StartType:   mgr.StartAutomatic,
		ErrorControl: mgr.ErrorNormal,
	}, "-service")
	if err != nil {
		return err
	}
	defer s.Close()

	// 延迟自启动：不与开机关键路径抢资源（agent 同款先例）
	_ = setDelayedAutostart(s.Handle)

	// 恢复策略：异常终止后自动重启（5s/10s/30s 三级，1 天重置）。
	// 没有这一步，一次静默死亡就让总控永久失联。
	if err := setServiceRecovery(s.Handle); err != nil {
		fmt.Fprintf(os.Stderr,
			"警告: %v\n  服务已安装，但异常终止后不会自动重启；\n"+
				"  可手动设置: sc failure %s reset= 86400 actions= restart/5000/restart/10000/restart/30000\n",
			err, serviceName)
	}

	// 服务的工作目录是 System32，配置必须从 exe 同目录或系统环境变量拿
	if _, err := config.LoadDotEnv(); err != nil {
		fmt.Fprintf(os.Stderr, "警告: 读取 .env 失败: %v\n", err)
	}

	return s.Start()
}

func uninstallServerService() error {
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

// ---------------------------------------------------------------- 恢复策略
// 与 cmd/agent/service_recovery.go 同构（cmd/ 下 main 包相互独立，
// 复制最小实现是可接受的取舍——两份的恢复策略必须保持一致）。

const (
	serviceConfigFailureActions = 2
	scActionRestart             = 1
)

var (
	modAdvapi32               = windows.NewLazySystemDLL("advapi32.dll")
	procChangeServiceConfig2W = modAdvapi32.NewProc("ChangeServiceConfig2W")
)

type scAction struct {
	Type  uint32
	Delay uint32
}

type serviceFailureActions struct {
	ResetPeriod uint32
	RebootMsg   *uint16
	Command     *uint16
	NumActions  uint32
	Actions     *scAction
}

// setServiceRecovery 配置"服务异常终止后自动重启"的恢复策略。
// 总控失联比探针失联更致命（全部终端失去大脑），策略与 agent 一致：
// 5s → 10s → 30s 三级退避，1 天无故障后计数重置。
func setServiceRecovery(h windows.Handle) error {
	actions := []scAction{
		{Type: scActionRestart, Delay: 5000},
		{Type: scActionRestart, Delay: 10000},
		{Type: scActionRestart, Delay: 30000},
	}
	sfa := serviceFailureActions{
		ResetPeriod: 86400,
		NumActions:  uint32(len(actions)),
		Actions:     &actions[0],
	}

	r, _, e := procChangeServiceConfig2W.Call(
		uintptr(h),
		serviceConfigFailureActions,
		uintptr(unsafe.Pointer(&sfa)),
	)
	if r == 0 {
		return fmt.Errorf("设置恢复策略失败: %v", e)
	}
	return nil
}

type delayedAutoStartInfo struct {
	FDelayedAutostart uint32
}

func setDelayedAutostart(h windows.Handle) error {
	info := delayedAutoStartInfo{FDelayedAutostart: 1}
	r, _, e := procChangeServiceConfig2W.Call(
		uintptr(h), 3, uintptr(unsafe.Pointer(&info)))
	if r == 0 {
		if ee, ok := e.(windows.Errno); ok && ee != 0 {
			return ee
		}
		return fmt.Errorf("ChangeServiceConfig2W 返回 0")
	}
	return nil
}
