//go:build windows
// +build windows

package main

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// 服务恢复策略相关常量（来自 winsvc.h）。
const (
	serviceConfigFailureActions = 2
	scActionRestart             = 1
)

var (
	modAdvapi32               = windows.NewLazySystemDLL("advapi32.dll")
	procChangeServiceConfig2W = modAdvapi32.NewProc("ChangeServiceConfig2W")
)

// scAction 对应 SC_ACTION。
type scAction struct {
	Type  uint32
	Delay uint32
}

// serviceFailureActions 对应 SERVICE_FAILURE_ACTIONSW。
type serviceFailureActions struct {
	ResetPeriod uint32
	RebootMsg   *uint16
	Command     *uint16
	NumActions  uint32
	Actions     *scAction
}

// setServiceRecovery 配置"服务异常终止后自动重启"的恢复策略。
//
// 这是探针自保护的最后一道防线，也是安全产品落地时最容易被漏掉的一步：
// 没有恢复策略时，攻击者或误操作的 `taskkill /f` 一次就能让防护永久失效，
// 而表面上系统一切正常——这是最危险的状态。
//
// 策略：5s → 10s → 30s 重启三级退避，1 天无故障后计数重置。
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

// SERVICE_CONFIG_DELAYED_AUTO_START_INFO = 3（Win32 文档值）。
type delayedAutoStartInfo struct {
	FDelayedAutostart uint32 // BOOL
}

// setDelayedAutostart 把服务设为「自动（延迟启动）」。
//
// 对办公机用户这是体验问题：安全探针通常不需要在开机争分夺秒的那几秒里
// 抢 IO 与 CPU（晚 1~2 分钟启动完全可接受），设为延迟启动可以显著
// 缩短开机到可用的时间——而服务器场景同样受益（重启窗口更短）。
func setDelayedAutostart(h windows.Handle) error {
	info := delayedAutoStartInfo{FDelayedAutostart: 1}
	r, _, e := procChangeServiceConfig2W.Call(
		uintptr(h), 3, uintptr(unsafe.Pointer(&info)))
	if r == 0 {
		// 与 setServiceRecovery 相同的惯例：errno==0 表示调用实际成功，
		// 只是 Windows 把 lastError 置非零（LazyProc 的 lazy error 语义）
		if ee, ok := e.(windows.Errno); ok && ee != 0 {
			return ee
		}
		return fmt.Errorf("ChangeServiceConfig2W 返回 0")
	}
	return nil
}
