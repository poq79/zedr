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
