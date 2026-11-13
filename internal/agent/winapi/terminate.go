//go:build windows
// +build windows

package winapi

import (
	"fmt"
)

const processTerminate = 0x0001

var procTerminateProcess = modKernel32.NewProc("TerminateProcess")

// ImageNameOf 返回指定 PID 的进程名（不检查路径，用于处置前的二次校验）。
func ImageNameOf(pid uint32) (string, error) {
	list, err := SnapshotProcesses()
	if err != nil {
		return "", err
	}
	for _, p := range list {
		if p.PID == pid {
			return p.Name, nil
		}
	}
	return "", fmt.Errorf("PID %d 不存在", pid)
}

// TerminatePID 结束指定进程。
//
// 安全约束：调用方必须先校验"进程名匹配告警记录"，避免 PID 复用导致误杀
// 无辜进程。本函数只做最小特权打开（PROCESS_TERMINATE）。
func TerminatePID(pid uint32) error {
	if pid <= 4 {
		return fmt.Errorf("拒绝终止系统关键进程 (PID %d)", pid)
	}
	h, err := openProcess(pid, processTerminate)
	if err != nil {
		return err
	}
	defer closeHandle(h)

	ret, _, e := procTerminateProcess.Call(uintptr(h), 1)
	if ret == 0 {
		return fmt.Errorf("TerminateProcess 失败: %w", e)
	}
	return nil
}
