package main

// 单实例与跨进程面板激活。
//
// 为什么用命名互斥量而不是找窗口：托盘窗口本来就不可见，面板窗口
// 在另一个进程里——互斥量是 Windows 单实例的事实标准（Local\ 前缀
// 绑定当前会话，多用户 RDP 互不干扰）。

import (
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	errorAlreadyExists = 183
)

var (
	procCreateMutexW    = modkernel32.NewProc("CreateMutexW")
	procEnumWindows     = moduser32.NewProc("EnumWindows")
	procGetClassNameW   = moduser32.NewProc("GetClassNameW")
	procGetWindowTextW  = moduser32.NewProc("GetWindowTextW")
)

// acquireMutex 尝试持有命名互斥量。返回 held=true 表示我们是第一个
// 持有者（调用方负责 release）；held=false 表示已有实例（锁在别人手里，
// release 仍需调用以关闭本进程的句柄）。
func acquireMutex(name string) (held bool, release func()) {
	p, _ := syscall.UTF16PtrFromString(name)
	h, _, err := procCreateMutexW.Call(0, 0, uintptr(unsafe.Pointer(p)))
	// CreateMutexW 成功时 err 恒非 nil（残留 LastErr），只比对 ERROR_ALREADY_EXISTS
	held = err != syscall.Errno(errorAlreadyExists)
	return held, func() { _ = windows.CloseHandle(windows.Handle(h)) }
}

// panelRunning 判断面板（UI 进程）是否在跑。
func panelRunning() bool {
	held, release := acquireMutex(panelMutexName)
	if held {
		// 我们拿到了锁 = 没有别的实例在跑
		release()
		return false
	}
	release()
	return true
}

// activatePanelWindow 把已运行的面板窗口调到前台（恢复+置顶）。
func activatePanelWindow() bool {
	var target uintptr
	cb := windows.NewCallback(func(hwnd, _ uintptr) uintptr {
		buf := make([]uint16, 256)
		procGetClassNameW.Call(hwnd, uintptr(unsafe.Pointer(&buf[0])), 256)
		title := make([]uint16, 256)
		procGetWindowTextW.Call(hwnd, uintptr(unsafe.Pointer(&title[0])), 256)
		if windows.UTF16ToString(buf) == "webview" &&
			strings.HasPrefix(windows.UTF16ToString(title), "Z-EDR") {
			target = hwnd
			return 0 // 停止枚举
		}
		return 1
	})
	procEnumWindows.Call(cb, 0)
	if target == 0 {
		return false
	}
	procShowWindow.Call(target, swRestore)
	procShowWindow.Call(target, swShow)
	procSetForegroundWindow.Call(target)
	return true
}
