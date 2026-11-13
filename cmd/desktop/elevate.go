//go:build windows
// +build windows

package main

// 以管理员身份运行外部命令（ShellExecuteExW verb="runas"）。
//
// 用途：托盘菜单里的"安装探针服务"——agent 的 -install 需要管理员，
// 从非提权进程触发 UAC 弹窗是 Windows 的标准通道。

import (
	"fmt"
	"syscall"
	"unsafe"
)

const (
	seeMaskNoAsync = 0x00001000
	swShownormal   = 1
)

type shellExecuteInfoW struct {
	CbSize       uint32
	FMask        uint32
	Hwnd         uintptr
	LpVerb       uintptr
	LpFile       uintptr
	LpParameters uintptr
	LpDirectory  uintptr
	LpShow       int32
	_            uint32
	HInstApp     uintptr
	LpIDList     uintptr
	LpClass      uintptr
	HkeyClass    uintptr
	DwHotKey     uint32
	_            uint32
	HIcon        uintptr // 与 hMonitor 的 union
	HProcess     uintptr
}

var procShellExecuteExW = modshell32.NewProc("ShellExecuteExW")

// runElevated 弹 UAC 并以管理员运行 exe args。用户取消 UAC 返回错误。
func runElevated(exe, args string) error {
	verb, _ := syscall.UTF16PtrFromString("runas")
	file, _ := syscall.UTF16PtrFromString(exe)
	params, _ := syscall.UTF16PtrFromString(args)
	sei := shellExecuteInfoW{
		CbSize:       uint32(unsafe.Sizeof(shellExecuteInfoW{})),
		FMask:        seeMaskNoAsync,
		LpVerb:       uintptr(unsafe.Pointer(verb)),
		LpFile:       uintptr(unsafe.Pointer(file)),
		LpParameters: uintptr(unsafe.Pointer(params)),
		LpShow:       swShownormal,
	}
	r, _, err := procShellExecuteExW.Call(uintptr(unsafe.Pointer(&sei)))
	// ShellExecuteEx 成功返回 TRUE；失败时 err 即 GetLastError
	if r == 0 {
		return fmt.Errorf("提权启动失败: %v", err)
	}
	return nil
}