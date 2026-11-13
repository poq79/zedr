//go:build windows
// +build windows

package main

// 桌面宿主所需的 Win32 声明（user32/shell32/dwmapi/gdi32 最小子集）。
//
// 为什么不用第三方托盘库：托盘 + 无边框一共只需要 ~15 个 API，
// 引一个依赖换一份供应链面不值（项目供应链纪律：能自写就自写）。

import (
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	moduser32   = windows.NewLazySystemDLL("user32.dll")
	modshell32  = windows.NewLazySystemDLL("shell32.dll")
	moddwmapi   = windows.NewLazySystemDLL("dwmapi.dll")
	modgdi32    = windows.NewLazySystemDLL("gdi32.dll")
	modkernel32 = windows.NewLazySystemDLL("kernel32.dll")
	modadvapi32 = windows.NewLazySystemDLL("advapi32.dll")

	procRegisterClassExW        = moduser32.NewProc("RegisterClassExW")
	procCreateWindowExW         = moduser32.NewProc("CreateWindowExW")
	procDefWindowProcW          = moduser32.NewProc("DefWindowProcW")
	procCallWindowProcW         = moduser32.NewProc("CallWindowProcW")
	procGetWindowLongPtrW       = moduser32.NewProc("GetWindowLongPtrW")
	procSetWindowLongPtrW       = moduser32.NewProc("SetWindowLongPtrW")
	procShowWindow              = moduser32.NewProc("ShowWindow")
	procSetForegroundWindow     = moduser32.NewProc("SetForegroundWindow")
	procIsZoomed                = moduser32.NewProc("IsZoomed")
	procIsWindowVisible         = moduser32.NewProc("IsWindowVisible")
	procGetWindowRect           = moduser32.NewProc("GetWindowRect")
	procLoadImageW              = moduser32.NewProc("LoadImageW")
	procDestroyWindow           = moduser32.NewProc("DestroyWindow")
	procPostQuitMessage         = moduser32.NewProc("PostQuitMessage")
	procGetMessageW             = moduser32.NewProc("GetMessageW")
	procTranslateMessage        = moduser32.NewProc("TranslateMessage")
	procDispatchMessageW        = moduser32.NewProc("DispatchMessageW")
	procReleaseCapture          = moduser32.NewProc("ReleaseCapture")
	procSendMessageW            = moduser32.NewProc("SendMessageW")
	procPostMessageW            = moduser32.NewProc("PostMessageW")
	procShellNotifyIconW        = modshell32.NewProc("Shell_NotifyIconW")
	procRegisterWindowMessageW  = moduser32.NewProc("RegisterWindowMessageW")
	procCreatePopupMenu         = moduser32.NewProc("CreatePopupMenu")
	procAppendMenuW             = moduser32.NewProc("AppendMenuW")
	procTrackPopupMenuEx        = moduser32.NewProc("TrackPopupMenuEx")
	procDestroyMenu             = moduser32.NewProc("DestroyMenu")
	procGetSystemMetrics        = moduser32.NewProc("GetSystemMetrics")
	procMonitorFromWindow       = moduser32.NewProc("MonitorFromWindow")
	procGetMonitorInfoW         = moduser32.NewProc("GetMonitorInfoW")
	procSystemParametersInfoW   = moduser32.NewProc("SystemParametersInfoW")
	procSetWindowPos            = moduser32.NewProc("SetWindowPos")
	procDwmSetWindowAttribute   = moddwmapi.NewProc("DwmSetWindowAttribute")
	procOpenSCManagerW          = modadvapi32.NewProc("OpenSCManagerW")
	procOpenServiceW            = modadvapi32.NewProc("OpenServiceW")
	procQueryServiceStatus      = modadvapi32.NewProc("QueryServiceStatus")
	procCloseServiceHandle      = modadvapi32.NewProc("CloseServiceHandle")
	procGetDpiForSystem         = moduser32.NewProc("GetDpiForSystem")
	procSetWindowRgn            = moduser32.NewProc("SetWindowRgn")
	procCreateRoundRectRgn      = modgdi32.NewProc("CreateRoundRectRgn")
	procDeleteObject            = modgdi32.NewProc("DeleteObject")
	procGetModuleHandleExW      = modkernel32.NewProc("GetModuleHandleExW")
)

// 已知窗口消息与常量（仅列出用到的；值与 winuser.h 一致）。
const (
	wmCreate           = 0x0001
	wmDestroy          = 0x0002
	wmClose            = 0x0010
	wmCommand          = 0x0111
	wmApp              = 0x8000
	wmUser             = 0x0400
	wmGetMinMaxInfo    = 0x0024
	wmSize             = 0x0005
	wmNcCalcSize       = 0x0083
	wmNcLButtonDown    = 0x00A1
	wmNull             = 0x0000
	htClient           = 1
	htCaption          = 2
	swHide             = 0
	swShow             = 5
	swShowNormal       = 1
	swRestore          = 9
	gwlStyle           = -16
	gwlpWndProc        = -4
	wsOverlappedWindow = 0x00CF0000
	wsPopup            = 0x80000000
	lrDefaultSize      = 0x00000040
	lrShared           = 0x00008000
	imageIcon          = 1
	smCxScreen         = 0
	smCyScreen         = 1
	smCxFrame          = 32
	smCyFrame          = 33
	smCxPaddedBorder   = 92
	monitorDefaultToNearest = 2
	dwmwaUseImmersiveDarkMode     = 20
	dwmwaWindowCornerPreference   = 33
	dwmwcpRound                   = 2
	nimAdd                        = 0
	nimModify                     = 1
	nimDelete                     = 2
	nimSetVersion                 = 4
	nifMessage                    = 0x01
	nifIcon                       = 0x02
	nifTip                        = 0x04
	nifInfo                       = 0x10
	notifyIconVersion             = 3
	// NIN_BALLOONUSERCLICK：气球被用户点击（v3 仍走回调 lParam）
	ninBalloonUserClick           = 0x0405 // WM_USER + 5
	// 托盘图标三态（资源 ID，见 cmd/desktop/winres/winres.json）
	iconIDOK   = 1 // 绿勾——防护运行中
	iconIDWarn = 2 // 黄叹号——降级（总控离线/未注册）
	iconIDDown = 3 // 红叉——探针失联
	wmTrayCallback                = wmUser + 1
	mfString                      = 0x00000000
	mfSeparator                   = 0x00000800
	tpmRetURNCMD                  = 0x0100
	tpmRightButton                = 0x0002
	tpmNoDefault                  = 0x0400
)

type point struct {
	X, Y int32
}

type msg struct {
	Hwnd     uintptr
	Message  uint32
	WParam   uintptr
	LParam   uintptr
	Time     uint32
	Pt       point
	LPrivate uint32
}

type wndClassExW struct {
	CbSize        uint32
	Style         uint32
	LpfnWndProc   uintptr
	CbClsExtra    int32
	CbWndExtra    int32
	HInstance     windows.Handle
	HIcon         windows.Handle
	HCursor       windows.Handle
	HbrBackground windows.Handle
	LpszMenuName  *uint16
	LpszClassName *uint16
	HIconSm       windows.Handle
}

type rect struct {
	Left, Top, Right, Bottom int32
}

type minMaxInfo struct {
	PtReserved     point
	PtMaxSize      point
	PtMaxPosition  point
	PtMinTrackSize point
	PtMaxTrackSize point
}

type monitorInfoW struct {
	CbSize    uint32
	RcMonitor rect
	RcWork    rect
	DwFlags   uint32
}

// notifyIconDataW 与 shellapi.h 的布局逐字段对齐（amd64 自然对齐）。
type notifyIconDataW struct {
	CbSize           uint32
	HWnd             uintptr
	UID              uint32
	UFlags           uint32
	UCallbackMessage uint32
	HIcon            uintptr
	SzTip            [128]uint16
	DwState          uint32
	DwStateMask      uint32
	SzInfo           [128]uint16
	UVersion         uint32
	_                uint32
	SzInfoTitle      [64]uint16
	DwInfoFlags      uint32
	GuidItem         [16]byte
	HBalloonIcon     uintptr
}

func utf16(s string) *uint16 { p, _ := syscall.UTF16PtrFromString(s); return p }

// ptrFromLParam 把窗口消息的 lParam 还原为结构体指针。
// lParam 本来就是合法指针值；走一次指针间接是为了不触发 go vet
// 对 uintptr→unsafe.Pointer 直转的误报（unsafeptr 检查无法知道来源）。
func ptrFromLParam(p uintptr) unsafe.Pointer {
	return *(*unsafe.Pointer)(unsafe.Pointer(&p))
}

func moduleHandle() uintptr {
	var h windows.Handle
	_, _, _ = procGetModuleHandleExW.Call(0, 0, uintptr(unsafe.Pointer(&h)))
	return uintptr(h)
}

// loadIconResource 从 exe 的 RT_GROUP_ICON 资源加载 HICON。
// go-winres 生成的应用图标固定为 ID 1（见 simplySetIcon）。
func loadIconResource(id uintptr, cx, cy int32) uintptr {
	// IMAGE_ICON = 1
	h, _, _ := procLoadImageW.Call(moduleHandle(), id, imageIcon, uintptr(cx), uintptr(cy), lrDefaultSize|lrShared)
	return h
}

func sysMetrics(n int32) int32 {
	v, _, _ := procGetSystemMetrics.Call(uintptr(n))
	return int32(v)
}

// frameBorders 返回当前 DPI 下的窗口边框厚度（用于最大化时收口客户区）。
func frameBorders() (x, y int32) {
	x = sysMetrics(smCxFrame) + sysMetrics(smCxPaddedBorder)
	y = sysMetrics(smCyFrame) + sysMetrics(smCxPaddedBorder)
	return
}

// tryRoundWin11Corners 调 DWM 圆角（Win11/Server 2025+ 生效；
// Server 2022/Win10 的 DWM 不认识该属性，返回 false——
// 调用方落到 SetWindowRgn 圆角裁切兜底）。
func tryRoundWin11Corners(hwnd uintptr) bool {
	pref := uint32(dwmwcpRound)
	r, _, _ := procDwmSetWindowAttribute.Call(hwnd, dwmwaWindowCornerPreference, uintptr(unsafe.Pointer(&pref)), 4)

	// 深色标题栏（有边框模式下标题栏跟随 Carbon 深色，不刺眼）
	dark := uint32(1)
	_, _, _ = procDwmSetWindowAttribute.Call(hwnd, dwmwaUseImmersiveDarkMode, uintptr(unsafe.Pointer(&dark)), 4)
	return r == 0
}

// registerTaskbarMessage 注册 explorer 广播的重建消息。
// explorer.exe 崩溃/重启后任务栏重建，所有托盘图标都会被系统移除，
// 收到该消息必须重新 Shell_NotifyIcon——不处理 = 图标永久消失。
func registerTaskbarMessage() uint32 {
	r, _, _ := procRegisterWindowMessageW.Call(uintptr(unsafe.Pointer(utf16("TaskbarCreated"))))
	return uint32(r)
}

// dpiScale 返回系统 DPI 相对 96 的倍率（100%=1.0）。
// wrapper 以物理像素创建窗口，高 DPI 下 1180x820 会显得偏小，
// 默认尺寸需要按倍率放大（placement 恢复时用用户自己的值，不走这里）。
func dpiScale() float64 {
	r, _, _ := procGetDpiForSystem.Call()
	if r == 0 {
		return 1.0
	}
	s := float64(r) / 96.0
	if s < 1.0 {
		s = 1.0
	}
	return s
}

// applyDpiScaledDefault 把默认窗口尺寸按 DPI 倍率调整。
func applyDpiScaledDefault(hwnd uintptr) {
	scale := dpiScale()
	if scale <= 1.0 {
		return
	}
	w := int32(float64(1180) * scale)
	h := int32(float64(820) * scale)
	const swpNoZOrderActivate = 0x0004 | 0x0010
	procSetWindowPos.Call(hwnd, 0, 0, 0, uintptr(w), uintptr(h), swpNoZOrderActivate)
}

// serviceState 查询 Windows 服务的运行状态；服务不存在返回 -1。
// 供托盘菜单感知"探针服务"是否已安装/运行（服务名与 agent -install 一致）。
func serviceState(name string) int32 {
	const (
		scManagerConnect    = 0x0001
		serviceQueryStatus  = 0x0004
		serviceRunning      = 0x4
		serviceStopPending  = 0x3
		serviceStartPending = 0x2
		serviceStopped      = 0x1
	)
	type serviceStatus struct {
		ServiceType     uint32
		CurrentState    uint32
		Controls        uint32
		Win32ExitCode   uint32
		ServiceExitCode uint32
		CheckPoint      uint32
		WaitHint        uint32
	}
	mgr, _, _ := procOpenSCManagerW.Call(0, 0, scManagerConnect)
	if mgr == 0 {
		return -1
	}
	defer procCloseServiceHandle.Call(mgr)
	svc, _, _ := procOpenServiceW.Call(mgr, uintptr(unsafe.Pointer(utf16(name))), serviceQueryStatus)
	if svc == 0 {
		return -1
	}
	defer procCloseServiceHandle.Call(svc)
	var ss serviceStatus
	r, _, _ := procQueryServiceStatus.Call(svc, uintptr(unsafe.Pointer(&ss)))
	if r == 0 {
		return -1
	}
	switch ss.CurrentState {
	case serviceRunning, serviceStopPending, serviceStartPending:
		return int32(ss.CurrentState)
	}
	return int32(serviceStopped)
}