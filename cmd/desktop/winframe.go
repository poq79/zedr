package main

// 无边框窗口：去掉 Windows 默认标题栏，面板顶栏自己当标题栏。
//
// 做法（业界标准三板斧）：
//  1. 保留 WS_OVERLAPPEDWINDOW（快照/最大化动画/系统级行为都在），
//     只在 WM_NCCALCSIZE 返回 0 抹掉非客户区——视觉无边框。
//  2. 拖动交给 WebView2 运行时的 CSS `app-region: drag`（见 static/styles.css），
//     宿主侧零代码；顶栏上的按钮用 no-drag 排除。
//  3. 缩放：贴边热区由前端调用 zedrHostResizeEdge → PostMessage(WM_NCLBUTTONDOWN,
//     HT*)，Windows 自己进入模态缩放循环（含正确的光标与镜像布局）。
//
// 最大化时把客户区收回工作区（work area），否则无边框窗口最大化会
// 溢出屏幕一圈并盖住任务栏——这是所有 NCCALCSIZE 方案的共同坑。

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	htLeft        = 10
	htRight       = 11
	htTop         = 12
	htTopLeft     = 13
	htTopRight    = 14
	htBottom      = 15
	htBottomLeft  = 16
	htBottomRight = 17
	swMinimize    = 6
	swMaximize    = 3
)

// minus 把负的 win32 常量转成 uintptr（API 期望的二补数形式）。
// minus(-4) → ^3 → 0xFF..FC，即 GWLP_WNDPROC 的真实位模式。
func minus(n int) uintptr { return ^uintptr(-n - 1) }

type frameState struct {
	hwnd    uintptr
	oldProc uintptr
}

var frame *frameState

// makeFrameless subclass 宿主窗口。必须在 webview Run 前调用一次。
func makeFrameless(hwnd uintptr) {
	frame = &frameState{hwnd: hwnd}
	frame.oldProc, _, _ = procGetWindowLongPtrW.Call(hwnd, minus(gwlpWndProc))
	procSetWindowLongPtrW.Call(hwnd, minus(gwlpWndProc), windows.NewCallback(frameWndProc))
	// 圆角：Win11/Server 2025 走 DWM 原生；Server 2022/Win10 的 DWM 无此
	// 能力。SetWindowRgn 裁切兜底实测有锯齿 + WebView2 合成残影（角落
	// 脏块），比直角更伤——按"做不了就承认"纪律砍掉，直角即最终形态。
	tryRoundWin11Corners(hwnd)
	// 用户上次调整的窗口大小/位置/最大化状态要记得——每次都回 1180x820
	// 居中是典型的"工具不尊重用户"体验。
	restorePlacement(hwnd)
	// subclass 不会追溯已发生的 NCCALCSIZE：必须主动触发一次
	// frame 重算，否则系统标题栏一直留着（窗口尺寸没变就再也不发）。
	const swpFrameChanged = 0x0020
	const swpNoMoveSizeActivateZorder = 0x0001 | 0x0002 | 0x0004 | 0x0010
	procSetWindowPos.Call(hwnd, 0, 0, 0, 0, 0, swpNoMoveSizeActivateZorder|swpFrameChanged)
}

func frameWndProc(hwnd, msg, wp, lp uintptr) uintptr {
	if frame == nil || hwnd != frame.hwnd {
		r, _, _ := procDefWindowProcW.Call(hwnd, msg, wp, lp)
		return r
	}
	switch msg {
	case wmNcCalcSize:
		if wp == 1 {
			// NCCALCSIZE_PARAMS.rgrc[0]：入参=新窗口矩形，返回 0 时=客户区。
			rc := (*rect)(ptrFromLParam(lp))
			if frame.isZoomed() {
				// 最大化：客户区收回到工作区，别盖任务栏、别溢出屏幕
				mi := monitorInfoW{CbSize: uint32(unsafe.Sizeof(monitorInfoW{}))}
				mon, _, _ := procMonitorFromWindow.Call(hwnd, monitorDefaultToNearest)
				procGetMonitorInfoW.Call(mon, uintptr(unsafe.Pointer(&mi)))
				*rc = mi.RcWork
			}
			return 0
		}
	case wmGetMinMaxInfo:
		mmi := (*minMaxInfo)(ptrFromLParam(lp))
		mmi.PtMinTrackSize = point{X: 900, Y: 620}
		return 0
	case wmDestroy:
		// 面板进程退出前记住窗口形态，下次打开原样恢复
		savePlacement(hwnd)
	}
	if frame.oldProc != 0 {
		r, _, _ := procCallWindowProcW.Call(frame.oldProc, hwnd, msg, wp, lp)
		return r
	}
	r, _, _ := procDefWindowProcW.Call(hwnd, msg, wp, lp)
	return r
}

// resizeEdge 前端贴边热区回调：让 Windows 接管缩放（模态循环）。
func resizeEdge(edge string) {
	if frame == nil {
		return
	}
	if frame.isZoomed() {
		return
	}
	var ht uintptr
	switch edge {
	case "left":
		ht = htLeft
	case "right":
		ht = htRight
	case "top":
		ht = htTop
	case "top-left":
		ht = htTopLeft
	case "top-right":
		ht = htTopRight
	case "bottom":
		ht = htBottom
	case "bottom-left":
		ht = htBottomLeft
	case "bottom-right":
		ht = htBottomRight
	default:
		return
	}
	// Post 而非 Send：Bind 回调跑在 WebView2 的 COM 事件线程上，
	// 阻塞它等模态循环结束会有死锁风险。模态循环由消息派发自然进入。
	procPostMessageW.Call(frame.hwnd, wmNcLButtonDown, ht, 0)
}

func (f *frameState) isZoomed() bool {
	r, _, _ := procIsZoomed.Call(f.hwnd)
	return r != 0
}

func (f *frameState) minimize() {
	procShowWindow.Call(f.hwnd, swMinimize)
}

// maximizeToggle 返回调用后的状态：true=现在最大化。
func (f *frameState) maximizeToggle() bool {
	if f.isZoomed() {
		procShowWindow.Call(f.hwnd, swRestore)
		return false
	}
	procShowWindow.Call(f.hwnd, swMaximize)
	return true
}
