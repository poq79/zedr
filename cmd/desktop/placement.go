//go:build windows
// +build windows

package main

// 窗口形态记忆：位置/大小/最大化存 HKCU，下次打开原样恢复。
//
// 用户体验依据：每次打开都回默认尺寸居中，等于告诉用户"我根本没记住
// 你是谁"——这是桌面工具最常被诟病的细节之一。

import (
	"unsafe"

	"golang.org/x/sys/windows/registry"
)

const placementKeyPath = `Software\Z-EDR\UI`

// savePlacement 在窗口销毁前把当前形态写入注册表。
// 用 CreateKey（父键 Software\Z-EDR 不存在时自动创建；OpenKey 不会建中间键）。
func savePlacement(hwnd uintptr) {
	var r rect
	if hr, _, _ := procGetWindowRect.Call(hwnd, uintptr(unsafe.Pointer(&r))); hr == 0 {
		return
	}
	k, _, err := registry.CreateKey(registry.CURRENT_USER, placementKeyPath, registry.SET_VALUE)
	if err != nil {
		return
	}
	defer k.Close()
	_ = k.SetDWordValue("Left", uint32(r.Left))
	_ = k.SetDWordValue("Top", uint32(r.Top))
	_ = k.SetDWordValue("Width", uint32(r.Right-r.Left))
	_ = k.SetDWordValue("Height", uint32(r.Bottom-r.Top))
	maximized := uint32(0)
	if frame != nil && frame.isZoomed() {
		maximized = 1
	}
	_ = k.SetDWordValue("Maximized", maximized)
}

// restorePlacement 在窗口创建后恢复上次的形态。
// 防御：保存值不完整/尺寸过小/落在任何显示器之外时静默放弃（用默认居中）。
func restorePlacement(hwnd uintptr) {
	k, err := registry.OpenKey(registry.CURRENT_USER, placementKeyPath, registry.QUERY_VALUE)
	if err != nil {
		return
	}
	defer k.Close()
	read := func(name string) (uint32, bool) {
		v, _, err := k.GetIntegerValue(name)
		return uint32(v), err == nil
	}
	l, ok1 := read("Left")
	t, ok2 := read("Top")
	w, ok3 := read("Width")
	h, ok4 := read("Height")
	maxv, _ := read("Maximized")
	if !ok1 || !ok2 || !ok3 || !ok4 {
		// 没有历史形态：默认尺寸按 DPI 放大，避免高缩放下窗口偏小
		applyDpiScaledDefault(hwnd)
		return
	}
	// 最小尺寸防线 + 双 uint32 转换越界防护（残值可能极大）
	if w < 900 || h < 620 || w > 10000 || h > 10000 {
		return
	}
	if !rectOnScreen(int32(l), int32(t), int32(w), int32(h)) {
		return
	}
	const (
		swpNoZOrder     = 0x0004
		swpNoActivate   = 0x0010
		swpFrameChanged = 0x0020
	)
	procSetWindowPos.Call(hwnd, 0,
		uintptr(int32(l)), uintptr(int32(t)), uintptr(w), uintptr(h),
		swpNoZOrder|swpNoActivate|swpFrameChanged)
	if maxv == 1 {
		procShowWindow.Call(hwnd, swMaximize)
	}
}

// rectOnScreen 校验矩形与虚拟桌面（所有显示器的并集）有交集，
// 防止拔掉显示器后窗口恢复到屏幕外摸不着。
func rectOnScreen(l, t int32, w, h int32) bool {
	const (
		smXVirtual = 76
		smYVirtual = 77
		smWVirtual = 78
		smHVirtual = 79
	)
	vx := sysMetrics(smXVirtual)
	vy := sysMetrics(smYVirtual)
	vw := sysMetrics(smWVirtual)
	vh := sysMetrics(smHVirtual)
	if vw == 0 || vh == 0 {
		return true // 虚拟屏查询失败时放行
	}
	return l+int32(w) > vx && t+int32(h) > vy && l < vx+vw && t < vy+vh
}