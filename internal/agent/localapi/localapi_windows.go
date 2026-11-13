//go:build windows
// +build windows

// localapi_windows.go：本地视图类型的 Windows 侧定义——直接别名到
// hygiene 类型。选别名而不是复制结构体的原因：
//  1. Backend 接口的既有实现方（internal/agent/app 的 Agent）签名零改动；
//  2. 线协议零变化（别名就是同一类型，不存在转换遗漏）；
//  3. hygiene 类型演进时本文件无需同步——视图天然跟随。
//
// hygiene 的 import 只出现在本 windows 标签文件里：Linux 构建不耦合
// hygiene 的并行改造窗口（见 api.go 头注释）。
package localapi

import (
	"zedr/internal/agent/hygiene"
)

type (
	// InstalledAppView 是 Backend.Apps 的行类型（Windows = hygiene.InstalledApp）。
	InstalledAppView = hygiene.InstalledApp
	// CheckView 是 Backend.Posture 的行类型。
	CheckView = hygiene.Check
	// ExposureView 是 Backend.Exposure 的返回类型。
	ExposureView = hygiene.ExposureReport
	// BrowserView 是 Backend.BrowserAudit 的返回类型。
	BrowserView = hygiene.BrowserReport
	// PersistAuditView 是 Backend.PersistAudit 的行类型。
	PersistAuditView = hygiene.PersistAudit
)
