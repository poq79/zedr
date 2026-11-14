// 本文件 NEUTRAL：systemd unit 文件的键值解析（无 IO、无构建标签）。
// services 与 tasks（timer）两个端点共用一份解析，避免两处各解一版
// unit 语法然后口径漂移；IO 壳（目录遍历）在 services_linux.go /
// tasks_linux.go。
//
// 未在 Linux 实机验证（待 Kali 复验）；验证口径 = GOOS=linux 交叉编译 +
// 本文件单测在 Windows 上运行。
package liveapi

// systemdunit_linuxparse.go：systemd unit 的 Description/ExecStart/User/
// Timer 调度键提取。

import "strings"

// linuxUnitInfo 是一个 unit 文件的解析产物（调查面所需的最小字段集）。
type linuxUnitInfo struct {
	Description string // [Unit] Description=；缺失为空
	ExecStart   string // [Service] ExecStart= 完整值（剥前缀修饰符）；缺失为空
	User        string // [Service] User=；缺失为空（systemd 默认 root，不冒填）
	TimerKey    string // [Timer] 首个 On* 键名（OnCalendar 等）；非 timer 为空
	TimerValue  string // 对应键值（如 "*-* 03:00:00"）
}

// parseLinuxUnit 解析 unit 文本。节内取键，节外同名键不收（与
// parseSystemdUnitExec / linuxinv parseUnitDescription 的节作用域口径
// 一致）；单行内联续行（行尾 \）不展开——v1 诚实边界：ExecStart 带内联
// 续行的 unit 极少，截断值仍可辨识主执行体。
func parseLinuxUnit(data []byte) linuxUnitInfo {
	var info linuxUnitInfo
	section := ""
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = line
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		val = strings.TrimSpace(val)
		switch section {
		case "[Unit]":
			if key == "Description" && info.Description == "" {
				info.Description = val
			}
		case "[Service]":
			switch key {
			case "ExecStart":
				// 与 parseSystemdUnitExec 同口径：剥前缀修饰符（"-"
				// 失败忽略 / ":" 静默 / "+" 提权环境 / "!"），保留完整
				// 命令行（/services 的 path_name 语义 = Windows 服务
				// 的二进制命令行，含参数）。
				if info.ExecStart == "" {
					info.ExecStart = strings.TrimLeft(val, "-:+!")
				}
			case "User":
				if info.User == "" {
					info.User = val
				}
			}
		case "[Timer]":
			// 调度键按文件内出现顺序取首个 On*（systemd timer 可以
			// 多键并存，调查面只报首个——完整调度语义以 unit 原文为准，
			// Location/路径可直达）。
			if info.TimerKey == "" && strings.HasPrefix(key, "On") {
				info.TimerKey, info.TimerValue = key, val
			}
		}
	}
	return info
}
