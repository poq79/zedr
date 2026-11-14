//go:build windows

package agentapp

// validCollector 校验采集器名（Windows 口径）：auto / ntquery / toolhelp。
// 校验放在按 OS 分文件里而不是硬编码在 config.go——Linux 的 procfs
// 是同名字段的合法取值（第二轮体检修复：此前 Linux 配 procfs 会被
// 中性校验直接拒绝）。
func validCollector(name string) bool {
	switch name {
	case "auto", "ntquery", "toolhelp":
		return true
	}
	return false
}
