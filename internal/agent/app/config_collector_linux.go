//go:build linux

package agentapp

// validCollector 校验采集器名（Linux 口径）：auto / procfs。
// ntquery/toolhelp 是 Windows 专属实现，Linux 构建里不存在。
func validCollector(name string) bool {
	switch name {
	case "auto", "procfs":
		return true
	}
	return false
}
