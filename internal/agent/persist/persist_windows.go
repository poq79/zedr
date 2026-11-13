//go:build windows

package persist

import (
	"strings"

	"zedr/internal/agent/winapi"
	"zedr/internal/model"
)

// enumeratePersistence 是 Windows 全量枚举器（winapi 的注册表/服务/
// 计划任务/启动文件夹六类位置实现），逐字段转换成 persist 形状
// （不直接用类型别名：winapi↔persist 经 enrich 成环）。
func enumeratePersistence() ([]PersistItem, []string) {
	items, errs := winapi.EnumeratePersistence()
	out := make([]PersistItem, 0, len(items))
	for _, it := range items {
		out = append(out, convertItem(it))
	}
	return out, errs
}

// convertItem 把 winapi.PersistItem 转成 persist.PersistItem。
func convertItem(it winapi.PersistItem) PersistItem {
	return PersistItem{
		Key: it.Key, Type: it.Type, Location: it.Location, Name: it.Name,
		Command: it.Command, Enabled: it.Enabled,
		RunAs: it.RunAs, Elevated: it.Elevated, Trigger: it.Trigger,
	}
}

// registryTypes 是定向重扫（ScanRegistry）覆盖的基线类型集合。
var registryTypes = map[string]bool{
	winapi.PersistRegistryRun:     true,
	winapi.PersistRegistryRunOnce: true,
	winapi.PersistWinlogon:        true,
	winapi.PersistIFEO:            true,
}

// ScanRegistry 只枚举注册表类位置并在该子集内 diff——regwatch 实时事件
// 路径用：全量枚举里服务/计划任务占大头，事件驱动的即时重扫只扫三节。
//
// 子集语义（两处都必须限定，否则定向扫描是错的）：
//   - diff 只对注册表类键做：其他节的键本轮根本没枚举；
//   - Removed 判定同样只删"注册表类基线键"——不限定的话会把全部
//     服务/计划任务误判成 Removed（且真的删掉它们的基线记录，
//     下一轮全量扫描会集体误报 Added）。
func (m *Monitor) ScanRegistry() (*Result, error) {
	return m.scanWith(func() ([]PersistItem, []string) {
		items, errs := winapi.EnumeratePersistenceRegistry()
		out := make([]PersistItem, 0, len(items))
		for _, it := range items {
			out = append(out, convertItem(it))
		}
		return out, errs
	}, registryTypes)
}

// commandPath 从自启动命令行还原可执行文件路径（Windows 口径：
// \??\ 前缀、%VAR% 展开、引号路径）。
func commandPath(cmd string) string { return winapi.PersistCommandPath(cmd) }

// 可写目录：攻击者最容易落地的地方。命中这些位置的自启动项风险显著更高。
var pathMarkers = []string{
	`\temp\`, `\tmp\`, `\downloads\`, `\appdata\local\temp`,
	`\users\public\`, `\programdata\`, `\recycle`, `\$recycle.bin\`,
	`\windows\temp\`, `\perflogs\`, `\desktop\`, `\documents\`,
}

// uncPaths：Windows 有 UNC 网络路径语义。
var uncPaths = true

// 危险命令解释器：自启动项通过它们拉起载荷，是"间接启动"的典型形态。
var interpreterMarkers = []string{
	"powershell", "pwsh", "mshta", "rundll32", "regsvr32", "wscript",
	"cscript", "cmd.exe", "cmd /c", "certutil", "bitsadmin", "msiexec",
}

// 隐藏/编码参数特征。
var hiddenArgMarkers = []string{
	"-enc", "-encodedcommand", "hidden", "bypass", "-w hidden", "/c start",
}

// addPrivilegeScore 计划任务的权限/触发组合加分（Windows）。
func addPrivilegeScore(it PersistItem, add func(int, string)) {
	// "以最高权限运行 + 开机即触发 + 指向可写目录"是持久化里风险最高的组合：
	// 它同时满足了自动性、高权限和不可信载荷三个条件。
	// 单看任何一条都不够，凑齐才有判别力，因此这里只做组合加分。
	if it.Elevated && strings.Contains(it.Trigger, "开机") {
		add(14, "计划任务以最高权限在开机时运行")
	} else if it.Elevated && it.Type == winapi.PersistScheduledTask {
		add(6, "计划任务以最高权限运行")
	}
	if it.RunAs != "" && strings.Contains(strings.ToLower(it.RunAs), "system") &&
		it.Type == winapi.PersistScheduledTask {
		add(4, "计划任务以 SYSTEM 身份运行")
	}
}

// mitreFor 把持久化类型映射到 ATT&CK 技术编号（Windows 枚举）。
func mitreFor(typ string) []string {
	switch typ {
	case winapi.PersistRegistryRun, winapi.PersistRegistryRunOnce:
		return []string{"T1547.001"}
	case winapi.PersistStartupFolder:
		return []string{"T1547.001"}
	case winapi.PersistService:
		return []string{"T1543.003"}
	case winapi.PersistScheduledTask:
		return []string{"T1053.005"}
	case winapi.PersistWinlogon:
		return []string{"T1547.004"}
	case winapi.PersistIFEO:
		return []string{"T1546.012"}
	default:
		return []string{"T1547"}
	}
}

// labelFor 返回便于人读的位置描述（Windows 类型）。
func labelFor(typ string) string {
	switch typ {
	case winapi.PersistRegistryRun:
		return "注册表 Run 键"
	case winapi.PersistRegistryRunOnce:
		return "注册表 RunOnce 键"
	case winapi.PersistWinlogon:
		return "Winlogon 登录脚本"
	case winapi.PersistStartupFolder:
		return "启动文件夹"
	case winapi.PersistService:
		return "自启动服务"
	case winapi.PersistScheduledTask:
		return "计划任务"
	case winapi.PersistIFEO:
		return "映像劫持(IFEO)"
	default:
		return typ
	}
}

// 确认 model 引用不悬空（assess 骨架在 neutral 文件里）。
var _ = model.VerdictMalicious
