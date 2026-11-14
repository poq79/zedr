// 本文件 NEUTRAL：/tasks Linux 口径的线协议投影（cron 条目 / systemd
// timer → Windows 计划任务字段，过滤/排序/截断），无 IO。IO 壳在
// tasks_linux.go；cron 行语法解析复用 persist_linuxparse.go 的
// parseCrontabEntries（两个视图共用一份解析，防口径漂移）。
//
// 未在 Linux 实机验证（待 Kali 复验）；验证口径 = GOOS=linux 交叉编译 +
// 本文件单测在 Windows 上运行。
package liveapi

// tasks_linuxparse.go：cron / systemd timer → 计划任务语义字段的投影。

import (
	"sort"
	"strings"
)

// linuxTasksDefaultLimit/Max 与 Windows tasks.go 的 tasksDefaultLimit /
// tasksMaxLimit 同值同语义。
const (
	linuxTasksDefaultLimit = 200
	linuxTasksMaxLimit     = 500
)

// linuxTaskItem 与 Windows tasks.go 的 taskItem 逐字段对齐。字段映射
// 决策（无对等结构的字段取值口径）：
//   - path：来源文件绝对路径（cron 文件 / timer unit 文件）——Windows
//     的 path 是任务层次路径，Linux 的自然对等是"配置文件路径"，调查
//     者可直达原文；filter 沿用它做子串匹配（文件级定位，与 Windows
//     "匹配完整任务路径"口径一致）；
//   - name：cron 条目 = 调度表达式（"0 3 * * *" / "@reboot"）——cron
//     条目在文件内的自然标识就是调度串，命令本体在 actions[0].command；
//     timer 条目 = unit 叶名（去 .timer 后缀，对齐 Windows 去扩展名口径）；
//   - state：恒 "unknown"——与 Windows 版同一既定口径（运行态需调度器
//     运行时查询，离线只读拿不到，输出照实透传、不伪造）；
//   - author：借用为 run-as 用户（cron 的 user 列 / timer 配套 service
//     的 User=；仅显式配置时填充）。Windows 语义是任务作者，Linux 无
//     对等字段，而 run-as 是调查的核心信息，丢掉它比词汇错位代价更大；
//   - enabled：cron 非 # 行恒 true；timer = wants 链接存在（同 /services）；
//   - run_level：恒空（LeastPrivilege/HighestAvailable 是 Windows 语义，
//     不硬凑）；
//   - triggers/actions：调度与执行体投影（见 cronTriggerType /
//     timerTriggerType / cronTaskActions）。cron 命令可能是完整 shell 行
//     （管道、重定向），整体放 command、arguments 留空——按引号规则切
//     二进制/参数在 shell 语法上不可靠，切错比不切更误导。
type linuxTaskItem struct {
	Path     string          `json:"path"`
	Name     string          `json:"name"`
	State    string          `json:"state"`
	Author   string          `json:"author"`
	Enabled  bool            `json:"enabled"`
	RunLevel string          `json:"run_level"`
	Triggers []linuxTaskTrig `json:"triggers"`
	Actions  []linuxTaskAct  `json:"actions"`
}

// linuxTaskTrig/linuxTaskAct 与 winapi.TaskTrigger/TaskAction 的 json tag
// 逐字段对齐（type/enabled、command/arguments）。
type linuxTaskTrig struct {
	Type    string `json:"type"`
	Enabled bool   `json:"enabled"`
}

type linuxTaskAct struct {
	Command   string `json:"command"`
	Arguments string `json:"arguments"`
}

// cronTriggerType 把 cron 调度串映射成触发器类型。@x 特殊串对齐 Windows
// 同义词汇（@reboot→Boot 等）；5 列常规表达式是 Linux 特有词汇，如实标
// "Cron" 不套 Windows 名——调查者看 type 即知口径。
func cronTriggerType(schedule string) string {
	switch schedule {
	case "@reboot":
		return "Boot"
	case "@daily", "@midnight":
		return "Daily"
	case "@weekly":
		return "Weekly"
	case "@monthly":
		return "Monthly"
	case "@yearly", "@annually":
		return "Monthly" // 年度即月度粒度的特例，Windows 无 Yearly 类型
	default:
		if strings.HasPrefix(schedule, "@") {
			return "Time"
		}
		return "Cron"
	}
}

// timerTriggerType 把 systemd timer 的 On* 键映射成触发器类型。Calendar
// 是 Windows 真实类型名（语义同为日历时间）；OnBootSec/OnStartupSec 是
// 开机后相对时间 → Boot；周期性 On*ActiveSec → Time；未知键如实标
// "Timer"。
func timerTriggerType(key string) string {
	switch key {
	case "OnBootSec", "OnStartupSec":
		return "Boot"
	case "OnCalendar":
		return "Calendar"
	case "OnActiveSec", "OnInactiveSec", "OnUnitActiveSec", "OnUnitInactiveSec":
		return "Time"
	default:
		return "Timer"
	}
}

// cronEntryToTaskItem 把一行 crontab 投影成计划任务条目。
func cronEntryToTaskItem(path string, e linuxCronEntry) linuxTaskItem {
	return linuxTaskItem{
		Path:    path,
		Name:    e.Schedule,
		State:   "unknown",
		Author:  e.User,
		Enabled: true,
		Triggers: []linuxTaskTrig{
			{Type: cronTriggerType(e.Schedule), Enabled: true},
		},
		Actions: []linuxTaskAct{{Command: e.Command}},
	}
}

// timerToTaskItem 把一个 timer unit 投影成计划任务条目。svcExecStart/
// svcUser 来自配套的 <name>.service（读不到时执行体/run-as 留空——
// actions 为空数组，不伪造）。
func timerToTaskItem(unitPath, unitName string, info linuxUnitInfo, enabled bool, svcExecStart, svcUser string) linuxTaskItem {
	item := linuxTaskItem{
		Path:     unitPath,
		Name:     unitName,
		State:    "unknown",
		Author:   svcUser,
		Enabled:  enabled,
		Triggers: []linuxTaskTrig{{Type: timerTriggerType(info.TimerKey), Enabled: true}},
		Actions:  []linuxTaskAct{},
	}
	if svcExecStart != "" {
		item.Actions = []linuxTaskAct{{Command: svcExecStart}}
	}
	return item
}

// buildLinuxTasksResult 是 /tasks 的纯投影：filter（path 子串，大小写
// 不敏感，Windows 同口径）→ 按 path+name 排序 → 截断。total 是过滤前
// 全量条数（Windows 契约：调查页需要"本机共 N 个任务"的事实）。
func buildLinuxTasksResult(items []linuxTaskItem, filter string, limit int) map[string]any {
	total := len(items)
	filter = strings.ToLower(strings.TrimSpace(filter))

	matched := make([]linuxTaskItem, 0, len(items))
	for _, t := range items {
		if filter != "" && !strings.Contains(strings.ToLower(t.Path), filter) {
			continue
		}
		matched = append(matched, t)
	}

	sort.Slice(matched, func(i, j int) bool {
		if matched[i].Path != matched[j].Path {
			return matched[i].Path < matched[j].Path
		}
		return matched[i].Name < matched[j].Name
	})

	truncated := len(matched) > limit
	if truncated {
		matched = matched[:limit]
	}
	if matched == nil {
		matched = []linuxTaskItem{}
	}
	return map[string]any{
		"items":     matched,
		"total":     total,
		"truncated": truncated,
	}
}
