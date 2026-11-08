package liveapi

// tasks.go：/tasks 计划任务全量详情端点（调查深化，隧道内只读）。
//
// 与 /persistence 的分工：persistence 是 Autoruns 视角的"启用态驻留
// 三来源"（服务/任务/启动项），只给驻留判定所需的最小字段；本端点是
// 计划任务的全量详情——含禁用任务，触发器/动作/运行级别齐备，供 AI
// 调查排查驻留、回溯 schtasks 远程创建这类横向手法时取证据。禁用任务
// 对调查同样重要：攻击者落地后常先禁用既有任务再建新任务，只看启用态
// 会漏掉这半边痕迹。
//
// 数据来源 winapi.TaskList：文件级枚举（System32\Tasks）+ 任务定义 XML
// 解析富化。单任务 XML 解析失败在 winapi 侧按零值富字段跳过（不中断
// 整轮），这里无需处理。State 恒为 "unknown"（运行态需 Task Scheduler
// COM 查询，winapi 侧的既定成本取舍），输出照实透传、不伪造。
//
// 契约：total 是过滤前的全量任务数——调查页需要"本机共 N 个任务"这个
// 事实，filter 无匹配时 total>0 而 items 为空，前端据此区分"没有任务"
// 与"没有匹配"。truncated 表示匹配集超出 limit 被截断。

import (
	"log/slog"
	"net/http"
	"strings"

	"zedr/internal/agent/winapi"
	"zedr/internal/platform/apperr"
	"zedr/internal/platform/httpx"
)

const (
	tasksDefaultLimit = 200
	tasksMaxLimit     = 500
)

// taskItem 是 items[] 的一行。不复用 winapi.TaskInfo 直接序列化：
// 其 Path/Name/State 三个字段没有 json tag（历史消费方按 Go 字段名取值），
// 直接 Marshal 会输出大写字段名与富字段的 snake_case 混排，这里统一收敛。
// Triggers/Actions 复用 winapi 类型（自带 json tag），避免两处定义漂移。
type taskItem struct {
	Path     string               `json:"path"`      // 完整任务路径，如 \Microsoft\Windows\...\X
	Name     string               `json:"name"`      // 叶子名
	State    string               `json:"state"`     // 恒 "unknown"（见文件头），如实透传
	Author   string               `json:"author"`
	Enabled  bool                 `json:"enabled"`
	RunLevel string               `json:"run_level"` // LeastPrivilege / HighestAvailable
	Triggers []winapi.TaskTrigger `json:"triggers"`
	Actions  []winapi.TaskAction  `json:"actions"`
}

func (s *server) handleTasks(w http.ResponseWriter, r *http.Request) {
	filter := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("filter")))
	limit := queryInt(r, "limit", tasksDefaultLimit, 1, tasksMaxLimit)

	tasks, err := winapi.TaskList()
	if err != nil {
		slog.Warn("liveapi_tasks_enum_failed", "err", err)
		httpx.WriteError(w, r, apperr.Internal(err))
		return
	}

	// filter 匹配完整任务路径而非仅叶子名：叶子名本就是路径的子串，
	// 这样"按名称过滤"与"按文件夹过滤"（\Microsoft\Windows\）一个
	// 参数全覆盖，调查员粘贴路径片段也能直接用
	matched := make([]taskItem, 0, len(tasks))
	for _, t := range tasks {
		if filter != "" && !strings.Contains(strings.ToLower(t.Path), filter) {
			continue
		}
		item := taskItem{
			Path:     t.Path,
			Name:     t.Name,
			State:    t.State,
			Author:   t.Author,
			Enabled:  t.Enabled,
			RunLevel: t.RunLevel,
			Triggers: t.Triggers,
			Actions:  t.Actions,
		}
		// winapi 侧解析不到定义时富字段为 nil，JSON 里是 null——
		// 统一为空数组，前端不用判空
		if item.Triggers == nil {
			item.Triggers = []winapi.TaskTrigger{}
		}
		if item.Actions == nil {
			item.Actions = []winapi.TaskAction{}
		}
		matched = append(matched, item)
	}

	truncated := len(matched) > limit
	if truncated {
		matched = matched[:limit]
	}
	httpx.WriteJSON(w, r, http.StatusOK, map[string]any{
		"items":     matched,
		"total":     len(tasks),
		"truncated": truncated,
	})
}
