//go:build windows
// +build windows

package liveapi

// persistence.go：持久化总览（Autoruns 风格，契约 §16.1）。
//
// 端点把三类"开机后会自己跑起来"的持久化点收敛成一张表：
//   - service：StartType=auto 的普通服务（延迟自动启动同属 auto 启动类型，
//     QUERY_SERVICE_CONFIG 不区分延迟标记，因此一并计入）；
//   - task：任务定义里 Enabled 为真的计划任务（含"XML 读不到按启用"的既有
//     口径，与 inventory tasks 节一致）；
//   - startup：Run/RunOnce/Winlogon/IFEO/启动目录五类自启动项。
//
// 刻意不复用 persist.EnumeratePersistence 里的 service/scheduled_task 两类：
// 它们已有专门的数据源（ServiceList/TaskList，字段更全），混进来会让同一
// 服务/任务在总览里出现两次，来源计数也失真。这里只从 EnumeratePersistence
// 的结果里挑五类启动项，枚举本身仍是既有的只读实现，不新增采集面。
//
// 预算口径：各枚举器都不接受 context，无法中途取消，因此在"每个来源开始前"
// 检查 10s 总预算——超预算的来源直接跳过并置 truncated=true（诚实表达
// "结果不完整"）。单个来源内部仍有各自的成本上界（任务 XML 枚举 5s）。
// 上限 2000 条同样置 truncated，且 counts 统计的是采集到的总数（不是
// items 数组长度），前端可用 sum(counts) > len(items) 判断被截断。

import (
	"log/slog"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"

	"zedr/internal/agent/winapi"
	"zedr/internal/platform/httpx"
)

const (
	persistenceMaxItems = 2000
	persistenceBudget   = 10 * time.Second

	persistenceSourceService = "service"
	persistenceSourceTask    = "task"
	persistenceSourceStartup = "startup"
)

// exePathRe 从命令行里提取第一个"盘符:\\...\\*.exe|dll|bat|cmd|ps1"。
//
// 为什么非贪婪 + 允许空格：服务 ImagePath 常见 `C:\Program Files\...\a.exe -k x`
// 这类未加引号但路径含空格的写法；非贪婪保证在第一个扩展名处停下，参数
// 不会被吞进 exe_path。`[^"\r\n]` 避免越过右引号或换行去匹配参数里的路径。
// 与前端 extractExePath 的基础口径保持一致（探针侧只做基础提取，不展开
// 环境变量、不解析 .lnk 目标——取不到就留空，让前端如实显示"未提取"）。
var exePathRe = regexp.MustCompile(`(?i)[A-Za-z]:\\[^"\r\n]*?\.(?:exe|dll|bat|cmd|ps1)`)

// persistenceItem 是 /persistence items[] 的一行（契约 §16.1）。
type persistenceItem struct {
	Source   string `json:"source"`
	Name     string `json:"name"`
	Command  string `json:"command"`
	ExePath  string `json:"exe_path"`
	User     string `json:"user"`
	Enabled  bool   `json:"enabled"`
	Location string `json:"location"`
}

// persistenceCounts 是三个来源的采集总数（截断前）。
type persistenceCounts struct {
	Service int `json:"service"`
	Task    int `json:"task"`
	Startup int `json:"startup"`
}

// persistenceResult 是 /persistence 的完整响应（httpx.WriteJSON 包进 data）。
type persistenceResult struct {
	GeneratedAt string            `json:"generated_at"`
	Truncated   bool              `json:"truncated"`
	Counts      persistenceCounts `json:"counts"`
	Items       []persistenceItem `json:"items"`
}

// HandlePersistence 返回 GET /persistence 的 handler（不依赖 Deps：
// 三个来源都是 winapi 的现成只读枚举器，路由由主会话在 New 里接线）。
func HandlePersistence() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		deadline := time.Now().Add(persistenceBudget)
		budgetHit := false

		var services []winapi.ServiceInfo
		if got, err := winapi.ServiceList(); err != nil {
			slog.Warn("liveapi_persistence_services_failed", "err", err)
		} else {
			services = got
		}

		var tasks []winapi.TaskInfo
		if time.Now().After(deadline) {
			budgetHit = true
		} else if got, err := winapi.TaskList(); err != nil {
			slog.Warn("liveapi_persistence_tasks_failed", "err", err)
		} else {
			tasks = got
		}

		var startup []winapi.PersistItem
		if time.Now().After(deadline) {
			budgetHit = true
		} else {
			got, errs := winapi.EnumeratePersistence()
			// 单个位置读不到是常态（受保护键/权限差异），照常使用其余结果；
			// errs 只落日志，不把整页打成 500——分析师需要看到能读到的部分。
			if len(errs) > 0 {
				slog.Warn("liveapi_persistence_startup_partial", "errs", strings.Join(errs, "; "))
			}
			startup = got
		}

		res := buildPersistenceResult(services, tasks, startup, time.Now().UTC())
		res.Truncated = res.Truncated || budgetHit
		httpx.WriteJSON(w, r, http.StatusOK, res)
	}
}

// buildPersistenceResult 是纯聚合逻辑（单测直接注入桩数据）。
// generatedAt 由调用方传入，保证响应里的 generated_at 与采集开始时刻
// 可对齐；单测可传固定值做断言。
func buildPersistenceResult(services []winapi.ServiceInfo, tasks []winapi.TaskInfo, startup []winapi.PersistItem, generatedAt time.Time) persistenceResult {
	items := make([]persistenceItem, 0, len(services)+len(tasks)+len(startup))

	// 服务：只取 auto（含延迟自动）。boot/system 是驱动启动类型，
	// ServiceList 本身已排除驱动，这里再按 auto 过滤把普通服务的
	// manual/disabled 挡在外面。
	for _, svc := range services {
		if !isAutoStart(svc.StartMode) {
			continue
		}
		name := svc.Name
		if name == "" {
			name = svc.DisplayName
		}
		items = append(items, newPersistenceItem(
			persistenceSourceService, name, svc.PathName, svc.Account, true, "service"))
	}

	// 计划任务：只保留 Enabled；command 取第一个动作（契约 §16.1）。
	// actions[0] 为空时 command 留空而不是退化成任务路径——任务路径不是
	// "会执行什么"，混进来会让"可执行路径风险"统计失真。
	for _, task := range tasks {
		if !task.Enabled {
			continue
		}
		cmd := ""
		if len(task.Actions) > 0 {
			cmd = strings.TrimSpace(strings.TrimSpace(task.Actions[0].Command) + " " +
				strings.TrimSpace(task.Actions[0].Arguments))
		}
		name := task.Name
		if name == "" {
			name = task.Path
		}
		items = append(items, newPersistenceItem(
			persistenceSourceTask, name, cmd, "", task.Enabled, task.Path))
	}

	// 启动项：从 persist 的七类里只挑五类。service/scheduled_task 两类
	// 已由上面的专门来源覆盖，重复计入会让同一对象出现两次。
	for _, it := range startup {
		if !isStartupKind(it.Type) {
			continue
		}
		items = append(items, newPersistenceItem(
			persistenceSourceStartup, it.Name, it.Command, it.RunAs, it.Enabled, it.Location))
	}

	// 排序保证输出稳定：先按来源（服务→任务→启动项），再按位置/名称/命令。
	// 截断发生在排序之后，否则同一次采集在多次调用间可能截出不同子集。
	rank := map[string]int{
		persistenceSourceService: 0,
		persistenceSourceTask:    1,
		persistenceSourceStartup: 2,
	}
	sort.Slice(items, func(i, j int) bool {
		if rank[items[i].Source] != rank[items[j].Source] {
			return rank[items[i].Source] < rank[items[j].Source]
		}
		if items[i].Location != items[j].Location {
			return items[i].Location < items[j].Location
		}
		if items[i].Name != items[j].Name {
			return items[i].Name < items[j].Name
		}
		return items[i].Command < items[j].Command
	})

	res := persistenceResult{
		GeneratedAt: generatedAt.Format(time.RFC3339),
		Counts:      persistenceCounts{},
		Items:       []persistenceItem{},
	}
	for _, it := range items {
		switch it.Source {
		case persistenceSourceService:
			res.Counts.Service++
		case persistenceSourceTask:
			res.Counts.Task++
		case persistenceSourceStartup:
			res.Counts.Startup++
		}
	}
	if len(items) > persistenceMaxItems {
		res.Truncated = true
		items = items[:persistenceMaxItems]
	}
	res.Items = items
	return res
}

// newPersistenceItem 统一填 exe_path：三类来源的 command 形态差别很大，
// 但"首个可执行路径"的提取口径必须一致，否则前端按来源分组后会出现
// 同样的路径有的能签名校验、有的不能。
func newPersistenceItem(source, name, command, user string, enabled bool, location string) persistenceItem {
	return persistenceItem{
		Source:   source,
		Name:     name,
		Command:  command,
		ExePath:  extractExePath(command),
		User:     user,
		Enabled:  enabled,
		Location: location,
	}
}

// extractExePath 从命令行里提取第一个绝对可执行路径（去引号）。
// 只识别盘符开头的绝对路径：`%SystemRoot%\...`、裸程序名这类无法在
// 不展开环境变量/不查 PATH 的前提下可靠解析，宁可留空也不猜。
func extractExePath(command string) string {
	return strings.TrimSpace(exePathRe.FindString(command))
}

// isAutoStart 判断服务启动类型是否属于"开机自动"。
// delayed-auto 在本仓库的 ServiceList 里目前与 auto 同值（延迟标记
// 需要 QueryServiceConfig2，额外一轮系统调用，本轮不引入），这里仍
// 兼容该字符串，避免未来采集口径变化时静默漏掉服务。
func isAutoStart(mode string) bool {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "auto", "delayed-auto":
		return true
	default:
		return false
	}
}

// isStartupKind 限定 startup 来源只取五类自启动位置。
func isStartupKind(kind string) bool {
	switch kind {
	case winapi.PersistRegistryRun,
		winapi.PersistRegistryRunOnce,
		winapi.PersistWinlogon,
		winapi.PersistStartupFolder,
		winapi.PersistIFEO:
		return true
	default:
		return false
	}
}
