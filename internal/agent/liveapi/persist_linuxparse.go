// 本文件 NEUTRAL：Linux 持久化条目的纯解析逻辑（无 IO、无构建标签）。
// 放中性文件的原因同 linuxpath.go：验证口径要求在 Windows 上跑单测锁定
// 解析口径；Linux 专属的目录遍历 IO 壳在 persistence_linux.go。
//
// 与 internal/agent/persist 枚举器是两份实现的原因：persist 包的 Linux
// 枚举（persist_linux.go）不在本次移植的所有权范围内，且其导出面服务于
// 检测管线的基线 diff（带打分/去重/基线语义）；/persistence 端点要的是
// "现在这张表上有什么"的一次性只读快照，语义更薄。两边各按自己的契约
// 演进，解析口径（cron/systemd 的行语法）以本文件单测锁样例。
//
// 未在 Linux 实机验证（本机无 Linux 测试环境）；验证口径 = GOOS=linux
// 交叉编译 + 本文件单测在 Windows 上运行。
package liveapi

// persist_linuxparse.go：crontab / systemd unit / XDG autostart 的行解析。

import (
	"sort"
	"strings"
	"time"
)

// linuxPersistRaw 是解析层的中间产物（persistence_linux.go 再投影成
// 线协议 item）。Enabled 表达"这条目会被调度器执行"。
type linuxPersistRaw struct {
	Source   string // service（systemd）| task（cron）| startup（autostart/rc.local）
	Name     string
	Command  string
	User     string
	Location string // 来源文件绝对路径
	Enabled  bool
}

// parseCrontabFile 解析 crontab 文本为持久化条目。
//
// withUser 区分两种形态：/etc/crontab 与 /etc/cron.d/* 的行是
// "m h dom mon dow user command"（6+ 列）；用户 spool（/var/spool/cron/*）
// 没有 user 列（5 列即命令）。注释行/空行/环境变量行（VAR=value）跳过；
// @reboot 特殊调度保留——它是"开机自跑"语义，恰是驻留高发位，条目
// Name 里标注调度串。
//
// 诚实边界：行级解析不展开 cron 环境变量（PATH 等），命令原样呈现。
func parseCrontabFile(path string, data []byte, withUser bool) []linuxPersistRaw {
	var out []linuxPersistRaw
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// 环境变量行（CRON_TZ=/etc/localtime 等）不是执行项
		if i := strings.IndexByte(line, '='); i > 0 && !strings.ContainsAny(line[:i], " \t") {
			continue
		}
		f := strings.Fields(line)
		var cmd, user string
		if strings.HasPrefix(f[0], "@") {
			// @reboot/@daily 等单字段调度：无 5 列时间规格。
			// 系统形态 = [@sched, user, cmd...]；spool 形态 = [@sched, cmd...]
			if withUser {
				if len(f) < 3 {
					continue
				}
				user, cmd = f[1], strings.Join(f[2:], " ")
			} else {
				if len(f) < 2 {
					continue
				}
				cmd = strings.Join(f[1:], " ")
			}
		} else {
			// 常规行：5 列时间规格（+ user 列）+ 命令
			minFields := 6 // 5 时间列 + 至少 1 列命令
			if withUser {
				minFields = 7
			}
			if len(f) < minFields {
				continue // 残行宁缺毋滥
			}
			cmd = strings.Join(f[minFields-1:], " ")
			if withUser {
				user = f[5]
			}
		}
		name := path
		if strings.HasPrefix(f[0], "@") {
			name = path + " (" + f[0] + ")" // @reboot 等调度语义在名字里可见
		}
		out = append(out, linuxPersistRaw{
			Source:   "task",
			Name:     name,
			Command:  cmd,
			User:     user,
			Location: path,
			Enabled:  true, // 非 # 行即会被 cron 执行
		})
	}
	return out
}

// parseSystemdUnitExec 提取 unit 文件 [Service] 节的 ExecStart 主执行体。
//
// 口径：ExecStartPre/ExecStartPost/ExecReload 不是"服务本体"，不收；
// 多个 ExecStart（systemd 不允许，容错取第一个）。ExecStart= 后允许的
// 前缀修饰符（"-" 失败忽略、":" 静默、"+" 提权环境、"!"）剥离后取首个
// token 作为命令。节外（[Unit]/[Install]）的同名键不收。
// Type=oneshot 常见的多 ExecStart 串行写法只报第一条——诚实边界：
// 这是"主执行体"清单不是完整执行序列。
func parseSystemdUnitExec(data []byte) (string, bool) {
	inService := false
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			inService = line == "[Service]"
			continue
		}
		if !inService || line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		val, ok := strings.CutPrefix(line, "ExecStart=")
		if !ok {
			continue
		}
		val = strings.TrimSpace(val)
		// 剥离前缀修饰符（systemd.exec 的 ExecStart 前缀语义）
		val = strings.TrimLeft(val, "-:+!")
		if val == "" {
			return "", false
		}
		// 引号包裹的可执行体（路径含空格的合法形态）按引号段取，
		// Fields 切分会把带空格的路径腰斩
		if strings.HasPrefix(val, `"`) {
			end := strings.IndexByte(val[1:], '"')
			if end < 0 {
				return "", false
			}
			return val[1 : 1+end], true
		}
		cmd := strings.Fields(val)
		if len(cmd) == 0 {
			return "", false
		}
		return cmd[0], true
	}
	return "", false
}

// parseAutostartDesktop 解析 XDG autostart 的 .desktop 条目，返回
// (Name, Exec, Hidden)。Hidden=true 的条目桌面不会启动——但攻击者常
// 用 Hidden=false 的注释块或双写键绕过，原样带出由调查者判断。
func parseAutostartDesktop(data []byte) (name, exec string, hidden bool) {
	inEntry := false
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			// 只认 [Desktop Entry]；其他节（[Desktop Action xxx]）不是
			// 自启动本体
			inEntry = line == "[Desktop Entry]"
			continue
		}
		if !inEntry || line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if v, ok := strings.CutPrefix(line, "Exec="); ok && exec == "" {
			exec = strings.TrimSpace(v)
		}
		if v, ok := strings.CutPrefix(line, "Name="); ok && name == "" {
			name = strings.TrimSpace(v)
		}
		if v, ok := strings.CutPrefix(line, "Hidden="); ok {
			hidden = strings.TrimSpace(v) == "true"
		}
	}
	return name, exec, hidden
}

// linuxExtractExePath 从命令行提取首个可执行路径（Linux 口径）：
// 首个以 "/" 开头的 token（绝对路径调用是持久化条目的主流形态）。
// 裸名命令（依赖 PATH 解析）与相对路径不猜——解析不了的诚实留空，
// 与 Windows 侧 extractExePath 的"宁缺毋滥"口径一致。引号包裹的路径
// 按引号段整体取（systemd/cron 都允许引号形态）。
func linuxExtractExePath(command string) string {
	command = strings.TrimSpace(command)
	if command == "" {
		return ""
	}
	// 引号开头 = 带空格路径的合法形态，按引号段整体取
	if strings.HasPrefix(command, `"`) {
		end := strings.IndexByte(command[1:], '"')
		if end < 0 {
			return ""
		}
		return command[1 : 1+end]
	}
	for _, tok := range strings.Fields(command) {
		if strings.HasPrefix(tok, "/") {
			return tok
		}
	}
	return ""
}

// ---------------------------------------------------------------- 线协议投影（中性，双平台契约一致）

// linuxPersistMaxItems 与 Windows 同上限（契约 §16.1）。
const linuxPersistMaxItems = 2000

// linuxPersistItem 是 /persistence items[] 的一行（字段与 Windows 版逐字
// 对齐，前端按来源分组的逻辑复用）。
type linuxPersistItem struct {
	Source   string `json:"source"`
	Name     string `json:"name"`
	Command  string `json:"command"`
	ExePath  string `json:"exe_path"`
	User     string `json:"user"`
	Enabled  bool   `json:"enabled"`
	Location string `json:"location"`
}

// linuxPersistCounts 是三来源的采集总数（截断前）。
type linuxPersistCounts struct {
	Service int `json:"service"`
	Task    int `json:"task"`
	Startup int `json:"startup"`
}

// linuxPersistResult 是 /persistence 的完整响应。
type linuxPersistResult struct {
	GeneratedAt string             `json:"generated_at"`
	Truncated   bool               `json:"truncated"`
	Counts      linuxPersistCounts `json:"counts"`
	Items       []linuxPersistItem `json:"items"`
}

// buildLinuxPersistenceResult 是纯聚合逻辑（单测直接注入桩条目）。
// 放中性文件的原因：排序/截断/exe_path 口径要能在 Windows 上单测锁定。
func buildLinuxPersistenceResult(raws []linuxPersistRaw, generatedAt time.Time) linuxPersistResult {
	items := make([]linuxPersistItem, 0, len(raws))
	for _, raw := range raws {
		items = append(items, linuxPersistItem{
			Source:   raw.Source,
			Name:     raw.Name,
			Command:  raw.Command,
			ExePath:  linuxExtractExePath(raw.Command),
			User:     raw.User,
			Enabled:  raw.Enabled,
			Location: raw.Location,
		})
	}

	// 排序保证输出稳定：来源（service→task→startup）→ 位置 → 名称 → 命令
	//（与 Windows 版同口径；截断发生在排序之后，同一次采集多次调用
	// 截出同一子集）。
	rank := map[string]int{"service": 0, "task": 1, "startup": 2}
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

	res := linuxPersistResult{
		GeneratedAt: generatedAt.Format(time.RFC3339),
		Items:       []linuxPersistItem{},
	}
	for _, it := range items {
		switch it.Source {
		case "service":
			res.Counts.Service++
		case "task":
			res.Counts.Task++
		case "startup":
			res.Counts.Startup++
		}
	}
	if len(items) > linuxPersistMaxItems {
		res.Truncated = true
		items = items[:linuxPersistMaxItems]
	}
	res.Items = items
	return res
}
