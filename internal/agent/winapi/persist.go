// Package winapi 的持久化项枚举。
//
// 为什么需要它：现有检测只看"进程创建"这一个时刻，而入侵的实质是"驻留"。
// 攻击者落地后几乎必然要建立一个开机自启点（注册表 Run 键、启动文件夹、
// 计划任务、自启动服务），这些位置是入侵检测里信噪比最高的一类证据——
// 正常软件很少新增自启动项，而新增项一定对应"有新东西要长期运行"。
package winapi

import (
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/sys/windows/registry"
)

// PersistItem 是一个持久化（自启动）项。
type PersistItem struct {
	// Key 是跨采集周期稳定的唯一标识：同一位置同名项才视为同一对象。
	Key string
	// Type 取值见 PersistType* 常量。
	Type string
	// Location 是注册表路径 / 目录 / 任务路径。
	Location string
	Name     string
	// Command 是原始命令行或镜像路径。
	Command string
	Enabled bool

	// 以下为附加信息（计划任务等场景），不参与基线 key。
	RunAs    string // 运行账号
	Elevated bool   // 是否以最高权限运行
	Trigger  string // 触发方式：开机/登录/定时
}

// 持久化项类型。
const (
	PersistRegistryRun     = "registry_run"
	PersistRegistryRunOnce = "registry_runonce"
	PersistWinlogon        = "winlogon"
	PersistStartupFolder   = "startup_folder"
	PersistService         = "service"
	PersistScheduledTask   = "scheduled_task"
	PersistIFEO            = "ifeo"
)

// PersistLocationLabel 返回便于人读的位置描述。
func PersistLocationLabel(typ string) string {
	switch typ {
	case PersistRegistryRun:
		return "注册表 Run 键"
	case PersistRegistryRunOnce:
		return "注册表 RunOnce 键"
	case PersistWinlogon:
		return "Winlogon 登录脚本"
	case PersistStartupFolder:
		return "启动文件夹"
	case PersistService:
		return "自启动服务"
	case PersistScheduledTask:
		return "计划任务"
	case PersistIFEO:
		return "映像劫持(IFEO)"
	default:
		return typ
	}
}

// EnumeratePersistence 枚举本机全部持久化项。
//
// 单个位置枚举失败不会中断整体流程——不同 Windows 版本、不同权限下
// 某些位置可能读不到，这种情况记录到 errs 里交给上层打日志，
// 而不是让整轮持久化监控失效。
func EnumeratePersistence() (items []PersistItem, errs []string) {
	collect := func(fn func() ([]PersistItem, error), what string) {
		got, err := fn()
		if err != nil {
			errs = append(errs, what+": "+err.Error())
			return
		}
		items = append(items, got...)
	}

	collect(enumerateRegistryRun, "注册表 Run 键")
	collect(enumerateWinlogon, "Winlogon")
	collect(enumerateStartupFolders, "启动文件夹")
	collect(enumerateAutoServices, "自启动服务")
	collect(enumerateScheduledTasks, "计划任务")
	collect(enumerateIFEO, "IFEO 映像劫持")

	return dedupePersistItems(items), errs
}

// EnumeratePersistenceRegistry 只枚举注册表类自启动位置
//（Run/RunOnce + Winlogon + IFEO），供 persist 的定向重扫使用。
//
// 为什么单独存在：实时事件路径（regwatch）只需要"注册表三节"，全量
// 枚举里服务/计划任务占大头（本机实测全量 ~160ms、三节 ~40ms）——
// 事件驱动的即时重扫不必为没变的节付全价。服务/计划任务仍由周期
// 轮询的全量扫描覆盖。
func EnumeratePersistenceRegistry() (items []PersistItem, errs []string) {
	collect := func(fn func() ([]PersistItem, error), what string) {
		got, err := fn()
		if err != nil {
			errs = append(errs, what+": "+err.Error())
			return
		}
		items = append(items, got...)
	}

	collect(enumerateRegistryRun, "注册表 Run 键")
	collect(enumerateWinlogon, "Winlogon")
	collect(enumerateIFEO, "IFEO 映像劫持")

	return dedupePersistItems(items), errs
}

// dedupePersistItems 是两类枚举共用的收尾：同一 Key 只保留一次并稳定
// 排序，保证基线 diff 的确定性。
func dedupePersistItems(items []PersistItem) []PersistItem {
	seen := make(map[string]struct{}, len(items))
	out := items[:0]
	for _, it := range items {
		if it.Key == "" {
			continue
		}
		if _, dup := seen[it.Key]; dup {
			continue
		}
		seen[it.Key] = struct{}{}
		out = append(out, it)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}

// regRunRoot 描述一个 Run 键位置。
type regRunRoot struct {
	root    registry.Key
	path    string
	typ     string
	label64 string
}

func enumerateRegistryRun() ([]PersistItem, error) {
	roots := []regRunRoot{
		{registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`, PersistRegistryRun, "HKLM"},
		{registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`, PersistRegistryRunOnce, "HKLM"},
		{registry.LOCAL_MACHINE, `SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run`, PersistRegistryRun, "HKLM(WOW64)"},
		{registry.LOCAL_MACHINE, `SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce`, PersistRegistryRunOnce, "HKLM(WOW64)"},
		{registry.CURRENT_USER, `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`, PersistRegistryRun, "HKCU"},
		{registry.CURRENT_USER, `SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`, PersistRegistryRunOnce, "HKCU"},
	}

	var out []PersistItem
	var firstErr error
	for _, r := range roots {
		items, err := readRunKey(r)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		out = append(out, items...)
	}
	if len(out) == 0 && firstErr != nil {
		return nil, firstErr
	}
	return out, nil
}

func readRunKey(r regRunRoot) ([]PersistItem, error) {
	k, err := registry.OpenKey(r.root, r.path, registry.QUERY_VALUE)
	if err != nil {
		return nil, err
	}
	defer k.Close()

	names, err := k.ReadValueNames(-1)
	if err != nil {
		return nil, err
	}
	out := make([]PersistItem, 0, len(names))
	for _, name := range names {
		val, _, err := k.GetStringValue(name)
		if err != nil {
			continue // 非字符串值（极少见）跳过
		}
		loc := r.label64 + `\` + r.path
		out = append(out, PersistItem{
			Key:      r.typ + "|" + loc + "|" + name,
			Type:     r.typ,
			Location: loc,
			Name:     name,
			Command:  val,
			Enabled:  true,
		})
	}
	return out, nil
}

func enumerateWinlogon() ([]PersistItem, error) {
	const path = `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.QUERY_VALUE)
	if err != nil {
		return nil, err
	}
	defer k.Close()

	var out []PersistItem
	for _, name := range []string{"Shell", "Userinit", "Taskman", "AppSetup"} {
		val, _, err := k.GetStringValue(name)
		if err != nil || strings.TrimSpace(val) == "" {
			continue
		}
		out = append(out, PersistItem{
			Key:      PersistWinlogon + `|HKLM\` + path + "|" + name,
			Type:     PersistWinlogon,
			Location: `HKLM\` + path,
			Name:     name,
			Command:  val,
			Enabled:  true,
		})
	}
	return out, nil
}

func enumerateStartupFolders() ([]PersistItem, error) {
	var dirs []string
	if appData := os.Getenv("APPDATA"); appData != "" {
		dirs = append(dirs, filepath.Join(appData,
			`Microsoft\Windows\Start Menu\Programs\Startup`))
	}
	if pd := os.Getenv("ProgramData"); pd != "" {
		dirs = append(dirs, filepath.Join(pd,
			`Microsoft\Windows\Start Menu\Programs\Startup`))
	}

	var out []PersistItem
	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() || strings.EqualFold(e.Name(), "desktop.ini") {
				continue
			}
			full := filepath.Join(dir, e.Name())
			// .lnk 只记录链接本身；解析目标需要 COM，成本高且价值有限，
			// 因为"启动文件夹里出现新文件"本身就是足够强的信号。
			out = append(out, PersistItem{
				Key:      PersistStartupFolder + "|" + dir + "|" + e.Name(),
				Type:     PersistStartupFolder,
				Location: dir,
				Name:     e.Name(),
				Command:  full,
				Enabled:  true,
			})
		}
	}
	return out, nil
}

// autoServiceStarts 是"会自启动"的服务启动类型：
// 0=Boot 1=System 2=Auto。3=Manual 4=Disabled 不计入。
var autoServiceStarts = map[uint64]bool{0: true, 1: true, 2: true}

func enumerateAutoServices() ([]PersistItem, error) {
	const path = `SYSTEM\CurrentControlSet\Services`
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.READ)
	if err != nil {
		return nil, err
	}
	defer k.Close()

	names, err := k.ReadSubKeyNames(-1)
	if err != nil {
		return nil, err
	}

	out := make([]PersistItem, 0, 64)
	for _, name := range names {
		sk, err := registry.OpenKey(k, name, registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		start, _, err := sk.GetIntegerValue("Start")
		if err != nil {
			sk.Close()
			continue
		}
		if !autoServiceStarts[start] {
			sk.Close()
			continue
		}
		image, _, err := sk.GetStringValue("ImagePath")
		display, _, _ := sk.GetStringValue("DisplayName")
		typ, _, _ := sk.GetIntegerValue("Type")
		sk.Close()
		if err != nil || strings.TrimSpace(image) == "" {
			continue
		}
		// Type 的高位标记驱动/内核组件，跳过：它们不是普通自启动项，
		// 且数量大、变化少，纳入基线只会增加噪声。
		if typ&0x00000001 != 0 && typ&0x00000020 != 0 {
			continue
		}
		nm := display
		if nm == "" {
			nm = name
		}
		out = append(out, PersistItem{
			Key:      PersistService + "|" + strings.ToLower(name),
			Type:     PersistService,
			Location: `HKLM\` + path + `\` + name,
			Name:     nm,
			Command:  image,
			Enabled:  true,
		})
	}
	return out, nil
}

func enumerateScheduledTasks() ([]PersistItem, error) {
	root := filepath.Join(os.Getenv("SystemRoot"), "System32", "Tasks")
	if _, err := os.Stat(root); err != nil {
		return nil, fmt.Errorf("任务目录不可读: %w", err)
	}

	var out []PersistItem
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info == nil || info.IsDir() {
			return nil // 权限不足的子目录直接跳过
		}
		rel, rerr := filepath.Rel(root, path)
		if rerr != nil {
			return nil
		}
		taskName := `\` + strings.TrimSuffix(rel, filepath.Ext(rel))

		// 解析任务定义，取出真正会被执行的东西。
		//
		// 这一步的成本很低（每个任务一个几 KB 的 XML，本机 184 个任务
		// 合计约 1~2 MB，耗时几十毫秒），但收益差别很大：
		//   - 只记录路径时，"新增任务"只能作为一个笼统信号，无法判断危险程度；
		//   - 解析出 Command/Arguments 后，才能复用统一的可执行文件信誉判定
		//     （指向可写目录？无签名？以最高权限运行？），也才能感知
		//     "同名任务被改写了执行内容"这类攻击者惯用手法。
		def := parseTaskXML(path)

		cmd := def.Command
		if def.Arguments != "" {
			cmd += " " + def.Arguments
		}
		if cmd == "" {
			cmd = path // 解析失败时退回路径，保证基线仍然稳定可比
		}

		out = append(out, PersistItem{
			Key:      PersistScheduledTask + "|" + strings.ToLower(taskName),
			Type:     PersistScheduledTask,
			Location: `\` + rel,
			Name:     taskName,
			Command:  cmd,
			Enabled:  true,
			// 以下用于信誉判定与展示，不影响基线 key
			RunAs:    def.UserID,
			Elevated: strings.EqualFold(def.RunLevel, "HighestAvailable"),
			Trigger:  def.TriggerKind(),
		})
		return nil
	})
	if err != nil && len(out) == 0 {
		return nil, err
	}
	return out, nil
}

// taskDefinition 是从任务 XML 里提取出来的关键字段。
type taskDefinition struct {
	Command   string
	Arguments string
	UserID    string
	RunLevel  string
	Author    string
	Desc      string
	Boot      bool
	Logon     bool
	Time      bool
}

// TriggerKind 概括触发方式。
// "开机触发 + 最高权限"是持久化里风险最高的一种组合，
// 单独标出来便于在告警里直接呈现。
func (t taskDefinition) TriggerKind() string {
	var kinds []string
	if t.Boot {
		kinds = append(kinds, "开机")
	}
	if t.Logon {
		kinds = append(kinds, "登录")
	}
	if t.Time {
		kinds = append(kinds, "定时")
	}
	return strings.Join(kinds, "+")
}

// taskXMLSchema 只声明关心的字段。
// 故意不声明完整 schema：任务定义里绝大多数内容（空闲设置、重试策略、
// 网络条件等）对入侵检测没有判别力，全量解析只会增加开销与出错面。
type taskXMLSchema struct {
	RegistrationInfo struct {
		Description string `xml:"Description"`
		Author      string `xml:"Author"`
	} `xml:"RegistrationInfo"`
	Triggers struct {
		Boot      []struct{} `xml:"BootTrigger"`
		Logon     []struct{} `xml:"LogonTrigger"`
		Time      []struct{} `xml:"TimeTrigger"`
		Calendar  []struct{} `xml:"CalendarTrigger"`
	} `xml:"Triggers"`
	Principals struct {
		Principal struct {
			UserID   string `xml:"UserId"`
			RunLevel string `xml:"RunLevel"`
		} `xml:"Principal"`
	} `xml:"Principals"`
	Actions struct {
		Exec []struct {
			Command   string `xml:"Command"`
			Arguments string `xml:"Arguments"`
		} `xml:"Exec"`
	} `xml:"Actions"`
}

// parseTaskXML 读取并解析任务定义。任何异常都退化为零值，不影响基线枚举。
func parseTaskXML(path string) taskDefinition {
	var out taskDefinition

	// 单个任务文件通常 < 20KB；设上限防止异常文件拖垮整轮扫描
	const maxTaskXML = 256 << 10
	st, err := os.Stat(path)
	if err != nil || st.Size() > maxTaskXML {
		return out
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return out
	}

	var doc taskXMLSchema
	if err := xml.Unmarshal(raw, &doc); err != nil {
		return out
	}

	if len(doc.Actions.Exec) > 0 {
		// 多个动作时取第一个：绝大多数任务只有一个，而攻击者的
		// 落地动作通常也是主执行体
		out.Command = strings.TrimSpace(doc.Actions.Exec[0].Command)
		out.Arguments = strings.TrimSpace(doc.Actions.Exec[0].Arguments)
	}
	out.UserID = strings.TrimSpace(doc.Principals.Principal.UserID)
	out.RunLevel = strings.TrimSpace(doc.Principals.Principal.RunLevel)
	out.Author = strings.TrimSpace(doc.RegistrationInfo.Author)
	out.Desc = strings.TrimSpace(doc.RegistrationInfo.Description)
	out.Boot = len(doc.Triggers.Boot) > 0
	out.Logon = len(doc.Triggers.Logon) > 0
	out.Time = len(doc.Triggers.Time) > 0 || len(doc.Triggers.Calendar) > 0
	return out
}

// enumerateIFEO 检查映像劫持：Debugger 键被设置意味着某程序被替换执行。
func enumerateIFEO() ([]PersistItem, error) {
	const path = `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options`
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.READ)
	if err != nil {
		return nil, err
	}
	defer k.Close()

	subs, err := k.ReadSubKeyNames(-1)
	if err != nil {
		return nil, err
	}

	var out []PersistItem
	for _, sub := range subs {
		sk, err := registry.OpenKey(k, sub, registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		dbg, _, err := sk.GetStringValue("Debugger")
		sk.Close()
		if err != nil || strings.TrimSpace(dbg) == "" {
			continue
		}
		out = append(out, PersistItem{
			Key:      PersistIFEO + "|" + strings.ToLower(sub),
			Type:     PersistIFEO,
			Location: `HKLM\` + path + `\` + sub,
			Name:     sub,
			Command:  dbg,
			Enabled:  true,
		})
	}
	return out, nil
}

// PersistCommandPath 从命令行中解析出可执行文件路径。
// TaskCommandPath 由计划任务注册名定位其执行命令（4698 事件入链用）。
//
// 4698 事件的 Data 只有任务名，不带命令——而任务定义落盘在
// System32\Tasks 目录树（注册名 \folder\task ↔ 同名无扩展文件），与
// persist 枚举同款解析即可拿到 Command。拿不到（权限/路径怪异/非 Exec
// 动作）返回空，调用方按"没有路径就不入链"降级，由 persist 周期扫描
// 兜底同一语义。
func TaskCommandPath(taskName string) string {
	name := strings.Trim(strings.TrimSpace(taskName), `"`)
	name = strings.TrimPrefix(name, `\`)
	if name == "" || strings.Contains(name, "..") {
		// 任务名来自事件日志，正常不含 ".."；防目录穿越是防御性收口
		return ""
	}
	path := filepath.Join(os.Getenv("SystemRoot"), "System32", "Tasks",
		filepath.FromSlash(name))
	def := parseTaskXML(path)
	return def.Command
}

//
// 自启动项的命令行格式五花八门：带引号、带参数、以环境变量开头、
// 只有裸程序名（依赖 PATH）。这里尽量还原出磁盘路径，供信誉判定使用。
func PersistCommandPath(cmd string) string {
	s := strings.TrimSpace(cmd)
	if s == "" {
		return ""
	}
	// 去掉 Windows 命令行常见前缀
	for {
		lower := strings.ToLower(s)
		switch {
		case strings.HasPrefix(lower, `\??\`):
			s = s[4:]
			continue
		case strings.HasPrefix(lower, `\\?\`):
			s = s[4:]
			continue
		case strings.HasPrefix(lower, `system32\`):
			s = filepath.Join(os.Getenv("SystemRoot"), s)
			continue
		}
		break
	}

	// 展开 %VAR%
	s = os.ExpandEnv(s)

	// 带引号：取第一段
	if strings.HasPrefix(s, `"`) {
		if end := strings.Index(s[1:], `"`); end > 0 {
			return s[1 : 1+end]
		}
		return strings.Trim(s, `"`)
	}

	// 无引号：以 .exe 为界截断（"C:\a b\svc.exe -k run" 这类）
	lower := strings.ToLower(s)
	if i := strings.Index(lower, ".exe"); i > 0 {
		return s[:i+4]
	}
	if i := strings.Index(lower, ".com"); i > 0 {
		return s[:i+4]
	}
	// 兜底：取第一个空格前
	if i := strings.IndexAny(s, " \t"); i > 0 {
		return s[:i]
	}
	return s
}
