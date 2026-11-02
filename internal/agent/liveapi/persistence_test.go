package liveapi

// persistence_test.go：/persistence 的聚合逻辑（桩数据）+ 真机冒烟。
// 聚合函数与 winapi 枚举解耦，单测不需要真实 SCM/任务目录；
// 真机用例按环境跳过，口径与 baseline/accounts 测试一致。

import (
	"net/http"
	"runtime"
	"testing"
	"time"

	"zedr/internal/agent/winapi"
)

func TestExtractExePath(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		// 带引号 + 参数：引号内允许空格，参数不能混进结果
		{`"C:\Program Files\App\app.exe" --flag`, `C:\Program Files\App\app.exe`},
		// 未加引号但路径含空格：非贪婪到第一个扩展名
		{`C:\Program Files\App\app.exe -k netsvcs`, `C:\Program Files\App\app.exe`},
		// 命令解释器包装：取参数里的第一个绝对路径
		{`cmd.exe /c "C:\Temp\evil.ps1"`, `C:\Temp\evil.ps1`},
		// 环境变量开头无法在不展开的前提下解析：如实留空
		{`%SystemRoot%\System32\svchost.exe`, ``},
		// dll/cmd/bat/ps1 与 exe 同等待遇
		{`"C:\x\a.dll"`, `C:\x\a.dll`},
		{`C:\a b\run.cmd /x`, `C:\a b\run.cmd`},
		{`C:\x\y.bat`, `C:\x\y.bat`},
		{`C:\x\z.ps1 -NoProfile`, `C:\x\z.ps1`},
		// 非可执行扩展名/空串
		{`C:\Users\Public\readme.txt`, ``},
		{``, ``},
	}
	for _, c := range cases {
		if got := extractExePath(c.in); got != c.want {
			t.Errorf("extractExePath(%q) = %q，期望 %q", c.in, got, c.want)
		}
	}
}

func TestBuildPersistenceResult(t *testing.T) {
	services := []winapi.ServiceInfo{
		{
			Name: "svcA", DisplayName: "Service A", State: "running", StartMode: "auto",
			PathName: `"C:\Program Files\A\a.exe" -k run`, Account: `LocalSystem`,
		},
		{
			Name: "svcB", StartMode: "delayed-auto",
			PathName: `C:\Windows\system32\b.dll`, Account: `NT AUTHORITY\NetworkService`,
		},
		{
			Name: "svcManual", StartMode: "manual",
			PathName: `C:\manual.exe`, Account: `LocalSystem`,
		},
	}
	tasks := []winapi.TaskInfo{
		{
			Path: `\Microsoft\Windows\A`, Name: "A", Enabled: true,
			Actions: []winapi.TaskAction{{Command: `C:\x\a.exe`, Arguments: "-run"}},
		},
		{
			Path: `\B`, Name: "B", Enabled: false,
			Actions: []winapi.TaskAction{{Command: `C:\x\b.exe`}},
		},
		{
			// 有触发器但动作列表为空：仍作为持久化点保留，command 留空
			Path: `\C`, Name: "C", Enabled: true,
		},
	}
	startup := []winapi.PersistItem{
		{
			Type: winapi.PersistRegistryRun, Name: "Run1",
			Command: `"C:\Tools\r.exe" /bg`, Enabled: true,
			Location: `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`,
		},
		{
			Type: winapi.PersistWinlogon, Name: "Shell",
			Command: `explorer.exe`, Enabled: true,
			Location: `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`,
		},
		{
			// 服务/任务类型已由专门来源覆盖，必须被 startup 过滤掉
			Type: winapi.PersistService, Name: "duplicate-svc",
			Command: `C:\dup.exe`, Enabled: true, Location: `HKLM\SYSTEM\...\Services\dup`,
		},
	}

	res := buildPersistenceResult(services, tasks, startup, time.Date(2026, 11, 2, 10, 0, 0, 0, time.UTC))

	if res.GeneratedAt != "2026-11-02T10:00:00Z" {
		t.Errorf("generated_at = %q", res.GeneratedAt)
	}
	if res.Truncated {
		t.Error("桩数据未超上限，truncated 应为 false")
	}
	if res.Counts != (persistenceCounts{Service: 2, Task: 2, Startup: 2}) {
		t.Fatalf("counts = %+v，期望 service=2 task=2 startup=2", res.Counts)
	}
	if len(res.Items) != 6 {
		t.Fatalf("items 长度 = %d，期望 6：%+v", len(res.Items), res.Items)
	}

	byKey := make(map[string]persistenceItem, len(res.Items))
	for _, it := range res.Items {
		byKey[it.Source+"|"+it.Name] = it
	}

	svc := byKey["service|svcA"]
	if svc.Command != `"C:\Program Files\A\a.exe" -k run` {
		t.Errorf("service command 未保留原值: %q", svc.Command)
	}
	if svc.ExePath != `C:\Program Files\A\a.exe` {
		t.Errorf("service exe_path = %q", svc.ExePath)
	}
	if svc.User != "LocalSystem" || !svc.Enabled || svc.Location != "service" {
		t.Errorf("service 字段不符: %+v", svc)
	}

	svcB := byKey["service|svcB"]
	if svcB.ExePath != `C:\Windows\system32\b.dll` {
		t.Errorf("delayed-auto 服务 exe_path = %q", svcB.ExePath)
	}

	task := byKey["task|A"]
	if task.Command != `C:\x\a.exe -run` || task.ExePath != `C:\x\a.exe` {
		t.Errorf("task command/exe_path 不符: %+v", task)
	}
	if task.User != "" || !task.Enabled || task.Location != `\Microsoft\Windows\A` {
		t.Errorf("task 字段不符: %+v", task)
	}
	if taskC := byKey["task|C"]; taskC.Command != "" || taskC.ExePath != "" {
		t.Errorf("无动作任务应留空 command/exe_path: %+v", taskC)
	}

	run := byKey["startup|Run1"]
	if run.ExePath != `C:\Tools\r.exe` || run.Location == "" || run.User != "" {
		t.Errorf("startup 字段不符: %+v", run)
	}
	if _, ok := byKey["startup|duplicate-svc"]; ok {
		t.Error("startup 来源不应包含 service 类型（重复来源）")
	}
	if _, ok := byKey["task|B"]; ok {
		t.Error("disabled 任务不应出现在结果里")
	}
	if _, ok := byKey["service|svcManual"]; ok {
		t.Error("manual 服务不应出现在结果里")
	}

	// 来源分组顺序：service → task → startup
	if res.Items[0].Source != "service" || res.Items[len(res.Items)-1].Source != "startup" {
		t.Errorf("来源排序不符: first=%s last=%s", res.Items[0].Source, res.Items[len(res.Items)-1].Source)
	}
}

func TestBuildPersistenceTruncation(t *testing.T) {
	services := make([]winapi.ServiceInfo, 0, persistenceMaxItems+1)
	for i := 0; i <= persistenceMaxItems; i++ {
		services = append(services, winapi.ServiceInfo{
			Name:      "svc",
			StartMode: "auto",
			PathName:  `C:\svc.exe`,
		})
	}
	res := buildPersistenceResult(services, nil, nil, time.Now())
	if !res.Truncated {
		t.Fatal("超过上限应置 truncated=true")
	}
	if len(res.Items) != persistenceMaxItems {
		t.Fatalf("items 长度 = %d，期望 %d", len(res.Items), persistenceMaxItems)
	}
	// counts 统计采集总数而非返回条数：前端据此知道"还有多少没展示"。
	if res.Counts.Service != persistenceMaxItems+1 {
		t.Errorf("counts.service = %d，期望 %d", res.Counts.Service, persistenceMaxItems+1)
	}
}

// TestPersistenceRealMachine 真机冒烟：本机应有上百个持久化点
// （服务 + 任务 + 启动项）。枚举失败时宁可直接失败——这个用例就是
// 用来发现"端点能返回但数据源静默为空"的。
func TestPersistenceRealMachine(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("仅 Windows")
	}
	code, body := doGet(t, HandlePersistence(), "/persistence")
	if code != http.StatusOK {
		t.Fatalf("期望 200 实得 %d body=%v", code, body)
	}
	d := dataOf(t, body)

	if _, err := time.Parse(time.RFC3339, d["generated_at"].(string)); err != nil {
		t.Errorf("generated_at 不是 RFC3339: %v", d["generated_at"])
	}
	if _, ok := d["truncated"].(bool); !ok {
		t.Errorf("truncated 不是布尔: %T", d["truncated"])
	}
	counts, ok := d["counts"].(map[string]any)
	if !ok {
		t.Fatalf("counts 不是对象: %T", d["counts"])
	}
	for _, k := range []string{"service", "task", "startup"} {
		if _, ok := counts[k].(float64); !ok {
			t.Errorf("counts.%s 不是数字: %T", k, counts[k])
		}
	}

	items, ok := d["items"].([]any)
	if !ok {
		t.Fatalf("items 不是数组: %T", d["items"])
	}
	if len(items) < 100 {
		t.Fatalf("本机持久化点仅 %d 条（<100），疑似枚举失败: counts=%v", len(items), counts)
	}
	t.Logf("真机持久化点 %d 条，counts=%v truncated=%v",
		len(items), counts, d["truncated"])

	withExe := 0
	for _, raw := range items {
		if it, ok := raw.(map[string]any); ok {
			if p, _ := it["exe_path"].(string); p != "" {
				withExe++
			}
		}
	}
	t.Logf("其中 exe_path 成功提取 %d 条", withExe)
	if withExe == 0 {
		t.Error("全部条目的 exe_path 都为空，提取逻辑疑似失效")
	}
	for i, raw := range items {
		it, ok := raw.(map[string]any)
		if !ok {
			t.Fatalf("items[%d] 不是对象", i)
		}
		src, _ := it["source"].(string)
		switch src {
		case "service", "task", "startup":
		default:
			t.Errorf("items[%d].source 非法: %q", i, src)
		}
		if name, _ := it["name"].(string); name == "" {
			t.Errorf("items[%d].name 为空: %v", i, it)
		}
		if _, ok := it["command"].(string); !ok {
			t.Errorf("items[%d].command 不是字符串", i)
		}
		if _, ok := it["exe_path"].(string); !ok {
			t.Errorf("items[%d].exe_path 不是字符串", i)
		}
		if _, ok := it["user"].(string); !ok {
			t.Errorf("items[%d].user 不是字符串", i)
		}
		if _, ok := it["enabled"].(bool); !ok {
			t.Errorf("items[%d].enabled 不是布尔", i)
		}
		if _, ok := it["location"].(string); !ok {
			t.Errorf("items[%d].location 不是字符串", i)
		}
	}
}
