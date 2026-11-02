package winapi

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf16"
)

// 本文件覆盖 Task Scheduler XML 富解析的编码/容错边界。
// 真机任务文件实测为 UTF-16LE + BOM（2026-11-02），所以 UTF-16 路径
// 不是"理论兼容"，而是主路径，必须有确定性单测兜住。

const sampleTaskXML = `<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Author>CONTOSO\alice</Author>
    <Description>demo task</Description>
  </RegistrationInfo>
  <Triggers>
    <BootTrigger>
      <Enabled>true</Enabled>
    </BootTrigger>
    <LogonTrigger>
      <Enabled>false</Enabled>
    </LogonTrigger>
    <TimeTrigger>
      <StartBoundary>2026-01-01T00:00:00</StartBoundary>
    </TimeTrigger>
    <CalendarTrigger>
      <Enabled>true</Enabled>
      <ScheduleByDay><DaysInterval>1</DaysInterval></ScheduleByDay>
    </CalendarTrigger>
    <EventTrigger>
      <Enabled>true</Enabled>
      <Subscription>&lt;QueryList&gt;&lt;Query Id="0" Path="System"&gt;&lt;Select Path="System"&gt;*&lt;/Select&gt;&lt;/Query&gt;&lt;/QueryList&gt;</Subscription>
    </EventTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>S-1-5-18</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <Enabled>false</Enabled>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>C:\Windows\System32\cmd.exe</Command>
      <Arguments>/c echo hello</Arguments>
    </Exec>
    <ComHandler>
      <ClassId>{11111111-2222-3333-4444-555555555555}</ClassId>
    </ComHandler>
  </Actions>
</Task>`

// encodeUTF16LE 生成带 BOM 的 UTF-16LE 字节（模拟真机任务文件）。
func encodeUTF16LE(s string) []byte {
	units := utf16.Encode([]rune(s))
	buf := make([]byte, 2+len(units)*2)
	buf[0], buf[1] = 0xFF, 0xFE
	for i, u := range units {
		binary.LittleEndian.PutUint16(buf[2+i*2:], u)
	}
	return buf
}

func TestParseTaskXMLUTF8(t *testing.T) {
	path := filepath.Join(t.TempDir(), "PlainTask")
	if err := os.WriteFile(path, []byte(sampleTaskXML), 0o644); err != nil {
		t.Fatalf("写测试文件失败: %v", err)
	}

	info, err := ParseTaskXML(path)
	if err != nil {
		t.Fatalf("ParseTaskXML 失败: %v", err)
	}
	if info.Author != `CONTOSO\alice` {
		t.Errorf("Author = %q, want CONTOSO\\alice", info.Author)
	}
	if info.Enabled {
		t.Error("Enabled = true, want false（Settings/Enabled=false）")
	}
	if info.RunLevel != "HighestAvailable" {
		t.Errorf("RunLevel = %q, want HighestAvailable", info.RunLevel)
	}

	wantTriggers := []TaskTrigger{
		{Type: "Boot", Enabled: true},
		{Type: "Logon", Enabled: false},
		{Type: "Time", Enabled: true}, // 缺省 Enabled 应按 true
		{Type: "Calendar", Enabled: true},
		{Type: "Event", Enabled: true},
	}
	if len(info.Triggers) != len(wantTriggers) {
		t.Fatalf("Triggers 数量 = %d, want %d: %+v", len(info.Triggers), len(wantTriggers), info.Triggers)
	}
	for i, want := range wantTriggers {
		if info.Triggers[i] != want {
			t.Errorf("Triggers[%d] = %+v, want %+v", i, info.Triggers[i], want)
		}
	}

	if len(info.Actions) != 2 {
		t.Fatalf("Actions 数量 = %d, want 2: %+v", len(info.Actions), info.Actions)
	}
	if info.Actions[0].Command != `C:\Windows\System32\cmd.exe` || info.Actions[0].Arguments != "/c echo hello" {
		t.Errorf("Exec action = %+v, want cmd.exe /c echo hello", info.Actions[0])
	}
	// ComHandler 没有命令行，按契约把 ClassId 记为 command。
	if info.Actions[1].Command != "{11111111-2222-3333-4444-555555555555}" || info.Actions[1].Arguments != "" {
		t.Errorf("ComHandler action = %+v, want ClassId 作为 command", info.Actions[1])
	}
}

func TestParseTaskXMLUTF16LEBOM(t *testing.T) {
	path := filepath.Join(t.TempDir(), "Utf16Task")
	if err := os.WriteFile(path, encodeUTF16LE(sampleTaskXML), 0o644); err != nil {
		t.Fatalf("写 UTF-16 测试文件失败: %v", err)
	}

	info, err := ParseTaskXML(path)
	if err != nil {
		t.Fatalf("ParseTaskXML(UTF-16LE) 失败: %v", err)
	}
	if info.Author != `CONTOSO\alice` || info.RunLevel != "HighestAvailable" {
		t.Errorf("UTF-16 解码结果不对: author=%q runlevel=%q", info.Author, info.RunLevel)
	}
	if len(info.Triggers) != 5 || len(info.Actions) != 2 {
		t.Errorf("UTF-16 解析数量不对: triggers=%d actions=%d", len(info.Triggers), len(info.Actions))
	}
}

func TestParseTaskXMLUTF16BEAndNoBOM(t *testing.T) {
	// BE + BOM：覆盖 FE FF 分支。
	units := utf16.Encode([]rune(sampleTaskXML))
	be := make([]byte, 2+len(units)*2)
	be[0], be[1] = 0xFE, 0xFF
	for i, u := range units {
		binary.BigEndian.PutUint16(be[2+i*2:], u)
	}
	bePath := filepath.Join(t.TempDir(), "BeTask")
	if err := os.WriteFile(bePath, be, 0o644); err != nil {
		t.Fatalf("写 UTF-16BE 文件失败: %v", err)
	}
	if info, err := ParseTaskXML(bePath); err != nil || info.Author != `CONTOSO\alice` {
		t.Errorf("UTF-16BE 解析失败: info=%+v err=%v", info, err)
	}

	// 无 BOM 的 UTF-16LE：真机上存在变体，用 "<\0" 魔数识别。
	noBOM := encodeUTF16LE(sampleTaskXML)[2:]
	noBOMPath := filepath.Join(t.TempDir(), "NoBomTask")
	if err := os.WriteFile(noBOMPath, noBOM, 0o644); err != nil {
		t.Fatalf("写无 BOM 文件失败: %v", err)
	}
	if info, err := ParseTaskXML(noBOMPath); err != nil || info.RunLevel != "HighestAvailable" {
		t.Errorf("无 BOM UTF-16LE 解析失败: info=%+v err=%v", info, err)
	}
}

func TestParseTaskXMLDefaultsAndBadXML(t *testing.T) {
	dir := t.TempDir()

	// 极简任务：没有 Triggers/Settings/Actions/Author，全部走默认值。
	minimal := `<?xml version="1.0" encoding="UTF-8"?><Task><RegistrationInfo/><Settings/></Task>`
	minPath := filepath.Join(dir, "Minimal")
	if err := os.WriteFile(minPath, []byte(minimal), 0o644); err != nil {
		t.Fatal(err)
	}
	info, err := ParseTaskXML(minPath)
	if err != nil {
		t.Fatalf("极简任务解析失败: %v", err)
	}
	if info.Author != "" || !info.Enabled || info.RunLevel != "" {
		t.Errorf("默认值不符合预期: %+v", info)
	}
	if info.Triggers == nil || info.Actions == nil || len(info.Triggers) != 0 || len(info.Actions) != 0 {
		t.Errorf("空触发器/动作应为非 nil 空切片（JSON 稳定性）: %+v", info)
	}

	badPath := filepath.Join(dir, "Broken")
	if err := os.WriteFile(badPath, []byte(`<Task><Triggers><BootTrigger>`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseTaskXML(badPath); err == nil {
		t.Fatal("坏 XML 应返回 error")
	}

	if _, err := ParseTaskXML(filepath.Join(dir, "not-exist")); err == nil {
		t.Fatal("不存在的文件应返回 error")
	}
}

func TestEnumerateTaskXMLMixed(t *testing.T) {
	root := t.TempDir()
	// 任务目录里的文件没有扩展名（真机事实），这里刻意保持同样口径。
	good := filepath.Join(root, "GoodTask")
	if err := os.WriteFile(good, encodeUTF16LE(sampleTaskXML), 0o644); err != nil {
		t.Fatal(err)
	}
	sub := filepath.Join(root, "Microsoft", "Windows")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	good2 := filepath.Join(sub, "NestedTask")
	if err := os.WriteFile(good2, encodeUTF16LE(sampleTaskXML), 0o644); err != nil {
		t.Fatal(err)
	}
	bad := filepath.Join(root, "BrokenTask")
	if err := os.WriteFile(bad, []byte("<Task>"), 0o644); err != nil {
		t.Fatal(err)
	}

	defs, err := EnumerateTaskXML(root)
	if err != nil {
		t.Fatalf("EnumerateTaskXML 失败: %v", err)
	}
	if len(defs) != 3 {
		t.Fatalf("枚举数量 = %d, want 3: %+v", len(defs), defs)
	}

	byName := make(map[string]TaskDef, len(defs))
	for _, d := range defs {
		byName[d.Name] = d
	}
	for _, want := range []string{`\GoodTask`, `\Microsoft\Windows\NestedTask`} {
		d, ok := byName[want]
		if !ok {
			t.Errorf("缺少任务 %q，实际: %v", want, keysOf(byName))
			continue
		}
		if d.Err != nil || d.Info == nil {
			t.Errorf("%q 应为解析成功: err=%v", want, d.Err)
		}
		if d.Path == "" {
			t.Errorf("%q 的 Path 为空", want)
		}
	}
	bd, ok := byName[`\BrokenTask`]
	if !ok {
		t.Errorf("坏文件应保留在结果里，实际: %v", keysOf(byName))
	} else if bd.Err == nil {
		t.Error("坏文件的 Err 应非空")
	} else if bd.Info != nil {
		t.Error("坏文件的 Info 应为 nil")
	}

	if _, err := EnumerateTaskXML(filepath.Join(root, "missing")); err == nil {
		t.Error("根目录不存在应返回 error")
	}
}

func keysOf(m map[string]TaskDef) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// TestParseRealTaskXML 真机冒烟：只读解析系统任务目录的 3 个文件。
// 目录不存在/没有可解析文件时跳过，不把环境差异变成红灯。
func TestParseRealTaskXML(t *testing.T) {
	root := filepath.Join(os.Getenv("SystemRoot"), "System32", "Tasks")
	if _, err := os.Stat(root); err != nil {
		t.Skipf("任务目录不可用，跳过: %v", err)
	}
	defs, err := EnumerateTaskXML(root)
	if err != nil {
		t.Fatalf("真机枚举失败: %v", err)
	}
	parsed := 0
	bad := 0
	var badSamples []string
	for _, d := range defs {
		if d.Err != nil {
			bad++
			if len(badSamples) < 5 {
				badSamples = append(badSamples, d.Name+": "+d.Err.Error())
			}
			continue
		}
		if d.Info == nil {
			continue
		}
		if parsed < 3 {
			t.Logf("  %s: author=%q enabled=%v run_level=%q triggers=%d actions=%d",
				d.Name, d.Info.Author, d.Info.Enabled, d.Info.RunLevel, len(d.Info.Triggers), len(d.Info.Actions))
		}
		parsed++
	}
	t.Logf("枚举 %d 个文件：解析成功 %d，失败 %d", len(defs), parsed, bad)
	if len(badSamples) > 0 {
		t.Logf("失败样例: %v", badSamples)
	}
	if parsed < 3 {
		t.Skipf("真机任务目录仅解析成功 %d 个文件，跳过", parsed)
	}
	if len(defs) == 0 {
		t.Fatal("真机任务目录枚举结果为空")
	}
	// 抽样断言命名口径：Name 必须以反斜杠开头且不含正斜杠。
	for _, d := range defs {
		if !strings.HasPrefix(d.Name, `\`) || strings.Contains(d.Name, "/") {
			t.Fatalf("任务命名口径不一致: %q", d.Name)
		}
	}

	// 端到端确认 join 生效：TaskList 是资产节真正的出口，
	// 枚举结果再完整，接不上也等于没做。
	tasks, err := TaskList()
	if err != nil {
		t.Fatalf("TaskList 失败: %v", err)
	}
	defNames := make(map[string]struct{}, len(defs))
	for _, d := range defs {
		defNames[d.Name] = struct{}{}
	}
	enriched, joined := 0, 0
	var missSamples []string
	for _, task := range tasks {
		if _, ok := defNames[task.Path]; ok {
			joined++
		} else if len(missSamples) < 5 {
			missSamples = append(missSamples, task.Path)
		}
		if len(task.Triggers) > 0 || task.RunLevel != "" {
			enriched++
		}
	}
	t.Logf("TaskList 富字段命中 %d/%d 条，命名 join 命中 %d/%d 条", enriched, len(tasks), joined, len(tasks))
	if len(missSamples) > 0 {
		t.Logf("命名不匹配样例: %v", missSamples)
	}
	if joined < len(tasks) {
		t.Errorf("命名口径不一致：%d 条 TaskList 条目找不到对应定义文件", len(tasks)-joined)
	}
	if enriched < 3 {
		t.Fatalf("TaskList 富字段 join 未生效：仅 %d/%d 条有触发器或权限级别", enriched, len(tasks))
	}
}
