package detect

import (
	"strings"
	"testing"

	"zedr/internal/agent/allow"
	"zedr/internal/agent/baseline"
	"zedr/internal/agent/enrich"
	"zedr/internal/ioc"
	"zedr/internal/model"
	"zedr/internal/rules"
)

// newTestEngine 构造一个不依赖宿主环境的引擎（空基线、空白名单）。
func newTestEngine(t *testing.T) *Engine {
	t.Helper()
	enr := enrich.New(0)
	base := baseline.Load("")
	alw := allow.New("")
	return New(enr, base, alw, Config{})
}

// TestKeywordMatcher 验证关键词表在编码存储后仍能正确解码并命中。
func TestKeywordMatcher(t *testing.T) {
	e := newTestEngine(t)
	if got := len(e.kw.patterns); got < 60 {
		t.Fatalf("关键词表规模异常: %d", got)
	}
	// 编码后必须能还原出可读的进程名，否则 AC 匹配会全部失效
	if tok := ioc.S("bm1hcC5leGU="); tok != "nmap.exe" {
		t.Fatalf("IOC 解码异常: %q", tok)
	}

	cases := []struct {
		name    string
		proc    string
		cmdline string
		wantID  string
	}{
		{"清空事件日志", "cmd.exe", `cmd.exe /c "echo wevtutil cl security"`, "K-022"},
		{"删除卷影副本", "vssadmin.exe", "vssadmin delete shadows /all /quiet", "K-014"},
		{"编码命令", "powershell.exe", "powershell -EncodedCommand SQBFAFgA", "K-001"},
		{"矿池协议", "x.exe", "x --url stratum+tcp://pool:3333", "K-028"},
		{"进程名命中扫描器", "nmap.exe", "", "N-009"},
		{"无可疑特征", "notepad.exe", `notepad.exe C:\a.txt`, ""},
	}
	for _, c := range cases {
		sigs := e.kw.match(c.proc, c.cmdline)
		found := ""
		for _, s := range sigs {
			if s.ID == c.wantID {
				found = s.ID
				break
			}
		}
		if c.wantID == "" {
			if len(sigs) > 0 {
				t.Errorf("%s: 不应产生信号，实际命中 %d 条", c.name, len(sigs))
			}
			continue
		}
		if found == "" {
			t.Errorf("%s: 期望命中 %s，实际 %v", c.name, c.wantID, signalIDs(sigs))
		}
	}
}

func signalIDs(sigs []model.Signal) []string {
	out := make([]string, 0, len(sigs))
	for _, s := range sigs {
		out = append(out, s.ID)
	}
	return out
}

// TestAhoCorasick 验证 AC 自动机的基本命中与不命中。
func TestAhoCorasick(t *testing.T) {
	ac := newAhoCorasick([]string{"abcd", "bcd", "cdef", "xyz"})
	got := ac.FindAll("zzabcdefzz")
	want := map[string]bool{"abcd": true, "bcd": true, "cdef": true}
	if len(got) != 3 {
		t.Fatalf("命中数量错误: %v", got)
	}
	for _, g := range got {
		if !want[g] {
			t.Fatalf("意外命中: %s", g)
		}
	}
	if len(ac.FindAll("nothing here")) != 0 {
		t.Fatal("不应命中")
	}
}

// TestBuiltinRulesCompile 确保 36 条内置规则全部可编译且能命中预期条件。
func TestBuiltinRulesCompile(t *testing.T) {
	builtins := rules.Builtins()
	if len(builtins) < 30 {
		t.Fatalf("内置规则数量异常: %d", len(builtins))
	}
	for _, b := range builtins {
		if _, err := rules.Compile(b.JSON()); err != nil {
			t.Fatalf("规则 %s(%s) 编译失败: %v", b.ID, b.Name, err)
		}
	}

	// 系统进程伪装：svchost.exe 出现在用户目录
	target := &rules.Target{
		Name:        "svchost.exe",
		Path:        `C:\Users\public\svchost.exe`,
		InSystem:    false,
		DirWritable: true,
		Signed:      false,
	}
	hit := matchRuleID(t, "HG-016", target)
	if !hit {
		t.Fatal("HG-016 未命中伪装系统进程")
	}

	// Office 拉起 shell
	target2 := &rules.Target{
		Name:       "powershell.exe",
		ParentName: "winword.exe",
	}
	if !matchRuleID(t, "HG-001", target2) {
		t.Fatal("HG-001 未命中 Office→shell 组合")
	}

	// 删除卷影副本
	target3 := &rules.Target{Name: "vssadmin.exe", CmdLine: "vssadmin delete shadows /all"}
	if !matchRuleID(t, "HG-009", target3) {
		t.Fatal("HG-009 未命中删除卷影副本")
	}
}

func matchRuleID(t *testing.T, id string, target *rules.Target) bool {
	t.Helper()
	for _, b := range rules.Builtins() {
		if b.ID != id {
			continue
		}
		def, err := rules.Compile(b.JSON())
		if err != nil {
			t.Fatalf("编译 %s 失败: %v", id, err)
		}
		ok, _ := def.Match(target)
		return ok
	}
	t.Fatalf("规则 %s 不存在", id)
	return false
}

// TestWhitelistGating 验证白名单在检测前生效（命中即不产生告警）。
func TestWhitelistGating(t *testing.T) {
	e := newTestEngine(t)
	if err := e.allow.AddLocal(allow.TypePath, `c:\trusted\app`, ""); err != nil {
		t.Fatalf("写入白名单失败: %v", err)
	}
	res := e.Analyze(Input{Proc: ProcessInfo{
		PID:  1234,
		Name: "evil.exe",
		Path: `C:\trusted\app\evil.exe`,
	}})
	if res == nil {
		t.Fatal("引擎应恒返回结果（便于 UI 展示评分与抑制原因）")
	}
	if res.Alert {
		t.Fatal("白名单命中的进程不应产生告警")
	}
	if res.Suppressed != "whitelist" {
		t.Fatalf("抑制原因应为 whitelist，实际 %q", res.Suppressed)
	}
	if e.Stats().Whitelisted == 0 {
		t.Fatal("白名单计数未生效")
	}
}

// TestBelowThresholdNoAlert 验证"低分但进引擎"的可见性设计：
// 结果始终返回，但 Alert=false、Suppressed=below_threshold。
func TestBelowThresholdNoAlert(t *testing.T) {
	e := newTestEngine(t)
	res := e.Analyze(Input{Proc: ProcessInfo{
		PID:  200,
		Name: "notepad.exe",
		Path: `C:\Windows\System32\notepad.exe`,
	}})
	if res == nil {
		t.Fatal("引擎应恒返回结果")
	}
	if res.Alert {
		t.Fatalf("普通系统进程不应告警，实际 score=%d verdict=%s", res.Score, res.Verdict)
	}
	if res.Verdict != model.VerdictSafe {
		t.Fatalf("应为 safe，实际 %s", res.Verdict)
	}
}

// TestHighSignalAlerts 验证高信号进程确实会置 Alert=true。
func TestHighSignalAlerts(t *testing.T) {
	e := newTestEngine(t)
	if ok, bad := e.SetRules(builtinRuleDTOs(t)); ok == 0 {
		t.Fatalf("规则加载失败: %v", bad)
	}
	res := e.Analyze(Input{Proc: ProcessInfo{
		PID:     300,
		Name:    "vssadmin.exe",
		Path:    `C:\Temp\vssadmin.exe`,
		CmdLine: "vssadmin delete shadows /all /quiet",
	}})
	if !res.Alert {
		t.Fatalf("删除卷影副本应告警，实际 score=%d suppressed=%s", res.Score, res.Suppressed)
	}
	if res.Verdict != model.VerdictMalicious {
		t.Fatalf("应判恶意，实际 %s (score=%d)", res.Verdict, res.Score)
	}
}

// builtinRuleDTOs 把内置规则转成下发格式，供引擎测试使用。
func builtinRuleDTOs(t *testing.T) []model.RuleDTO {
	t.Helper()
	out := make([]model.RuleDTO, 0, 40)
	for _, b := range rules.Builtins() {
		out = append(out, model.RuleDTO{
			ID: b.ID, Name: b.Name, Severity: b.Severity, Score: b.Score,
			MITRE: b.MITRE, Enabled: true, Definition: b.JSON(), Version: 1,
		})
	}
	return out
}

// TestSeverityAndFusion 验证融合定级：分量叠加后能跨过阈值。
func TestSeverityAndFusion(t *testing.T) {
	if got := severityFor(90, model.VerdictMalicious, nil); got != model.SeverityCritical {
		t.Fatalf("90 分应为 critical，实际 %s", got)
	}
	if got := severityFor(45, model.VerdictSuspicious, nil); got != model.SeverityLow {
		t.Fatalf("45 分应为 low，实际 %s", got)
	}
	// 命中高危规则时要抬升严重度
	hits := []model.RuleHit{{RuleID: "X", Severity: model.SeverityCritical, Score: 50}}
	if got := severityFor(45, model.VerdictSuspicious, hits); got != model.SeverityCritical {
		t.Fatalf("命中 critical 规则后应抬升，实际 %s", got)
	}
}

// TestObserveRuleCountsButDoesNotAlert 观察模式核心语义：
// 命中只进计数（随心跳快照上报），不参与打分/告警；转正后同一规则
// 立即恢复完整检测力。
func TestObserveRuleCountsButDoesNotAlert(t *testing.T) {
	observeRule := func(mode string) model.RuleDTO {
		return model.RuleDTO{
			ID: "HG-C-obs1", Name: "观察中的自定义规则", Severity: model.SeverityCritical,
			Score: 90, Enabled: true, Mode: mode, Version: 1,
			Definition: `{"all":[{"field":"process.name","op":"in","value":["observed-proc.exe"]}]}`,
		}
	}
	proc := ProcessInfo{PID: 400, Name: "observed-proc.exe", Path: `C:\Users\public\observed-proc.exe`}

	// 观察模式：命中计数，不告警
	e := newTestEngine(t)
	if _, bad := e.SetRules([]model.RuleDTO{observeRule("observe")}); len(bad) != 0 {
		t.Fatalf("规则编译失败: %v", bad)
	}
	res := e.Analyze(Input{Proc: proc})
	if res == nil {
		t.Fatal("引擎应恒返回结果")
	}
	if res.Alert {
		t.Fatalf("观察模式不应产生告警，实际 score=%d", res.Score)
	}
	snap, ok := e.ObserveSnapshot()
	if !ok {
		t.Fatal("存在观察规则时快照必须可上报")
	}
	if snap["HG-C-obs1"] != 1 {
		t.Fatalf("观察计数应为 1，实际 %d", snap["HG-C-obs1"])
	}

	// 从未见过观察规则的引擎：不应触发上报（服务端不动已存数据）
	e2 := newTestEngine(t)
	if _, ok := e2.ObserveSnapshot(); ok {
		t.Fatal("无观察规则且无历史计数时不应上报快照")
	}

	// 转正后：同一规则恢复告警能力（用独立引擎避免去重窗口干扰）
	e3 := newTestEngine(t)
	if _, bad := e3.SetRules([]model.RuleDTO{observeRule("")}); len(bad) != 0 {
		t.Fatalf("规则编译失败: %v", bad)
	}
	res3 := e3.Analyze(Input{Proc: proc})
	if !res3.Alert {
		t.Fatalf("转正后应正常告警，实际 score=%d verdict=%s", res3.Score, res3.Verdict)
	}
}

// TestIntelIPPathKeyword 非哈希情报三条匹配面（v0.9.11 扩维）：
// 远端 IP / 镜像路径精确匹配 → 情报加成直达恶意线；动态关键词参与
// 关键词层打分；三类命中都进计数快照随心跳回传。
func TestIntelIPPathKeyword(t *testing.T) {
	e := newTestEngine(t)
	e.SetIntel([]model.IntelDTO{
		{Type: "ip", Value: "203.0.113.9", Note: "演练外联对端"},
		{Type: "path", Value: `c:\temp\hg-obstest\zedr-diag.exe`, Note: "演练路径"},
		{Type: "keyword", Value: "zedr-obstest-token", Score: 30, Name: "演练关键词", MITRE: "T1059"},
	})

	proc := ProcessInfo{
		PID:     501,
		Name:    "zedr-diag.exe",
		Path:    `C:\Temp\hg-obstest\zedr-diag.exe`, // 大小写不同——查找已归一
		CmdLine: `zedr-diag.exe --report zedr-obstest-token`,
	}
	res := e.Analyze(Input{
		Proc: proc,
		Connections: []model.NetConn{
			{RemoteIP: "203.0.113.9", RemotePort: 443},
			{RemoteIP: "203.0.113.9", RemotePort: 80}, // 同 IP 去重，只计一次
		},
	})
	if res == nil {
		t.Fatal("引擎应恒返回结果")
	}
	if res.Verdict != model.VerdictMalicious {
		t.Fatalf("三重情报命中应直达恶意线，实际 %s score=%d", res.Verdict, res.Score)
	}
	sigIDs := map[string]bool{}
	for _, s := range res.Evidence.Signals {
		if s.Layer == "static" || s.Layer == "keyword" {
			sigIDs[s.ID] = true
		}
	}
	for _, want := range []string{"S-IOC-IP", "S-IOC-PATH", "KW-D-"} {
		found := false
		for id := range sigIDs {
			if strings.HasPrefix(id, want) {
				found = true
			}
		}
		if !found {
			t.Fatalf("缺少信号 %s，实际 %v", want, sigIDs)
		}
	}

	snap, ok := e.IntelHitsSnapshot()
	if !ok {
		t.Fatal("有情报时快照必须可上报")
	}
	for _, key := range []string{"ip:203.0.113.9", `path:c:\temp\hg-obstest\zedr-diag.exe`, "keyword:zedr-obstest-token"} {
		if snap[key] < 1 {
			t.Fatalf("命中计数缺失 %s，实际 %v", key, snap)
		}
	}

	// 清空语义：SetIntel(nil) 后不再有情报面，但历史计数触发一次
	// 空快照上报（服务端清理残留行）
	e.SetIntel(nil)
	if _, ok := e.IntelHitsSnapshot(); !ok {
		t.Fatal("清空后仍有历史计数，应触发一次空快照上报")
	}

	// 全新引擎：从未有过情报面 → 不上报
	e2 := newTestEngine(t)
	if _, ok := e2.IntelHitsSnapshot(); ok {
		t.Fatal("无情报且无命中时不应上报快照")
	}
}
