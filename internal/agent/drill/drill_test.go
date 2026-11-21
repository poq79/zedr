package drill

import (
	"runtime"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeAlerts 是可合成时间线的告警存储替身：测试按脚本往里投递告警，
// 验证"只认步骤开始之后的新告警"的判定口径。
type fakeAlerts struct {
	mu sync.Mutex
	as []AlertView
}

func (f *fakeAlerts) add(a AlertView) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.as = append(f.as, a)
}

func (f *fakeAlerts) since(t time.Time) []AlertView {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []AlertView
	for _, a := range f.as {
		if !a.OccurredAt.Before(t) {
			out = append(out, a)
		}
	}
	return out
}

// shortenPoll 缩短轮询节奏，让命中/超时判定在毫秒级完成。
func shortenPoll(t *testing.T) {
	t.Helper()
	old := pollEvery
	pollEvery = 20 * time.Millisecond
	t.Cleanup(func() { pollEvery = old })
}

// ---------------------------------------------------------------- 白名单与 payload

func TestParsePayloadEmptyMeansAll(t *testing.T) {
	for _, raw := range []string{"", "   ", "{}", `{"steps":[]}`, `{"steps":null}`} {
		steps, err := ParsePayload(raw)
		if err != nil {
			t.Fatalf("ParsePayload(%q) err = %v", raw, err)
		}
		if len(steps) != len(AllSteps()) {
			t.Fatalf("ParsePayload(%q) = %v, want 全部 %d 步", raw, steps, len(AllSteps()))
		}
	}
}

func TestParsePayloadSubsetAndDedupe(t *testing.T) {
	steps, err := ParsePayload(`{"steps":["port_scan","reg_run","port_scan"]}`)
	if err != nil {
		t.Fatalf("ParsePayload err = %v", err)
	}
	if len(steps) != 2 || steps[0] != "port_scan" || steps[1] != "reg_run" {
		t.Fatalf("ParsePayload = %v, want [port_scan reg_run]（去重保序）", steps)
	}
}

func TestParsePayloadRejectsUnknownAndBroken(t *testing.T) {
	// 未知步骤名用中性字符串：源码禁现明文恶意工具名（AGENTS §5.1，
	// 编译产物会被本机安全产品拦）。
	if _, err := ParsePayload(`{"steps":["port_scan","not_a_real_step"]}`); err == nil ||
		!strings.Contains(err.Error(), "未知步骤") {
		t.Fatalf("未知步骤应被拒绝，got err = %v", err)
	}
	if _, err := ParsePayload(`{broken`); err == nil || !strings.Contains(err.Error(), "JSON") {
		t.Fatalf("非法 JSON 应被拒绝，got err = %v", err)
	}
	// 白名单本身闭合：AllSteps 里的每个名字都必须通过
	for _, s := range AllSteps() {
		if _, err := ParsePayload(`{"steps":["` + s + `"]}`); err != nil {
			t.Fatalf("步骤 %s 应在白名单内，err = %v", s, err)
		}
	}
}

// ---------------------------------------------------------------- skipped 语义

func TestRunBudgetExhaustedSkipsRemainder(t *testing.T) {
	// 预取消的 ctx 模拟"总预算已耗尽"：整场演练不 spawn 任何进程，
	// 只验证超预算路径——剩余步骤记 skipped 而不是失败，且进入 Skipped 名单。
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	deps := Deps{Log: testLogger(t)}
	res := Run(ctx, []string{StepProcChain, StepPortScan}, deps)
	if len(res) != 2 {
		t.Fatalf("Run 返回 %d 步，want 2", len(res))
	}
	rep := BuildReport(res)
	if len(rep.Skipped) != 2 {
		t.Fatalf("Skipped = %v, want 两步都在", rep.Skipped)
	}
	for _, s := range res {
		if s.Hit || s.LatencyMs != 0 || !strings.HasPrefix(s.Note, "skipped: ") {
			t.Fatalf("超预算步骤应为 skipped 原语形态，got %+v", s)
		}
	}
}

func TestRunUnknownStepSkippedNotFatal(t *testing.T) {
	res := Run(context.Background(), []string{"nope"}, Deps{Log: testLogger(t)})
	if len(res) != 1 || res[0].Hit || !strings.Contains(res[0].Note, "skipped: 未知步骤") {
		t.Fatalf("未知步骤应记 skipped，got %+v", res)
	}
	if !IsValidStep(StepProcChain) || IsValidStep("nope") {
		t.Fatal("IsValidStep 白名单判定不符")
	}
}

func TestStepGatesProduceSkippedWithoutSpawning(t *testing.T) {
	// 各步骤前置不满足时必须零副作用返回（不 spawn、不轮询）。
	cases := []struct {
		name string
		deps Deps
		step string
		want string // Note 应包含的片段
		// winOnly：Windows 才断言 Note 片段（E1 等平台专属信号源在
		// Linux 上以平台理由跳过，Note 不同——GitHub Actions 首跑实测）。
		winOnly bool
	}{
		{"proc 无快照", Deps{}, StepProcChain, "ProcSnapshot", false},
		{"portscan 关网检", Deps{NetWatchEnabled: false}, StepPortScan, "NETWATCH", false},
		{"portscan 无告警源", Deps{NetWatchEnabled: true}, StepPortScan, "AlertsSince", false},
		{"svcevt 关 E1", Deps{EvtLogEnabled: false}, StepServiceEvt, "EVTLOG", true},
		{"canary 未接线", Deps{}, StepCanaryTouch, "CanaryFile", false},
		{"canary 无诱饵", Deps{CanaryFile: func() string { return "" }, AlertsSince: func(time.Time) []AlertView { return nil }}, StepCanaryTouch, "诱饵", false},
		{"reg 无告警源", Deps{}, StepRegRun, "AlertsSince", false},
	}
	for _, c := range cases {
		if c.winOnly && runtime.GOOS != "windows" {
			continue
		}
		c.deps.Log = testLogger(t)
		res := runStep(context.Background(), c.step, c.deps)
		if res.skipped != true || res.Hit || !strings.Contains(res.Note, c.want) {
			t.Fatalf("%s: got %+v, want skipped 且 Note 含 %q", c.name, res, c.want)
		}
		if res.Name != c.step {
			t.Fatalf("%s: 步骤名回填错误 got %q", c.name, res.Name)
		}
	}
}

// ---------------------------------------------------------------- 判定口径（假告警时间线）

func TestAlertHitOnlySeesNewAlerts(t *testing.T) {
	deps := Deps{AlertsSince: func(t time.Time) []AlertView { return nil }}
	start := time.Now()
	old := AlertView{ID: "old", RuleIDs: []string{"NW-001"}, OccurredAt: start.Add(-time.Second)}
	deps.AlertsSince = func(since time.Time) []AlertView {
		return fakeSingle(old, since)
	}
	if _, ok := deps.alertHit(start, "NW-001"); ok {
		t.Fatal("步骤开始之前的告警不得计入命中")
	}
	fresh := AlertView{ID: "fresh", RuleIDs: []string{"HG-023", "NW-001"}, OccurredAt: start.Add(time.Millisecond)}
	deps.AlertsSince = func(since time.Time) []AlertView { return fakeSingle(fresh, since) }
	a, ok := deps.alertHit(start, "NW-001", "NW-004")
	if !ok || a.ID != "fresh" {
		t.Fatalf("开始之后且规则匹配的告警应命中，got %v ok=%v", a, ok)
	}
	if _, ok := deps.alertHit(start, "EVT-SVCINST"); ok {
		t.Fatal("规则不匹配不得命中")
	}
	if _, ok := (Deps{}).alertHit(start, "NW-001"); ok {
		t.Fatal("AlertsSince 未接线时不得命中")
	}
}

// fakeSingle 模拟 AlertsSince 的时间窗过滤。
func fakeSingle(a AlertView, since time.Time) []AlertView {
	if a.OccurredAt.Before(since) {
		return nil
	}
	return []AlertView{a}
}

func TestAwaitHitTimesOutWhenNothingMatches(t *testing.T) {
	shortenPoll(t)
	f := &fakeAlerts{}
	deps := Deps{AlertsSince: f.since}
	start := time.Now()
	// 窗口中途出现"规则对不上"的告警 → 依然 miss
	time.AfterFunc(30*time.Millisecond, func() {
		f.add(AlertView{ID: "x", RuleIDs: []string{"HG-002"}, OccurredAt: time.Now()})
	})
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	if _, ok := awaitHit(ctx, func() bool { _, ok := deps.alertHit(start, "FILE-CANARY"); return ok }); ok {
		t.Fatal("规则不匹配时应超时 miss")
	}
}

func TestCanaryStepEndToEndHit(t *testing.T) {
	shortenPoll(t)
	f := &fakeAlerts{}
	start := time.Now()
	// 100ms 后出现 FILE-CANARY 告警，模拟勒索防御真实触发
	time.AfterFunc(100*time.Millisecond, func() {
		f.add(AlertView{ID: "al-1", RuleIDs: []string{"FILE-CANARY"}, OccurredAt: time.Now()})
	})
	deps := Deps{
		AlertsSince: f.since,
		CanaryFile:  func() string { return canaryVictim(t) },
		Log:         testLogger(t),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	res := stepCanaryTouch(ctx, start, deps)
	if !res.Hit || res.AlertID != "al-1" || res.LatencyMs < 0 {
		t.Fatalf("诱饵删除应命中，got %+v", res)
	}
	if !strings.Contains(res.Note, "静默重建") || res.ExpectedRule != "FILE-CANARY" {
		t.Fatalf("Note/ExpectedRule 不符: %+v", res)
	}
}

func TestCanaryStepMissOnSilence(t *testing.T) {
	shortenPoll(t)
	f := &fakeAlerts{}
	deps := Deps{
		AlertsSince: f.since,
		CanaryFile:  func() string { return canaryVictim(t) },
		Log:         testLogger(t),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	res := stepCanaryTouch(ctx, time.Now(), deps)
	if res.Hit || res.skipped || !strings.Contains(res.Note, "FILE-CANARY") {
		t.Fatalf("无声窗口应 miss 且非 skipped，got %+v", res)
	}
}

// canaryVictim 在测试临时目录放一个"诱饵"，验证 os.Remove 真实发生。
func canaryVictim(t *testing.T) string {
	t.Helper()
	p := t.TempDir() + "\\backup_report.docx"
	if err := os.WriteFile(p, []byte("zedr drill decoy"), 0o644); err != nil {
		t.Fatalf("准备诱饵失败: %v", err)
	}
	return p
}

// testLogger 输出丢弃：演练步骤的日志断言走返回值，不走日志。
func testLogger(t *testing.T) *slog.Logger {
	t.Helper()
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// ---------------------------------------------------------------- 报告序列化

func TestBuildReportCollectsSkipped(t *testing.T) {
	rep := BuildReport([]StepResult{
		{Name: StepProcChain, Hit: true},
		skip(StepServiceEvt, "E1 未启用"),
	})
	if len(rep.Skipped) != 1 || rep.Skipped[0] != StepServiceEvt {
		t.Fatalf("Skipped = %v, want [service_event]", rep.Skipped)
	}
	if len(rep.Steps) != 2 {
		t.Fatalf("Steps 应原样保留（含 skipped 条目），got %d", len(rep.Steps))
	}
}

func TestMarshalReportShape(t *testing.T) {
	raw := MarshalReport(BuildReport([]StepResult{{
		Name: StepPortScan, ExpectedRule: "NW-001/NW-004", Hit: true,
		LatencyMs: 1234, AlertID: "al-9",
	}}))
	var m map[string]any
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		t.Fatalf("报告应为合法 JSON: %v", err)
	}
	steps, _ := m["steps"].([]any)
	if len(steps) != 1 {
		t.Fatalf("steps = %v", steps)
	}
	s0, _ := steps[0].(map[string]any)
	for _, key := range []string{"name", "expected_rule", "hit", "latency_ms", "alert_id"} {
		if _, ok := s0[key]; !ok {
			t.Fatalf("步骤 JSON 缺字段 %q: %v", key, s0)
		}
	}
	if _, leak := s0["skipped"]; leak {
		t.Fatal("skipped 内部标记不得泄漏进 JSON")
	}
}
