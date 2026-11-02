package ransom

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"zedr/internal/model"
)

// fakeClock 合成时钟：窗口/冷却全部走注入的 now，测试不休眠。
type fakeClock struct{ t time.Time }

func (c *fakeClock) Now() time.Time          { return c.t }
func (c *fakeClock) advance(d time.Duration) { c.t = c.t.Add(d) }

type recorder struct {
	fs []Finding
}

func (r *recorder) on(f Finding) { r.fs = append(r.fs, f) }

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func newDefense(t *testing.T, dirs []string, mutate func(*Options)) (*Defense, *recorder, *fakeClock) {
	t.Helper()
	ck := &fakeClock{t: time.Date(2026, 11, 3, 10, 0, 0, 0, time.UTC)}
	r := &recorder{}
	opt := Options{
		CanaryDirs: dirs,
		Log:        testLogger(),
		OnFinding:  r.on,
		Now:        ck.Now,
	}
	if mutate != nil {
		mutate(&opt)
	}
	d := New(opt)
	t.Cleanup(d.Close)
	return d, r, ck
}

// 首次落盘：文件存在、内容透明（写明用途），不产任何告警。
func TestNewPlantsTransparentCanaries(t *testing.T) {
	dir := t.TempDir()
	d, r, _ := newDefense(t, []string{dir}, nil)
	for _, name := range canaryNames {
		raw, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("诱饵 %s 未落盘: %v", name, err)
		}
		content := string(raw)
		if !strings.Contains(content, "Z-EDR") ||
			!strings.Contains(content, "decoy") ||
			!strings.Contains(content, "篡改检测") {
			t.Fatalf("诱饵 %s 内容不透明: %q", name, content)
		}
	}
	if len(r.fs) != 0 {
		t.Fatalf("正常落盘不应告警, got %+v", r.fs)
	}
	if got := d.CanaryDirs(); len(got) != 1 || got[0] != dir {
		t.Fatalf("CanaryDirs() = %v", got)
	}
}

// 已存在但内容不匹配：视为被篡改，New 期产出 medium Finding（不悄悄覆盖证据）。
func TestNewContentMismatchEmitsFinding(t *testing.T) {
	dir := t.TempDir()
	victim := filepath.Join(dir, canaryNames[0])
	if err := os.WriteFile(victim, []byte("已被改写的内容"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, r, _ := newDefense(t, []string{dir}, nil)
	if len(r.fs) != 1 {
		t.Fatalf("findings = %+v, want 1 条（内容不符=篡改）", r.fs)
	}
	f := r.fs[0]
	if f.RuleID != RuleCanary || f.Severity != model.SeverityMedium || f.Score != 45 {
		t.Fatalf("finding = %+v, want FILE-CANARY medium 45", f)
	}
	if !strings.Contains(f.Summary, "内容与预期不符") {
		t.Fatalf("summary = %s", f.Summary)
	}
	// 原内容保留，没有被悄悄重写
	raw, _ := os.ReadFile(victim)
	if string(raw) != "已被改写的内容" {
		t.Fatal("篡改后的诱饵被悄悄覆盖，销毁了证据")
	}
}

// 单独触碰诱饵 = medium 观察级 + 15 分钟冷却（键 = 诱饵路径）。
func TestCanaryRemovedMediumAndCooldown(t *testing.T) {
	dir := t.TempDir()
	d, r, ck := newDefense(t, []string{dir}, nil)
	canary := filepath.Join(dir, canaryNames[0])

	d.Consume(Event{Kind: "removed", Path: canary, Source: "rdcw", When: ck.Now()})
	if len(r.fs) != 1 {
		t.Fatalf("findings = %+v, want 1", r.fs)
	}
	f := r.fs[0]
	if f.RuleID != RuleCanary || f.Severity != model.SeverityMedium ||
		f.Score != 45 || f.Verdict != model.VerdictSuspicious {
		t.Fatalf("finding = %+v, want FILE-CANARY medium 45 suspicious", f)
	}
	if !strings.Contains(f.Summary, "可能是人工删除，请人工确认") {
		t.Fatalf("summary = %s", f.Summary)
	}
	if len(f.MITRE) != 1 || f.MITRE[0] != "T1565.001" {
		t.Fatalf("MITRE = %v", f.MITRE)
	}
	if f.Notes[0] != "source=rdcw kind=removed" {
		t.Fatalf("notes = %v", f.Notes)
	}

	// 冷却内：同诱饵不重复告警
	ck.advance(14 * time.Minute)
	d.Consume(Event{Kind: "removed", Path: canary, Source: "rdcw", When: ck.Now()})
	if len(r.fs) != 1 {
		t.Fatalf("冷却期内重复告警: %+v", r.fs)
	}
	// 冷却过期后再触再报
	ck.advance(2 * time.Minute)
	d.Consume(Event{Kind: "modified", Path: canary, Source: "rdcw", When: ck.Now()})
	if len(r.fs) != 2 {
		t.Fatalf("冷却过期后应再报: %+v", r.fs)
	}
	// 另一个诱饵是独立冷却键
	other := filepath.Join(dir, canaryNames[1])
	d.Consume(Event{Kind: "removed", Path: other, Source: "rdcw", When: ck.Now()})
	if len(r.fs) != 3 {
		t.Fatalf("不同诱饵应独立冷却: %+v", r.fs)
	}
}

// renamed 事件以 OldPath 命中诱饵；renamed_old 以 Path 命中；两者同键，
// 同一轮只告警一次（避免双事件双重计数）。
func TestCanaryRenameHits(t *testing.T) {
	dir := t.TempDir()
	d, r, ck := newDefense(t, []string{dir}, nil)
	oldPath := filepath.Join(dir, canaryNames[0])
	newPath := filepath.Join(dir, "renamed.docx")

	d.Consume(Event{Kind: "renamed_old", Path: oldPath, Source: "rdcw", When: ck.Now()})
	d.Consume(Event{Kind: "renamed", Path: newPath, OldPath: oldPath, Source: "rdcw", When: ck.Now()})
	if len(r.fs) != 1 {
		t.Fatalf("findings = %+v, want 1（同诱饵冷却去重）", r.fs)
	}
	if !strings.Contains(r.fs[0].Summary, canaryNames[0]) {
		t.Fatalf("summary 应含诱饵路径: %s", r.fs[0].Summary)
	}
}

// USN 来源只有 leaf name：按名命中 + 摘要如实标注路径未知。
func TestUSNLeafHit(t *testing.T) {
	dir := t.TempDir()
	d, r, ck := newDefense(t, []string{dir}, nil)

	d.Consume(Event{Kind: "removed", Path: canaryNames[2], Source: "usn", When: ck.Now()})
	if len(r.fs) != 1 {
		t.Fatalf("findings = %+v, want 1", r.fs)
	}
	f := r.fs[0]
	if !strings.Contains(f.Summary, "路径未知（USN 记录仅文件名）") {
		t.Fatalf("summary = %s", f.Summary)
	}
	if f.Notes[0] != "source=usn kind=removed" {
		t.Fatalf("notes = %v", f.Notes)
	}
	// 冷却键是 usn:leaf，冷却内同 leaf 不重复
	ck.advance(time.Minute)
	d.Consume(Event{Kind: "renamed", Path: canaryNames[2], OldPath: "x." + canaryNames[2], Source: "usn", When: ck.Now()})
	if len(r.fs) != 1 {
		t.Fatalf("USN 冷却失效: %+v", r.fs)
	}
	// 非诱饵文件名不误报
	d.Consume(Event{Kind: "removed", Path: "normal.docx", Source: "usn", When: ck.Now()})
	if len(r.fs) != 1 {
		t.Fatalf("非诱饵误报: %+v", r.fs)
	}
}

// USN 改名：诱饵被改成 a.encrypted 之类的新名（不再是诱饵名），必须按
// OldPath 的旧名命中——否则"改名加密"路径下 USN 永远抓不到诱饵。
func TestUSNRenamedHitByOldLeaf(t *testing.T) {
	dir := t.TempDir()
	d, r, ck := newDefense(t, []string{dir}, nil)

	d.Consume(Event{Kind: "renamed", Path: "renamed.encrypted",
		OldPath: canaryNames[3], Source: "usn", When: ck.Now()})
	if len(r.fs) != 1 {
		t.Fatalf("findings = %+v, want 1", r.fs)
	}
	if !strings.Contains(r.fs[0].Summary, "路径未知（USN 记录仅文件名）") {
		t.Fatalf("summary = %s", r.fs[0].Summary)
	}
	// 新旧名都与诱饵无关 → 不命中
	d.Consume(Event{Kind: "renamed", Path: "x.enc", OldPath: "y.docx",
		Source: "usn", When: ck.Now()})
	if len(r.fs) != 1 {
		t.Fatalf("非诱饵改名误报: %+v", r.fs)
	}
}

// 速率阈值与权重：removed=1，跨扩展名 renamed=2，同扩展名 renamed=1；
// 60s 窗口加权 ≥20 触发 FILE-RANSOM（high/60/T1486），冷却期内不重复。
func TestRateThresholdWeightsAndCooldown(t *testing.T) {
	dir := t.TempDir()
	d, r, ck := newDefense(t, []string{dir}, nil)
	// rdcw 事件给完整路径（同目录），供摘要 Top 统计
	path := func(i int, ext string) string {
		return filepath.Join(dir, fmt.Sprintf("doc%d.%s", i, ext))
	}
	consume := func(n int, kind, oldExt, newExt string) {
		for i := 0; i < n; i++ {
			ev := Event{Kind: kind, Path: path(i, newExt), Source: "rdcw", When: ck.Now()}
			if kind == "renamed" {
				ev.OldPath = path(i, oldExt)
			}
			d.Consume(ev)
		}
	}

	consume(5, "removed", "", "docx")       // 5
	consume(5, "renamed", "docx", "locked") // +10 = 15（跨扩展名权重 2）
	if len(r.fs) != 0 {
		t.Fatalf("15 分不应触发: %+v", r.fs)
	}
	// 同扩展名改名权重 1：只换主名、扩展名不动
	for i := 0; i < 4; i++ {
		d.Consume(Event{Kind: "renamed",
			Path:    filepath.Join(dir, fmt.Sprintf("moved%d.xlsx", i)),
			OldPath: filepath.Join(dir, fmt.Sprintf("keep%d.xlsx", i)),
			Source:  "rdcw", When: ck.Now()})
	}
	if len(r.fs) != 0 {
		t.Fatalf("19 分不应触发: %+v", r.fs)
	}
	consume(1, "removed", "", "pdf") // 20 → 触发
	if len(r.fs) != 1 {
		t.Fatalf("findings = %+v, want 1 条 FILE-RANSOM", r.fs)
	}
	f := r.fs[0]
	if f.RuleID != RuleRansom || f.Severity != model.SeverityHigh ||
		f.Score != 60 || f.Verdict != model.VerdictSuspicious {
		t.Fatalf("finding = %+v, want FILE-RANSOM high 60 suspicious", f)
	}
	if len(f.MITRE) != 1 || f.MITRE[0] != "T1486" {
		t.Fatalf("MITRE = %v", f.MITRE)
	}
	if !strings.Contains(f.Summary, "计数 20（阈值 20）") ||
		!strings.Contains(f.Summary, filepath.Clean(dir)+"(15)") {
		t.Fatalf("summary = %s", f.Summary)
	}
	// 冷却内继续爆发不重复告警
	consume(5, "removed", "", "docx")
	if len(r.fs) != 1 {
		t.Fatalf("速率冷却失效: %+v", r.fs)
	}
	// 冷却过期 + 旧事件滚出窗口后不残留触发
	ck.advance(16 * time.Minute)
	consume(1, "removed", "", "docx")
	if len(r.fs) != 1 {
		t.Fatalf("窗口过期后不应再触发: %+v", r.fs)
	}
}

// canary 分级：窗口计数达到阈值一半即 critical（无需速率检测器先触发）。
func TestCanaryCriticalAtHalfRate(t *testing.T) {
	dir := t.TempDir()
	d, r, ck := newDefense(t, []string{dir}, nil)
	for i := 0; i < 10; i++ { // 10 = 20/2
		d.Consume(Event{Kind: "removed", Path: filepath.Join(dir, fmt.Sprintf("f%d.docx", i)),
			Source: "rdcw", When: ck.Now()})
	}
	d.Consume(Event{Kind: "removed", Path: filepath.Join(dir, canaryNames[0]), Source: "rdcw", When: ck.Now()})
	// 只有 canary finding（10 < 20 不触发速率）
	if len(r.fs) != 1 {
		t.Fatalf("findings = %+v, want 1", r.fs)
	}
	f := r.fs[0]
	if f.Severity != model.SeverityCritical || f.Score != 75 {
		t.Fatalf("finding = %+v, want critical 75", f)
	}
	if !strings.Contains(f.Title, "勒索软件") {
		t.Fatalf("title = %s", f.Title)
	}
}

// canary 分级：速率检测器已独立触发（冷却期内）→ critical。
func TestCanaryCriticalAfterRateTrigger(t *testing.T) {
	dir := t.TempDir()
	d, r, ck := newDefense(t, []string{dir}, nil)
	for i := 0; i < 20; i++ {
		d.Consume(Event{Kind: "removed", Path: filepath.Join(dir, fmt.Sprintf("f%d.docx", i)),
			Source: "rdcw", When: ck.Now()})
	}
	ck.advance(time.Second) // 让 canary 事件时间晚于触发时刻
	d.Consume(Event{Kind: "removed", Path: filepath.Join(dir, canaryNames[0]),
		Source: "rdcw", When: ck.Now()})
	if len(r.fs) != 2 {
		t.Fatalf("findings = %+v, want 速率+canary 两条", r.fs)
	}
	canary := r.fs[1]
	if canary.RuleID != RuleCanary || canary.Severity != model.SeverityCritical {
		t.Fatalf("canary finding = %+v, want critical", canary)
	}
}

// 速率窗口只收 removed/renamed：renamed_old 命中诱饵但不计窗口权重，
// added/modified 同样不计。窗口压在阈值下方逐级逼近，任何一处多计 1 分
// 都会让"不应触发"的断言翻车。
func TestRenamedOldNotCountedInWindow(t *testing.T) {
	dir := t.TempDir()
	d, r, ck := newDefense(t, []string{dir}, nil)
	push := func(n int, kind string) {
		for i := 0; i < n; i++ {
			d.Consume(Event{Kind: kind,
				Path:   filepath.Join(dir, fmt.Sprintf("%s%d.docx", kind, i)),
				Source: "rdcw", When: ck.Now()})
		}
	}

	push(5, "removed") // 窗口 5（< 阈值一半 10，canary 应为 medium）
	d.Consume(Event{Kind: "renamed_old", Path: filepath.Join(dir, canaryNames[0]),
		Source: "rdcw", When: ck.Now()})
	if len(r.fs) != 1 || r.fs[0].RuleID != RuleCanary {
		t.Fatalf("findings = %+v", r.fs)
	}
	if r.fs[0].Severity != model.SeverityMedium {
		t.Fatalf("renamed_old 不进窗口，应为 medium: %+v", r.fs[0])
	}

	// 5 + 14 = 19：若 renamed_old 被误计 1 分，这里就是 20 → 会触发
	push(14, "removed")
	if len(r.fs) != 1 {
		t.Fatalf("renamed_old 疑似被计入窗口: %+v", r.fs)
	}
	// added/modified 不计：50 条后窗口仍是 19
	push(50, "modified")
	push(1, "removed") // 20 → 触发
	if len(r.fs) != 2 || r.fs[1].RuleID != RuleRansom {
		t.Fatalf("findings = %+v, want 第 2 条为 FILE-RANSOM", r.fs)
	}
}

// 缺失重建是静默的：删掉诱饵后自检只补文件、计数，绝不告警。
func TestMaintainRebuildsSilently(t *testing.T) {
	dir := t.TempDir()
	d, r, _ := newDefense(t, []string{dir}, nil)
	victim := filepath.Join(dir, canaryNames[1])
	if err := os.Remove(victim); err != nil {
		t.Fatal(err)
	}
	before := d.Rebuilt()
	d.maintain()
	if _, err := os.Stat(victim); err != nil {
		t.Fatalf("诱饵未重建: %v", err)
	}
	if d.Rebuilt() != before+1 {
		t.Fatalf("Rebuilt() = %d, want %d", d.Rebuilt(), before+1)
	}
	if len(r.fs) != 0 {
		t.Fatalf("重建不应告警: %+v", r.fs)
	}
}

// Start/Close 生命周期：ctx 取消后 goroutine 退出，Close 可重复调用。
func TestStartCloseLifecycle(t *testing.T) {
	dir := t.TempDir()
	d, _, _ := newDefense(t, []string{dir}, nil)
	ctx, cancel := context.WithCancel(context.Background())
	d.Start(ctx)
	cancel()
	d.Close()
	d.Close() // 幂等
}

// 窗口环形队列触顶：丢最旧 + Dropped() 诚实计数，不膨胀不 panic。
func TestWindowCapDropsOldestAndCounts(t *testing.T) {
	dir := t.TempDir()
	d, r, ck := newDefense(t, []string{dir}, func(o *Options) {
		o.RateThreshold = 1 << 30 // 永不触发，专注容量纪律
	})
	total := windowCap + 104
	for i := 0; i < total; i++ {
		d.Consume(Event{Kind: "removed", Path: filepath.Join(dir, fmt.Sprintf("f%d.bin", i)),
			Source: "rdcw", When: ck.Now()})
	}
	if d.Dropped() != 104 {
		t.Fatalf("Dropped() = %d, want 104", d.Dropped())
	}
	d.mu.Lock()
	n := len(d.window)
	sum := d.weightSum
	d.mu.Unlock()
	if n != windowCap || sum != windowCap {
		t.Fatalf("window=%d weightSum=%d, want %d/%d", n, sum, windowCap, windowCap)
	}
	if len(r.fs) != 0 {
		t.Fatalf("不应有 finding: %+v", r.fs)
	}
}

// nil Defense 安全（配置关闭时主线上可直接调）。
func TestNilDefenseSafe(t *testing.T) {
	var d *Defense
	d.Consume(Event{Kind: "removed", Path: "x.docx", Source: "rdcw"})
	if d.Dropped() != 0 || d.CanaryDirs() != nil {
		t.Fatal("nil 接收者行为异常")
	}
	d.Close()
}
