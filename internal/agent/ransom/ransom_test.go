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
	// 验真语义（2026-11-18）：诱饵 mtime（真实 now）晚于 fake 事件时刻
	// （2026-11-03）→ "删除后被重写"形态，单候选归属本体路径
	f := r.fs[0]
	if !strings.Contains(f.Summary, "验真后唯一候选即本诱饵") {
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
	if !strings.Contains(r.fs[0].Summary, "验真后唯一候选即本诱饵") {
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
// 60s 窗口加权 ≥20 触发 FILE-RANSOM（独立速率=medium/45——2026-11-03
// 上线首日实测浏览器缓存/构建工具良性 churn 与勒索行为同形后降级，
// critical 只能由 canary 关联升级），冷却期内不重复。
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
	if f.RuleID != RuleRansom || f.Severity != model.SeverityMedium ||
		f.Score != 45 || f.Verdict != model.VerdictSuspicious {
		t.Fatalf("finding = %+v, want FILE-RANSOM medium 45 suspicious", f)
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

// 缓存/临时目录的高频增删不进速率窗口——2026-11-03 上线首日实测：
// 浏览器缓存清理（8 权重）+ 会话临时文件（9 权重）即触发独立告警，
// 这类目录的批量增删是正常软件行为，必须在权重层剔除而不是靠定级兜底。
func TestChurnDirsExcludedFromRate(t *testing.T) {
	dir := t.TempDir()
	d, r, ck := newDefense(t, []string{dir}, nil)
	cache := filepath.Join(dir, "Cache", "Cache_Data")
	for i := 0; i < 30; i++ {
		d.Consume(Event{Kind: "removed",
			Path:   filepath.Join(cache, fmt.Sprintf("f_%02d", i)),
			Source: "rdcw", When: ck.Now()})
	}
	if len(r.fs) != 0 {
		t.Fatalf("缓存目录 churn 不应触发: %+v", r.fs)
	}
	// 非缓存目录的批量删除照常触发（对照组）
	for i := 0; i < 20; i++ {
		d.Consume(Event{Kind: "removed",
			Path:   filepath.Join(dir, fmt.Sprintf("doc_%02d.docx", i)),
			Source: "rdcw", When: ck.Now()})
	}
	found := false
	for _, f := range r.fs {
		if f.RuleID == RuleRansom {
			found = true
		}
	}
	if !found {
		t.Fatalf("非缓存目录的批量删除应触发 FILE-RANSOM: %+v", r.fs)
	}
}

// 周期自检的内容校验：Documents 这类 RDCW 覆盖不到的目录，诱饵被
// "原地改写不删不改名"时文件系统事件一路都收不到，只有这里能抓到
// （v0.9.10 深化收口的漏报盲区）。发现篡改只告警不恢复——覆盖=销毁证据。
func TestMaintainDetectsContentTamper(t *testing.T) {
	dir := t.TempDir()
	d, r, _ := newDefense(t, []string{dir}, nil)
	target := filepath.Join(dir, "backup_report.docx")
	if err := os.WriteFile(target, []byte("ENCRYPTED"), 0o644); err != nil {
		t.Fatal(err)
	}
	d.maintain()
	found := false
	for _, f := range r.fs {
		if f.RuleID == RuleCanary && strings.Contains(f.Summary, "内容与预期不符") {
			found = true
		}
	}
	if !found {
		t.Fatalf("内容篡改未被周期自检发现: %+v", r.fs)
	}
	raw, err := os.ReadFile(target)
	if err != nil || string(raw) != "ENCRYPTED" {
		t.Fatal("自检不应覆盖被篡改的诱饵（销毁证据）")
	}
}

// 清空回收站 = $Recycle.Bin 内批量删除 + 改名进回收站（新路径命中），
// 都应被剔除——否则用户清一次回收站就是一次 FILE-RANSOM 误报。
func TestRecycleBinChurnExcluded(t *testing.T) {
	dir := t.TempDir()
	d, r, ck := newDefense(t, []string{dir}, nil)
	rb := `C:\$Recycle.Bin\S-1-5-21-1234`
	for i := 0; i < 25; i++ {
		d.Consume(Event{Kind: "removed",
			Path:   fmt.Sprintf(`%s\$R%02dX.docx`, rb, i),
			Source: "rdcw", When: ck.Now()})
		d.Consume(Event{Kind: "renamed",
			Path:    fmt.Sprintf(`%s\$R%02dX.docx`, rb, i),
			OldPath: filepath.Join(dir, fmt.Sprintf("doc%02d.docx", i)),
			Source:  "rdcw", When: ck.Now()})
	}
	for _, f := range r.fs {
		if f.RuleID == RuleRansom {
			t.Fatalf("回收站 churn 不应触发: %+v", f)
		}
	}
}

// 观察级速率发现的指纹口径：HourlyFP 置位 → 接线层按小时分桶（持续
// churn 下 Top 目录随批次漂移，路径指纹互不去重 = 每 15min 冷却期一行，
// 实测 13 天 888 行）；升级级（同目录集中爆发）保持路径指纹——真实
// 信号值得按目标独立成行。
func TestRateFindingHourlyFPScopes(t *testing.T) {
	// 观察级：达到阈值但未达升级条件（w < 2×阈值）
	dir := t.TempDir()
	d, r, ck := newDefense(t, []string{dir}, nil)
	for i := 0; i < 20; i++ {
		d.Consume(Event{Kind: "removed",
			Path:   filepath.Join(dir, fmt.Sprintf("doc%d.docx", i)),
			Source: "rdcw", When: ck.Now()})
	}
	if len(r.fs) != 1 {
		t.Fatalf("observe findings = %+v, want 1", r.fs)
	}
	if !r.fs[0].HourlyFP {
		t.Fatalf("观察级应置 HourlyFP: %+v", r.fs[0])
	}
	if r.fs[0].Severity != model.SeverityMedium {
		t.Fatalf("观察级应为 medium: %+v", r.fs[0].Severity)
	}

	// 升级级的定级与指纹口径见 TestRateFindingEscalatedViaBulkWindow：
	// Consume 逐事件路径到不了 2×阈值（潜伏缺陷，独立切片处理）。
}

// 升级分支（2026-11-18 可达性重排后的端到端口径）：持续单目录爆发
// 经 Consume 公开路径分两级——首越阈值发观察级（medium/HourlyFP），
// 同冷却窗内继续翻倍且集中占比 ≥0.6 补发升级告警（high/路径指纹），
// 每冷却窗最多补发一次。
func TestRateEscalatedViaConsume(t *testing.T) {
	dir := t.TempDir()
	d, r, ck := newDefense(t, []string{dir}, nil)
	consume := func(n int) {
		for i := 0; i < n; i++ {
			d.Consume(Event{Kind: "removed",
				Path:   filepath.Join(dir, fmt.Sprintf("doc%d.docx", i)),
				Source: "rdcw", When: ck.Now()})
		}
	}
	// 20 分首越阈值 → 观察级首发
	consume(20)
	if len(r.fs) != 1 || r.fs[0].Severity != model.SeverityMedium {
		t.Fatalf("首发应为观察级: %+v", r.fs)
	}
	if !r.fs[0].HourlyFP {
		t.Fatalf("观察级应置 HourlyFP: %+v", r.fs[0])
	}
	// 同冷却窗内继续翻倍（20→40）且全部单目录 → 升级告警补发
	consume(20)
	if len(r.fs) != 2 || r.fs[1].Severity != model.SeverityHigh {
		t.Fatalf("翻倍集中应补发升级: %+v", r.fs)
	}
	if r.fs[1].HourlyFP {
		t.Fatalf("升级级应保持路径指纹: %+v", r.fs[1])
	}
	if !strings.Contains(r.fs[1].Summary, "升级确认") {
		t.Fatalf("升级告警应说明是对先前的升级确认: %s", r.fs[1].Summary)
	}
	// 同窗口再翻倍（40→80）：每冷却窗最多补发一次
	consume(40)
	if len(r.fs) != 2 {
		t.Fatalf("同冷却窗不应重复补发: %+v", r.fs)
	}
}

// 首发即集中（两个事件内跨过 2×阈值）：首发直接升级，无需等冷却复查。
func TestRateEscalatedAtFirstHit(t *testing.T) {
	dir := t.TempDir()
	d, r, ck := newDefense(t, []string{dir}, nil)
	// renamed 跨扩展名权重 2，10 条 = 20 分即阈值；用 pushLocked 直填
	// 单批 42 分（w ≥ 2×阈值且单目录占比 ≥0.6）模拟批处理工具瞬时爆发
	d.mu.Lock()
	for i := 0; i < 42; i++ {
		d.pushLocked(ck.Now(), 1, Event{Kind: "removed",
			Path: filepath.Join(dir, fmt.Sprintf("doc%d.docx", i)), Source: "rdcw"})
	}
	d.mu.Unlock()
	d.Consume(Event{Kind: "removed",
		Path: filepath.Join(dir, "final.docx"), Source: "rdcw", When: ck.Now()})
	if len(r.fs) != 1 || r.fs[0].Severity != model.SeverityHigh {
		t.Fatalf("首发即满足升级条件应直接 high: %+v", r.fs)
	}
}

// AV/更新器自维护目录必须整段剔除出速率窗口（2026-11-18 实测：火绒
// Sysdiag 单轮 59-61 删除直接灌满窗口并联动把诱饵告警升级成假 critical）。
func TestChurnMarkersExcludeAVSelfMaintainDirs(t *testing.T) {
	avDirs := []string{
		`C:\ProgramData\Huorong\Sysdiag\engines\1.0.0.1\wsctrl.dat`,
		`C:\ProgramData\360zip\components\update\tmp0001.part`,
		`C:\ProgramData\Microsoft\Windows Defender\Definition Updates\{GUID}\mpengine.dll`,
		`C:\Windows\SoftwareDistribution\Download\xyz\windows10-kb.msu`,
		`C:\ProgramData\Mozilla-1de4eec8-1241-4177-a864-e594e8d1fb38\updates\308046B0\patch.exe`,
	}
	for _, p := range avDirs {
		if w := rateWeight(Event{Kind: "removed", Path: p, Source: "rdcw"}); w != 0 {
			t.Fatalf("AV 自维护路径 %s 权重 = %d, want 0", p, w)
		}
	}
	// 用户目录不受影响：Document 删除仍计数
	if w := rateWeight(Event{Kind: "removed", Path: `C:\Users\bob\Documents\a.docx`, Source: "rdcw"}); w != 1 {
		t.Fatalf("用户目录删除权重 = %d, want 1", w)
	}
	// 端到端：AV 目录删 60 个文件不触发速率告警
	dir := t.TempDir()
	d, r, _ := newDefense(t, []string{dir}, nil)
	for i := 0; i < 60; i++ {
		d.Consume(Event{Kind: "removed",
			Path:   fmt.Sprintf(`C:\ProgramData\Huorong\Sysdiag\tmp\file%d.dat`, i),
			Source: "rdcw"})
	}
	for _, f := range r.fs {
		if f.RuleID == RuleRansom {
			t.Fatalf("AV 自维护 60 删除不应触发 FILE-RANSOM: %+v", f)
		}
	}
}

// 递进冷却：同一诱饵 24h 内第 3 次告警起带"杀软隔离循环"提示，且该键
// 冷却升到 2h——15min 后的第 4 次触碰被吞，2h 后恢复。
func TestCanaryRepeatEscalatesCooldown(t *testing.T) {
	dir := t.TempDir()
	d, r, ck := newDefense(t, []string{dir}, nil)
	canary := filepath.Join(dir, canaryNames[0])
	touch := func() { d.Consume(Event{Kind: "removed", Path: canary, Source: "rdcw", When: ck.Now()}) }

	for i := 0; i < 3; i++ {
		touch()
		if len(r.fs) != i+1 {
			t.Fatalf("第 %d 次触碰应发射（15min 冷却间隔）", i+1)
		}
		ck.advance(16 * time.Minute) // 越过普通冷却
	}
	third := r.fs[2]
	if !strings.Contains(third.Summary, "安全软件") || !strings.Contains(third.Summary, "24 小时内已第 3 次") {
		t.Fatalf("第 3 次告警应带杀软隔离提示: %s", third.Summary)
	}
	// 16min < 2h：第 4 次被递进冷却吞掉
	touch()
	if len(r.fs) != 3 {
		t.Fatalf("递进冷却失效（第 4 次不应发射）: %+v", r.fs)
	}
	// 2h 后恢复发射，且计数说明第 4 次
	ck.advance(2*time.Hour + time.Minute)
	touch()
	if len(r.fs) != 4 {
		t.Fatalf("2h 递进冷却过期后应恢复: %+v", r.fs)
	}
	if !strings.Contains(r.fs[3].Summary, "第 4 次") {
		t.Fatalf("第 4 次告警应带累计计数: %s", r.fs[3].Summary)
	}
}

// USN 封顶（2026-11-18 误报治理收尾）：目录盲源单靠自身永远够不到
// 触发线（20）也够不到 canary 升级线（10）——火绒引擎风暴（实测单分钟
// 3000+ 删除经 USN）灌不进窗口；RDCW（目录可知）不受限，USN 只作
// 封顶内助推。
func TestUSNRateCapBlocksDirBlindStorm(t *testing.T) {
	dir := t.TempDir()
	d, r, ck := newDefense(t, []string{dir}, nil)

	// 风暴：300 条 USN 删除（leaf 名，无目录）
	for i := 0; i < 300; i++ {
		d.Consume(Event{Kind: "removed", Path: fmt.Sprintf("eng%03d.dat", i), Source: "usn", When: ck.Now()})
	}
	for _, f := range r.fs {
		if f.RuleID == RuleRansom {
			t.Fatalf("USN 单源风暴不应触发 FILE-RANSOM: %+v", f)
		}
	}
	if got := d.USNCapped(); got != int64(300-d.usnCap) {
		t.Fatalf("USNCapped = %d, want %d（只有封顶额度内的进了窗）", got, 300-d.usnCap)
	}
	// 风暴期间触碰诱饵：不应被升级成 critical（半阈值分支被封顶挡住）
	canary := filepath.Join(dir, canaryNames[0])
	d.Consume(Event{Kind: "removed", Path: canary, Source: "rdcw", When: ck.Now()})
	for _, f := range r.fs {
		if f.RuleID == RuleCanary && f.Severity == model.SeverityCritical {
			t.Fatalf("USN 风暴不应把诱饵触碰升级成 critical: %+v", f)
		}
	}
}

// 封顶不误伤真实爆发：RDCW（用户目录）不受限，USN 在封顶内助推——
// rdcw 12 + usn 9 = 21 ≥ 20 触发，证明封顶挡的是"单源"而不是信号本身。
func TestUSNCappedContributionStillHelpsRealBurst(t *testing.T) {
	dir := t.TempDir()
	d, r, ck := newDefense(t, []string{dir}, nil)

	for i := 0; i < 12; i++ {
		d.Consume(Event{Kind: "removed", Path: filepath.Join(dir, fmt.Sprintf("f%d.docx", i)), Source: "rdcw", When: ck.Now()})
	}
	for i := 0; i < 30; i++ {
		d.Consume(Event{Kind: "removed", Path: fmt.Sprintf("leaf%d.dat", i), Source: "usn", When: ck.Now()})
	}
	if len(r.fs) == 0 {
		t.Fatalf("rdcw 12 + usn 封顶 9 = 21 应触发 FILE-RANSOM")
	}
	if r.fs[0].RuleID != RuleRansom {
		t.Fatalf("首条 finding 应是 FILE-RANSOM: %+v", r.fs[0])
	}
}

// USN 同名碰撞验真（2026-11-18 实测事故回归）：go test 勒索夹具在别处
// 建删同名文件，真探针 USN 只认 leaf 名。完好诱饵（mtime 早于事件时刻）
// 与该事件无关 → 吸收不告警；真被删/改的诱饵（缺失或 mtime ≥ 事件）→
// 照常告警。攻击面：先删后回填同内容可绕过（见 matchCanary 头注释）。
func TestUSNLeafCollisionAbsorbed(t *testing.T) {
	dir := t.TempDir()
	d, r, _ := newDefense(t, []string{dir}, nil)

	// 场景一：同名文件在别处被删，真诱饵完好（mtime 在事件前）→ 吸收。
	// 验真比较的是事件时刻与真实 mtime，事件 When 必须用真实时间
	// （fake clock 在 2026-11-03，比任何真实 mtime 都早，测不出碰撞）。
	canaryPath := filepath.Join(dir, canaryNames[2])
	past := time.Now().Add(-time.Hour)
	if err := os.Chtimes(canaryPath, past, past); err != nil {
		t.Fatal(err)
	}
	d.Consume(Event{Kind: "removed", Path: canaryNames[2], Source: "usn", When: time.Now()})
	if len(r.fs) != 0 {
		t.Fatalf("完好诱饵的同名碰撞应吸收: %+v", r.fs)
	}

	// 场景二：真诱饵被删（文件不存在）→ 照常告警
	if err := os.Remove(canaryPath); err != nil {
		t.Fatal(err)
	}
	d.Consume(Event{Kind: "removed", Path: canaryNames[2], Source: "usn", When: time.Now()})
	if len(r.fs) != 1 {
		t.Fatalf("真删除必须告警: %+v", r.fs)
	}
	if !strings.Contains(r.fs[0].Summary, canaryPath) {
		t.Fatalf("唯一候选应归属诱饵本体路径: %s", r.fs[0].Summary)
	}

	// 场景三：停机补采形态——USN 事件早于诱饵重种时刻（mtime 晚于事件）
	// → "删除后被重写"，验真判真、照常告警（杀软隔离循环归递进冷却治理）
	d.Consume(Event{Kind: "removed", Path: canaryNames[3], Source: "usn", When: time.Now().Add(-10 * time.Minute)})
	if len(r.fs) != 2 {
		t.Fatalf("mtime 晚于事件的原地改写必须告警: %+v", r.fs)
	}
}
