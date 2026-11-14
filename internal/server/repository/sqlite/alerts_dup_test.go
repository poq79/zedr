package sqlite

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"zedr/internal/server/domain"
)

// TestFindDuplicatesStats 锁定自适应抑制的数据面契约：窗口内行数、
// 最近时刻、以及 duplicate 计数落点必须是"最近一行"（运营在列表里
// 看到的是最近还在发生的那个条目在涨计数，而不是任意旧行）。
func TestFindDuplicatesStats(t *testing.T) {
	ctx := context.Background()
	store, repos, err := Open(ctx, filepath.Join(t.TempDir(), "dupstats.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	now := time.Now()
	mk := func(i int, fp string, createdAt time.Time) *domain.Alert {
		return &domain.Alert{
			ID: fmt.Sprintf("dup%06d", i), AgentID: "agent-dup", Hostname: "HOST-DUP",
			Fingerprint: fp, Title: "自适应查重测试", Verdict: domain.VerdictSuspicious,
			Severity: domain.SeverityMedium, Score: 40, Status: domain.StatusOpen,
			OccurredAt: createdAt, CreatedAt: createdAt, HostCount: 1,
		}
	}

	// 同指纹三行：2h/1h/5min 前——最近行应是 5min 前那行
	old, mid := now.Add(-2*time.Hour), now.Add(-time.Hour)
	recent := now.Add(-5 * time.Minute)
	for i, at := range []time.Time{old, mid, recent} {
		if err := repos.Alerts.Create(ctx, mk(i, "fp-repeat", at)); err != nil {
			t.Fatalf("insert %d: %v", i, err)
		}
	}
	// 干扰项：另一指纹一行 + 超出 24h 视野的同指纹旧行
	if err := repos.Alerts.Create(ctx, mk(9, "fp-other", now.Add(-time.Minute))); err != nil {
		t.Fatal(err)
	}
	if err := repos.Alerts.Create(ctx, mk(10, "fp-repeat", now.Add(-48*time.Hour))); err != nil {
		t.Fatal(err)
	}

	got, err := repos.Alerts.FindDuplicates(ctx, "agent-dup", now.Add(-24*time.Hour),
		[]string{"fp-repeat", "fp-other", "fp-miss"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("视野外指纹不得返回，实际 %d 个: %v", len(got), got)
	}
	hit := got["fp-repeat"]
	if hit.Count != 3 {
		t.Fatalf("视野内行数应为 3（48h 前的行被窗口裁掉），实际 %d", hit.Count)
	}
	if d := hit.LastSeenAt.Sub(recent); d < -time.Second || d > time.Second {
		t.Fatalf("最近时刻应为 5min 前，实际 %v", hit.LastSeenAt)
	}
	if hit.AlertID != "dup000002" {
		t.Fatalf("计数落点应为最近一行 dup000002，实际 %s", hit.AlertID)
	}
	if other := got["fp-other"]; other.Count != 1 || other.AlertID != "dup000009" {
		t.Fatalf("单行指纹摘要不符: %+v", other)
	}
	if _, ok := got["fp-miss"]; ok {
		t.Fatal("不存在的指纹不应返回")
	}
}
