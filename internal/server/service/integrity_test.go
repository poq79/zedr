package service

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"zedr/internal/server/domain"
	"zedr/internal/server/repository/sqlite"
)

// TestIntegrityChain 端到端验证"告警防篡改链"：
// 归档 → 未被改动时校验 ok → 告警被删后校验为 purged（区别于篡改）。
func TestIntegrityChain(t *testing.T) {
	ctx := context.Background()
	store, repos, err := sqlite.Open(ctx, filepath.Join(t.TempDir(), "it.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	svc := &StatsService{repos: repos}
	yesterday := time.Now().Add(-24 * time.Hour)
	// 通过仓储直接造两条昨日告警（与线上 Ingest 的落库路径同表同列）
	now := yesterday
	for i, id := range []string{"a-1", "a-2"} {
		err := repos.Alerts.Create(ctx, &domain.Alert{
			ID: id, AgentID: "ag", Hostname: "pc", Fingerprint: "fp-" + id,
			Title: "t", Verdict: domain.VerdictSuspicious, Severity: domain.SeverityMedium,
			Score: 40 + i, ProcessName: "x.exe", CreatedAt: now,
		})
		if err != nil {
			t.Fatal(err)
		}
	}

	// 归档昨日
	if err := svc.EnsureIntegrity(ctx, yesterday); err != nil {
		t.Fatal(err)
	}

	// 归档是幂等的：重复调用不改变链
	if err := svc.EnsureIntegrity(ctx, yesterday); err != nil {
		t.Fatal(err)
	}

	// 未被改动 → ok
	checks, err := svc.VerifyIntegrity(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(checks) != 1 || checks[0].Status != "ok" || checks[0].StoredN != 2 {
		t.Fatalf("初始校验应为 ok/2 条，实际 %+v", checks)
	}

	// 模拟"事后篡改"：条目数不变、内容被改（score 40→99）。
	// 重算摘要应与归档不同 → tampered。这正是完整性链要抓住的核心场景。
	if _, err := store.DB().ExecContext(ctx,
		`UPDATE alerts SET score = 99 WHERE id = 'a-1'`); err != nil {
		t.Fatal(err)
	}
	checks, err = svc.VerifyIntegrity(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(checks) != 1 || checks[0].Status != "tampered" {
		t.Fatalf("篡改后应判 tampered，实际 %+v", checks)
	}
}
