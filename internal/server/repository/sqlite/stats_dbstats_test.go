package sqlite

// DBStats 回归（2026-11-19 数据库健康度轮 P0-2）：行数口径 / 最老 open
// 年龄 / 尺寸字段的基本健全性。这是 /metrics zedr_db_* 的数据源，
// 口径错了监控就跟着错，锁死在这里。

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"zedr/internal/server/domain"
)

func TestDBStats(t *testing.T) {
	ctx := context.Background()
	store, repos, err := Open(ctx, filepath.Join(t.TempDir(), "dbstats.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	mk := func(id, status string, age time.Duration) *domain.Alert {
		return &domain.Alert{
			ID: id, AgentID: "ag-db", Hostname: "pc-db",
			Fingerprint: "fp-" + id,
			Title:       "dbstats 回归", Verdict: domain.VerdictSuspicious,
			Severity: domain.SeverityLow, Score: 10,
			Status:     domain.AlertStatus(status),
			OccurredAt: time.Now().Add(-age), CreatedAt: time.Now().Add(-age),
		}
	}
	seed := []struct {
		id     string
		status string
		age    time.Duration
	}{
		{"open-old", "open", 2 * time.Hour},
		{"open-new", "open", time.Minute},
		{"ack-1", "acknowledged", time.Hour},
		{"res-1", "resolved", time.Hour},
	}
	for _, s := range seed {
		if err := repos.Alerts.Create(ctx, mk(s.id, s.status, s.age)); err != nil {
			t.Fatalf("create %s: %v", s.id, err)
		}
	}

	dbStats, err := repos.Stats.DBStats(ctx)
	if err != nil {
		t.Fatalf("DBStats: %v", err)
	}

	if dbStats.FileBytes <= 0 {
		t.Fatalf("file_bytes = %d, want > 0", dbStats.FileBytes)
	}
	if dbStats.AlertsByStatus["open"] != 2 ||
		dbStats.AlertsByStatus["acknowledged"] != 1 ||
		dbStats.AlertsByStatus["resolved"] != 1 {
		t.Fatalf("alerts_by_status = %v, want open=2 ack=1 resolved=1", dbStats.AlertsByStatus)
	}
	// 最老 open 是 2 小时前那条：年龄必须落在 (1h, 24h] 区间，
	// 说明 MIN(created_at) 走的是毫秒口径且时区无关。
	if age := dbStats.OldestOpenAgeSeconds; age <= 3600 || age > 86400 {
		t.Fatalf("oldest_open_age_seconds = %d, want (3600, 86400]", age)
	}
	if dbStats.FreeBytes < 0 {
		t.Fatalf("free_bytes = %d, want >= 0", dbStats.FreeBytes)
	}
}
