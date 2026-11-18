package service

// 告警生命周期闭环回归（2026-11-18 数据库健康度轮，P0-1）：
// 1) acknowledged 纳入保留清理——OpenAlertTTL 归档只是 open→ack 换桶，
//    ack 再豁免等于把存储黑洞换个桶（11-14 洪水 11.9 万行的教训）；
// 2) OpenAlertTTL 超期归档必须循环收敛到清空，而不是每轮只吃一页 200 条。

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"zedr/internal/model"
	"zedr/internal/server/domain"
	"zedr/internal/server/repository/sqlite"
)

func ttlAlert(id, status string, age time.Duration) *domain.Alert {
	return &domain.Alert{
		ID: id, AgentID: "ag-ttl", Hostname: "pc-ttl",
		Fingerprint: "fp-" + id,
		Title:       "生命周期回归", Verdict: domain.VerdictSuspicious,
		Severity: domain.SeverityLow, Score: 10,
		Status:     domain.AlertStatus(status),
		OccurredAt: time.Now().Add(-age), CreatedAt: time.Now().Add(-age),
	}
}

// TestPurgeIncludesAcknowledged 保留清理必须覆盖 acknowledged：超期四态
// （open 豁免 + ack/resolved/false_positive）里应恰好删掉三个已处置态，
// 留下 open 与未超期 ack。
func TestPurgeIncludesAcknowledged(t *testing.T) {
	ctx := context.Background()
	store, repos, err := sqlite.Open(ctx, filepath.Join(t.TempDir(), "lifecycle.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	old := 40 * 24 * time.Hour // 超过清理线
	recent := time.Hour
	seed := []struct {
		id     string
		status string
		age    time.Duration
	}{
		{"open-old", "open", old},
		{"ack-old", "acknowledged", old},
		{"res-old", "resolved", old},
		{"fp-old", "false_positive", old},
		{"ack-new", "acknowledged", recent},
	}
	for _, s := range seed {
		if err := repos.Alerts.Create(ctx, ttlAlert(s.id, s.status, s.age)); err != nil {
			t.Fatalf("create %s: %v", s.id, err)
		}
	}

	n, err := repos.Alerts.PurgeBefore(ctx, time.Now().Add(-30*24*time.Hour))
	if err != nil {
		t.Fatalf("purge: %v", err)
	}
	if n != 3 {
		t.Fatalf("purged = %d, want 3（ack/resolved/fp 各一，open 与新 ack 豁免）", n)
	}

	_, total, err := repos.Alerts.List(ctx, domain.AlertFilter{})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if total != 2 {
		t.Fatalf("remaining = %d, want 2（open-old 与 ack-new）", total)
	}
}

// TestOpenAlertTTLDrainsBeyondSinglePage 250 条超期 open（>单页 200），
// 一次归档调用必须全部收敛为 acknowledged；旧实现每轮只吃一页，
// 要几十个同步周期才追平。
func TestOpenAlertTTLDrainsBeyondSinglePage(t *testing.T) {
	ctx := context.Background()
	store, repos, err := sqlite.Open(ctx, filepath.Join(t.TempDir(), "ttl.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	svc := &IncidentService{
		repos: repos,
		cfg:   Config{OpenAlertTTL: 24 * time.Hour},
		log:   slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	const total = 250
	age := 48 * time.Hour // 超过 TTL
	for i := 0; i < total; i++ {
		if err := repos.Alerts.Create(ctx, ttlAlert(
			fmt.Sprintf("ttl-%03d", i), "open", age)); err != nil {
			t.Fatalf("create %d: %v", i, err)
		}
	}

	svc.applyOpenAlertTTL(ctx, time.Now())

	_, openLeft, err := repos.Alerts.List(ctx, domain.AlertFilter{
		Status: []domain.AlertStatus{model.StatusOpen},
	})
	if err != nil {
		t.Fatalf("list open: %v", err)
	}
	if openLeft != 0 {
		t.Fatalf("open left = %d, want 0（循环未收敛到清空）", openLeft)
	}
	_, ackTotal, err := repos.Alerts.List(ctx, domain.AlertFilter{
		Status: []domain.AlertStatus{model.StatusAcknowledged},
	})
	if err != nil {
		t.Fatalf("list ack: %v", err)
	}
	if ackTotal != total {
		t.Fatalf("ack = %d, want %d", ackTotal, total)
	}
}
