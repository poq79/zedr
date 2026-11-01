package service

// 事件聚类分页全量的端到端测试：临时 SQLite（照 integrity_test.go 基建）
// 造超过单页 200 条的 open 告警 → Sync → 断言聚类覆盖全量。
// 旧实现单页 PageSize=200，open+acknowledged 超 200 时聚类永远缺尾巴。

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"hostguard/internal/model"
	"hostguard/internal/server/domain"
	"hostguard/internal/server/repository/sqlite"
)

// TestSyncCoversBeyondSinglePage 同主机 250 条 open 告警、相邻间隔 1 分钟
// （全部落在 30 分钟聚类窗口内）→ 应聚成 1 个事件且覆盖全部 250 条。
// 旧实现只翻到第 200 条：AlertCount 会停在 200。
func TestSyncCoversBeyondSinglePage(t *testing.T) {
	ctx := context.Background()
	store, repos, err := sqlite.Open(ctx, filepath.Join(t.TempDir(), "incidents.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	svc := &IncidentService{
		repos: repos,
		log:   slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	// 秒级截断：created_at 以毫秒存储，往返后仍可与 FirstSeen/LastSeen 精确比对
	base := time.Now().Add(-48 * time.Hour).Truncate(time.Second)
	const total = 250
	for i := 0; i < total; i++ {
		err := repos.Alerts.Create(ctx, &domain.Alert{
			ID: fmt.Sprintf("a-%03d", i), AgentID: "ag-1", Hostname: "pc-1",
			Fingerprint: fmt.Sprintf("fp-%03d", i),
			Title:       "可疑活动", Verdict: domain.VerdictSuspicious,
			Severity: domain.SeverityMedium, Score: 50, ProcessName: "x.exe",
			Status:    model.StatusOpen,
			CreatedAt: base.Add(time.Duration(i) * time.Minute),
		})
		if err != nil {
			t.Fatal(err)
		}
	}

	n, err := svc.Sync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("250 条连续告警应聚成 1 个事件，实际 %d 个", n)
	}

	incs, _, err := repos.Incidents.List(ctx, "", 1, 50)
	if err != nil {
		t.Fatal(err)
	}
	if len(incs) != 1 {
		t.Fatalf("持久化事件应为 1 条，实际 %d", len(incs))
	}
	if incs[0].AlertCount != total {
		t.Fatalf("事件应覆盖全部 %d 条告警（旧实现只覆盖 200），实际 %d", total, incs[0].AlertCount)
	}
	if incs[0].OpenCount != total {
		t.Fatalf("open 计数应为 %d，实际 %d", total, incs[0].OpenCount)
	}
	// 时间锚点正确 = 翻页拼接后全局升序没被破坏（clusterByGap 的输入契约）
	wantLast := base.Add(time.Duration(total-1) * time.Minute)
	if !incs[0].FirstSeen.Equal(base) || !incs[0].LastSeen.Equal(wantLast) {
		t.Fatalf("时间锚点漂移：first=%v want=%v, last=%v want=%v",
			incs[0].FirstSeen, base, incs[0].LastSeen, wantLast)
	}
}

// TestSyncCoversAllClustersAcrossPages 另一种形态验证翻页：
// 220 条间隔 31 分钟的告警各自成簇（220 个事件）。旧实现只覆盖最老
// 200 条 → Sync 返回 200；翻页全量后应返回 220。
func TestSyncCoversAllClustersAcrossPages(t *testing.T) {
	ctx := context.Background()
	store, repos, err := sqlite.Open(ctx, filepath.Join(t.TempDir(), "incidents.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	svc := &IncidentService{
		repos: repos,
		log:   slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	base := time.Now().Add(-48 * time.Hour)
	const total = 220
	for i := 0; i < total; i++ {
		err := repos.Alerts.Create(ctx, &domain.Alert{
			ID: fmt.Sprintf("b-%03d", i), AgentID: "ag-1", Hostname: "pc-2",
			Fingerprint: fmt.Sprintf("fpb-%03d", i),
			Title:       "可疑活动", Verdict: domain.VerdictSuspicious,
			Severity: domain.SeverityLow, Score: 30, ProcessName: "y.exe",
			Status:    model.StatusOpen,
			CreatedAt: base.Add(time.Duration(i) * 31 * time.Minute),
		})
		if err != nil {
			t.Fatal(err)
		}
	}

	n, err := svc.Sync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if n != total {
		t.Fatalf("间隔超 30 分钟的 %d 条告警应各自成簇（旧实现只覆盖 200），实际 %d 个", total, n)
	}

	_, totalIncs, err := repos.Incidents.List(ctx, "", 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	if totalIncs != total {
		t.Fatalf("持久化事件应 %d 条，实际 %d", total, totalIncs)
	}
}
