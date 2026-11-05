package service

import (
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"zedr/internal/ai"
	"zedr/internal/server/domain"
	"zedr/internal/server/repository/sqlite"
)

// 值班队列的核心纪律：爆发聚合（同主机同标题只留代表条目）、
// 审批只改状态绝不处置、结案理由码受控。走真实仓储（同 ai_test 基建）。

func newOpsTest(t *testing.T) (*AIService, context.Context) {
	t.Helper()
	ctx := context.Background()
	store, repos, err := sqlite.Open(ctx, filepath.Join(t.TempDir(), "ops.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := &AIService{repos: repos, eng: ai.NewEngine(ai.Config{Provider: "none"}, log), log: log}
	return svc, ctx
}

func mkItem(id, alertID, title, host string) *OpsItem {
	return &OpsItem{
		ID: id, AlertID: alertID, Title: title, Hostname: host,
		Severity: "critical", Score: 75, Engine: "heuristic",
		CreatedAt: time.Now(), Status: "pending",
	}
}

// TestOpsBurstAggregation 爆发聚合：同主机同标题的后续告警并入代表
// 条目（occurrences 递增 + last_alert_id 跟最新），不同标题不聚合。
func TestOpsBurstAggregation(t *testing.T) {
	svc, ctx := newOpsTest(t)
	if err := svc.enqueueOps(ctx, mkItem("op1", "a1", "诱饵文件被篡改", "PC-01")); err != nil {
		t.Fatal(err)
	}

	agg := func(alertID string) bool {
		return svc.tryAggregateOps(ctx, &domain.Alert{ID: alertID, Hostname: "PC-01", Title: "诱饵文件被篡改", Score: 80})
	}
	if !agg("a2") || !agg("a3") || !agg("a4") {
		t.Fatal("同主机同标题应持续聚合（计数继续涨）")
	}
	if svc.tryAggregateOps(ctx, &domain.Alert{ID: "b1", Hostname: "PC-01", Title: "另一条规则", Score: 80}) {
		t.Fatal("不同标题不应聚合")
	}

	list, err := svc.ListOpsQueue(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 {
		t.Fatalf("爆发应只留 1 条代表条目，实际 %d", len(list))
	}
	it := list[0]
	if it.Occurrences != 3 {
		t.Errorf("occurrences 应为 3，实际 %d", it.Occurrences)
	}
	if it.LastAlertID != "a4" {
		t.Errorf("last_alert_id 应指向最新告警 a4，实际 %q", it.LastAlertID)
	}
	if it.Score != 80 {
		t.Errorf("代表条目分数应取最大值 80，实际 %d", it.Score)
	}
	if it.LastSeenAt == nil {
		t.Error("last_seen_at 应被刷新")
	}
}

// TestOpsBulkReviewAndReason 批量忽略 + 理由码：只动 pending、非法
// 理由拒绝、理由落条目。
func TestOpsBulkReviewAndReason(t *testing.T) {
	svc, ctx := newOpsTest(t)
	for _, id := range []string{"op1", "op2", "op3"} {
		if err := svc.enqueueOps(ctx, mkItem(id, "a-"+id, "测试告警", "PC-01")); err != nil {
			t.Fatal(err)
		}
	}

	if _, _, err := svc.BulkReviewOps(ctx, []string{"op1", "op2"}, "dismiss", "analyst", "not-a-reason"); err == nil {
		t.Fatal("非法理由码应被拒绝")
	}
	if _, _, err := svc.BulkReviewOps(ctx, nil, "dismiss", "analyst", "false_positive"); err == nil {
		t.Fatal("空 ids 应被拒绝")
	}

	updated, skipped, err := svc.BulkReviewOps(ctx, []string{"op1", "op2", "op3", "op-none"}, "dismiss", "analyst", "false_positive")
	if err != nil {
		t.Fatal(err)
	}
	if len(updated) != 3 || skipped != 1 {
		t.Fatalf("应更新 3 条跳过 1 条，实际 %d/%d", len(updated), skipped)
	}

	// 已处理条目再次批量：全部跳过
	_, skipped2, err := svc.BulkReviewOps(ctx, []string{"op1", "op2", "op3"}, "dismiss", "analyst", "false_positive")
	if err != nil {
		t.Fatal(err)
	}
	if skipped2 != 3 {
		t.Fatalf("已处理条目应全部跳过，实际 %d", skipped2)
	}

	list, _ := svc.ListOpsQueue(ctx)
	for _, it := range list {
		if it.Status != "dismissed" || it.ReviewReason != "false_positive" || it.ReviewedBy != "analyst" {
			t.Errorf("条目 %s 状态/理由未落盘: %+v", it.ID, it)
		}
	}
}

// TestOpsReviewReasonValidation 单条审批同样受理由码约束。
func TestOpsReviewReasonValidation(t *testing.T) {
	svc, ctx := newOpsTest(t)
	if err := svc.enqueueOps(ctx, mkItem("op1", "a1", "测试告警", "PC-01")); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ReviewOps(ctx, "op1", "dismiss", "analyst", "bogus"); err == nil {
		t.Fatal("非法理由码应被拒绝")
	}
	if _, err := svc.ReviewOps(ctx, "op1", "approve", "analyst", "known_benign"); err != nil {
		t.Fatalf("合法理由码应通过: %v", err)
	}
	if _, err := svc.ReviewOps(ctx, "op1", "approve", "analyst", "other"); err == nil {
		t.Fatal("重复审批应报冲突")
	}
}
