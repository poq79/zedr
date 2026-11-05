package service

import (
	"context"
	"testing"
	"time"

	"zedr/internal/server/domain"
)

// 研判质量对账：AI 结论 × 分析师处置。对账口径是产品级契约
// （误报/漏报直接决定 AI 功能的信任度），必须锁死。
func newQualityTest(t *testing.T) (*AIService, context.Context) {
	t.Helper()
	return newOpsTest(t)
}

func seedQualityAlert(t *testing.T, svc *AIService, ctx context.Context, id, title string, status domain.AlertStatus) {
	t.Helper()
	if err := svc.repos.Alerts.Create(ctx, &domain.Alert{
		ID: id, AgentID: "ag-1", Hostname: "PC-01", Fingerprint: "fp-" + id,
		Title: title, Severity: domain.SeverityCritical, Score: 75,
		Status: status, CreatedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
}

func seedTruthByOps(t *testing.T, svc *AIService, ctx context.Context, alertID, reason string) {
	t.Helper()
	if err := svc.enqueueOps(ctx, mkItem("op-"+alertID, alertID, "测试-"+alertID, "PC-01")); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ReviewOps(ctx, "op-"+alertID, "dismiss", "analyst", reason); err != nil {
		t.Fatal(err)
	}
}

func TestQualityReportMatrix(t *testing.T) {
	svc, ctx := newQualityTest(t)

	cases := []struct {
		alertID, title, aiVerdict string
		truth                     string // 经值班队列结案理由给出
		wantCell                  string // tp_agree | ai_fp | ai_miss | noise_agree
	}{
		{"a1", "AI 说有问题，分析师确认真阳性", "malicious", "true_positive", "tp_agree"},
		{"a2", "AI 说没问题，分析师判真阳性（漏报）", "benign", "true_positive", "ai_miss"},
		{"a3", "AI 说有问题，分析师判误报（AI 误报）", "suspicious", "false_positive", "ai_fp"},
		{"a4", "AI 说没问题，分析师判误报（降噪正确）", "benign", "false_positive", "noise_agree"},
		{"a5", "AI 说有问题，分析师确认良性（AI 误报）", "inconclusive", "true_positive", "ai_miss"},
		{"a6", "AI 兜底说没问题，分析师判误报", "benign", "false_positive", "noise_agree"},
	}
	for _, c := range cases {
		seedQualityAlert(t, svc, ctx, c.alertID, c.title, domain.StatusOpen)
		svc.recordTriage(ctx, c.alertID, triageSourceHeuristic, c.aiVerdict, 0.5, "heuristic")
		seedTruthByOps(t, svc, ctx, c.alertID, c.truth)
	}

	rep, err := svc.QualityReport(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Sampled != 6 {
		t.Fatalf("应采样 6 条，实际 %d", rep.Sampled)
	}
	if rep.Counts["tp_agree"] != 1 || rep.Counts["ai_fp"] != 1 || rep.Counts["ai_miss"] != 2 || rep.Counts["noise_agree"] != 2 {
		t.Fatalf("对账四格不符: %+v", rep.Counts)
	}
	if rep.AgreeRate != 0.5 {
		t.Errorf("一致率应 3/6=0.5，实际 %v", rep.AgreeRate)
	}
	if rep.AIFPRate != float64(1)/float64(6) {
		t.Errorf("AI 误报率应 1/6，实际 %v", rep.AIFPRate)
	}
	if rep.AIMissRate != float64(2)/float64(6) {
		t.Errorf("AI 漏报率应 2/6，实际 %v", rep.AIMissRate)
	}
	if len(rep.Disagreements) != 3 {
		t.Errorf("分歧样本应 3 条（1 fp + 2 miss），实际 %d", len(rep.Disagreements))
	}
	for _, d := range rep.Disagreements {
		if d.Title == "" || d.AlertID == "" {
			t.Errorf("分歧样本缺告警上下文: %+v", d)
		}
	}
}

// TestQualityReportTruthViaAlertStatus 误报标记（告警页 status=false_positive）
// 同样是真值来源——不是所有误报都走值班队列。
func TestQualityReportTruthViaAlertStatus(t *testing.T) {
	svc, ctx := newQualityTest(t)
	seedQualityAlert(t, svc, ctx, "fp1", "告警页标记的误报", domain.StatusFalsePositive)
	svc.recordTriage(ctx, "fp1", triageSourceAI, "malicious", 0.8, "deepseek-v4.1")

	rep, err := svc.QualityReport(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Sampled != 1 || rep.Counts["ai_fp"] != 1 {
		t.Fatalf("告警页误报标记应入对账: sampled=%d counts=%+v", rep.Sampled, rep.Counts)
	}
	if len(rep.Disagreements) != 1 || rep.Disagreements[0].Kind != "ai_fp" {
		t.Fatalf("应产出 ai_fp 分歧样本: %+v", rep.Disagreements)
	}
}

// TestQualityReportAIPriority 同告警同存 ai/heuristic 两来源时以 ai 为准
// （与界面呈现一致：模型结论优先于兜底结论）。
func TestQualityReportAIPriority(t *testing.T) {
	svc, ctx := newQualityTest(t)
	seedQualityAlert(t, svc, ctx, "p1", "双来源告警", domain.StatusFalsePositive)
	svc.recordTriage(ctx, "p1", triageSourceHeuristic, "malicious", 0.5, "heuristic")
	svc.recordTriage(ctx, "p1", triageSourceAI, "benign", 0.3, "deepseek")

	rep, err := svc.QualityReport(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Counts["noise_agree"] != 1 || rep.Counts["ai_fp"] != 0 {
		t.Fatalf("应取 ai 来源 benign 参与对账: %+v", rep.Counts)
	}
}
