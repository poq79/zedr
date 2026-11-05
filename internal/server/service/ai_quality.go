package service

import (
	"context"
	"sort"
	"time"

	"zedr/internal/server/domain"
)

// ---------------------------------------------------------------- 研判质量运营闭环
//
// 依据（2026-11-06 联网调研，来源见 overview.md）：Prophet 的信任三步
// ——先记录 AI 结论与分析师处置的对错矩阵，观察模式先行，准确率达标
// 才谈自治。此前研判/调查只在日志里留结论，"AI 到底准不准"没有数据
// 可回答。本文件把三路判定（AI 研判 / 确定性五步 / Agentic 调查）落到
// 台账，并与分析师处置结论（值班队列结案理由 + 告警误报标记）对账。

// 判定来源常量（台账 source 列）。
const (
	triageSourceAI        = "ai"        // 模型研判 / Agentic 调查
	triageSourceHeuristic = "heuristic" // 确定性五步
)

// recordTriage 写一条判定台账；失败只记日志绝不阻断主链路——
// 质量运营是旁路观测，不能变成研判主路径的故障点。
func (s *AIService) recordTriage(ctx context.Context, alertID, source, verdict string, confidence float64, engine string) {
	if s.repos.ATriage == nil || alertID == "" || verdict == "" {
		return
	}
	err := s.repos.ATriage.Upsert(ctx, &domain.AITriageLog{
		AlertID: alertID, Source: source,
		Verdict: verdict, Confidence: confidence,
		Engine: engine, CreatedAt: time.Now(),
	})
	if err != nil && s.log != nil {
		s.log.WarnContext(ctx, "ai_triage_log_failed", "alert_id", alertID, "err", err)
	}
}

// AIQualityReport 是研判质量对账报告。
//
// 口径：AI 预测两分（malicious/suspicious=有问题，benign/inconclusive=
// 没问题）× 分析师结论两分（true_positive=有问题，false_positive/
// known_benign=没问题）。duplicate/test_exercise/other/仅 resolved 是
// "处理了但没给定性理由"，不计入严格对账——把模糊样本塞进矩阵只会
// 制造虚假的准确率。
type AIQualityReport struct {
	// Sampled 是纳入对账的告警数（AI 有结论 × 分析师有定性结论）。
	Sampled int `json:"sampled"`
	// AgreeRate 一致率：(AI 误报预警正确 + AI 降噪正确) / Sampled。
	AgreeRate float64 `json:"agree_rate"`
	// AIFPRate AI 误报率：AI 说有问题、分析师判良性/误报。
	// Scanner 实测教训：误报 Malicious 最毁信任，这项是头号监控指标。
	AIFPRate float64 `json:"ai_fp_rate"`
	// AIMissRate AI 漏报率：AI 说没问题、分析师判真阳性。最危险的一格。
	AIMissRate float64 `json:"ai_miss_rate"`
	// Counts 是对账四格的原始计数，前端画矩阵用。
	Counts map[string]int `json:"counts"`
	// Unscored 是有 AI 结论、有处置、但处置不带定性理由的条数。
	Unscored int `json:"unscored"`
	// Disagreements 是最近的分歧样本（跳告警人工复核的入口）。
	Disagreements []AIQualityDisagreement `json:"disagreements"`
}

type AIQualityDisagreement struct {
	AlertID       string  `json:"alert_id"`
	Title         string  `json:"title"`
	Hostname      string  `json:"hostname"`
	AIVerdict     string  `json:"ai_verdict"`
	AIConfidence  float64 `json:"ai_confidence"`
	AISource      string  `json:"ai_source"`
	AnalystSaid   string  `json:"analyst_said"` // true_positive | false_positive | known_benign
	Kind          string  `json:"kind"`         // ai_fp | ai_miss
	OccurredAt    time.Time `json:"occurred_at"`
}

// QualityReport 生成研判质量对账。
//
// 真值来源两路：值班队列的结案理由（最完整）+ 告警页的误报标记
// （status=false_positive）。台账取每告警最新一条（ai 与 heuristic
// 两来源并存时优先 ai——模型结论优先于兜底结论，与界面呈现一致）。
func (s *AIService) QualityReport(ctx context.Context) (*AIQualityReport, error) {
	rep := &AIQualityReport{Counts: map[string]int{}}

	// ---- 真值集合 ----
	truth := map[string]string{} // alert_id -> true_positive | false_positive | known_benign
	if q, err := s.ListOpsQueue(ctx); err == nil {
		for _, it := range q {
			if it.Status == "pending" || it.ReviewReason == "" {
				continue
			}
			switch it.ReviewReason {
			case "true_positive", "false_positive", "known_benign":
				truth[it.AlertID] = it.ReviewReason
			default:
				// duplicate/test_exercise/other：有处置无定性，不入严格对账
			}
		}
	}
	if fps, _, err := s.repos.Alerts.List(ctx, domain.AlertFilter{
		Status: []domain.AlertStatus{domain.StatusFalsePositive}, Page: 1, PageSize: 200, Sort: "oldest",
	}); err == nil {
		for _, a := range fps {
			if _, ok := truth[a.ID]; !ok {
				truth[a.ID] = "false_positive"
			}
		}
	}
	if len(truth) == 0 {
		return rep, nil
	}

	// ---- AI 结论（每告警最新，ai 来源优先于 heuristic）----
	logs, err := s.repos.ATriage.List(ctx, 2000)
	if err != nil {
		return nil, err
	}
	latest := map[string]domain.AITriageLog{}
	for _, l := range logs {
		if cur, ok := latest[l.AlertID]; !ok || (l.Source == triageSourceAI && cur.Source != triageSourceAI) {
			latest[l.AlertID] = l
		}
	}

	// ---- 对账 ----
	type disagree struct {
		AIQualityDisagreement
		at time.Time
	}
	var dis []disagree
	for alertID, said := range truth {
		l, ok := latest[alertID]
		if !ok {
			continue
		}
		rep.Sampled++
		predBad := l.Verdict == "malicious" || l.Verdict == "suspicious"
		truthBad := said == "true_positive"
		var kind string
		switch {
		case predBad && truthBad:
			rep.Counts["tp_agree"]++
		case predBad && !truthBad:
			rep.Counts["ai_fp"]++
			kind = "ai_fp"
		case !predBad && truthBad:
			rep.Counts["ai_miss"]++
			kind = "ai_miss"
		default:
			rep.Counts["noise_agree"]++
		}
		if kind != "" && len(dis) < 10 {
			a, err := s.repos.Alerts.ByID(ctx, alertID)
			if err != nil || a == nil {
				continue
			}
			dis = append(dis, disagree{
				AIQualityDisagreement: AIQualityDisagreement{
					AlertID: alertID, Title: a.Title, Hostname: a.Hostname,
					AIVerdict: l.Verdict, AIConfidence: l.Confidence, AISource: l.Source,
					AnalystSaid: said, Kind: kind, OccurredAt: a.CreatedAt,
				},
				at: l.CreatedAt,
			})
		}
	}
	rep.Unscored = len(truth) - rep.Sampled
	if rep.Sampled > 0 {
		ok := rep.Counts["tp_agree"] + rep.Counts["noise_agree"]
		rep.AgreeRate = float64(ok) / float64(rep.Sampled)
		rep.AIFPRate = float64(rep.Counts["ai_fp"]) / float64(rep.Sampled)
		rep.AIMissRate = float64(rep.Counts["ai_miss"]) / float64(rep.Sampled)
	}
	sort.Slice(dis, func(i, j int) bool { return dis[i].at.After(dis[j].at) })
	for _, d := range dis {
		rep.Disagreements = append(rep.Disagreements, d.AIQualityDisagreement)
	}
	return rep, nil
}
