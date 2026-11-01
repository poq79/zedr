package service

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"hostguard/internal/ai"
	"hostguard/internal/model"
	"hostguard/internal/platform/apperr"
	"hostguard/internal/server/domain"
	"hostguard/internal/server/repository"
)

// AIService 把存储层的告警转换成分析引擎的输入，并做结果回填。
//
// 这一层的价值在于"转换"：库里的告警是扁平的（evidence 是一个大 JSON），
// 而推理需要一个**编号清晰的证据清单**——因为结论要逐条引用。
// 编号规则必须稳定（同一告警每次编号一致），否则缓存和分析师记忆都会失效。
type AIService struct {
	repos repository.Repos
	eng   *ai.Engine
	log   *slog.Logger
}

// Triage 研判一条告警。
func (s *AIService) Triage(ctx context.Context, alertID string) (*ai.TriageResult, error) {
	a, err := s.repos.Alerts.ByID(ctx, alertID)
	if err != nil {
		return nil, err
	}
	if a == nil {
		return nil, apperr.NotFound("告警不存在")
	}

	in, err := s.buildInput(ctx, a)
	if err != nil {
		return nil, err
	}
	res := s.eng.Triage(ctx, in)

	s.log.InfoContext(ctx, "ai_triage",
		"alert_id", alertID, "verdict", res.Verdict, "confidence", res.Confidence,
		"engine", res.Engine, "grounded", res.Grounded, "ignored_injection", res.UntrustedIgnored,
		"latency_ms", res.LatencyMs)
	return res, nil
}

// Hunt 把自然语言查询翻译成受控条件并执行。
func (s *AIService) Hunt(ctx context.Context, nl string) (*HuntResult, error) {
	q, err := s.eng.Translate(ctx, nl)
	if err != nil {
		return nil, apperr.Invalid("%s", err.Error())
	}

	f := domain.AlertFilter{
		Page:     1,
		PageSize: q.Limit,
	}
	// DSL → 仓储过滤条件。字段到 SQL 的映射集中在这里，
	// 模型永远接触不到 SQL，也就不存在"模型写注入"的路径。
	for _, flt := range q.Filters {
		switch flt.Field {
		case "process_name":
			f.ProcessLike = flt.Value
		case "image_path":
			f.PathLike = flt.Value
		case "cmdline":
			f.CmdLike = flt.Value
		case "hash_sha256":
			f.Hash = flt.Value
		case "verdict":
			f.Verdict = []domain.Verdict{domain.Verdict(flt.Value)}
		case "severity":
			f.Severity = []domain.Severity{domain.Severity(flt.Value)}
		case "score":
			if n, ok := atoiSafe(flt.Value); ok {
				f.MinScore = n
			}
		case "signed":
			v := flt.Value == "false" || flt.Value == "0"
			f.Unsigned = &v
		case "proc_user":
			f.UserLike = flt.Value
		case "hostname":
			f.HostLike = flt.Value
		case "rule_ids":
			f.RuleLike = flt.Value
		case "status":
			f.Status = []domain.AlertStatus{domain.AlertStatus(flt.Value)}
		}
	}

	items, total, err := s.repos.Alerts.List(ctx, f)
	if err != nil {
		return nil, err
	}

	return &HuntResult{
		Query:   q,
		Total:   total,
		Alerts:  items,
		Elapsed: time.Now(),
	}, nil
}

// HuntResult 是自然语言查询的结果。
type HuntResult struct {
	Query  *ai.Query        `json:"query"`
	Total  int              `json:"total"`
	Alerts []domain.Alert   `json:"alerts"`
	Elapsed time.Time       `json:"elapsed"`
}

// Stats 返回引擎统计。
func (s *AIService) Stats() ai.Stats { return s.eng.Stats() }

// Engine 暴露引擎给上层（用于配置变更等场景）。
func (s *AIService) Engine() *ai.Engine { return s.eng }

// buildInput 把领域告警转成有编号证据链的推理输入。
func (s *AIService) buildInput(ctx context.Context, a *domain.Alert) (*ai.TriageInput, error) {
	in := &ai.TriageInput{
		AlertID:     a.ID,
		Title:       a.Title,
		Summary:     a.Summary,
		Score:       a.Score,
		Verdict:     string(a.Verdict),
		Severity:    string(a.Severity),
		ProcessName: a.ProcessName,
		ImagePath:   a.ImagePath,
		CmdLine:     a.CmdLine,
		User:        a.ProcUser,
		Hash:        a.HashSHA256,
		Signed:      a.Signed,
		Signer:      a.Signer,
		RuleIDs:     a.RuleIDs,
		MITRE:       a.MITRE,
		OccurredAt:  a.OccurredAt,
		Host: ai.HostContext{
			Hostname: a.Hostname,
			OS:       "-",
		},
	}

	// ---- 证据编号：按层次优先级排序，保证同一告警每次编号一致 ----
	//
	// 顺序刻意是"越硬的证据越靠前"，因为模型和人都更容易把 E1 当成主要依据。
	order := map[string]int{
		"static": 0, "rule": 1, "persist": 2, "behavior": 3, "lineage": 4, "keyword": 5,
	}
	ev := a.Evidence.Signals
	ranked := make([]model.Signal, len(ev))
	copy(ranked, ev)
	for i := 1; i < len(ranked); i++ {
		for j := i; j > 0; j-- {
			ri, _ := order[ranked[j].Layer]
			rj, _ := order[ranked[j-1].Layer]
			if ri < rj {
				ranked[j], ranked[j-1] = ranked[j-1], ranked[j]
			}
		}
	}

	for i, sig := range ranked {
		in.Evidence = append(in.Evidence, ai.EvidenceItem{
			ID:    fmt.Sprintf("E%d", i+1),
			Layer: sig.Layer,
			Name:  sig.Name,
			Score: sig.Score,
			// Detail 里可能带着命令行片段，属于攻击者可控内容
			Detail: sig.Note,
			Trust:  ai.Untrusted,
			MITRE:  sig.MITRE,
		})
	}

	// ---- 血缘链 ----
	for _, anc := range a.Evidence.Ancestry {
		in.Ancestry = append(in.Ancestry, ai.AncestorItem{
			PID: anc.PID, Name: anc.Name, Path: anc.Path,
		})
		if len(in.Ancestry) >= 5 {
			break // 更远的祖先对判断帮助有限，却会显著拉长提示
		}
	}

	// ---- 主机上下文 ----
	if ag, err := s.repos.Agents.ByID(ctx, a.AgentID); err == nil && ag != nil {
		in.Host.OS = ag.OSVersion
	}
	if cnt, err := s.repos.Alerts.CountOpenByAgent(ctx); err == nil {
		in.Host.RecentAlertCount = cnt[a.AgentID]
	}
	// BaselineSamples 暂不填充：探针心跳里虽有 Samples 字段，但未落库。
	// 保持 0 是安全的——启发式只在"已知且样本不足"时才下调置信度。

	return in, nil
}

func atoiSafe(s string) (int, bool) {
	n := 0
	if s == "" {
		return 0, false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0, false
		}
		n = n*10 + int(r-'0')
		if n > 1_000_000 {
			return 0, false
		}
	}
	return n, true
}
