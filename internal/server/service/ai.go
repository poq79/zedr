package service

import (
	"context"
	"encoding/json"
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
	osVersion := ""
	if ag, err := s.repos.Agents.ByID(ctx, a.AgentID); err == nil && ag != nil {
		in.Host.OS = ag.OSVersion
		osVersion = ag.OSVersion
	}
	if cnt, err := s.repos.Alerts.CountOpenByAgent(ctx); err == nil {
		in.Host.RecentAlertCount = cnt[a.AgentID]
	}
	// 资产摘要拼进 Host.OS：HostContext 是 internal/ai 的共享输入契约
	// （本层不得改共享包），OS 是其中唯一的自由文本行，提示词里恰好
	// 独占一行"系统: ..."，一行放得下且模型读起来是自然连贯的。
	// 摘要缺席时 Host.OS 保持终端心跳上报的 OS 版本，不受影响。
	if sum := s.assetSummary(ctx, a.AgentID, osVersion); sum != "" {
		in.Host.OS = sum
	}
	// BaselineSamples 暂不填充：探针心跳里虽有 Samples 字段，但未落库。
	// 保持 0 是安全的——启发式只在"已知且样本不足"时才下调置信度。

	return in, nil
}

// assetSummary 从资产清单拼一行资产摘要，形如
// "Windows 11 专业版 / 监听 35 / 服务 247 / 任务 18"，让模型知道
// "这台机器长什么样"——监听面大小与服务规模会改变可疑行为的解释方式
// （一台 247 个服务的服务器上多一个服务不稀奇，在一台裸机上就是信号）。
//
// 静默失败是硬约定：清单缺失、需要的节没采上来（探针采集失败时该节
// 整体缺席）、payload 为空/解析失败、解析出 0 条（真实 Windows 主机
// 不可能枚举到 0 个服务/任务，出现 0 只说明采集侧有别的毛病——给模型
// "服务 0" 只会诱导误判，比不给更糟）。以上任一情况都返回 "" 整体跳过，
// 绝不能因为资产上下文缺失让研判降级。
//
// 边界说明：这里只读仓储、只把计数拼进摘要字符串，payload 原文不进
// 提示词（清单内容是终端可控的，计数是标量、无从当注入载体），
// 模型依旧接触不到 SQL。
func (s *AIService) assetSummary(ctx context.Context, agentID, osVersion string) string {
	secs, err := s.repos.Inventory.ListByAgent(ctx, agentID)
	if err != nil || len(secs) == 0 {
		return ""
	}
	var listeners, services, tasks string
	for _, sec := range secs {
		switch sec.Name {
		case "listeners":
			listeners = sec.Payload
		case "services":
			services = sec.Payload
		case "tasks":
			tasks = sec.Payload
		}
	}
	if listeners == "" || services == "" || tasks == "" {
		return ""
	}

	// 只取计数不展开明细：json.RawMessage 让 payload 字段怎么漂移都不影响解析
	var lis struct {
		TCP []json.RawMessage `json:"tcp"`
		UDP []json.RawMessage `json:"udp"`
	}
	var svcList, taskList []json.RawMessage
	if json.Unmarshal([]byte(listeners), &lis) != nil ||
		json.Unmarshal([]byte(services), &svcList) != nil ||
		json.Unmarshal([]byte(tasks), &taskList) != nil {
		return ""
	}
	nSvc, nTask := len(svcList), len(taskList)
	if nSvc == 0 || nTask == 0 {
		return "" // 见函数头"解析出 0 条"的取舍
	}

	os := osVersion
	if os == "" {
		os = "-"
	}
	return fmt.Sprintf("%s / 监听 %d / 服务 %d / 任务 %d", os, len(lis.TCP)+len(lis.UDP), nSvc, nTask)
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
