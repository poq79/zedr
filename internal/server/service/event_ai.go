package service

import (
	"context"
	"encoding/json"
	"time"

	"zedr/internal/ai"
	"zedr/internal/model"
	"zedr/internal/platform/apperr"
	"zedr/internal/server/domain"
)

// 事件级 AI 检测：把同一事件内的告警按时间线交给叙事引擎，
// 产出跨告警的攻击链叙事（阶段 / 风险分 / 缺失环节 / 建议）。
//
// 缓存策略：settings KV（key = incident_narrative_<id>），随事件 LastSeen
// 变化失效——事件新增告警后旧叙事自动过时，GET 时发现 LastSeen 不一致
// 就返回 nil（提示前端重新生成），而不是把陈旧结论当真。
//
// 与单告警研判共用 AIService（同一引擎引用，配置热更新天然一致）。

const incidentNarrativeKeyPrefix = "incident_narrative_"

// incidentNarrativeMaxAlerts 是喂给叙事引擎的时间线上限：
// 40 条足够覆盖典型攻击链，再多只会拉长提示词并稀释阶段划分。
const incidentNarrativeMaxAlerts = 40

// IncidentNarrativeView 是事件叙事的 API 视图（时间线 + 结论 + 元信息）。
type IncidentNarrativeView struct {
	IncidentID string                `json:"incident_id"`
	Hostname   string                `json:"hostname"`
	AlertTotal int                   `json:"alert_total"`
	Timeline   []ai.IncidentAlert    `json:"timeline"`
	Narrative  *ai.IncidentNarrative `json:"narrative"`
	// IncidentLastSeen 是生成叙事时事件的最后观测时间——
	// 与当前事件不一致说明叙事已过时（新告警加入了同一事件）。
	IncidentLastSeen time.Time `json:"incident_last_seen"`
	GeneratedAt      time.Time `json:"generated_at"`
}

// NarrateIncident 生成（或重新生成）某个事件的 AI 攻击链叙事。
func (s *AIService) NarrateIncident(ctx context.Context, incidentID string) (*IncidentNarrativeView, error) {
	inc, err := s.repos.Incidents.ByID(ctx, incidentID)
	if err != nil {
		return nil, err
	}
	if inc == nil {
		return nil, apperr.NotFound("事件")
	}

	in, err := s.buildIncidentInput(ctx, inc)
	if err != nil {
		return nil, err
	}
	n := s.eng.NarrateIncident(ctx, in)

	view := &IncidentNarrativeView{
		IncidentID:       inc.ID,
		Hostname:         inc.Hostname,
		AlertTotal:       in.AlertTotal,
		Timeline:         in.Alerts,
		Narrative:        n,
		IncidentLastSeen: inc.LastSeen,
		GeneratedAt:      time.Now(),
	}
	// 持久化最近一次叙事：重启后 GET 仍可看到（快照，非流水）
	if raw, err := json.Marshal(view); err == nil {
		_ = s.repos.AIConfig.SetSetting(ctx, incidentNarrativeKeyPrefix+inc.ID, string(raw))
	}
	if s.log != nil {
		s.log.InfoContext(ctx, "ai_incident_narrated", "incident_id", inc.ID,
			"alerts", len(in.Alerts), "risk", n.RiskScore, "engine", n.Engine,
			"grounded", n.Grounded, "ignored_injection", n.UntrustedIgnored,
			"latency_ms", n.LatencyMs)
	}
	return view, nil
}

// GetIncidentNarrative 返回缓存的叙事；未生成过返回 (nil, nil)；
// 事件在叙事之后又新增了告警（LastSeen 变化）时同样返回 nil——
// 过时的攻击链叙事比没有叙事更危险。
func (s *AIService) GetIncidentNarrative(ctx context.Context, incidentID string) (*IncidentNarrativeView, error) {
	raw, ok, err := s.repos.AIConfig.GetSetting(ctx, incidentNarrativeKeyPrefix+incidentID)
	if err != nil || !ok || raw == "" {
		return nil, err
	}
	var view IncidentNarrativeView
	if json.Unmarshal([]byte(raw), &view) != nil {
		return nil, nil
	}
	if inc, err := s.repos.Incidents.ByID(ctx, incidentID); err == nil && inc != nil {
		if !inc.LastSeen.Equal(view.IncidentLastSeen) {
			return nil, nil // 已过时
		}
	}
	return &view, nil
}

// buildIncidentInput 把事件聚合成叙事输入（时间线 + 主机上下文）。
func (s *AIService) buildIncidentInput(ctx context.Context, inc *domain.Incident) (*ai.IncidentInput, error) {
	alerts, _, err := s.repos.Alerts.List(ctx, domain.AlertFilter{
		AgentID:  inc.AgentID,
		Page:     1,
		PageSize: 200,
		Sort:     "oldest",
	})
	if err != nil {
		return nil, err
	}

	// 事件窗口：告警创建时间落在 [FirstSeen, LastSeen] 附近。
	// 时间比较用 OccurredAt（采集侧时钟），窗口两侧各放宽 2 分钟
	// 吸收心跳批次的落库延迟。
	from := inc.FirstSeen.Add(-2 * time.Minute)
	to := inc.LastSeen.Add(2 * time.Minute)
	var timeline []ai.IncidentAlert
	for _, a := range alerts {
		ts := a.OccurredAt
		if ts.IsZero() {
			ts = a.CreatedAt
		}
		if ts.Before(from) || ts.After(to) {
			continue
		}
		timeline = append(timeline, ai.IncidentAlert{
			ID:          a.ID,
			Title:       a.Title,
			ProcessName: a.ProcessName,
			ImagePath:   a.ImagePath,
			CmdLine:     a.CmdLine,
			User:        a.ProcUser,
			Severity:    string(a.Severity),
			Verdict:     string(a.Verdict),
			Score:       a.Score,
			Signed:      a.Signed,
			Signer:      a.Signer,
			MITRE:       a.MITRE,
			RuleIDs:     a.RuleIDs,
			Layers:      signalLayers(a.Evidence.Signals),
			OccurredAt:  ts,
		})
	}
	if len(timeline) == 0 {
		// 极端情况：事件表与告警状态不同步（告警已被清理）。
		// 如实返回空时间线，让引擎产出"无证据"结论而不是编造。
		return &ai.IncidentInput{
			IncidentID: inc.ID, Hostname: inc.Hostname,
			FirstSeen: inc.FirstSeen, LastSeen: inc.LastSeen,
			PeakSeverity: string(inc.PeakSeverity), MaxScore: inc.MaxScore,
			AlertTotal: inc.AlertCount,
			Host:       ai.HostContext{Hostname: inc.Hostname, OS: "-"},
		}, nil
	}
	if len(timeline) > incidentNarrativeMaxAlerts {
		timeline = timeline[:incidentNarrativeMaxAlerts]
	}

	host := ai.HostContext{Hostname: inc.Hostname, OS: "-"}
	if ag, err := s.repos.Agents.ByID(ctx, inc.AgentID); err == nil && ag != nil {
		host.OS = ag.OSVersion
	}
	if sum := s.assetSummary(ctx, inc.AgentID, host.OS); sum != "" {
		host.OS = sum
	}

	return &ai.IncidentInput{
		IncidentID:   inc.ID,
		Hostname:     inc.Hostname,
		FirstSeen:    inc.FirstSeen,
		LastSeen:     inc.LastSeen,
		PeakSeverity: string(inc.PeakSeverity),
		MaxScore:     inc.MaxScore,
		AlertTotal:   inc.AlertCount,
		Alerts:       timeline,
		Host:         host,
	}, nil
}

// signalLayers 汇总一条告警命中的证据层（去重、保序）。
func signalLayers(signals []model.Signal) []string {
	seen := map[string]bool{}
	var out []string
	for _, sig := range signals {
		if sig.Layer == "" || seen[sig.Layer] {
			continue
		}
		seen[sig.Layer] = true
		out = append(out, sig.Layer)
	}
	return out
}
