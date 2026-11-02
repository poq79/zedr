package service

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"time"

	"zedr/internal/ai"
	"zedr/internal/platform/apperr"
	"zedr/internal/platform/idgen"
)

// ---------------- B：网页内 AI 助手（2026-11 方向 B） ----------------

// chatToolExec 把 MCP 工具执行器适配成 Agent 循环的 ToolExecutor。
type chatToolExec struct{ ex *MCPExecutor }

func (a chatToolExec) Execute(ctx context.Context, name string, args json.RawMessage) (string, error) {
	v, err := a.ex.Call(ctx, name, args)
	if err != nil {
		return "", err
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

// mcpToolsAsAgentTools 把对外工具定义复用为对话工具（同一白名单、同一纪律）。
func mcpToolsAsAgentTools() []ai.AgentTool {
	src := MCPTools()
	out := make([]ai.AgentTool, 0, len(src))
	for _, t := range src {
		out = append(out, ai.AgentTool{Name: t.Name, Description: t.Description, Parameters: t.InputSchema})
	}
	return out
}

// Chat 是管理台 AI 助手的对话入口。
// 未配置模型时诚实降级（不编造回答）；有模型时走与 Agent 调查同一循环。
func (s *AIService) Chat(ctx context.Context, question string, history []ai.ChatTurn) (*ai.ChatReport, error) {
	q := strings.TrimSpace(question)
	if q == "" {
		return nil, apperr.Invalid("问题不能为空")
	}
	if len(q) > 500 {
		return nil, apperr.Invalid("问题过长（上限 500 字）")
	}
	if len(history) > 12 {
		history = history[len(history)-12:]
	}
	if !s.eng.AgentAvailable() {
		return &ai.ChatReport{
			Engine: "none", Degraded: true,
			DegradedReason: "未配置模型服务：AI 助手需要模型才能对话；告警研判/狩猎/事件叙事等确定性能力不受影响",
		}, nil
	}
	return s.eng.AgentChat(ctx, q, history, mcpToolsAsAgentTools(), chatToolExec{ex: NewMCPExecutor(s)}), nil
}

// ---------------- C：AI 值班队列（2026-11 方向 C） ----------------

// 设计依据（2026-11 取证）：agentic 工作流应"只读/仅建议起步 + 人审批门 +
// 全链路审计"；审批请求要包含发生了什么/证据/建议动作/影响/置信度。
// 因此自动路径保持**确定性调查**（零 token、无风暴风险），产出建议进队列，
// 审批只改变队列状态、绝不自动执行处置（执行仍走既有指令铁律）。

const aiOpsQueueKey = "ai_ops_queue"

// OpsItem 是一条待审的 AI 值班建议。
type OpsItem struct {
	ID         string      `json:"id"`
	AlertID    string      `json:"alert_id"`
	Title      string      `json:"title"`
	Hostname   string      `json:"hostname"`
	Severity   string      `json:"severity"`
	Score      int         `json:"score"`
	Verdict    string      `json:"verdict"`
	Confidence float64     `json:"confidence"`
	Summary    string      `json:"summary"`
	Findings   []ai.Reason `json:"findings,omitempty"`
	Actions    []ai.Action `json:"actions,omitempty"`
	Engine     string      `json:"engine"`
	CreatedAt  time.Time   `json:"created_at"`
	Status     string      `json:"status"` // pending / approved / dismissed
	ReviewedBy string      `json:"reviewed_by,omitempty"`
	ReviewedAt *time.Time  `json:"reviewed_at,omitempty"`
}

var opsQueueMu sync.Mutex

// AutoOps 是 critical 告警的自动值班路径：确定性五步调查 → 建议入队。
// 刻意不做 LLM 自动调查：爆发时每条 critical 触发一次 agent 循环会烧穿预算，
// 值班队列的价值在"人来了有东西看"，不在"没有人也要自动烧钱"。
func (s *AIService) AutoOps(ctx context.Context, alertID string) {
	a, err := s.repos.Alerts.ByID(ctx, alertID)
	if err != nil || a == nil {
		return
	}
	inv, err := s.Investigate(ctx, alertID)
	if err != nil {
		if s.log != nil {
			s.log.WarnContext(ctx, "ai_auto_ops_failed", "alert_id", alertID, "err", err)
		}
		return
	}
	item := &OpsItem{
		ID: idgen.URLSafe(10), AlertID: a.ID, Title: a.Title, Hostname: a.Hostname,
		Severity: string(a.Severity), Score: a.Score,
		Verdict: inv.VerdictSuggestion, Confidence: inv.Confidence,
		Summary: "自动值班调查（确定性五步）：" + inv.VerdictSuggestion + "，建议人工复核后处置",
		Engine:  "heuristic", CreatedAt: time.Now(), Status: "pending",
	}
	for _, st := range inv.Steps {
		cites := st.Citations
		if len(cites) == 0 {
			cites = []string{"核查:" + a.ID}
		}
		item.Findings = append(item.Findings, ai.Reason{Text: st.Name + "：" + st.Finding, Citations: cites})
	}
	for _, ra := range inv.RecommendedActions {
		item.Actions = append(item.Actions, ai.Action{Type: ra.Action, Target: ra.Target, Detail: ra.Reason, RequiresApproval: true})
	}
	if err := s.enqueueOps(ctx, item); err != nil && s.log != nil {
		s.log.WarnContext(ctx, "ai_ops_enqueue_failed", "alert_id", alertID, "err", err)
	}
}

// enqueueOps 写队列：同告警去重、上限 50（丢最老）。
func (s *AIService) enqueueOps(ctx context.Context, item *OpsItem) error {
	opsQueueMu.Lock()
	defer opsQueueMu.Unlock()
	list, err := s.loadOpsQueue(ctx)
	if err != nil {
		return err
	}
	for _, it := range list {
		if it.AlertID == item.AlertID && it.Status == "pending" {
			return nil // 已有待审建议，不重复入队
		}
	}
	list = append([]OpsItem{*item}, list...)
	if len(list) > 50 {
		list = list[:50]
	}
	return s.saveOpsQueue(ctx, list)
}

func (s *AIService) loadOpsQueue(ctx context.Context) ([]OpsItem, error) {
	raw, ok, err := s.repos.AIConfig.GetSetting(ctx, aiOpsQueueKey)
	if err != nil || !ok || raw == "" {
		return nil, err
	}
	var list []OpsItem
	if json.Unmarshal([]byte(raw), &list) != nil {
		return nil, nil
	}
	return list, nil
}

func (s *AIService) saveOpsQueue(ctx context.Context, list []OpsItem) error {
	raw, err := json.Marshal(list)
	if err != nil {
		return err
	}
	return s.repos.AIConfig.SetSetting(ctx, aiOpsQueueKey, string(raw))
}

// ListOpsQueue 返回值班队列（新的在前）。
func (s *AIService) ListOpsQueue(ctx context.Context) ([]OpsItem, error) {
	opsQueueMu.Lock()
	defer opsQueueMu.Unlock()
	list, err := s.loadOpsQueue(ctx)
	if err != nil {
		return nil, err
	}
	if list == nil {
		list = []OpsItem{}
	}
	return list, nil
}

// ReviewOps 审批一条建议：approved（认可建议，执行仍需人工走指令）/ dismissed（忽略）。
// 本函数只改队列状态，绝不触发任何处置动作。
func (s *AIService) ReviewOps(ctx context.Context, id, action, by string) (*OpsItem, error) {
	if action != "approve" && action != "dismiss" {
		return nil, apperr.Invalid("action 只能是 approve 或 dismiss")
	}
	opsQueueMu.Lock()
	defer opsQueueMu.Unlock()
	list, err := s.loadOpsQueue(ctx)
	if err != nil {
		return nil, err
	}
	for i := range list {
		if list[i].ID != id {
			continue
		}
		if list[i].Status != "pending" {
			return nil, apperr.Conflict("该建议已处理")
		}
		now := time.Now()
		if action == "approve" {
			list[i].Status = "approved"
		} else {
			list[i].Status = "dismissed"
		}
		list[i].ReviewedBy = by
		list[i].ReviewedAt = &now
		if err := s.saveOpsQueue(ctx, list); err != nil {
			return nil, err
		}
		out := list[i]
		return &out, nil
	}
	return nil, apperr.NotFound("建议")
}
