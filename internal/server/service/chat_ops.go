package service

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"zedr/internal/ai"
	"zedr/internal/platform/apperr"
	"zedr/internal/platform/idgen"
	"zedr/internal/server/domain"
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

// VerdictLabel 把调查判定枚举映射成值班界面的中文。
// 队列里存有历史字符串（如旧版 "benign-需人工确认"），按关键词兜底。
func VerdictLabel(v string) string {
	switch v {
	case "malicious":
		return "恶意"
	case "suspicious":
		return "可疑"
	case "inconclusive":
		return "证据不足"
	case "benign":
		return "倾向误报"
	}
	if strings.Contains(v, "benign") {
		return "证据不足"
	}
	return v
}

// verdictAdvice 给出与判定配套的下一步建议（摘要文案的一部分）。
func verdictAdvice(v string) string {
	switch v {
	case "malicious":
		return "复核属实后请人工执行处置"
	case "suspicious":
		return "请人工复核告警详情后决定处置"
	case "inconclusive":
		return "现有证据不足以定性，请点开告警详情核对"
	default:
		return "无加重证据，可结合上下文后忽略"
	}
}

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
	// ReviewReason 是审批时的结案理由码（业界 closure reason codes）：
	// true_positive / known_benign / false_positive / duplicate /
	// test_exercise / other。空表示旧条目或未选。
	ReviewReason string `json:"review_reason,omitempty"`
	// Occurrences/LastAlertID/LastSeenAt 是爆发聚合记账：同主机同标题
	// 的 critical 爆发只留一条代表条目，计数与最新告警 ID 随爆发更新
	// （告警风暴时队列不再被同一条规则刷屏）。
	Occurrences int        `json:"occurrences,omitempty"`
	LastAlertID string     `json:"last_alert_id,omitempty"`
	LastSeenAt  *time.Time `json:"last_seen_at,omitempty"`
}

// OpsReviewReasons 是合法的结案理由码全集与值班界面的中文文案。
// 口径对齐业界 closure reason codes：真阳性要区分"已处置"与"确认良性"
// （运维操作/软件自启在很多产品里叫 benign true positive）——两者是
// 不同的降噪信号，混在一起会让后续调优失去依据。
var OpsReviewReasons = map[string]string{
	"true_positive":  "真阳性：确认攻击，转入人工处置",
	"known_benign":   "真实行为但确认良性（运维/软件自启等）",
	"false_positive": "误报：规则/阈值打错对象",
	"duplicate":      "重复告警（同类爆发的一条）",
	"test_exercise":  "测试或攻防演练产生",
	"other":          "其他（备注说明）",
}

func validReviewReason(r string) bool {
	if r == "" {
		return true
	}
	_, ok := OpsReviewReasons[r]
	return ok
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
	// 爆发聚合优先：同主机同标题已有待审条目时，只更新计数与最新
	// 告警指针，不再重跑调查——告警风暴时队列保持 1 条代表 + ×N 计数，
	// 也不再为每条重复告警付 4 次查询的调查成本。
	if s.tryAggregateOps(ctx, a) {
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
		Engine: "heuristic", CreatedAt: time.Now(), Status: "pending",
	}
	fillOpsFromInvestigation(item, inv)
	if err := s.enqueueOps(ctx, item); err != nil && s.log != nil {
		s.log.WarnContext(ctx, "ai_ops_enqueue_failed", "alert_id", alertID, "err", err)
	}
}

// tryAggregateOps 把一条 critical 告警聚合进已有的同 (主机,标题) 待审
// 条目。返回 true 表示已聚合（不需要新建条目）。
//
// 聚合是"代表条目"模型：调查结论属于首次调查的那条告警（同标题同
// 主机下结论一致），计数与 LastAlertID 指向最新触发——值班的人点
// "打开原告警"看到的是最新的那条，×N 计数告诉他这是一次爆发。
func (s *AIService) tryAggregateOps(ctx context.Context, a *domain.Alert) bool {
	opsQueueMu.Lock()
	defer opsQueueMu.Unlock()
	list, err := s.loadOpsQueue(ctx)
	if err != nil {
		return false
	}
	now := time.Now()
	for i := range list {
		it := &list[i]
		if it.Status != "pending" || it.Hostname != a.Hostname || it.Title != a.Title {
			continue
		}
		it.Occurrences++
		it.LastAlertID = a.ID
		it.LastSeenAt = &now
		if a.Score > it.Score {
			it.Score = a.Score
		}
		if err := s.saveOpsQueue(ctx, list); err != nil && s.log != nil {
			s.log.WarnContext(ctx, "ai_ops_aggregate_failed", "alert_id", a.ID, "err", err)
		}
		return true
	}
	return false
}

// fillOpsFromInvestigation 把调查报告的内容装进队列条目。
// AutoOps（建条目）与 ReevaluateOps（刷新旧条目）共用，保证两处口径一致。
// 摘要写人话：判定用中文 + 置信度 + 下一步建议——2026-11-06 复盘发现
// 旧摘要直接拼英文枚举（"…:suspicious,建议人工复核后处置"），值班的人
// 要自己翻译。
func fillOpsFromInvestigation(item *OpsItem, inv *Investigation) {
	item.Verdict = inv.VerdictSuggestion
	item.Confidence = inv.Confidence
	item.Summary = fmt.Sprintf("确定性五步调查：%s（置信 %.0f%%）——%s",
		VerdictLabel(inv.VerdictSuggestion), inv.Confidence*100, verdictAdvice(inv.VerdictSuggestion))
	item.Findings = nil
	item.Actions = nil
	for _, st := range inv.Steps {
		cites := st.Citations
		if len(cites) == 0 {
			cites = []string{"核查:" + item.AlertID}
		}
		item.Findings = append(item.Findings, ai.Reason{Text: st.Name + "：" + st.Finding, Citations: cites})
	}
	for _, ra := range inv.RecommendedActions {
		item.Actions = append(item.Actions, ai.Action{Type: ra.Action, Target: ra.Target, Detail: ra.Reason, RequiresApproval: true})
	}
}

// ReevaluateOps 用当前调查逻辑重评一条队列建议并刷新其判定/摘要/证据。
//
// 为什么需要：队列条目是入队时刻的快照，而调查逻辑会改进（如 2026-11-06
// 的打分重构）；旧条目带着旧结论躺在队列里，值班的人无从知道它已经
// 过期。重评不改变条目的审批状态与审批人记录。
func (s *AIService) ReevaluateOps(ctx context.Context, id string) (*OpsItem, error) {
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
		inv, err := s.Investigate(ctx, list[i].AlertID)
		if err != nil {
			return nil, err
		}
		fillOpsFromInvestigation(&list[i], inv)
		if err := s.saveOpsQueue(ctx, list); err != nil {
			return nil, err
		}
		out := list[i]
		return &out, nil
	}
	return nil, apperr.NotFound("建议")
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

// AllowlistSuggestionFor 根据告警生成加白建议（hash 优先，其次镜像路径）。
// 只读——真正的加白必须由人显式点按钮走既有 POST /allowlist（带加白
// 回收与审计），AI/队列永远不代执行降噪动作。
func (s *AIService) AllowlistSuggestionFor(ctx context.Context, alertID string) (string, string, bool) {
	a, err := s.repos.Alerts.ByID(ctx, alertID)
	if err != nil || a == nil {
		return "", "", false
	}
	if len(a.HashSHA256) == 64 {
		return "hash", a.HashSHA256, true
	}
	if a.ImagePath != "" {
		return "path", a.ImagePath, true
	}
	return "", "", false
}

// ReviewOps 审批一条建议：approved（认可建议，执行仍需人工走指令）/
// dismissed（忽略，可附结案理由）。本函数只改队列状态，绝不触发任何处置。
func (s *AIService) ReviewOps(ctx context.Context, id, action, by, reason string) (*OpsItem, error) {
	if action != "approve" && action != "dismiss" {
		return nil, apperr.Invalid("action 只能是 approve 或 dismiss")
	}
	if !validReviewReason(reason) {
		return nil, apperr.Invalid("结案理由码非法")
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
		list[i].ReviewReason = reason
		if err := s.saveOpsQueue(ctx, list); err != nil {
			return nil, err
		}
		out := list[i]
		return &out, nil
	}
	return nil, apperr.NotFound("建议")
}

// BulkReviewOps 批量审批：告警爆发场景下逐条点审批不现实。
// 只处理 pending 条目，返回成功列表与跳过数（已处理的跳过不算错误）。
// 同样绝不触发任何处置动作。
func (s *AIService) BulkReviewOps(ctx context.Context, ids []string, action, by, reason string) ([]OpsItem, int, error) {
	if action != "approve" && action != "dismiss" {
		return nil, 0, apperr.Invalid("action 只能是 approve 或 dismiss")
	}
	if !validReviewReason(reason) {
		return nil, 0, apperr.Invalid("结案理由码非法")
	}
	if len(ids) == 0 {
		return nil, 0, apperr.Invalid("未选择任何建议")
	}
	if len(ids) > 100 {
		return nil, 0, apperr.Invalid("单次批量上限 100 条")
	}
	want := make(map[string]bool, len(ids))
	for _, id := range ids {
		want[id] = true
	}
	opsQueueMu.Lock()
	defer opsQueueMu.Unlock()
	list, err := s.loadOpsQueue(ctx)
	if err != nil {
		return nil, 0, err
	}
	var updated []OpsItem
	skipped := 0
	now := time.Now()
	for i := range list {
		if !want[list[i].ID] || list[i].Status != "pending" {
			continue
		}
		if action == "approve" {
			list[i].Status = "approved"
		} else {
			list[i].Status = "dismissed"
		}
		list[i].ReviewedBy = by
		list[i].ReviewedAt = &now
		list[i].ReviewReason = reason
		out := list[i]
		updated = append(updated, out)
	}
	skipped = len(ids) - len(updated)
	if len(updated) > 0 {
		if err := s.saveOpsQueue(ctx, list); err != nil {
			return nil, 0, err
		}
	}
	return updated, skipped, nil
}
