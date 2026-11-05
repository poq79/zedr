package api

import (
	"errors"
	"fmt"
	"net/http"

	"zedr/internal/ai"
	"zedr/internal/platform/httpx"
)

// errAgentNotCached 表示该告警还没有缓存的 Agent 调查报告。
var errAgentNotCached = errors.New("该告警暂无 Agent 调查报告，请先 POST 触发")

// agentInvestigate 对一条告警运行 Agentic 调查（模型自主调用只读工具）。
// 未配置模型时自动回退确定性五步（报告结构一致，degraded 标注原因）。
func (h *adminHandler) agentInvestigate(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	rep, err := h.deps.Services.AI.AgentInvestigate(r.Context(), id)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if p := principal(r); p != nil {
		h.deps.Services.Audit.Record(r.Context(), p.UserID, p.Username, "alert.agent_investigate", id,
			"engine="+rep.Engine+",tools="+itoa(rep.ToolCalls)+",degraded="+boolText(rep.Degraded), httpx.ClientIP(r))
	}
	httpx.WriteJSON(w, r, http.StatusOK, rep)
}

// getAgentInvestigation 返回缓存的 Agent 报告（不重算）。
func (h *adminHandler) getAgentInvestigation(w http.ResponseWriter, r *http.Request) {
	rep := h.deps.Services.AI.CachedAgentReport(r.PathValue("id"))
	if rep == nil {
		httpx.WriteError(w, r, errAgentNotCached)
		return
	}
	httpx.WriteJSON(w, r, http.StatusOK, rep)
}

// itoa 复用 agent.go 里的包级实现（int 十进制）。

func boolText(v bool) string {
	if v {
		return "true"
	}
	return "false"
}

// aiChat 是管理台 AI 助手的对话端点（方向 B）。
func (h *adminHandler) aiChat(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Question string      `json:"question"`
		History  []aiTurn    `json:"history"`
	}
	if err := httpx.DecodeJSON(r, &req); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	hist := make([]ai.ChatTurn, 0, len(req.History))
	for _, t := range req.History {
		hist = append(hist, ai.ChatTurn{Role: t.Role, Content: t.Content})
	}
	rep, err := h.deps.Services.AI.Chat(r.Context(), req.Question, hist)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if p := principal(r); p != nil {
		h.deps.Services.Audit.Record(r.Context(), p.UserID, p.Username, "ai.chat", "",
			"engine="+rep.Engine+",tools="+itoa(rep.ToolCalls)+",degraded="+boolText(rep.Degraded), httpx.ClientIP(r))
	}
	httpx.WriteJSON(w, r, http.StatusOK, rep)
}

type aiTurn struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// aiOpsQueue 返回 AI 值班队列（方向 C）。
func (h *adminHandler) aiOpsQueue(w http.ResponseWriter, r *http.Request) {
	list, err := h.deps.Services.AI.ListOpsQueue(r.Context())
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, r, http.StatusOK, list)
}

// aiOpsReview 审批一条值班建议（只改队列状态，不触发任何处置）。
// 结案理由可选；理由为误报/确认良性且告警可加白时，回传加白建议
// （只建议不执行——真正的加白由人显式调 POST /allowlist）。
func (h *adminHandler) aiOpsReview(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Action string `json:"action"`
		Reason string `json:"reason"`
	}
	if err := httpx.DecodeJSON(r, &req); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	item, err := h.deps.Services.AI.ReviewOps(r.Context(), r.PathValue("id"), req.Action, actorName(r), req.Reason)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if p := principal(r); p != nil {
		h.deps.Services.Audit.Record(r.Context(), p.UserID, p.Username, "ai.ops.review", item.ID,
			"alert="+item.AlertID+",action="+req.Action+",reason="+req.Reason, httpx.ClientIP(r))
	}
	resp := map[string]any{"item": item}
	if req.Action == "dismiss" && (req.Reason == "false_positive" || req.Reason == "known_benign") {
		if typ, val, ok := h.deps.Services.AI.AllowlistSuggestionFor(r.Context(), item.AlertID); ok {
			resp["allowlist_suggestion"] = map[string]string{"type": typ, "value": val, "reason": req.Reason}
		}
	}
	httpx.WriteJSON(w, r, http.StatusOK, resp)
}

// aiOpsBulkReview 批量审批：爆发场景下逐条点审批不现实。
// 只处理 pending；误报理由的加白建议按条聚合去重后回传。
func (h *adminHandler) aiOpsBulkReview(w http.ResponseWriter, r *http.Request) {
	var req struct {
		IDs    []string `json:"ids"`
		Action string   `json:"action"`
		Reason string   `json:"reason"`
	}
	if err := httpx.DecodeJSON(r, &req); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	updated, skipped, err := h.deps.Services.AI.BulkReviewOps(r.Context(), req.IDs, req.Action, actorName(r), req.Reason)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if p := principal(r); p != nil {
		h.deps.Services.Audit.Record(r.Context(), p.UserID, p.Username, "ai.ops.bulk_review", "",
			fmt.Sprintf("action=%s,reason=%s,count=%d,skipped=%d", req.Action, req.Reason, len(updated), skipped),
			httpx.ClientIP(r))
	}
	resp := map[string]any{"updated": updated, "skipped": skipped}
	if req.Action == "dismiss" && (req.Reason == "false_positive" || req.Reason == "known_benign") {
		seen := map[string]bool{}
		var suggestions []map[string]string
		for i := range updated {
			typ, val, ok := h.deps.Services.AI.AllowlistSuggestionFor(r.Context(), updated[i].AlertID)
			if !ok || seen[typ+"|"+val] {
				continue
			}
			seen[typ+"|"+val] = true
			suggestions = append(suggestions, map[string]string{"type": typ, "value": val, "reason": req.Reason})
		}
		resp["allowlist_suggestions"] = suggestions
	}
	httpx.WriteJSON(w, r, http.StatusOK, resp)
}

// aiOpsReevaluate 用当前调查逻辑重评一条队列建议（刷新判定/摘要/证据，
// 不改审批状态）。调查规则改进后旧条目靠它跟上，不再带着过期结论躺队列。
func (h *adminHandler) aiOpsReevaluate(w http.ResponseWriter, r *http.Request) {
	item, err := h.deps.Services.AI.ReevaluateOps(r.Context(), r.PathValue("id"))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if p := principal(r); p != nil {
		h.deps.Services.Audit.Record(r.Context(), p.UserID, p.Username, "ai.ops.reevaluate", item.ID,
			"alert="+item.AlertID+",verdict="+item.Verdict, httpx.ClientIP(r))
	}
	httpx.WriteJSON(w, r, http.StatusOK, item)
}
