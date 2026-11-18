package api

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"zedr/internal/ai"
	"zedr/internal/platform/apperr"
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

// getCachedInvestigation 返回缓存的关联核查报告（不重算，无缓存返回 null）。
// 值班队列的自动调查/重评估与告警抽屉「关联核查」Tab 共用同一份缓存——
// 队列跑过的告警，抽屉打开即有结果，不必再从空态开始。
func (h *adminHandler) getCachedInvestigation(w http.ResponseWriter, r *http.Request) {
	inv := h.deps.Services.AI.CachedInvestigation(r.PathValue("id"))
	httpx.WriteJSON(w, r, http.StatusOK, inv)
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
		Question string   `json:"question"`
		History  []aiTurn `json:"history"`
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

// aiChatStream 是 AI 助手的流式对话端点（SSE）。
//
// 用 POST + fetch 流读取而不是 EventSource：事件带 Authorization 头
// 鉴权（EventSource 不能带自定义头，告警流为此走一次性票据，这里
// 没必要复用那套）。响应头 X-Accel-Buffering:no 防代理缓冲。
// 非流式 /api/v1/ai/chat 保留：老前端兼容 + 流式不可用时的回退。
func (h *adminHandler) aiChatStream(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Question string   `json:"question"`
		Scope    string   `json:"scope"`
		History  []aiTurn `json:"history"`
	}
	if err := httpx.DecodeJSON(r, &req); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		httpx.WriteError(w, r, apperr.Unavailable("当前服务端不支持流式响应"))
		return
	}
	hdr := w.Header()
	hdr.Set("Content-Type", "text/event-stream; charset=utf-8")
	hdr.Set("Cache-Control", "no-cache, no-transform")
	hdr.Set("X-Accel-Buffering", "no")
	// 长推理流会被全局 WriteTimeout(60s) 硬切：模型思考+长答案轻松超过
	// 60s，答案在半路被掐。清写截止，寿命由 r.Context()（客户端断开）
	// 与 writeErr 出口管理。
	httpx.DisableWriteTimeout(w)
	w.WriteHeader(http.StatusOK)

	hist := make([]ai.ChatTurn, 0, len(req.History))
	for _, t := range req.History {
		hist = append(hist, ai.ChatTurn{Role: t.Role, Content: t.Content})
	}
	var writeErr once
	emit := func(ev ai.ChatStreamEvent) {
		if writeErr.done {
			return
		}
		payload, err := marshalJSON(ev)
		if err != nil {
			return
		}
		frame := "event: " + ev.Type + "\ndata: " + string(payload) + "\n\n"
		if _, werr := w.Write([]byte(frame)); werr != nil {
			writeErr.done = true // 客户端断开（停止生成），停止写出
			return
		}
		flusher.Flush()
	}
	h.deps.Services.AI.ChatStream(r.Context(), req.Question, req.Scope, hist, emit)
	if p := principal(r); p != nil && !writeErr.done {
		h.deps.Services.Audit.Record(r.Context(), p.UserID, p.Username, "ai.chat.stream", "",
			"question_len="+itoa(len(req.Question)), httpx.ClientIP(r))
	}
}

// once 是单布尔栅栏（aiChatStream 专用）：客户端断开后停止写 SSE。
type once struct{ done bool }

// aiOpsQueue 返回 AI 值班队列（方向 C）。
func (h *adminHandler) aiOpsQueue(w http.ResponseWriter, r *http.Request) {
	list, err := h.deps.Services.AI.ListOpsQueue(r.Context())
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, r, http.StatusOK, list)
}

// aiBriefing 返回今日值班简报（纯确定性聚合，零模型调用——
// 简报的可靠性优先于聪明；AI 解读由用户点击"追问 AI"进作用域对话）。
func (h *adminHandler) aiBriefing(w http.ResponseWriter, r *http.Request) {
	hours := 24
	if v, err := strconv.Atoi(r.URL.Query().Get("hours")); err == nil && v > 0 && v <= 168 {
		hours = v
	}
	b, err := h.deps.Services.AI.DailyBriefing(r.Context(), hours)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, r, http.StatusOK, b)
}

// aiQualityReport 返回研判质量对账（AI 结论 × 分析师处置）。
// 这是 AI 能力迭代的方向盘：没有一致率/误报/漏报数据，调提示词
// 和阈值都是盲调。
func (h *adminHandler) aiQualityReport(w http.ResponseWriter, r *http.Request) {
	rep, err := h.deps.Services.AI.QualityReport(r.Context())
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, r, http.StatusOK, rep)
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
