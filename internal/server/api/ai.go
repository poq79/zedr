package api

import (
	"net/http"

	"zedr/internal/platform/apperr"
	"zedr/internal/platform/httpx"
)

// triageAlert 对单条告警做 AI 研判。
//
// 注意这是 POST 而非 GET：一次研判可能触发一次模型调用（有成本、有时间开销），
// 不适合被浏览器预取、也不适合被当作幂等读取缓存。
func (h *adminHandler) triageAlert(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		httpx.WriteError(w, r, apperr.Invalid("告警 ID 不能为空"))
		return
	}

	res, err := h.deps.Services.AI.Triage(r.Context(), id)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}

	if p := principal(r); p != nil {
		h.deps.Services.Audit.Record(r.Context(), p.UserID, p.Username, "alert.triage", id,
			"verdict="+res.Verdict+",engine="+res.Engine, httpx.ClientIP(r))
	}
	httpx.WriteJSON(w, r, http.StatusOK, res)
}

// hunt 把自然语言查询翻译成受控条件并返回结果。
func (h *adminHandler) hunt(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Query string `json:"query"`
	}
	if err := httpx.DecodeJSON(r, &req); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if len(req.Query) > 500 {
		httpx.WriteError(w, r, apperr.Invalid("查询语句过长（上限 500 字）"))
		return
	}

	res, err := h.deps.Services.AI.Hunt(r.Context(), req.Query)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}

	if p := principal(r); p != nil {
		h.deps.Services.Audit.Record(r.Context(), p.UserID, p.Username, "ai.hunt", "",
			req.Query, httpx.ClientIP(r))
	}
	httpx.WriteJSON(w, r, http.StatusOK, res)
}

// aiStats 返回分析引擎的可用性与用量。
//
// 前端需要它来决定是否展示"AI 研判"入口——没有配置模型时该入口
// 依然可用（走确定性引擎），但要如实告知用户当前是哪种引擎。
func (h *adminHandler) aiStats(w http.ResponseWriter, r *http.Request) {
	st := h.deps.Services.AI.Stats()
	httpx.WriteJSON(w, r, http.StatusOK, map[string]any{
		"stats":   st,
		"enabled": st.Engine == "llm",
	})
}
