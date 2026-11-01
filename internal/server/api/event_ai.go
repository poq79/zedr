package api

import (
	"net/http"
	"strconv"

	"zedr/internal/platform/apperr"
	"zedr/internal/platform/httpx"
)

// narrateIncident 生成（或重新生成）事件的 AI 攻击链叙事。
//
// POST 而非 GET：一次叙事可能触发模型调用（有成本/耗时），
// 与单告警研判同口径，不给幂等读缓存留错误暗示。
func (h *adminHandler) narrateIncident(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		httpx.WriteError(w, r, apperr.Invalid("事件 ID 不能为空"))
		return
	}
	view, err := h.deps.Services.AI.NarrateIncident(r.Context(), id)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if p := principal(r); p != nil {
		h.deps.Services.Audit.Record(r.Context(), p.UserID, p.Username, "incident.narrate", id,
			"risk="+strconv.Itoa(view.Narrative.RiskScore)+",engine="+view.Narrative.Engine, httpx.ClientIP(r))
	}
	httpx.WriteJSON(w, r, http.StatusOK, view)
}

// getIncidentNarrative 返回最近一次攻击链叙事（无缓存或已过时返回 null）。
func (h *adminHandler) getIncidentNarrative(w http.ResponseWriter, r *http.Request) {
	view, err := h.deps.Services.AI.GetIncidentNarrative(r.Context(), r.PathValue("id"))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, r, http.StatusOK, view)
}
