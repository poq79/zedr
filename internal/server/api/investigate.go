package api

import (
	"errors"
	"net/http"

	"zedr/internal/platform/httpx"
)

// errInvestigationNotCached 表示该告警还没有已缓存的调查报告。
var errInvestigationNotCached = errors.New("该告警暂无调查报告，请先 POST 触发调查")

// investigateAlert 对一条告警执行确定性自动调查。
// 重复调用会重算并覆盖缓存（证据随时会变，重算永远新鲜）。
func (h *adminHandler) investigateAlert(w http.ResponseWriter, r *http.Request) {
	inv, err := h.deps.Services.AI.Investigate(r.Context(), r.PathValue("id"))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, r, http.StatusOK, inv)
}

// getInvestigation 返回缓存的调查报告（不重算；需要最新结果请 POST）。
func (h *adminHandler) getInvestigation(w http.ResponseWriter, r *http.Request) {
	inv := h.deps.Services.AI.CachedInvestigation(r.PathValue("id"))
	if inv == nil {
		httpx.WriteError(w, r, errInvestigationNotCached)
		return
	}
	httpx.WriteJSON(w, r, http.StatusOK, inv)
}
