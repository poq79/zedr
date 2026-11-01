package api

import (
	"net/http"

	"zedr/internal/platform/httpx"
)

// getHostChanges 返回主机的资产变更事件（inventory 层告警）。
// ?section= 可选过滤（7 节白名单），?limit= 默认 100、上限 200。
// 供主机详情页"变更历史"Tab 消费——主机详情页 API 契约见 docs/HOST-DETAIL-API.md。
func (h *adminHandler) getHostChanges(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit := clampInt(atoiDefault(q.Get("limit"), 100), 1, 200)
	items, err := h.deps.Services.Incident.GetHostChanges(
		r.Context(), r.PathValue("id"), q.Get("section"), limit)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, r, http.StatusOK, map[string]any{
		"items": items,
		"total": len(items),
	})
}
