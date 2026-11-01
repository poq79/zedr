package api

import (
	"net/http"

	"hostguard/internal/platform/httpx"
	"hostguard/internal/server/service"
)

// saveInventory 探针上报主机资产清单（分节、hash 幂等）。
// 终端身份来自 agentAuth 中间件注入的上下文，agent_id 不从请求体取。
func (h *agentHandler) saveInventory(w http.ResponseWriter, r *http.Request) {
	a := agentFrom(r.Context())
	var req struct {
		Sections []service.InventorySection `json:"sections"`
	}
	if err := httpx.DecodeJSON(r, &req); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	applied, err := h.deps.Services.Agent.SaveInventory(r.Context(), a.ID, req.Sections)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, r, http.StatusOK, map[string]any{"applied": applied})
}

// getHostInventory 管理台查询主机资产清单。
func (h *adminHandler) getHostInventory(w http.ResponseWriter, r *http.Request) {
	sections, err := h.deps.Services.Agent.GetInventory(r.Context(), r.PathValue("id"))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, r, http.StatusOK, map[string]any{
		"sections": sections, "total": len(sections),
	})
}
