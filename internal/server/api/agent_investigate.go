package api

import (
	"errors"
	"net/http"

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
