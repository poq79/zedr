package api

import (
	"net/http"
	"strconv"
	"strings"

	"zedr/internal/platform/httpx"
	"zedr/internal/server/domain"
	"zedr/internal/server/service"
)

// 本文件是 AI 配置中心的控制器：模型槽位、连通性测试、提示词模板、技能包。
// 全部端点 admin-only：这些配置影响全局成本与判定行为，
// analyst 角色可以研判告警，但不应该能换模型、改提示词。

// auditAI 是配置类操作的审计便捷封装。
func (h *adminHandler) auditAI(r *http.Request, action, target, detail string) {
	if p := principal(r); p != nil {
		h.deps.Services.Audit.Record(r.Context(), p.UserID, p.Username, action, target, detail, httpx.ClientIP(r))
	}
}

// aiGetConfig 返回打码后的 AI 配置。
func (h *adminHandler) aiGetConfig(w http.ResponseWriter, r *http.Request) {
	view, err := h.deps.Services.AI.GetConfig(r.Context())
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, r, http.StatusOK, view)
}

// aiPutConfig 保存配置并热更新引擎。
func (h *adminHandler) aiPutConfig(w http.ResponseWriter, r *http.Request) {
	var req service.SaveAIConfigInput
	if err := httpx.DecodeJSON(r, &req); err != nil {
		httpx.WriteError(w, r, err)
		return
	}

	view, err := h.deps.Services.AI.SaveConfig(r.Context(), &req)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}

	// 审计里绝不落 API Key：只记改了哪些槽位与开关状态
	changed := make([]string, 0, len(req.Slots))
	for task, s := range req.Slots {
		state := "enable"
		if s.Enabled != nil && !*s.Enabled {
			state = "disable"
		}
		changed = append(changed, task+"("+state+")")
	}
	h.auditAI(r, "ai.config.update", "", "slots="+strings.Join(changed, ","))
	httpx.WriteJSON(w, r, http.StatusOK, view)
}

// aiTestConfig 对提交的接入配置做连通性拨测（不保存）。
func (h *adminHandler) aiTestConfig(w http.ResponseWriter, r *http.Request) {
	var req service.SaveSlotInput
	if err := httpx.DecodeJSON(r, &req); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	res, err := h.deps.Services.AI.TestConfig(r.Context(), &req)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	h.auditAI(r, "ai.config.test", req.BaseURL,
		"ok="+strconv.FormatBool(res.OK)+",latency_ms="+strconv.FormatInt(res.LatencyMs, 10))
	httpx.WriteJSON(w, r, http.StatusOK, res)
}

// aiGetPrompts 返回全部任务的提示词模板（含历史版本）。
func (h *adminHandler) aiGetPrompts(w http.ResponseWriter, r *http.Request) {
	out := map[string]any{}
	for _, task := range service.PromptTasks {
		p, err := h.deps.Services.AI.GetPrompt(r.Context(), task)
		if err != nil {
			httpx.WriteError(w, r, err)
			return
		}
		out[task] = p
	}
	httpx.WriteJSON(w, r, http.StatusOK, out)
}

// aiPutPrompt 保存某任务的提示词覆盖。
func (h *adminHandler) aiPutPrompt(w http.ResponseWriter, r *http.Request) {
	task := r.PathValue("task")
	var req struct {
		Content string `json:"content"`
	}
	if err := httpx.DecodeJSON(r, &req); err != nil {
		httpx.WriteError(w, r, err)
		return
	}

	ver, err := h.deps.Services.AI.SavePrompt(r.Context(), task, req.Content, actorName(r))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	h.auditAI(r, "ai.prompt.update", task, "version="+strconv.Itoa(ver))
	httpx.WriteJSON(w, r, http.StatusOK, map[string]any{"version": ver})
}

// aiRollbackPrompt 回滚到指定版本。
func (h *adminHandler) aiRollbackPrompt(w http.ResponseWriter, r *http.Request) {
	task := r.PathValue("task")
	var req struct {
		Version int `json:"version"`
	}
	if err := httpx.DecodeJSON(r, &req); err != nil {
		httpx.WriteError(w, r, err)
		return
	}

	ver, err := h.deps.Services.AI.RollbackPrompt(r.Context(), task, req.Version, actorName(r))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	h.auditAI(r, "ai.prompt.rollback", task, "from="+strconv.Itoa(req.Version)+",to="+strconv.Itoa(ver))
	httpx.WriteJSON(w, r, http.StatusOK, map[string]any{"version": ver})
}

// aiListSkills 技能包清单。
func (h *adminHandler) aiListSkills(w http.ResponseWriter, r *http.Request) {
	list, err := h.deps.Services.AI.ListSkills(r.Context())
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, r, http.StatusOK, list)
}

// aiUpsertSkill 新建或更新技能包（body 带 id 即更新）。
func (h *adminHandler) aiUpsertSkill(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID      string `json:"id"`
		Task    string `json:"task"`
		Name    string `json:"name"`
		Content string `json:"content"`
		Enabled bool   `json:"enabled"`
		Sort    int    `json:"sort"`
	}
	if err := httpx.DecodeJSON(r, &req); err != nil {
		httpx.WriteError(w, r, err)
		return
	}

	in := &domain.AISkill{
		ID: req.ID, Task: domain.AISkillTask(req.Task), Name: req.Name,
		Content: req.Content, Enabled: req.Enabled, Sort: req.Sort,
	}
	sk, err := h.deps.Services.AI.UpsertSkill(r.Context(), in, actorName(r))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	action := "ai.skill.create"
	if req.ID != "" {
		action = "ai.skill.update"
	}
	h.auditAI(r, action, sk.Name, "task="+req.Task)
	httpx.WriteJSON(w, r, http.StatusOK, sk)
}

// aiDeleteSkill 删除技能包。
func (h *adminHandler) aiDeleteSkill(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := h.deps.Services.AI.DeleteSkill(r.Context(), id); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	h.auditAI(r, "ai.skill.delete", id, "")
	httpx.WriteJSON(w, r, http.StatusOK, map[string]any{"deleted": true})
}

// aiRunEval 运行一次 AI 质量评测（heuristic 结构自检 / llm 质量评测）。
func (h *adminHandler) aiRunEval(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Mode string `json:"mode"`
	}
	if err := httpx.DecodeJSON(r, &req); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	rr, err := h.deps.Services.AI.RunEval(r.Context(), req.Mode)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	h.auditAI(r, "ai.eval.run", req.Mode,
		"passed="+strconv.FormatBool(rr.Passed)+",accuracy="+strconv.FormatFloat(rr.Metrics.Accuracy, 'f', 3, 64))
	httpx.WriteJSON(w, r, http.StatusOK, rr)
}

// aiLastEval 返回最近一次评测结果（从未运行过时为 null）。
func (h *adminHandler) aiLastEval(w http.ResponseWriter, r *http.Request) {
	rr, err := h.deps.Services.AI.LastEval(r.Context())
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, r, http.StatusOK, rr)
}

// actorName 取操作者（审计用）；principal 缺失时给占位。
func actorName(r *http.Request) string {
	if p := principal(r); p != nil {
		return p.Username
	}
	return "-"
}
