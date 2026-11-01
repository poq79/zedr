package api

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"hostguard/internal/platform/httpx"
	"hostguard/internal/server/auth"
	"hostguard/internal/server/domain"
)

type adminHandler struct{ deps Deps }

func principal(r *http.Request) *auth.Principal {
	p, _ := auth.FromContext(r.Context())
	return p
}

func pageResp(items any, total, page, size int) map[string]any {
	return map[string]any{
		"items":     items,
		"total":     total,
		"page":      page,
		"page_size": size,
	}
}

// ---------------------------------------------------------------- 会话

func (h *adminHandler) me(w http.ResponseWriter, r *http.Request) {
	p := principal(r)
	httpx.WriteJSON(w, r, http.StatusOK, map[string]any{
		"id":       p.UserID,
		"username": p.Username,
		"role":     string(p.Role),
	})
}

// ---------------------------------------------------------------- 仪表盘

func (h *adminHandler) dashboard(w http.ResponseWriter, r *http.Request) {
	sum, err := h.deps.Services.Stats.Dashboard(r.Context(), 24*time.Hour, time.Hour)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, r, http.StatusOK, sum)
}

// ---------------------------------------------------------------- 告警

func (h *adminHandler) listAlerts(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := domain.AlertFilter{
		AgentID: q.Get("agent_id"),
		Query:   q.Get("q"),
		Sort:    q.Get("sort"),
		Page:     clampInt(atoiDefault(q.Get("page"), 1), 1, 10000),
		PageSize: clampInt(atoiDefault(q.Get("page_size"), 20), 1, 200),
	}
	for _, s := range splitParam(q.Get("status")) {
		st := domain.AlertStatus(s)
		if st.Valid() {
			f.Status = append(f.Status, st)
		}
	}
	for _, s := range splitParam(q.Get("severity")) {
		sv := domain.Severity(s)
		if sv.Valid() {
			f.Severity = append(f.Severity, sv)
		}
	}
	for _, s := range splitParam(q.Get("verdict")) {
		v := domain.Verdict(s)
		if v.Valid() {
			f.Verdict = append(f.Verdict, v)
		}
	}

	items, total, err := h.deps.Services.Alert.List(r.Context(), f)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	f.Normalize()
	httpx.WriteJSON(w, r, http.StatusOK, pageResp(items, total, f.Page, f.PageSize))
}

func (h *adminHandler) getAlert(w http.ResponseWriter, r *http.Request) {
	a, err := h.deps.Services.Alert.Get(r.Context(), r.PathValue("id"))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, r, http.StatusOK, a)
}

type alertStatusReq struct {
	Status string `json:"status"`
	Note   string `json:"note"`
}

func (h *adminHandler) updateAlertStatus(w http.ResponseWriter, r *http.Request) {
	p := principal(r)
	var req alertStatusReq
	if err := httpx.DecodeJSON(r, &req); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	id := r.PathValue("id")
	if err := h.deps.Services.Alert.UpdateStatus(r.Context(), id,
		domain.AlertStatus(req.Status), p.Username, req.Note); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	h.deps.Services.Audit.Record(r.Context(), p.UserID, p.Username, "alert.status",
		id, req.Status+" "+req.Note, httpx.ClientIP(r))
	httpx.WriteNoContent(w)
}

// bulkStatusReq 是批量处置的请求体。
type bulkStatusReq struct {
	IDs    []string `json:"ids"`
	Status string   `json:"status"`
	Note   string   `json:"note"`
}

// bulkUpdateStatus 批量处置：一条审计记录覆盖整批操作。
func (h *adminHandler) bulkUpdateStatus(w http.ResponseWriter, r *http.Request) {
	p := principal(r)
	var req bulkStatusReq
	if err := httpx.DecodeJSON(r, &req); err != nil {
		httpx.WriteError(w, r, err)
		return
	}

	updated, failed, err := h.deps.Services.Alert.BulkUpdateStatus(r.Context(),
		req.IDs, domain.AlertStatus(req.Status), p.Username, req.Note)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}

	h.deps.Services.Audit.Record(r.Context(), p.UserID, p.Username, "alert.bulk_status",
		fmt.Sprintf("%d ids", len(req.IDs)),
		fmt.Sprintf("status=%s updated=%d failed=%d note=%s",
			req.Status, len(updated), len(failed), req.Note),
		httpx.ClientIP(r))

	httpx.WriteJSON(w, r, http.StatusOK, map[string]any{
		"updated": updated,
		"failed":  failed,
	})
}

// ---------------------------------------------------------------- 主机

func (h *adminHandler) listHosts(w http.ResponseWriter, r *http.Request) {
	agents, err := h.deps.Services.Agent.List(r.Context())
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	// 时钟偏移是运行时值（不落库），在这里合入响应
	skews := h.deps.Services.Agent.SkewMap()
	for i := range agents {
		if v, ok := skews[agents[i].ID]; ok {
			agents[i].ClockSkewMS = v
		}
	}
	httpx.WriteJSON(w, r, http.StatusOK, map[string]any{"items": agents, "total": len(agents)})
}

func (h *adminHandler) getHost(w http.ResponseWriter, r *http.Request) {
	a, err := h.deps.Services.Agent.Get(r.Context(), r.PathValue("id"))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	// 附带该主机最近告警，便于详情页联动
	alerts, total, err := h.deps.Services.Alert.List(r.Context(), domain.AlertFilter{
		AgentID: a.ID, Page: 1, PageSize: 20,
	})
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, r, http.StatusOK, map[string]any{
		"agent": a, "alerts": alerts, "alert_total": total,
	})
}

func (h *adminHandler) deleteHost(w http.ResponseWriter, r *http.Request) {
	p := principal(r)
	id := r.PathValue("id")
	if err := h.deps.Services.Agent.Delete(r.Context(), id); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	h.deps.Services.Audit.Record(r.Context(), p.UserID, p.Username, "host.delete", id, "", httpx.ClientIP(r))
	httpx.WriteNoContent(w)
}

type commandReq struct {
	Type    string `json:"type"`
	Payload string `json:"payload"`
}

func (h *adminHandler) sendCommand(w http.ResponseWriter, r *http.Request) {
	p := principal(r)
	var req commandReq
	if err := httpx.DecodeJSON(r, &req); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	id := r.PathValue("id")
	c, err := h.deps.Services.Agent.EnqueueCommand(r.Context(), id, req.Type, req.Payload, p.Username)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	h.deps.Services.Audit.Record(r.Context(), p.UserID, p.Username, "host.command",
		id, req.Type+" "+req.Payload, httpx.ClientIP(r))
	httpx.WriteJSON(w, r, http.StatusOK, c)
}

func (h *adminHandler) listCommands(w http.ResponseWriter, r *http.Request) {
	items, err := h.deps.Services.Agent.ListCommands(r.Context(), 100)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, r, http.StatusOK, map[string]any{"items": items, "total": len(items)})
}

// ---------------------------------------------------------------- 规则

func (h *adminHandler) listRules(w http.ResponseWriter, r *http.Request) {
	items, err := h.deps.Services.Rule.List(r.Context())
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, r, http.StatusOK, map[string]any{"items": items, "total": len(items)})
}

type ruleReq struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Severity    string   `json:"severity"`
	MITRE       []string `json:"mitre"`
	Score       int      `json:"score"`
	Enabled     bool     `json:"enabled"`
	Definition  string   `json:"definition"`
}

func (h *adminHandler) upsertRule(w http.ResponseWriter, r *http.Request) {
	p := principal(r)
	var req ruleReq
	if err := httpx.DecodeJSON(r, &req); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	rule, err := h.deps.Services.Rule.Upsert(r.Context(), &domain.Rule{
		ID:          req.ID,
		Name:        req.Name,
		Description: req.Description,
		Severity:    domain.Severity(req.Severity),
		MITRE:       req.MITRE,
		Score:       req.Score,
		Enabled:     req.Enabled,
		Definition:  req.Definition,
	}, p.Username)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	h.deps.Services.Audit.Record(r.Context(), p.UserID, p.Username, "rule.upsert", rule.ID, rule.Name, httpx.ClientIP(r))
	httpx.WriteJSON(w, r, http.StatusOK, rule)
}

type toggleReq struct {
	Enabled bool `json:"enabled"`
}

func (h *adminHandler) toggleRule(w http.ResponseWriter, r *http.Request) {
	p := principal(r)
	var req toggleReq
	if err := httpx.DecodeJSON(r, &req); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	id := r.PathValue("id")
	rule, err := h.deps.Services.Rule.SetEnabled(r.Context(), id, req.Enabled, p.Username)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	h.deps.Services.Audit.Record(r.Context(), p.UserID, p.Username, "rule.toggle", id,
		strconv.FormatBool(req.Enabled), httpx.ClientIP(r))
	httpx.WriteJSON(w, r, http.StatusOK, rule)
}

func (h *adminHandler) deleteRule(w http.ResponseWriter, r *http.Request) {
	p := principal(r)
	id := r.PathValue("id")
	if err := h.deps.Services.Rule.Delete(r.Context(), id, p.Username); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	h.deps.Services.Audit.Record(r.Context(), p.UserID, p.Username, "rule.delete", id, "", httpx.ClientIP(r))
	httpx.WriteNoContent(w)
}

// ---------------------------------------------------------------- 白名单

func (h *adminHandler) listAllowlist(w http.ResponseWriter, r *http.Request) {
	items, err := h.deps.Services.Rule.ListAllowlist(r.Context())
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, r, http.StatusOK, map[string]any{"items": items, "total": len(items)})
}

type allowReq struct {
	Type  string `json:"type"`
	Value string `json:"value"`
	Note  string `json:"note"`
}

func (h *adminHandler) addAllowlist(w http.ResponseWriter, r *http.Request) {
	p := principal(r)
	var req allowReq
	if err := httpx.DecodeJSON(r, &req); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	e, recycled, err := h.deps.Services.Rule.AddAllowlist(r.Context(), req.Type, req.Value, req.Note, p.Username)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	h.deps.Services.Audit.Record(r.Context(), p.UserID, p.Username, "allowlist.add", e.ID,
		fmt.Sprintf("%s=%s（自动回收告警 %d 条）", req.Type, req.Value, recycled), httpx.ClientIP(r))
	httpx.WriteJSON(w, r, http.StatusOK, map[string]any{
		"entry":           e,
		"recycled_alerts": recycled,
	})
}

func (h *adminHandler) deleteAllowlist(w http.ResponseWriter, r *http.Request) {
	p := principal(r)
	id := r.PathValue("id")
	if err := h.deps.Services.Rule.DeleteAllowlist(r.Context(), id, p.Username); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	h.deps.Services.Audit.Record(r.Context(), p.UserID, p.Username, "allowlist.delete", id, "", httpx.ClientIP(r))
	httpx.WriteNoContent(w)
}

// ---------------------------------------------------------------- 审计与账号

func (h *adminHandler) listAudit(w http.ResponseWriter, r *http.Request) {
	limit := atoiDefault(r.URL.Query().Get("limit"), 200)
	items, err := h.deps.Services.Audit.List(r.Context(), limit)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, r, http.StatusOK, map[string]any{"items": items, "total": len(items)})
}

func (h *adminHandler) listUsers(w http.ResponseWriter, r *http.Request) {
	items, err := h.deps.Services.Auth.ListUsers(r.Context())
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, r, http.StatusOK, map[string]any{"items": items, "total": len(items)})
}

type createUserReq struct {
	Username    string `json:"username"`
	DisplayName string `json:"display_name"`
	Password    string `json:"password"`
	Role        string `json:"role"`
}

func (h *adminHandler) createUser(w http.ResponseWriter, r *http.Request) {
	p := principal(r)
	var req createUserReq
	if err := httpx.DecodeJSON(r, &req); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	u, err := h.deps.Services.Auth.CreateUser(r.Context(), req.Username, req.DisplayName,
		req.Password, domain.Role(req.Role))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	h.deps.Services.Audit.Record(r.Context(), p.UserID, p.Username, "user.create", u.ID, u.Username, httpx.ClientIP(r))
	httpx.WriteJSON(w, r, http.StatusOK, u)
}

// ---------------------------------------------------------------- helpers

func splitParam(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// clampInt 把参数钳制在合理区间。
//
// 分页参数来自 URL，必须假设它是恶意的：`page_size=1000000` 会让服务端
// 一次性把整张告警表读进内存并序列化，既是内存风险也是响应时间风险。
func clampInt(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func atoiDefault(s string, def int) int {
	if s == "" {
		return def
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return def
	}
	return n
}
