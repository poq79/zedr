package api

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
	"zedr/internal/platform/apperr"

	"zedr/internal/platform/httpx"
	"zedr/internal/server/auth"
	"zedr/internal/server/domain"
	"zedr/internal/server/notify"
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
	// mfa_enabled 是登录后前端判断"是否已绑双因素"的事实源（设置页
	// 绑定卡片状态）；principal 只带 JWT claims 里的固定身份字段，
	// 这个运行时可变状态必须查库。
	mfaEnabled := false
	if u, err := h.deps.Services.Auth.Me(r.Context(), p.UserID); err == nil && u != nil {
		mfaEnabled = u.TotpEnabled
	}
	httpx.WriteJSON(w, r, http.StatusOK, map[string]any{
		"id":          p.UserID,
		"username":    p.Username,
		"role":        string(p.Role),
		"mfa_enabled": mfaEnabled,
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

// attackMatrix 返回 ATT&CK 战术×技术覆盖矩阵。
// days 查询参数控制告警聚合窗口（默认 30 天，上限 365）。
func (h *adminHandler) attackMatrix(w http.ResponseWriter, r *http.Request) {
	days := clampInt(atoiDefault(r.URL.Query().Get("days"), 30), 1, 365)
	m, err := h.deps.Services.Stats.AttackMatrix(r.Context(), days)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, r, http.StatusOK, m)
}

// ---------------------------------------------------------------- 告警

func (h *adminHandler) listAlerts(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := domain.AlertFilter{
		AgentID:  q.Get("agent_id"),
		Query:    q.Get("q"),
		Sort:     q.Get("sort"),
		Mitre:    strings.ToUpper(strings.TrimSpace(q.Get("mitre"))),
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

// ---------------------------------------------------------------- 威胁指标 IOC

func (h *adminHandler) listIOCs(w http.ResponseWriter, r *http.Request) {
	items, err := h.deps.Services.Rule.ListIOCs(r.Context())
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, r, http.StatusOK, map[string]any{"items": items, "total": len(items)})
}

type iocReq struct {
	Hash string `json:"hash"`
	Note string `json:"note"`
}

func (h *adminHandler) addIOC(w http.ResponseWriter, r *http.Request) {
	p := principal(r)
	var req iocReq
	if err := httpx.DecodeJSON(r, &req); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	e, err := h.deps.Services.Rule.AddIOC(r.Context(), req.Hash, req.Note, p.Username)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	h.deps.Services.Audit.Record(r.Context(), p.UserID, p.Username, "ioc.add",
		e.Hash[:12]+"...", req.Note, httpx.ClientIP(r))
	httpx.WriteJSON(w, r, http.StatusOK, e)
}

func (h *adminHandler) deleteIOC(w http.ResponseWriter, r *http.Request) {
	p := principal(r)
	id := r.PathValue("id")
	if err := h.deps.Services.Rule.DeleteIOC(r.Context(), id, p.Username); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	h.deps.Services.Audit.Record(r.Context(), p.UserID, p.Username, "ioc.delete", id, "", httpx.ClientIP(r))
	httpx.WriteNoContent(w)
}

// ---------------------------------------------------------------- 主机

func (h *adminHandler) listHosts(w http.ResponseWriter, r *http.Request) {
	agents, err := h.deps.Services.Agent.List(r.Context())
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	// 时钟偏移与队列丢弃都是运行时值（不落库），在这里合入响应
	skews := h.deps.Services.Agent.SkewMap()
	drops := h.deps.Services.Agent.DroppedMap()
	for i := range agents {
		if v, ok := skews[agents[i].ID]; ok {
			agents[i].ClockSkewMS = v
		}
		if v, ok := drops[agents[i].ID]; ok && v > 0 {
			agents[i].QueueDropped = v
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
	// 升级是唯一方向不可逆的指令（版本只升不降，降级必须走运维通道），
	// 且会让探针进程退出重启——收口到 admin；其余指令维持 writer 口径。
	if req.Type == "self_upgrade" && p.Role != domain.RoleAdmin {
		httpx.WriteError(w, r, apperr.Forbidden("探针自升级仅管理员可发起"))
		return
	}
	// 主机网络隔离切断整台终端的业务网络，是响应动作里业务影响最大的
	// 一类——与自升级同级收口到 admin（R+3）。审计行已带操作者。
	if req.Type == "isolate_host" && p.Role != domain.RoleAdmin {
		httpx.WriteError(w, r, apperr.Forbidden("主机网络隔离仅管理员可发起"))
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
	items, err := h.deps.Services.Rule.ListWithObserve(r.Context())
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, r, http.StatusOK, map[string]any{"items": items, "total": len(items)})
}

// ruleSchema 规则 DSL 的字段/操作符参考与模板库（表单编辑器的数据源）。
func (h *adminHandler) ruleSchema(w http.ResponseWriter, r *http.Request) {
	schema, err := h.deps.Services.Rule.Schema()
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, r, http.StatusOK, schema)
}

type ruleReq struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Severity    string   `json:"severity"`
	MITRE       []string `json:"mitre"`
	Score       int      `json:"score"`
	Enabled     bool     `json:"enabled"`
	Mode        string   `json:"mode"`
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
		Mode:        req.Mode,
		Definition:  req.Definition,
	}, p.Username)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	h.deps.Services.Audit.Record(r.Context(), p.UserID, p.Username, "rule.upsert", rule.ID, rule.Name, httpx.ClientIP(r))
	httpx.WriteJSON(w, r, http.StatusOK, rule)
}

// importSigmaRules 批量导入 Sigma YAML 规则（adminOnly）。
// 转换门禁/DNF 展开在 internal/rules/sigma.go；入库统一 observe 模式
// 且 Enabled=false——先观察后转正，绝不直接进告警面。
func (h *adminHandler) importSigmaRules(w http.ResponseWriter, r *http.Request) {
	p := principal(r)
	var req struct {
		YAML string `json:"yaml"`
	}
	if err := httpx.DecodeJSON(r, &req); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if strings.TrimSpace(req.YAML) == "" {
		httpx.WriteError(w, r, apperr.Invalid("YAML 内容不能为空"))
		return
	}
	rep, err := h.deps.Services.Rule.SigmaImport(r.Context(), req.YAML, p.Username)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	h.deps.Services.Audit.Record(r.Context(), p.UserID, p.Username, "rule.sigma_import", "",
		fmt.Sprintf("docs=%d,created=%d,skipped=%d", rep.Docs, len(rep.Created), len(rep.Skipped)),
		httpx.ClientIP(r))
	httpx.WriteJSON(w, r, http.StatusOK, rep)
}

// setRuleMode 观察模式/正常模式切换。独立端点而非复用 upsert：
// 转正是运营高频动作且语义单一，独立路由让审计记录一眼可读
// （rule.mode 而不是一条内容不明的 rule.upsert）。
func (h *adminHandler) setRuleMode(w http.ResponseWriter, r *http.Request) {
	p := principal(r)
	var req struct {
		Mode string `json:"mode"`
	}
	if err := httpx.DecodeJSON(r, &req); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	id := r.PathValue("id")
	rule, err := h.deps.Services.Rule.SetMode(r.Context(), id, req.Mode, p.Username)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	h.deps.Services.Audit.Record(r.Context(), p.UserID, p.Username, "rule.mode", id, req.Mode, httpx.ClientIP(r))
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

// listIntel 非哈希威胁情报列表（type 过滤可选）。
func (h *adminHandler) listIntel(w http.ResponseWriter, r *http.Request) {
	items, err := h.deps.Services.Rule.ListIntel(r.Context(), r.URL.Query().Get("type"))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, r, http.StatusOK, map[string]any{"items": items, "total": len(items)})
}

type intelReq struct {
	Type  string `json:"type"`
	Value string `json:"value"`
	Score int    `json:"score"`
	Name  string `json:"name"`
	Note  string `json:"note"`
	MITRE string `json:"mitre"`
}

func (h *adminHandler) addIntel(w http.ResponseWriter, r *http.Request) {
	p := principal(r)
	var req intelReq
	if err := httpx.DecodeJSON(r, &req); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	e, err := h.deps.Services.Rule.AddIntel(r.Context(), req.Type, req.Value, req.Score,
		req.Name, req.Note, req.MITRE, p.Username)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	h.deps.Services.Audit.Record(r.Context(), p.UserID, p.Username, "intel.add",
		e.Type+":"+e.Value, e.Name, httpx.ClientIP(r))
	httpx.WriteJSON(w, r, http.StatusOK, e)
}

func (h *adminHandler) deleteIntel(w http.ResponseWriter, r *http.Request) {
	p := principal(r)
	id := r.PathValue("id")
	if err := h.deps.Services.Rule.DeleteIntel(r.Context(), id, p.Username); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	h.deps.Services.Audit.Record(r.Context(), p.UserID, p.Username, "intel.delete", id, "", httpx.ClientIP(r))
	httpx.WriteNoContent(w)
}

// ---------------------------------------------------------------- 白名单

// exportAllowlist 白名单整表导出（灾备/迁移）。
// 白名单是降噪闭环的资产：重建服务端或迁移环境时，丢白名单
// 等于把误报治理推倒重来。
func (h *adminHandler) exportAllowlist(w http.ResponseWriter, r *http.Request) {
	p := principal(r)
	items, err := h.deps.Services.Rule.ListAllowlist(r.Context())
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	h.deps.Services.Audit.Record(r.Context(), p.UserID, p.Username,
		"allowlist.export", "", fmt.Sprintf("%d 条", len(items)), httpx.ClientIP(r))
	w.Header().Set("Content-Disposition", `attachment; filename="zedr-allowlist.json"`)
	httpx.WriteJSON(w, r, http.StatusOK, map[string]any{
		"exported_at": time.Now().UTC(), "items": items,
	})
}

// importAllowlistReq 导入载荷：与导出格式对称，便于"导出→导入"直通。
type importAllowlistReq struct {
	Entries []struct {
		Type  string `json:"type"`
		Value string `json:"value"`
		Note  string `json:"note"`
	} `json:"entries"`
}

// importAllowlist 批量导入白名单。
// 已存在的条目跳过（幂等）——导入应当可以安全地重复执行。
func (h *adminHandler) importAllowlist(w http.ResponseWriter, r *http.Request) {
	p := principal(r)
	var req importAllowlistReq
	if err := httpx.DecodeJSON(r, &req); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if len(req.Entries) > 500 {
		httpx.WriteError(w, r, apperr.Invalid("单次导入不能超过 500 条"))
		return
	}

	added, skipped, failed := 0, 0, 0
	for _, e := range req.Entries {
		if _, _, err := h.deps.Services.Rule.AddAllowlist(r.Context(),
			e.Type, e.Value, e.Note, p.Username); err != nil {
			// 唯一键冲突 = 已存在 = 跳过；其他错误计失败
			if strings.Contains(err.Error(), "已存在") || strings.Contains(err.Error(), "duplicate") ||
				strings.Contains(err.Error(), "UNIQUE") {
				skipped++
			} else {
				failed++
			}
			continue
		}
		added++
	}
	h.deps.Services.Audit.Record(r.Context(), p.UserID, p.Username,
		"allowlist.import", "",
		fmt.Sprintf("added=%d skipped=%d failed=%d", added, skipped, failed),
		httpx.ClientIP(r))
	httpx.WriteJSON(w, r, http.StatusOK, map[string]any{
		"added": added, "skipped": skipped, "failed": failed,
	})
}

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

// verifyAudit 全量校验审计防篡改链。只读操作，viewer 可见——
// 断链状态本身就该被最多人看到，藏成 adminOnly 等于帮篡改者遮丑。
func (h *adminHandler) verifyAudit(w http.ResponseWriter, r *http.Request) {
	rep, err := h.deps.Services.Audit.Verify(r.Context())
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, r, http.StatusOK, rep)
}

// notifyHealth 通知看门狗快照：渠道级计数、连续失败窗数与整体状态。
// viewer 可读——"通知坏没坏"应该被最多的人看到，静默故障才好遮丑。
func (h *adminHandler) notifyHealth(w http.ResponseWriter, r *http.Request) {
	if h.deps.NotifyReport == nil {
		httpx.WriteJSON(w, r, http.StatusOK, notify.Report{State: "unconfigured"})
		return
	}
	httpx.WriteJSON(w, r, http.StatusOK, h.deps.NotifyReport())
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
