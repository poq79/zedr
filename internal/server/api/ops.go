package api

// 运维支撑端点：/metrics（Prometheus 文本格式）、告警 CSV 导出、事件聚合。
//
// 这些端点的共同特征是"给系统和运维看的"，与管理台的 JSON API 分开，
// 避免把面向人的分页/筛选语义和面向机器的稳定契约混在一起。

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"hostguard/internal/platform/apperr"
	"hostguard/internal/platform/httpx"
	"hostguard/internal/server/domain"
)

// ---------------------------------------------------------------- /metrics

// metricsHandler 输出 Prometheus 文本格式指标。
//
// 刻意手写文本而不引 client 库：指标数量少（十几个 gauge）、
// 格式稳定，引依赖只为了省一个 fmt.Fprintf 不划算——
// 与"零外部依赖可交叉编译"的工程约束保持一致。
func (h *adminHandler) metrics(w http.ResponseWriter, r *http.Request) {
	m := h.deps.Services.Stats.Metrics(r.Context(), h.deps.StartedAt, h.deps.Notifier.Stats)

	var b strings.Builder
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")

	gauge := func(name, help string, val any) {
		fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s gauge\n%s %v\n", name, help, name, name, val)
	}

	gauge("hg_hosts_total", "注册的主机总数", m.TotalHosts)
	gauge("hg_hosts_online", "在线主机数（3 分钟内有心跳）", m.OnlineHosts)
	gauge("hg_alerts_24h", "过去 24 小时收到的告警数", m.Alerts24h)
	gauge("hg_alerts_open", "未处置告警数（open + acknowledged）", m.OpenAlerts)
	gauge("hg_alerts_critical_open", "未处置的 critical 告警数", m.CriticalOpen)
	gauge("hg_alert_avg_score", "24 小时告警平均分", fmt.Sprintf("%.2f", m.AvgScore))

	for _, sev := range []string{"critical", "high", "medium", "low"} {
		fmt.Fprintf(&b, "hg_alerts_by_severity{severity=%q} %d\n", sev, m.SeverityDist[sev])
	}

	sent, failed, dropped := h.deps.Notifier.Stats()
	gauge("hg_webhook_sent_total", "webhook 通知成功数", sent)
	gauge("hg_webhook_failed_total", "webhook 通知失败数", failed)
	gauge("hg_webhook_dropped_total", "webhook 队列满丢弃数", dropped)

	// 版本分布：每个版本一条样本行。版本碎片化是升级管理的日常，
	// SIEM/看板据此画"还有多少台没升上来"的趋势
	if vd, err := h.deps.Services.Stats.Versions(r.Context()); err == nil {
		for v, n := range vd {
			fmt.Fprintf(&b, "hg_agent_versions{version=%q} %d\n", v, n)
		}
	}

	// 事件状态分布 + MTTA：处置效率的量化口径（首次人工动作延迟）
	if counts, err := h.deps.Services.Incident.CountByStatus(r.Context()); err == nil {
		openish := 0
		for st, n := range counts {
			fmt.Fprintf(&b, "hg_incidents{status=%q} %d\n", st, n)
			if st != string(domain.IncidentResolved) {
				openish += n
			}
		}
		gauge("hg_incidents_open", "未进入 resolved 的事件数", openish)
	}
	if mtta, err := h.deps.Services.Incident.AvgFirstActionMinutes(
		r.Context(), time.Now().Add(-7*24*time.Hour)); err == nil {
		gauge("hg_incident_mtta_minutes", "事件创建→首次人工动作平均分钟数（7 天窗口）",
			fmt.Sprintf("%.2f", mtta))
	}

	gauge("hg_go_goroutines", "当前 goroutine 数", m.Goroutines)
	gauge("hg_go_heap_alloc_bytes", "Go 堆已分配字节", m.HeapAlloc)
	gauge("hg_uptime_seconds", "服务运行秒数", fmt.Sprintf("%.0f", m.UptimeSec))

	_, _ = w.Write([]byte(b.String()))
}

// ---------------------------------------------------------------- CSV 导出

// exportCSV 流式导出告警为 CSV。
//
// 用 200 条一页的翻页循环而不是一次性大查询：导出上限 5000 条，
// 既覆盖了运维归档的常见需求，又把内存与响应时间的上界钉死。
// 超过上限时在响应头标注 truncated，让调用方知道数据不完整。
func (h *adminHandler) exportCSV(w http.ResponseWriter, r *http.Request) {
	const (
		pageSize  = 200
		maxRows   = 5000
	)

	p := principal(r)
	h.deps.Services.Audit.Record(r.Context(), p.UserID, p.Username,
		"alert.export_csv", "", "text/csv", httpx.ClientIP(r))

	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition",
		fmt.Sprintf(`attachment; filename="hostguard-alerts-%s.csv"`, time.Now().Format("20060102-1504")))

	// UTF-8 BOM：让 Excel 正确识别中文列
	_, _ = w.Write([]byte{0xEF, 0xBB, 0xBF})

	flusher, _ := w.(http.Flusher)
	writeRow := func(fields []string) {
		for i, f := range fields {
			if i > 0 {
				_, _ = w.Write([]byte(","))
			}
			// CSV 转义：引号翻倍 + 前缀防公式注入（Excel 会执行 =开头的单元格）
			_, _ = w.Write([]byte(csvField(f)))
		}
		_, _ = w.Write([]byte("\r\n"))
	}

	writeRow([]string{"id", "time", "hostname", "severity", "verdict", "score",
		"status", "process", "path", "cmdline", "user", "hash", "signed", "rules", "mitre", "title"})

	total := 0
	truncated := false
	for page := 1; page <= maxRows/pageSize && total < maxRows; page++ {
		alerts, _, err := h.deps.Services.Alert.List(r.Context(), parseAlertFilter(r.URL.Query(), page, pageSize))
		if err != nil {
			return // 头已发出，无法再改状态码；截断即语义的一部分
		}
		if len(alerts) == 0 {
			break
		}
		for _, a := range alerts {
			if total >= maxRows {
				truncated = true
				break
			}
			writeRow([]string{
				a.ID,
				a.CreatedAt.Format(time.RFC3339),
				a.Hostname,
				string(a.Severity),
				string(a.Verdict),
				fmt.Sprintf("%d", a.Score),
				string(a.Status),
				a.ProcessName,
				a.ImagePath,
				a.CmdLine,
				a.ProcUser,
				a.HashSHA256,
				fmt.Sprintf("%v", a.Signed),
				strings.Join(a.RuleIDs, "|"),
				strings.Join(a.MITRE, "|"),
				a.Title,
			})
			total++
		}
		if flusher != nil {
			flusher.Flush()
		}
	}
	if truncated {
		w.Header().Set("X-HG-Export-Truncated", "true")
	}
}

// csvField 做 CSV 字段转义，并对以 =/+/-/@ 开头的值前缀单引号，
// 防止电子表格软件把告警字段（攻击者可控的进程名/命令行）当公式执行
// ——这是 CSV 导出最常见的二次伤害路径（CSV Injection）。
func csvField(s string) string {
	if s == "" {
		return `""`
	}
	if strings.HasPrefix(s, "=") || strings.HasPrefix(s, "+") ||
		strings.HasPrefix(s, "-") || strings.HasPrefix(s, "@") {
		s = "'" + s
	}
	return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
}

// ---------------------------------------------------------------- 事件聚合

// listIncidents 返回持久化事件（懒同步后读库）+ 跨主机爆发。
// 两者都在同一个接口里：值班打开"事件"页要回答的正是
// "本机在发生什么 + 整个环境在发生什么"。
func (h *adminHandler) listIncidents(w http.ResponseWriter, r *http.Request) {
	page := clampInt(atoiDefault(r.URL.Query().Get("page"), 1), 1, 10000)
	pageSize := clampInt(atoiDefault(r.URL.Query().Get("page_size"), 50), 1, 200)
	status := r.URL.Query().Get("status")

	incidents, total, err := h.deps.Services.Incident.ListIncidents(r.Context(), status, page, pageSize)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	bursts, err := h.deps.Services.Stats.ListBursts(r.Context())
	if err != nil {
		httpx.WriteError(w, r, apperr.Internal(err))
		return
	}
	httpx.WriteJSON(w, r, http.StatusOK, map[string]any{
		"items":     incidents,
		"total":     total,
		"page":      page,
		"page_size": pageSize,
		"bursts":    bursts,
		"generated": time.Now().UTC(),
	})
}

// transitionIncident 推进事件处置状态机（writer 权限）。
func (h *adminHandler) transitionIncident(w http.ResponseWriter, r *http.Request) {
	p := principal(r)
	var req struct {
		Status string `json:"status"`
		Note   string `json:"note"`
	}
	if err := httpx.DecodeJSON(r, &req); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	id := r.PathValue("id")
	inc, err := h.deps.Services.Incident.TransitionIncident(r.Context(), id,
		domain.IncidentStatus(req.Status), req.Note, p.Username)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	h.deps.Services.Audit.Record(r.Context(), p.UserID, p.Username, "incident.status",
		id, req.Status+" "+req.Note, httpx.ClientIP(r))
	httpx.WriteJSON(w, r, http.StatusOK, inc)
}

// integrityReport 告警完整性链校验结果。
// 面向合规审计："日志防篡改"从口号变成一个可导出的证据页面。
func (h *adminHandler) integrityReport(w http.ResponseWriter, r *http.Request) {
	checks, err := h.deps.Services.Stats.VerifyIntegrity(r.Context())
	if err != nil {
		httpx.WriteError(w, r, apperr.Internal(err))
		return
	}
	ok, purged, tampered := 0, 0, 0
	for _, c := range checks {
		switch c.Status {
		case "ok":
			ok++
		case "purged":
			purged++
		case "tampered":
			tampered++
		}
	}
	httpx.WriteJSON(w, r, http.StatusOK, map[string]any{
		"days": checks, "ok": ok, "purged": purged, "tampered": tampered,
	})
}

// weeklyReport 运营周报（7 天窗口）。
func (h *adminHandler) weeklyReport(w http.ResponseWriter, r *http.Request) {
	rep, err := h.deps.Services.Stats.WeeklyReport(r.Context(), 7*24*time.Hour)
	if err != nil {
		httpx.WriteError(w, r, apperr.Internal(err))
		return
	}
	httpx.WriteJSON(w, r, http.StatusOK, rep)
}

// parseAlertFilter 从查询串构造告警过滤器（与 listAlerts 同一套语义，
// 导出与列表看到的必须是同一个世界，否则"我在页面上看到的"和
// "我导出的"对不上，运营会失去对数据的信任）。
func parseAlertFilter(q url.Values, page, pageSize int) domain.AlertFilter {
	f := domain.AlertFilter{
		AgentID:  q.Get("agent_id"),
		Query:    q.Get("q"),
		Sort:     q.Get("sort"),
		Page:     page,
		PageSize: pageSize,
	}
	for _, s := range splitParam(q.Get("status")) {
		if st := domain.AlertStatus(s); st.Valid() {
			f.Status = append(f.Status, st)
		}
	}
	for _, s := range splitParam(q.Get("severity")) {
		if sv := domain.Severity(s); sv.Valid() {
			f.Severity = append(f.Severity, sv)
		}
	}
	for _, s := range splitParam(q.Get("verdict")) {
		if v := domain.Verdict(s); v.Valid() {
			f.Verdict = append(f.Verdict, v)
		}
	}
	return f
}
