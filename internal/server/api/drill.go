package api

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"zedr/internal/platform/apperr"
	"zedr/internal/platform/httpx"
	"zedr/internal/server/domain"
)

// 检测演练（Detection Drill）：管理员对一台主机发起受控自测 → 指令经
// 现有 agent_commands 管线下发（type=drill）→ 探针本地执行自造样本触发
// 各检测层 → 回执 JSON 随指令回传 → 本文件把回执投影成结构化演练报告。
//
// 本文件刻意薄：指令创建/投递/回执存储全部复用 Commands 管线（不建新表），
// 这里只做 总开关门禁 + 步骤白名单校验 + 审计 + 回执 JSON 投影。
// 执行语义（自造样本形态/判定口径/清理责任）在 internal/agent/drill。

// drillStepNames 与 internal/agent/drill.AllSteps() 保持一致。
// 为什么不直接 import：探针侧包带 Windows 专属 syscall，引入会把服务端
// 绑死在 windows 构建；白名单两侧各存一份、探针侧 ParsePayload 再校验一次
// 兜底，drift 时探针回 skipped 并在 Note 说明，不会静默错判。
var drillStepNames = []string{"proc_chain", "port_scan", "service_event", "reg_run", "canary_touch"}

func validDrillStep(s string) bool {
	for _, n := range drillStepNames {
		if s == n {
			return true
		}
	}
	return false
}

// startDrill 发起演练。body 可空或 {"steps":["port_scan","reg_run"]}，
// 缺省全跑。权限走 writer 包装（admin/analyst），与 sendCommand 同口径。
func (h *adminHandler) startDrill(w http.ResponseWriter, r *http.Request) {
	p := principal(r)
	hostID := r.PathValue("id")

	// body 可空：直接 DecodeJSON 会把空 body 当错误，这里手工读一次
	// （64KB 上限，实际合法载荷只有几十字节）
	var req struct {
		Steps []string `json:"steps"`
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 64<<10))
	if err != nil {
		httpx.WriteError(w, r, apperr.Invalid("请求体读取失败"))
		return
	}
	if len(bytes.TrimSpace(body)) > 0 {
		dec := json.NewDecoder(bytes.NewReader(body))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&req); err != nil {
			httpx.WriteError(w, r, apperr.Invalid("请求体格式错误: %v", err))
			return
		}
	}
	steps := req.Steps
	if len(steps) == 0 {
		steps = drillStepNames
	}
	for _, s := range steps {
		if !validDrillStep(strings.TrimSpace(s)) {
			httpx.WriteError(w, r, apperr.Invalid("未知演练步骤 %q（可用: %s）",
				s, strings.Join(drillStepNames, ", ")))
			return
		}
	}
	payload, err := json.Marshal(map[string][]string{"steps": steps})
	if err != nil {
		httpx.WriteError(w, r, apperr.Invalid("演练参数序列化失败"))
		return
	}

	c, err := h.deps.Services.Agent.EnqueueCommand(r.Context(), hostID, "drill", string(payload), p.Username)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	// 审计口径与 sendCommand 一致：记"谁对哪台主机发了什么"
	h.deps.Services.Audit.Record(r.Context(), p.UserID, p.Username, "host.drill",
		hostID, "steps="+strings.Join(steps, ","), httpx.ClientIP(r))
	httpx.WriteJSON(w, r, http.StatusOK, c)
}

// drillStepView 是演练报告里的单步结果（与 internal/agent/drill.StepResult
// 的 JSON 形状对齐：name/expected_rule/hit/latency_ms/alert_id/note）。
type drillStepView struct {
	Name         string `json:"name"`
	ExpectedRule string `json:"expected_rule"`
	Hit          bool   `json:"hit"`
	LatencyMs    int64  `json:"latency_ms"`
	AlertID      string `json:"alert_id,omitempty"`
	Note         string `json:"note,omitempty"`
}

// drillView 是对外演练报告。
type drillView struct {
	DrillID   string          `json:"drill_id"`
	CreatedAt time.Time       `json:"created_at"`
	Status    string          `json:"status"` // pending|done|failed
	Steps     []drillStepView `json:"steps"`
	Skipped   []string        `json:"skipped,omitempty"`
	// Note 承载"回执不是演练报告 JSON"的人工可读说明（如探针关闭演练时
	// 回的 "drill disabled"）；正常报告此字段为空。
	Note string `json:"note,omitempty"`
}

// listDrills 列出该主机的演练指令与回执（从 commands 按 type=drill 过滤，
// 分页钳制遵循全站契约 page_size ≤ 200）。
func (h *adminHandler) listDrills(w http.ResponseWriter, r *http.Request) {
	hostID := r.PathValue("id")
	q := r.URL.Query()
	page := clampInt(atoiDefault(q.Get("page"), 1), 1, 10000)
	size := clampInt(atoiDefault(q.Get("page_size"), 20), 1, 200)

	items, total, err := h.deps.Services.Agent.ListCommandsByType(r.Context(), hostID, "drill", page, size)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	views := make([]drillView, 0, len(items))
	for i := range items {
		views = append(views, drillViewOf(items[i]))
	}
	httpx.WriteJSON(w, r, http.StatusOK, pageResp(views, total, page, size))
}

// drillViewOf 把指令记录投影成演练报告：回执 JSON 解析成结构化步骤结果；
// 解析不出（pending / 纯文本回执）时 steps 留空、原文进 Note。
func drillViewOf(c domain.AgentCommand) drillView {
	v := drillView{DrillID: c.ID, CreatedAt: c.CreatedAt}
	switch c.Status {
	case "done":
		v.Status = "done"
	case "failed":
		v.Status = "failed"
	default:
		// pending / delivered：已下发未回执
		v.Status = "pending"
	}
	var rep struct {
		Steps   []drillStepView `json:"steps"`
		Skipped []string        `json:"skipped"`
	}
	if c.Result != "" && json.Unmarshal([]byte(c.Result), &rep) == nil && len(rep.Steps) > 0 {
		v.Steps = rep.Steps
		v.Skipped = rep.Skipped
	} else if c.Result != "" {
		v.Note = c.Result
	}
	if v.Steps == nil {
		v.Steps = []drillStepView{}
	}
	return v
}
