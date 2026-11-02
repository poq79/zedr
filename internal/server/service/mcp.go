package service

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"zedr/internal/mcp"
	"zedr/internal/server/domain"
)

// MCP 对外工具集的只读实现（与 Agent 调查同一纪律：模型/客户端只能读）。
//
// 证据（2026-11 取证）：Wazuh 生态的 MCP Server 全部只读默认、写入需显式
// ALLOW_WRITES；工具按功能域拆分、数量控制在数十个以内。我们 v1 八件工具，
// 覆盖"查告警/事件/情报/清单/猎况/状态"，不提供任何写操作。

// MCPTools 返回对外工具定义（JSON Schema）。
func MCPTools() []mcp.Tool {
	return []mcp.Tool{
		{Name: "query_alerts", Description: "查询告警（只读）。支持按进程名/主机/结论/严重度/最低分/签名过滤，最多 50 条",
			InputSchema: json.RawMessage(`{"type":"object","properties":{
				"process_name":{"type":"string"},"hostname":{"type":"string"},
				"verdict":{"type":"string","enum":["malicious","suspicious","benign","inconclusive"]},
				"severity":{"type":"string","enum":["critical","high","medium","low"]},
				"score_gte":{"type":"integer","minimum":0,"maximum":100},
				"signed":{"type":"boolean"},"limit":{"type":"integer","minimum":1,"maximum":50}}}`)},
		{Name: "get_alert", Description: "按 ID 读取一条告警的完整证据链（只读）",
			InputSchema: json.RawMessage(`{"type":"object","properties":{"id":{"type":"string"}},"required":["id"]}`)},
		{Name: "list_incidents", Description: "列出事件（攻击链聚类，只读）；status 可选 open/investigating/contained/resolved",
			InputSchema: json.RawMessage(`{"type":"object","properties":{"status":{"type":"string"},"limit":{"type":"integer","minimum":1,"maximum":50}}}`)},
		{Name: "get_incident_narrative", Description: "读取事件最近一次 AI 攻击链叙事（只读；未生成时提示先在管理台生成）",
			InputSchema: json.RawMessage(`{"type":"object","properties":{"id":{"type":"string"}},"required":["id"]}`)},
		{Name: "ioc_lookup", Description: "在威胁情报库比对 SHA256 是否已知恶意（只读）",
			InputSchema: json.RawMessage(`{"type":"object","properties":{"hash":{"type":"string"}},"required":["hash"]}`)},
		{Name: "host_inventory", Description: "读取主机资产清单：不带 section 返回节名与摘要，带 section 返回该节 JSON（只读）",
			InputSchema: json.RawMessage(`{"type":"object","properties":{"agent_id":{"type":"string"},"section":{"type":"string","enum":["system","adapters","listeners","services","tasks","startup","agent"]}},"required":["agent_id"]}`)},
		{Name: "hunt", Description: "自然语言检索告警（内部翻译成受控 DSL 后执行；模型接触不到 SQL）",
			InputSchema: json.RawMessage(`{"type":"object","properties":{"query":{"type":"string","maxLength":500}},"required":["query"]}`)},
		{Name: "system_status", Description: "平台运况摘要：主机数/在线数/未处置告警/AI 引擎与预算（只读）",
			InputSchema: json.RawMessage(`{"type":"object","properties":{}}`)},
	}
}

// MCPExecutor 实现 mcp.Executor。
type MCPExecutor struct {
	ai *AIService
}

func NewMCPExecutor(ai *AIService) *MCPExecutor { return &MCPExecutor{ai: ai} }

func (x *MCPExecutor) Call(ctx context.Context, name string, args json.RawMessage) (any, error) {
	switch name {
	case "query_alerts":
		var in struct {
			ProcessName string `json:"process_name"`
			Hostname    string `json:"hostname"`
			Verdict     string `json:"verdict"`
			Severity    string `json:"severity"`
			ScoreGTE    int    `json:"score_gte"`
			Signed      *bool  `json:"signed"`
			Limit       int    `json:"limit"`
		}
		_ = json.Unmarshal(args, &in)
		if in.Limit <= 0 || in.Limit > 50 {
			in.Limit = 20
		}
		f := domain.AlertFilter{
			Page: 1, PageSize: in.Limit, Sort: "newest",
			ProcessLike: in.ProcessName, HostLike: in.Hostname,
			MinScore: in.ScoreGTE,
		}
		if in.Verdict != "" {
			f.Verdict = []domain.Verdict{domain.Verdict(in.Verdict)}
		}
		if in.Severity != "" {
			f.Severity = []domain.Severity{domain.Severity(in.Severity)}
		}
		if in.Signed != nil {
			unsigned := !*in.Signed
			f.Unsigned = &unsigned
		}
		items, total, err := x.ai.repos.Alerts.List(ctx, f)
		if err != nil {
			return nil, err
		}
		out := make([]map[string]any, 0, len(items))
		for _, a := range items {
			out = append(out, alertDigest(a))
		}
		return map[string]any{"total": total, "count": len(out), "alerts": out}, nil

	case "get_alert":
		var in struct {
			ID string `json:"id"`
		}
		_ = json.Unmarshal(args, &in)
		if in.ID == "" {
			return nil, fmt.Errorf("缺少 id")
		}
		a, err := x.ai.repos.Alerts.ByID(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		if a == nil {
			return nil, fmt.Errorf("告警不存在")
		}
		sigs := make([]map[string]any, 0, len(a.Evidence.Signals))
		for _, s := range a.Evidence.Signals {
			sigs = append(sigs, map[string]any{"layer": s.Layer, "name": s.Name, "score": s.Score, "note": s.Note})
		}
		return map[string]any{
			"alert": alertDigest(*a), "summary": a.Summary,
			"cmdline": a.CmdLine, "pid": a.PID, "ppid": a.PPID,
			"rule_ids": a.RuleIDs, "signals": sigs,
		}, nil

	case "list_incidents":
		var in struct {
			Status string `json:"status"`
			Limit  int    `json:"limit"`
		}
		_ = json.Unmarshal(args, &in)
		if in.Limit <= 0 || in.Limit > 50 {
			in.Limit = 20
		}
		items, total, err := x.ai.repos.Incidents.List(ctx, in.Status, 1, in.Limit)
		if err != nil {
			return nil, err
		}
		out := make([]map[string]any, 0, len(items))
		for _, it := range items {
			out = append(out, map[string]any{
				"id": it.ID, "hostname": it.Hostname, "title": it.Title,
				"status": string(it.Status), "peak_severity": string(it.PeakSeverity),
				"alert_count": it.AlertCount, "open_count": it.OpenCount,
				"max_score": it.MaxScore, "first_seen": it.FirstSeen, "last_seen": it.LastSeen,
				"processes": it.Processes, "mitre": it.MITRE,
			})
		}
		return map[string]any{"total": total, "items": out}, nil

	case "get_incident_narrative":
		var in struct {
			ID string `json:"id"`
		}
		_ = json.Unmarshal(args, &in)
		if in.ID == "" {
			return nil, fmt.Errorf("缺少 id")
		}
		view, err := x.ai.GetIncidentNarrative(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		if view == nil {
			return map[string]any{"generated": false,
				"note": "该事件尚无有效的 AI 攻击链叙事（未生成或事件已新增告警）；请在管理台「事件」页生成后再查询"}, nil
		}
		return map[string]any{"generated": true, "narrative": view.Narrative,
			"incident_last_seen": view.IncidentLastSeen, "generated_at": view.GeneratedAt}, nil

	case "ioc_lookup":
		var in struct {
			Hash string `json:"hash"`
		}
		_ = json.Unmarshal(args, &in)
		if in.Hash == "" {
			return nil, fmt.Errorf("缺少 hash")
		}
		ioc, err := x.ai.repos.IOCs.ByHash(ctx, in.Hash)
		if err != nil {
			return nil, err
		}
		if ioc == nil {
			return map[string]any{"hit": false, "hash": in.Hash}, nil
		}
		return map[string]any{"hit": true, "hash": ioc.Hash, "note": ioc.Note, "created_at": ioc.CreatedAt}, nil

	case "host_inventory":
		var in struct {
			AgentID string `json:"agent_id"`
			Section string `json:"section"`
		}
		_ = json.Unmarshal(args, &in)
		if in.AgentID == "" {
			return nil, fmt.Errorf("缺少 agent_id")
		}
		secs, err := x.ai.repos.Inventory.ListByAgent(ctx, in.AgentID)
		if err != nil {
			return nil, err
		}
		if in.Section != "" {
			for _, sec := range secs {
				if sec.Name == in.Section {
					return map[string]any{"section": sec.Name, "updated_at": sec.UpdatedAt, "payload": json.RawMessage(sec.Payload)}, nil
				}
			}
			return map[string]any{"section": in.Section, "absent": true}, nil
		}
		out := make([]map[string]any, 0, len(secs))
		for _, sec := range secs {
			out = append(out, map[string]any{"section": sec.Name, "bytes": len(sec.Payload), "updated_at": sec.UpdatedAt})
		}
		return map[string]any{"agent_id": in.AgentID, "sections": out}, nil

	case "hunt":
		var in struct {
			Query string `json:"query"`
		}
		_ = json.Unmarshal(args, &in)
		q := strings.TrimSpace(in.Query)
		if q == "" {
			return nil, fmt.Errorf("缺少 query")
		}
		if len(q) > 500 {
			return nil, fmt.Errorf("query 过长（上限 500 字）")
		}
		res, err := x.ai.Hunt(ctx, q)
		if err != nil {
			return nil, err
		}
		alerts := make([]map[string]any, 0, len(res.Alerts))
		for _, a := range res.Alerts {
			alerts = append(alerts, alertDigest(a))
		}
		return map[string]any{"query": res.Query, "total": res.Total, "alerts": alerts}, nil

	case "system_status":
		agents, err := x.ai.repos.Agents.List(ctx)
		if err != nil {
			return nil, err
		}
		online := 0
		for _, a := range agents {
			if string(a.Status) == "online" {
				online++
			}
		}
		openMap, err := x.ai.repos.Alerts.CountOpenByAgent(ctx)
		if err != nil {
			return nil, err
		}
		open := 0
		for _, n := range openMap {
			open += n
		}
		st := x.ai.Stats()
		return map[string]any{
			"hosts_total": len(agents), "hosts_online": online,
			"open_alerts": open, "ai_engine": st.Engine, "ai_model": st.Model,
			"ai_budget_used": st.BudgetUsed, "ai_budget_cap": st.BudgetCap,
		}, nil
	}
	return nil, fmt.Errorf("未知工具 %q", name)
}
