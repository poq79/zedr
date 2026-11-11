package service

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"sync"
	"time"

	"zedr/internal/ai"
	"zedr/internal/livecatalog"
	"zedr/internal/platform/apperr"
	"zedr/internal/server/domain"
)

// agentLiveBodyCap 是 Agentic 调查 host_live 工具的响应读取上限：引擎
// 循环本就把工具结果截到 4000 字节喂给模型，这里放宽只为 JSON 完整。
const agentLiveBodyCap = 2 << 20

// Agentic 调查 v2 的服务端部分：工具白名单实现 + 编排 + 确定性回退。
//
// 工具只有**只读**七件落库查询 + 一件实时快照：主机近期告警、同哈希
// 跨主机、IOC 比对、同进程名、清单节、指纹历史、清单变更、host_live
// （2026-11-09 新增，主机在线时经隧道现采，端点限快速枚举子集）。
// 模型能影响的只有参数值——字段到查询的映射与单告警研判/狩猎同一纪律
// （模型接触不到 SQL，也写不了任何东西）。

// agentLiveEndpoints 是 Agentic 调查可用的实时端点子集——**由
// livecatalog 派生**（AI 开放 + 非内容出站 + 代理预算 ≤ 配置的工具
// 超时）：引擎单工具超时可配（HG_AI_AGENT_TOOL_TIMEOUT，默认 10s），
// 调大后 persistence/evtlog 等慢端点自动入列——子集与超时同源，才
// 不会出现永远超时的工具。ping/_catalog 对调查循环没有信息价值，排除。
func agentLiveEndpoints(maxToolTimeoutMs int) map[string]bool {
	m := make(map[string]bool)
	for _, ep := range livecatalog.All() {
		if ep.AI && !ep.FileRead && !ep.Collect && ep.TimeoutMs <= maxToolTimeoutMs &&
			ep.Name != "_catalog" && ep.Name != "ping" {
			m[ep.Name] = true
		}
	}
	return m
}

// agentLiveSchema 生成 host_live 的参数 schema：endpoint 枚举直接从
// livecatalog 派生子集（与执行白名单同一来源，永不漂移）。
func agentLiveSchema(toolTimeoutMs int) string {
	names := make([]string, 0, len(agentLiveEndpoints(toolTimeoutMs)))
	for n := range agentLiveEndpoints(toolTimeoutMs) {
		names = append(names, n)
	}
	sort.Strings(names)
	enum, _ := json.Marshal(names)
	return fmt.Sprintf(`{"type":"object","properties":{
		"endpoint":{"type":"string","enum":%s},
		"params":{"type":"object","additionalProperties":{"type":["string","number","boolean"]}}},
		"required":["endpoint"]}`, enum)
}

// agentTools 返回给模型的工具定义（JSON Schema）。
func agentTools(toolTimeoutMs int) []ai.AgentTool {
	return []ai.AgentTool{
		{Name: "host_recent_alerts", Description: "列出该主机最近 N 分钟的告警（默认 120 分钟，最多 50 条）",
			Parameters: json.RawMessage(`{"type":"object","properties":{"minutes":{"type":"integer","minimum":5,"maximum":1440},"limit":{"type":"integer","minimum":1,"maximum":50}}}`)},
		{Name: "hash_occurrences", Description: "查询同一文件哈希在其他主机/时间的告警（跨主机扩散证据）",
			Parameters: json.RawMessage(`{"type":"object","properties":{"hash":{"type":"string","description":"SHA256；留空则用当前告警的哈希"},"limit":{"type":"integer","minimum":1,"maximum":50}}}`)},
		{Name: "ioc_check", Description: "在威胁情报库中比对该哈希是否已知恶意",
			Parameters: json.RawMessage(`{"type":"object","properties":{"hash":{"type":"string","description":"SHA256；留空则用当前告警的哈希"}}}`)},
		{Name: "process_occurrences", Description: "按进程名检索其他主机的同名进程告警（同族/同工具扩散面）",
			Parameters: json.RawMessage(`{"type":"object","properties":{"process_name":{"type":"string","description":"留空则用当前告警的进程名"},"limit":{"type":"integer","minimum":1,"maximum":50}}}`)},
		{Name: "inventory_section", Description: "读取主机资产清单的某一节：listeners/services/tasks/startup",
			Parameters: json.RawMessage(`{"type":"object","properties":{"section":{"type":"string","enum":["listeners","services","tasks","startup"]}},"required":["section"]}`)},
		{Name: "fingerprint_history", Description: "该主机上该告警指纹的历史（此前是否出现过、是否被标记误报）——判断复发性告警的关键",
			Parameters: json.RawMessage(`{"type":"object","properties":{"limit":{"type":"integer","minimum":1,"maximum":50}}}`)},
		{Name: "inventory_changes", Description: "该主机近期资产变更事件（服务/任务/启动项新增）",
			Parameters: json.RawMessage(`{"type":"object","properties":{"limit":{"type":"integer","minimum":1,"maximum":20}}}`)},
		{Name: "host_live", Description: "在该告警主机上实时现采（探针在线时；主机离线返回说明）。endpoint 枚举为快速子集（≤当前工具超时），参数经 params 传（如 {\"pid\":123}、{\"path\":\"HKLM\\\\...\"}），完整契约见工具描述或 endpoint 枚举",
			Parameters: json.RawMessage(agentLiveSchema(toolTimeoutMs))},
	}
}

type agentToolExec struct {
	s     *AIService
	alert *domain.Alert
}

func (x *agentToolExec) Execute(ctx context.Context, name string, args json.RawMessage) (string, error) {
	switch name {
	case "host_recent_alerts":
		var in struct {
			Minutes int `json:"minutes"`
			Limit   int `json:"limit"`
		}
		_ = json.Unmarshal(args, &in)
		if in.Minutes <= 0 || in.Minutes > 1440 {
			in.Minutes = 120
		}
		if in.Limit <= 0 || in.Limit > 50 {
			in.Limit = 20
		}
		items, _, err := x.s.repos.Alerts.List(ctx, domain.AlertFilter{
			AgentID: x.alert.AgentID, Page: 1, PageSize: in.Limit, Sort: "oldest",
		})
		if err != nil {
			return "", err
		}
		since := time.Now().Add(-time.Duration(in.Minutes) * time.Minute)
		out := make([]map[string]any, 0, len(items))
		for _, a := range items {
			if a.CreatedAt.Before(since) {
				continue
			}
			out = append(out, alertDigest(a))
		}
		return marshalJSON(map[string]any{"count": len(out), "alerts": out})

	case "hash_occurrences":
		var in struct {
			Hash  string `json:"hash"`
			Limit int    `json:"limit"`
		}
		_ = json.Unmarshal(args, &in)
		hash := in.Hash
		if hash == "" {
			hash = x.alert.HashSHA256
		}
		if hash == "" {
			return "", fmt.Errorf("该告警没有文件哈希")
		}
		if in.Limit <= 0 || in.Limit > 50 {
			in.Limit = 20
		}
		items, _, err := x.s.repos.Alerts.List(ctx, domain.AlertFilter{Hash: hash, Page: 1, PageSize: in.Limit, Sort: "oldest"})
		if err != nil {
			return "", err
		}
		hosts := map[string]bool{}
		out := make([]map[string]any, 0, len(items))
		for _, a := range items {
			hosts[a.Hostname] = true
			out = append(out, alertDigest(a))
		}
		return marshalJSON(map[string]any{"hash": hash, "host_count": len(hosts), "count": len(out), "alerts": out})

	case "ioc_check":
		var in struct {
			Hash string `json:"hash"`
		}
		_ = json.Unmarshal(args, &in)
		hash := in.Hash
		if hash == "" {
			hash = x.alert.HashSHA256
		}
		if hash == "" {
			return "", fmt.Errorf("该告警没有文件哈希")
		}
		ioc, err := x.s.repos.IOCs.ByHash(ctx, hash)
		if err != nil {
			return "", err
		}
		if ioc == nil {
			return marshalJSON(map[string]any{"hit": false, "hash": hash})
		}
		return marshalJSON(map[string]any{"hit": true, "hash": ioc.Hash, "note": ioc.Note, "created_at": ioc.CreatedAt})

	case "process_occurrences":
		var in struct {
			ProcessName string `json:"process_name"`
			Limit       int    `json:"limit"`
		}
		_ = json.Unmarshal(args, &in)
		name := in.ProcessName
		if name == "" {
			name = x.alert.ProcessName
		}
		if name == "" {
			return "", fmt.Errorf("该告警没有进程名")
		}
		if in.Limit <= 0 || in.Limit > 50 {
			in.Limit = 20
		}
		items, _, err := x.s.repos.Alerts.List(ctx, domain.AlertFilter{ProcessLike: name, Page: 1, PageSize: in.Limit, Sort: "oldest"})
		if err != nil {
			return "", err
		}
		hosts := map[string]bool{}
		out := make([]map[string]any, 0, len(items))
		for _, a := range items {
			hosts[a.Hostname] = true
			out = append(out, alertDigest(a))
		}
		return marshalJSON(map[string]any{"process_name": name, "host_count": len(hosts), "count": len(out), "alerts": out})

	case "inventory_section":
		var in struct {
			Section string `json:"section"`
		}
		_ = json.Unmarshal(args, &in)
		switch in.Section {
		case "listeners", "services", "tasks", "startup":
		default:
			return "", fmt.Errorf("section 只支持 listeners/services/tasks/startup")
		}
		secs, err := x.s.repos.Inventory.ListByAgent(ctx, x.alert.AgentID)
		if err != nil {
			return "", err
		}
		for _, sec := range secs {
			if sec.Name == in.Section {
				return sec.Payload, nil // 原样返回该节 JSON（引擎负责截断）
			}
		}
		return marshalJSON(map[string]any{"section": in.Section, "absent": true, "note": "该节尚未上报（探针可能未采集成功）"})

	case "fingerprint_history":
		var in struct {
			Limit int `json:"limit"`
		}
		_ = json.Unmarshal(args, &in)
		if in.Limit <= 0 || in.Limit > 50 {
			in.Limit = 20
		}
		// 仓储没有 fingerprint 过滤（内部索引列），按主机最近 200 条粗筛后按指纹精确匹配
		items, _, err := x.s.repos.Alerts.List(ctx, domain.AlertFilter{
			AgentID: x.alert.AgentID, Page: 1, PageSize: 200, Sort: "newest",
		})
		if err != nil {
			return "", err
		}
		same := make([]map[string]any, 0, 8)
		// 判定台账按告警 ID 建索引：同指纹的历史不只看"发生过"，还要看
		// "当时 AI 怎么判、有没有被分析员改判"——复现告警不必从零调查。
		// List 时间倒序，先到者新（同告警多来源只留最新一条）。
		triage := map[string]domain.AITriageLog{}
		if logs, err := x.s.repos.ATriage.List(ctx, 500); err == nil {
			for _, l := range logs {
				if _, ok := triage[l.AlertID]; !ok {
					triage[l.AlertID] = l
				}
			}
		}
		for _, a := range items {
			if a.Fingerprint != x.alert.Fingerprint || a.ID == x.alert.ID {
				continue
			}
			entry := map[string]any{
				"id": a.ID, "hostname": a.Hostname, "status": string(a.Status),
				"verdict": string(a.Verdict), "score": a.Score, "created_at": a.CreatedAt,
			}
			if l, ok := triage[a.ID]; ok {
				entry["ai_triage"] = map[string]any{"source": l.Source, "verdict": l.Verdict,
					"confidence": l.Confidence, "engine": l.Engine, "at": l.CreatedAt}
			}
			same = append(same, entry)
			if len(same) >= in.Limit {
				break
			}
		}
		return marshalJSON(map[string]any{"fingerprint": x.alert.Fingerprint, "count": len(same),
			"note": "仅统计本机历史（仓储无跨主机指纹过滤）；ai_triage=该告警最近一次自动研判快照",
			"history": same})

	case "inventory_changes":
		var in struct {
			Limit int `json:"limit"`
		}
		_ = json.Unmarshal(args, &in)
		if in.Limit <= 0 || in.Limit > 20 {
			in.Limit = 10
		}
		items, err := x.s.repos.Alerts.ListInventoryChanges(ctx, x.alert.AgentID, in.Limit)
		if err != nil {
			return "", err
		}
		out := make([]map[string]any, 0, len(items))
		for _, a := range items {
			out = append(out, alertDigest(a))
		}
		return marshalJSON(map[string]any{"count": len(out), "changes": out})

	case "host_live":
		var in struct {
			Endpoint string         `json:"endpoint"`
			Params   map[string]any `json:"params"`
		}
		_ = json.Unmarshal(args, &in)
		if !agentLiveEndpoints(x.s.eng.AgentToolTimeoutMs())[in.Endpoint] {
			return "", fmt.Errorf("endpoint 不在快速子集内（见工具 schema 枚举；慢端点走管理台或 MCP）")
		}
		if x.s.live == nil || !x.s.live.Enabled {
			return "", fmt.Errorf("实时查询未启用（HG_SERVER_LIVEQUERY_ENABLED），只能基于落库数据调查")
		}
		q := url.Values{}
		for k, v := range in.Params {
			q.Set(k, fmt.Sprint(v))
		}
		// agent 固定为告警主机：模型不能借调查工具横向游走到别的终端
		conn, err := x.s.live.Open(ctx, x.alert.AgentID, in.Endpoint, q, "", "ai-investigate", "")
		if err != nil {
			return "", err
		}
		defer conn.Close()
		body, err := io.ReadAll(io.LimitReader(conn.Body, agentLiveBodyCap))
		if err != nil {
			return "", fmt.Errorf("读取探针响应失败: %w", err)
		}
		if conn.Status != http.StatusOK {
			return "", fmt.Errorf("探针返回 %d: %s", conn.Status, truncateRunes(string(body), 200))
		}
		return string(body), nil
	}
	return "", fmt.Errorf("未知工具 %q", name)
}

func alertDigest(a domain.Alert) map[string]any {
	d := map[string]any{
		"id": a.ID, "title": a.Title, "hostname": a.Hostname, "process_name": a.ProcessName,
		"score": a.Score, "severity": string(a.Severity), "verdict": string(a.Verdict),
		"status": string(a.Status), "created_at": a.CreatedAt,
	}
	if a.HashSHA256 != "" {
		d["hash_sha256"] = a.HashSHA256
	}
	if len(a.MITRE) > 0 {
		d["mitre"] = a.MITRE
	}
	return d
}

func marshalJSON(v any) (string, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

// agentBrief 构造给模型的初始简报（含 E1..En 证据编号，便于 findings 引用）。
func (s *AIService) agentBrief(ctx context.Context, a *domain.Alert) string {
	in, err := s.buildInput(ctx, a)
	if err != nil {
		// 退化为最小简报：宁可少给上下文也不让调查直接失败
		return fmt.Sprintf("告警 %s：%s（%s，%d 分）", a.ID, a.Title, a.Severity, a.Score)
	}
	var b []byte
	b = fmt.Appendf(b, "告警 %s：%s\n主机: %s（agent_id=%s）\n进程: %s 路径: %s\n",
		a.ID, a.Title, a.Hostname, a.AgentID, a.ProcessName, a.ImagePath)
	if a.CmdLine != "" {
		b = fmt.Appendf(b, "命令行: %s\n", a.CmdLine)
	}
	b = fmt.Appendf(b, "账号: %s 哈希: %s 签名: signed=%v signer=%s\n", a.ProcUser, a.HashSHA256, a.Signed, a.Signer)
	if len(a.MITRE) > 0 {
		b = fmt.Appendf(b, "ATT&CK: %v 规则: %v\n", a.MITRE, a.RuleIDs)
	}
	b = fmt.Appendf(b, "指纹: %s 状态: %s 引擎结论: %s/%d 分\n证据:\n", a.Fingerprint, a.Status, a.Verdict, a.Score)
	for _, e := range in.Evidence {
		b = fmt.Appendf(b, "%s [%s] %s（%d 分）：%s\n", e.ID, e.Layer, e.Name, e.Score, e.Detail)
	}
	for _, anc := range in.Ancestry {
		b = fmt.Appendf(b, "祖先: pid=%d %s %s\n", anc.PID, anc.Name, anc.Path)
	}
	if in.Host.OS != "" {
		b = fmt.Appendf(b, "系统: %s\n", in.Host.OS)
	}
	return string(b)
}

// agentInvestigateCache 是 Agent 报告缓存（与确定性调查同一 TTL 口径）。
const agentInvestigateCacheTTL = 30 * time.Minute

type agentCacheEntry struct {
	rep *ai.AgentReport
	at  time.Time
}

var agentCacheMu sync.Mutex
var agentCache = map[string]agentCacheEntry{}

// AgentInvestigate 运行 Agent 调查；模型不可用时回退确定性五步并如实标注。
func (s *AIService) AgentInvestigate(ctx context.Context, alertID string) (*ai.AgentReport, error) {
	a, err := s.repos.Alerts.ByID(ctx, alertID)
	if err != nil {
		return nil, err
	}
	if a == nil {
		return nil, apperr.NotFound("告警不存在")
	}

	rep := s.eng.AgentInvestigate(ctx, s.agentBrief(ctx, a),
		agentTools(s.eng.AgentToolTimeoutMs()), &agentToolExec{s: s, alert: a})
	if rep.Degraded && len(rep.Findings) == 0 {
		// 确定性五步兜底：报告结构与字段对齐，界面无需区分两种模式
		if inv, err := s.Investigate(ctx, alertID); err == nil {
			rep = deterministicAgentReport(inv, rep.DegradedReason)
		}
	}

	// 判定台账：Agentic 结论（模型自主调查）进质量对账；降级走兜底时
	// Investigate 内部已写过 heuristic 台账，这里只在模型真出结论时覆盖
	if !rep.Degraded {
		s.recordTriage(ctx, alertID, triageSourceAI, rep.Verdict, rep.Confidence, rep.Engine)
	}

	agentCacheMu.Lock()
	agentCache[alertID] = agentCacheEntry{rep: rep, at: time.Now()}
	agentCacheMu.Unlock()

	if s.log != nil {
		s.log.InfoContext(ctx, "ai_agent_investigate", "alert_id", alertID,
			"engine", rep.Engine, "tool_calls", rep.ToolCalls, "steps", len(rep.Steps),
			"degraded", rep.Degraded, "latency_ms", rep.LatencyMs)
	}
	return rep, nil
}

// CachedAgentReport 返回缓存的 Agent 报告（过期返回 nil）。
func (s *AIService) CachedAgentReport(alertID string) *ai.AgentReport {
	agentCacheMu.Lock()
	defer agentCacheMu.Unlock()
	ent, ok := agentCache[alertID]
	if !ok || time.Since(ent.at) > agentInvestigateCacheTTL {
		return nil
	}
	return ent.rep
}

// deterministicAgentReport 把五步确定性调查映射成 Agent 报告结构。
func deterministicAgentReport(inv *Investigation, reason string) *ai.AgentReport {
	rep := &ai.AgentReport{
		Engine: "heuristic", Model: "heuristic-v1",
		Degraded: true, DegradedReason: reason,
		Verdict: inv.VerdictSuggestion, Confidence: inv.Confidence,
		Summary: fmt.Sprintf("确定性五步调查完成：%d 步取证，结论 %s（置信度 %.0f%%）。",
			len(inv.Steps), VerdictLabel(inv.VerdictSuggestion), inv.Confidence*100),
	}
	uncited := 0
	for i, st := range inv.Steps {
		cites := st.Citations
		if len(cites) == 0 {
			// 否定性发现（"未发现持久化痕迹"/"无关联告警"）没有独立证据可引，
			// 以"对本次告警的核查"为锚点——保留可追溯性，不假装有独立证据。
			cites = []string{"核查:" + inv.AlertID}
		}
		rep.Findings = append(rep.Findings, ai.Reason{Text: st.Name + "：" + st.Finding, Citations: cites})
		rep.Steps = append(rep.Steps, ai.AgentStep{
			Step: i + 1, Tool: "确定性:" + st.Name,
			ResultPreview: st.Finding, ResultBytes: len(st.Finding),
		})
	}
	rep.Uncited = uncited
	rep.Grounded = len(rep.Findings) > 0 && uncited == 0
	for _, ra := range inv.RecommendedActions {
		rep.Actions = append(rep.Actions, ai.Action{
			Type: ra.Action, Target: ra.Target, Detail: ra.Reason, RequiresApproval: true,
		})
	}
	return rep
}
