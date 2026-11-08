package service

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"zedr/internal/mcp"
	"zedr/internal/server/domain"
)

// MCP 对外工具集的只读实现（与 Agent 调查同一纪律：模型/客户端只能读）。
//
// 证据（2026-11 取证）：Wazuh 生态的 MCP Server 全部只读默认、写入需显式
// ALLOW_WRITES；工具按功能域拆分、数量控制在数十个以内。v1 八件工具覆盖
// "查告警/事件/情报/清单/猎况/状态"；v2（2026-11-09）补实时调查桥：
// host_live 经隧道现采（与管理台同一执法点 service.LiveQueryService），
// intel_lookup 补非哈希情报面，host_inventory 补齐落库未暴露的三节。
// 仍无任何写操作。

// mcpLiveBlocked 是 host_live 对 AI 关闭的端点：fs/read 是文本内容流、
// collect 是 128MB 二进制 zip——两者都是大块内容出站，对模型价值低
// （模型要哈希用 fs/hash、要 PE 分析用 analyze 即可）且审计回放成本高，
// 白名单在此二次收口（服务端 LiveQueryService 还有子开关兜底）。
var mcpLiveBlocked = map[string]bool{"fs/read": true, "collect": true}

// mcpLiveBodyCap 是 host_live 单次响应的读取上限：MCP 协议层本就截断
// 64KB（internal/mcp server.go），这里放宽到 4MB 只为 JSON 完整解析，
// 防止个别枚举端点在异常大主机上把服务端内存吃穿。
const mcpLiveBodyCap = 4 << 20

// truncateRunes 截断超长文本（错误摘要用），不产生半个 rune。
func truncateRunes(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}

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
		{Name: "intel_lookup", Description: "在非哈希威胁情报库中精确匹配一个值（只读）：ip=远端IP、path=文件路径、keyword=动态关键词；哈希请改用 ioc_lookup",
			InputSchema: json.RawMessage(`{"type":"object","properties":{"type":{"type":"string","enum":["ip","path","keyword"]},"value":{"type":"string"}},"required":["type","value"]}`)},
		{Name: "host_inventory", Description: "读取主机资产清单：不带 section 返回节名与摘要，带 section 返回该节 JSON（只读）",
			InputSchema: json.RawMessage(`{"type":"object","properties":{"agent_id":{"type":"string"},"section":{"type":"string","enum":["system","adapters","listeners","services","tasks","startup","agent","accounts","defender","firewall"]}},"required":["agent_id"]}`)},
		{Name: "hunt", Description: "自然语言检索告警（内部翻译成受控 DSL 后执行；模型接触不到 SQL）",
			InputSchema: json.RawMessage(`{"type":"object","properties":{"query":{"type":"string","maxLength":500}},"required":["query"]}`)},
		{Name: "host_live", Description: "对指定主机实时只读调查（探针在线时经隧道现采，非落库快照）。endpoint 取值：" +
			"processes 进程表 | netstat 连接 | procinfo 单进程详情(pid) | persistence 持久化驻留 | " +
			"tasks 计划任务 | services 服务 | drivers 内核驱动 | registry 注册表键值(path=HKLM\\...) | " +
			"evtlog 事件日志(channel,ids,minutes) | accounts 账户 | sessions 登录会话 | " +
			"netinfo ARP·路由·DNS缓存 | usn 卷级文件活动(volume,minutes) | info 探针状态 | " +
			"baseline 安全基线 | recon 资产侦查 | peers 外联聚合 | " +
			"fs 目录浏览(path) | fs/stat 文件属性(path) | fs/hash 文件SHA256(path) | fs/search 限深搜索(path,pattern) | " +
			"analyze PE分析(md5/sha1/sha256/熵/imphash)(path) | ads 流与下载来源(path) | " +
			"handles 进程句柄(pid) | handleowners 文件占用者(path) | threads 线程起始地址(pid) | memscan 内存元数据(pid)。括号内为 params 键",
			InputSchema: json.RawMessage(`{"type":"object","properties":{
				"agent_id":{"type":"string"},
				"endpoint":{"type":"string"},
				"params":{"type":"object","additionalProperties":{"type":["string","number","boolean"]}}},
				"required":["agent_id","endpoint"]}`)},
		{Name: "system_status", Description: "平台运况摘要：主机数/在线数/未处置告警/AI 引擎与预算（只读）",
			InputSchema: json.RawMessage(`{"type":"object","properties":{}}`)},
	}
}

// MCPExecutor 实现 mcp.Executor。
type MCPExecutor struct {
	ai   *AIService
	live *LiveQueryService
}

func NewMCPExecutor(ai *AIService, live *LiveQueryService) *MCPExecutor {
	return &MCPExecutor{ai: ai, live: live}
}

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

	case "intel_lookup":
		var in struct {
			Type  string `json:"type"`
			Value string `json:"value"`
		}
		_ = json.Unmarshal(args, &in)
		switch in.Type {
		case "ip", "path", "keyword":
		default:
			return nil, fmt.Errorf("type 只支持 ip/path/keyword")
		}
		if in.Value == "" {
			return nil, fmt.Errorf("缺少 value")
		}
		it, err := x.ai.repos.Intel.ByValue(ctx, in.Type, in.Value)
		if err != nil {
			return nil, err
		}
		if it == nil {
			return map[string]any{"hit": false, "type": in.Type, "value": in.Value}, nil
		}
		out := map[string]any{"hit": true, "id": it.ID, "type": it.Type, "value": it.Value,
			"name": it.Name, "note": it.Note, "score": it.Score, "created_at": it.CreatedAt}
		if it.MITRE != "" {
			out["mitre"] = it.MITRE
		}
		return out, nil

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

	case "host_live":
		var in struct {
			AgentID  string         `json:"agent_id"`
			Endpoint string         `json:"endpoint"`
			Params   map[string]any `json:"params"`
		}
		_ = json.Unmarshal(args, &in)
		if in.AgentID == "" {
			return nil, fmt.Errorf("缺少 agent_id")
		}
		if in.Endpoint == "" {
			return nil, fmt.Errorf("缺少 endpoint")
		}
		if mcpLiveBlocked[in.Endpoint] {
			return nil, fmt.Errorf("endpoint %q 不对 AI 开放（内容出站面；用 fs/hash 或 analyze 代替）", in.Endpoint)
		}
		if _, ok := LiveEndpoints[in.Endpoint]; !ok {
			return nil, fmt.Errorf("未知 endpoint %q（可选值见 tools/list 的 host_live 描述）", in.Endpoint)
		}
		if x.live == nil {
			return nil, fmt.Errorf("实时查询未接线（HG_SERVER_LIVEQUERY_ENABLED 关闭或老版本部署）")
		}
		q := url.Values{}
		for k, v := range in.Params {
			q.Set(k, fmt.Sprint(v))
		}
		conn, err := x.live.Open(ctx, in.AgentID, in.Endpoint, q, "", "mcp", "")
		if err != nil {
			return nil, err
		}
		defer conn.Close()
		body, err := io.ReadAll(io.LimitReader(conn.Body, mcpLiveBodyCap+1))
		if err != nil {
			return nil, fmt.Errorf("读取探针响应失败: %w", err)
		}
		if int64(len(body)) > mcpLiveBodyCap {
			return nil, fmt.Errorf("响应超过 %d 字节上限（收窄查询参数后重试）", mcpLiveBodyCap)
		}
		if conn.Status != http.StatusOK {
			return nil, fmt.Errorf("探针返回 %d: %s", conn.Status, truncateRunes(string(body), 300))
		}
		if !json.Valid(body) {
			return map[string]any{"agent_id": in.AgentID, "endpoint": in.Endpoint,
				"status": conn.Status, "raw": string(body)}, nil
		}
		// 探针侧 httpx.WriteJSON 带 {data:...} 全站包装；对模型解掉一层，
		// 让工具结果直接就是端点数据（错误结构 {error:{message}} 同理解包）
		var env struct {
			Data  json.RawMessage `json:"data"`
			Error *struct {
				Code    string `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}
		payload := json.RawMessage(body)
		if err := json.Unmarshal(body, &env); err == nil && env.Error != nil {
			return nil, fmt.Errorf("探针错误 %s: %s", env.Error.Code, env.Error.Message)
		} else if err == nil && len(env.Data) > 0 {
			payload = env.Data
		}
		return map[string]any{"agent_id": in.AgentID, "endpoint": in.Endpoint,
			"status": conn.Status, "data": payload}, nil

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
