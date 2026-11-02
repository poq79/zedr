package ai

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// fakeRawServer 起一个假模型服务：解码请求体交给 fn，返回 fn 的结果。
func fakeRawServer(t *testing.T, fn func(body map[string]any) map[string]any) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/chat/completions" {
			http.NotFound(w, r)
			return
		}
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(fn(body))
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

// fakeAgentModel 按脚本返回响应，并记录每一次请求体（用于断言回喂内容）。
type fakeAgentModel struct {
	responses []string // 依次返回的 assistant content（可为工具调用 JSON）
	requests  []map[string]any
}

func newAgentEngine(t *testing.T, fm *fakeAgentModel) *Engine {
	t.Helper()
	srv := fakeRawServer(t, func(body map[string]any) map[string]any {
		fm.requests = append(fm.requests, body)
		idx := len(fm.requests) - 1
		content := ""
		if idx < len(fm.responses) {
			content = fm.responses[idx]
		}
		msg := map[string]any{"content": content}
		if strings.HasPrefix(content, "TOOLCALL:") {
			// 格式：TOOLCALL:<id>:<name>:<args-json>
			parts := strings.SplitN(strings.TrimPrefix(content, "TOOLCALL:"), ":", 3)
			msg["content"] = ""
			msg["tool_calls"] = []map[string]any{{
				"id": parts[0], "type": "function",
				"function": map[string]any{"name": parts[1], "arguments": parts[2]},
			}}
		}
		return map[string]any{
			"choices": []map[string]any{{"message": msg, "finish_reason": "stop"}},
			"usage":   map[string]any{"total_tokens": 10},
		}
	})
	eng := NewEngine(Config{Slots: map[string]SlotConfig{
		SlotTriage: {Provider: "openai", BaseURL: srv, Model: "fake-model", Timeout: 5 * time.Second, Enabled: true},
	}}, testLogger())
	return eng
}

type recordingExecutor struct {
	calls  []string
	result string
	err    error
}

func (r *recordingExecutor) Execute(_ context.Context, name string, _ json.RawMessage) (string, error) {
	r.calls = append(r.calls, name)
	if r.err != nil {
		return "", r.err
	}
	return r.result, nil
}

func agentToolsForTest() []AgentTool {
	return []AgentTool{{Name: "host_recent_alerts", Description: "test", Parameters: json.RawMessage(`{"type":"object"}`)}}
}

const agentFinalJSON = `{"summary":"样本未扩散","verdict":"suspicious","confidence":0.7,` +
	`"findings":[{"text":"其他主机未检出同一样本","citations":["abc123"]}],` +
	`"actions":[{"type":"hunt","target":"EVAL","detail":"检索扩散","requires_approval":false}]}`

// 完整循环：工具调用 → 结果回喂 → 最终 JSON；引用/审批/引擎标注。
func TestAgentInvestigateLoop(t *testing.T) {
	fm := &fakeAgentModel{responses: []string{
		`TOOLCALL:call1:host_recent_alerts:{"limit":5}`,
		agentFinalJSON,
	}}
	eng := newAgentEngine(t, fm)
	ex := &recordingExecutor{result: `{"count":0}`}

	rep := eng.AgentInvestigate(context.Background(), "告警 X：测试", agentToolsForTest(), ex)
	if rep.Degraded {
		t.Fatalf("不应降级: %s", rep.DegradedReason)
	}
	if rep.Engine != "llm" || rep.Model != "openai-compatible:fake-model" {
		t.Fatalf("引擎标注不对: %s/%s", rep.Engine, rep.Model)
	}
	if len(ex.calls) != 1 || ex.calls[0] != "host_recent_alerts" {
		t.Fatalf("工具应被调用一次: %v", ex.calls)
	}
	if rep.ToolCalls != 1 || len(rep.Steps) != 1 {
		t.Fatalf("步数记录不对: calls=%d steps=%d", rep.ToolCalls, len(rep.Steps))
	}
	if rep.Verdict != "suspicious" || !rep.Grounded || rep.Uncited != 0 {
		t.Fatalf("结论/引用不对: %+v", rep)
	}
	if len(rep.Actions) != 1 || !rep.Actions[0].RequiresApproval {
		t.Fatal("处置建议必须被强制人工确认")
	}
	// 第二次请求必须携带 tool 消息（工具结果回喂）
	if len(fm.requests) != 2 {
		t.Fatalf("应有两次模型调用，实际 %d", len(fm.requests))
	}
	msgs, _ := fm.requests[1]["messages"].([]any)
	foundTool := false
	for _, m := range msgs {
		if mm, ok := m.(map[string]any); ok && mm["role"] == "tool" {
			foundTool = true
		}
	}
	if !foundTool {
		t.Fatal("工具结果没有回喂给模型")
	}
}

// 未知工具：不执行、错误作为结果回喂，模型仍能收尾。
func TestAgentRejectsUnknownTool(t *testing.T) {
	fm := &fakeAgentModel{responses: []string{
		`TOOLCALL:call1:delete_everything:{}`,
		agentFinalJSON,
	}}
	eng := newAgentEngine(t, fm)
	ex := &recordingExecutor{result: "ok"}
	rep := eng.AgentInvestigate(context.Background(), "brief", agentToolsForTest(), ex)
	if len(ex.calls) != 0 {
		t.Fatalf("未知工具绝不能被执行: %v", ex.calls)
	}
	if len(rep.Steps) != 1 || !strings.Contains(rep.Steps[0].Err, "未知工具") {
		t.Fatalf("应记录未知工具错误: %+v", rep.Steps)
	}
	if rep.Degraded {
		t.Fatal("模型收尾成功时不应降级")
	}
}

// 步数硬顶：模型一直要工具 → 到上限强制收尾并标注；不无限循环。
func TestAgentStepLimit(t *testing.T) {
	seq := make([]string, agentMaxSteps)
	for i := range seq {
		seq[i] = `TOOLCALL:c:host_recent_alerts:{}`
	}
	fm := &fakeAgentModel{responses: seq}
	eng := newAgentEngine(t, fm)
	rep := eng.AgentInvestigate(context.Background(), "brief", agentToolsForTest(), &recordingExecutor{result: `{"count":1}`})
	if len(fm.requests) != agentMaxSteps {
		t.Fatalf("模型调用次数应等于步数上限 %d，实际 %d", agentMaxSteps, len(fm.requests))
	}
	if !rep.StepsLimitReached {
		t.Fatal("应标注触顶")
	}
	if !rep.Degraded || !strings.Contains(rep.DegradedReason, "未给出结论") {
		t.Fatalf("触顶无结论时应降级并说明: %+v", rep)
	}
	// 最后一次调用必须带 tool_choice:none（收尾调用）
	last := fm.requests[len(fm.requests)-1]
	if last["tool_choice"] != "none" {
		t.Fatalf("收尾调用应 tool_choice=none，实际 %v", last["tool_choice"])
	}
}

// 工具错误回喂：错误文本进入 tool 消息，模型可据此调整。
func TestAgentToolErrorFedBack(t *testing.T) {
	fm := &fakeAgentModel{responses: []string{
		`TOOLCALL:c1:host_recent_alerts:{}`,
		agentFinalJSON,
	}}
	eng := newAgentEngine(t, fm)
	ex := &recordingExecutor{err: errors.New("查询超时")}
	rep := eng.AgentInvestigate(context.Background(), "brief", agentToolsForTest(), ex)
	if len(rep.Steps) != 1 || !strings.Contains(rep.Steps[0].Err, "查询超时") {
		t.Fatalf("步骤应记录错误: %+v", rep.Steps)
	}
	msgs, _ := fm.requests[1]["messages"].([]any)
	found := false
	for _, m := range msgs {
		if mm, ok := m.(map[string]any); ok && mm["role"] == "tool" && strings.Contains(mm["content"].(string), "工具错误") {
			found = true
		}
	}
	if !found {
		t.Fatal("工具错误应作为结果回喂")
	}
}

// 结果截断：10KB 结果回喂时保留头尾并标注截断。
func TestAgentToolResultTruncated(t *testing.T) {
	fm := &fakeAgentModel{responses: []string{
		`TOOLCALL:c1:host_recent_alerts:{}`,
		agentFinalJSON,
	}}
	eng := newAgentEngine(t, fm)
	big := strings.Repeat("A", 5000) + strings.Repeat("B", 5000)
	ex := &recordingExecutor{result: big}
	rep := eng.AgentInvestigate(context.Background(), "brief", agentToolsForTest(), ex)
	if rep.Steps[0].ResultBytes != 10000 {
		t.Fatalf("应记录原始大小 10000，实际 %d", rep.Steps[0].ResultBytes)
	}
	msgs, _ := fm.requests[1]["messages"].([]any)
	for _, m := range msgs {
		if mm, ok := m.(map[string]any); ok && mm["role"] == "tool" {
			content := mm["content"].(string)
			if len(content) > agentToolResultCap+200 {
				t.Fatalf("回喂内容未截断: %d 字节", len(content))
			}
			if !strings.Contains(content, "已截断") {
				t.Fatal("截断应带标注")
			}
			if !strings.HasPrefix(content, "AAAA") || !strings.HasSuffix(content, "BBBB") {
				t.Fatal("截断应保留头尾")
			}
		}
	}
}

// 未配置模型：直接降级（服务层据此回退确定性五步）。
func TestAgentWithoutModelDegrades(t *testing.T) {
	eng := NewEngine(Config{Provider: "none"}, testLogger())
	rep := eng.AgentInvestigate(context.Background(), "brief", agentToolsForTest(), &recordingExecutor{})
	if !rep.Degraded || !strings.Contains(rep.DegradedReason, "未配置") {
		t.Fatalf("应降级并说明原因: %+v", rep)
	}
	if eng.AgentAvailable() {
		t.Fatal("无模型时 AgentAvailable 应为 false")
	}
}

// Agent Chat：历史传入 + 工具调用 + 最终 answer 解析；历史条数与长度被钳制。
func TestAgentChatLoop(t *testing.T) {
	fm := &fakeAgentModel{responses: []string{
		`TOOLCALL:c1:host_recent_alerts:{"limit":5}`,
		`{"answer":"最近 24 小时有 0 条未签名告警（引用：无）。"}`,
	}}
	eng := newAgentEngine(t, fm)
	ex := &recordingExecutor{result: `{"count":0}`}
	hist := []ChatTurn{
		{Role: "user", Content: strings.Repeat("旧问题", 2000)},
		{Role: "assistant", Content: "旧回答"},
	}
	rep := eng.AgentChat(context.Background(), "最近有没有未签名告警？", hist, agentToolsForTest(), ex)
	if rep.Degraded {
		t.Fatalf("不应降级: %s", rep.DegradedReason)
	}
	if !strings.Contains(rep.Answer, "未签名") || rep.ToolCalls != 1 {
		t.Fatalf("回答/工具调用不对: %+v", rep)
	}
	// 第一次请求的 messages：system + 钳制后的历史 + 当前问题
	msgs, _ := fm.requests[0]["messages"].([]any)
	if len(msgs) != 4 { // system + user(hist) + assistant(hist) + user(question)
		t.Fatalf("历史消息数不对: %d", len(msgs))
	}
	last := msgs[len(msgs)-1].(map[string]any)
	if last["role"] != "user" || !strings.Contains(last["content"].(string), "未签名") {
		t.Fatalf("最后一条应是当前问题: %v", last)
	}
}

// 未配置模型：chat 诚实降级，不抛出错误。
func TestAgentChatWithoutModel(t *testing.T) {
	eng := NewEngine(Config{Provider: "none"}, testLogger())
	rep := eng.AgentChat(context.Background(), "帮我查最近告警", nil, agentToolsForTest(), &recordingExecutor{})
	if !rep.Degraded || !strings.Contains(rep.DegradedReason, "未配置") {
		t.Fatalf("应降级并说明原因: %+v", rep)
	}
	if rep.Answer != "" {
		t.Fatal("降级时不应编造回答")
	}
}
