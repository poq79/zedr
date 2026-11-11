package ai

// agent_budget_test.go：Agent 循环预算可配置化（HG_AI_AGENT_MAX_STEPS /
// HG_AI_AGENT_TOOL_TIMEOUT → ai.Config → ApplyConfig 钳制 → 循环生效）
// 的契约测试。核心保证：未配置时行为与历史硬编码完全一致。

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// scriptedEngine 与 newAgentEngine 同构，但预算字段与槽位可指定。
func scriptedEngine(t *testing.T, fm *fakeAgentModel, cfg Config) *Engine {
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
	if cfg.Slots == nil {
		cfg.Slots = map[string]SlotConfig{
			SlotTriage: {Provider: "openai", BaseURL: srv, Model: "fake-model", Timeout: 5 * time.Second, Enabled: true},
		}
	}
	return NewEngine(cfg, testLogger())
}

// 模型永远只回工具调用：循环必须被步数预算强行终止。
func TestAgentBudgetMaxStepsHonored(t *testing.T) {
	alwaysCall := &fakeAgentModel{responses: []string{
		"TOOLCALL:t1:host_recent_alerts:{}",
		"TOOLCALL:t2:host_recent_alerts:{}",
		"TOOLCALL:t3:host_recent_alerts:{}",
		"TOOLCALL:t4:host_recent_alerts:{}",
		"TOOLCALL:t5:host_recent_alerts:{}",
		"TOOLCALL:t6:host_recent_alerts:{}",
		"TOOLCALL:t7:host_recent_alerts:{}",
		"TOOLCALL:t8:host_recent_alerts:{}",
		"TOOLCALL:t9:host_recent_alerts:{}",
		"TOOLCALL:t10:host_recent_alerts:{}",
	}}
	eng := scriptedEngine(t, alwaysCall, Config{AgentMaxSteps: 2, AgentMaxToolCalls: 99})
	ex := &recordingExecutor{result: `{"count":0}`}
	rep := eng.AgentInvestigate(context.Background(), "告警：预算测试", agentToolsForTest(), ex)
	if !rep.Degraded {
		t.Fatal("步数耗尽应降级")
	}
	if rep.ToolCalls > 2 {
		t.Fatalf("步数预算未生效：tool_calls=%d", rep.ToolCalls)
	}
	if !rep.StepsLimitReached && len(rep.Steps) == 0 {
		t.Fatal("应有步骤留痕")
	}
}

// 默认零值配置：行为与历史硬编码一致（6 步/8 次）。
func TestAgentBudgetDefaults(t *testing.T) {
	maxSteps, maxCalls, timeout := (&Engine{}).agentBudget()
	if maxSteps != 6 || maxCalls != 8 || timeout != 10*time.Second {
		t.Fatalf("默认预算漂移: %d/%d/%s", maxSteps, maxCalls, timeout)
	}
}

// ApplyConfig 钳制：防误配（99 步 → 12 上限）。
func TestAgentBudgetClamped(t *testing.T) {
	eng := NewEngine(Config{}, testLogger())
	eng.ApplyConfig(Config{AgentMaxSteps: 99, AgentMaxToolCalls: 500,
		AgentToolTimeout: 5 * time.Minute}, nil, nil)
	maxSteps, maxCalls, timeout := eng.agentBudget()
	if maxSteps != 12 || maxCalls != 24 || timeout != 60*time.Second {
		t.Fatalf("钳制未生效: %d/%d/%s", maxSteps, maxCalls, timeout)
	}
}

// 单工具超时可配：慢执行器在短预算下必须报错而不是挂满默认 10s。
func TestAgentBudgetToolTimeout(t *testing.T) {
	eng := NewEngine(Config{}, testLogger())
	slow := &sleepExecutor{d: 300 * time.Millisecond}
	start := time.Now()
	_, errStr := eng.execTool(context.Background(),
		map[string]AgentTool{"slow": {Name: "slow", Description: "d", Parameters: json.RawMessage(`{}`)}},
		slow, ToolCall{ID: "1", Name: "slow", Arguments: "{}"}, 50*time.Millisecond)
	if errStr == "" {
		t.Fatal("超时应产生错误说明")
	}
	if time.Since(start) > 2*time.Second {
		t.Fatalf("超时未生效，耗时 %s", time.Since(start))
	}
}

type sleepExecutor struct{ d time.Duration }

func (s *sleepExecutor) Execute(ctx context.Context, name string, args json.RawMessage) (string, error) {
	select {
	case <-ctx.Done():
		return "", ctx.Err()
	case <-time.After(s.d):
		return `{"ok":true}`, nil
	}
}

// ToolCall 结构在测试外不可直接构造时的兜底（若字段不导出本测试会编译失败，
// 届时改走 AgentInvestigate 全链路）。
var _ = http.MethodPost
var _ = httptest.NewServer
