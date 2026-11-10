package mcp

// server_test.go：官方 SDK 协议面下的本包契约测试。协议正确性（握手/
// discover/协商）由 SDK 上游保证；这里锁的是**我们的层**——工具注册与
// 分发、错误 isError 语义、结果截断、annotations 透传、无状态 POST
//（不握手直接调用）、无 session 头（2026-07-28 无状态核心特征）。

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type fakeExecutor struct {
	lastArgs string
	result   any
	err      error
}

func (f *fakeExecutor) Call(ctx context.Context, name string, args json.RawMessage) (any, error) {
	f.lastArgs = string(args)
	if f.err != nil {
		return nil, f.err
	}
	if f.result != nil {
		return f.result, nil
	}
	return map[string]any{"ok": true}, nil
}

func newTestServer(t *testing.T, ex Executor) (*Server, *httptest.Server) {
	t.Helper()
	s := &Server{
		Name: "zedr-test", Version: "v0",
		Tools: []Tool{
			{Name: "alpha", Description: "A 工具", InputSchema: json.RawMessage(`{"type":"object","properties":{"x":{"type":"integer"}}}`),
				Annotations: map[string]any{"readOnlyHint": true, "openWorldHint": false}},
			{Name: "beta", Description: "B 工具", InputSchema: json.RawMessage(`{"type":"object"}`)},
		},
		Ex: ex,
	}
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)
	return s, ts
}

func post(t *testing.T, url string, body any) (int, map[string]any) {
	t.Helper()
	raw, _ := json.Marshal(body)
	req, _ := http.NewRequest("POST", url, strings.NewReader(string(raw)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream") // Streamable HTTP 规范要求双类型
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("响应不是 JSON: %v", err)
	}
	return resp.StatusCode, out
}

// 无握手直接 tools/call：无状态模式每请求自包含，不需要 initialize。
func TestStatelessCallWithoutHandshake(t *testing.T) {
	ex := &fakeExecutor{}
	_, ts := newTestServer(t, ex)
	code, out := post(t, ts.URL, map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "tools/call",
		"params": map[string]any{"name": "alpha", "arguments": map[string]any{"x": 7}},
	})
	if code != http.StatusOK {
		t.Fatalf("状态码 %d", code)
	}
	if _, hasErr := out["error"]; hasErr {
		t.Fatalf("不应有协议错误: %v", out["error"])
	}
	if ex.lastArgs != `{"x":7}` {
		t.Fatalf("参数透传失真: %s", ex.lastArgs)
	}
}

func TestToolErrorIsResultNotProtocolError(t *testing.T) {
	ex := &fakeExecutor{err: fmt.Errorf("主机离线")}
	_, ts := newTestServer(t, ex)
	_, out := post(t, ts.URL, map[string]any{
		"jsonrpc": "2.0", "id": 2, "method": "tools/call",
		"params": map[string]any{"name": "alpha"},
	})
	res, _ := out["result"].(map[string]any)
	if res == nil {
		t.Fatal("缺 result")
	}
	if res["isError"] != true {
		t.Fatalf("工具错误应置 isError=true: %v", res)
	}
	content, _ := res["content"].([]any)
	if len(content) == 0 {
		t.Fatal("缺错误文本")
	}
}

func TestUnknownToolIsProtocolError(t *testing.T) {
	// 未知工具在 SDK 分发层按规范拒绝（协议错误 -32602），不到工具 handler
	_, ts := newTestServer(t, &fakeExecutor{})
	_, out := post(t, ts.URL, map[string]any{
		"jsonrpc": "2.0", "id": 3, "method": "tools/call",
		"params": map[string]any{"name": "nope"},
	})
	e, _ := out["error"].(map[string]any)
	if e == nil {
		t.Fatalf("未知工具应是协议错误: %v", out)
	}
	if code, _ := e["code"].(float64); code != -32602 {
		t.Fatalf("错误码应为 -32602: %v", e)
	}
}

func TestToolsListSortedWithAnnotations(t *testing.T) {
	_, ts := newTestServer(t, &fakeExecutor{})
	_, out := post(t, ts.URL, map[string]any{"jsonrpc": "2.0", "id": 4, "method": "tools/list"})
	res, _ := out["result"].(map[string]any)
	tools, _ := res["tools"].([]any)
	if len(tools) != 2 {
		t.Fatalf("工具数 %d", len(tools))
	}
	first, _ := tools[0].(map[string]any)
	if first["name"] != "alpha" {
		t.Fatalf("排序错误: %v", first["name"])
	}
	ann, _ := first["annotations"].(map[string]any)
	if ann["readOnlyHint"] != true {
		t.Fatalf("readOnlyHint 未透传: %v", ann)
	}
}

func TestResultTruncated(t *testing.T) {
	ex := &fakeExecutor{result: map[string]any{"blob": strings.Repeat("x", 200<<10)}}
	_, ts := newTestServer(t, ex)
	_, out := post(t, ts.URL, map[string]any{
		"jsonrpc": "2.0", "id": 5, "method": "tools/call",
		"params": map[string]any{"name": "beta"},
	})
	res, _ := out["result"].(map[string]any)
	content, _ := res["content"].([]any)
	first, _ := content[0].(map[string]any)
	text, _ := first["text"].(string)
	if !strings.HasSuffix(text, "(结果超限已截断)") {
		t.Fatalf("截断标记缺失: %d ...%q", len(text), text[max(0, len(text)-40):])
	}
	if len(text) > mcpResultLimit+64 {
		t.Fatalf("结果未截断: %d", len(text))
	}
}

// 2026-07-28 无状态规范的 server/discover：SDK 自动实现——需带协议版本
// 头（无头请求按 legacy 2025-11-25 处理，discover 在该版本不存在，
// 这正是双版本协商的预期行为）。
func TestServerDiscover(t *testing.T) {
	_, ts := newTestServer(t, &fakeExecutor{})
	body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 6, "method": "server/discover",
		"params": map[string]any{"_meta": map[string]any{
				"io.modelcontextprotocol/protocolVersion": "2026-07-28",
				"io.modelcontextprotocol/clientCapabilities": map[string]any{},
			}}})
	req, _ := http.NewRequest("POST", ts.URL, strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("MCP-Protocol-Version", "2026-07-28")
	req.Header.Set("Mcp-Method", "server/discover") // 2026-07-28：方法名走头，网关可直接路由
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	res, _ := out["result"].(map[string]any)
	if res == nil {
		t.Fatalf("discover 应可用: %v", out)
	}
	versions, _ := res["supportedVersions"].([]any)
	if len(versions) == 0 {
		t.Fatalf("discover 缺 supportedVersions: %v", res)
	}
	// 2026-07-28 可缓存列表（SEP-2549）：resultType 必在
	if _, ok := res["resultType"]; !ok {
		t.Fatalf("discover 缺 resultType: %v", res)
	}
}

// 无状态核心的行为特征：响应不带 Mcp-Session-Id。
func TestNoSessionHeader(t *testing.T) {
	ex := &fakeExecutor{}
	_, ts := newTestServer(t, ex)
	raw, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": 7, "method": "tools/call",
		"params": map[string]any{"name": "alpha"},
	})
	req, _ := http.NewRequest("POST", ts.URL, strings.NewReader(string(raw)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if sid := resp.Header.Get("Mcp-Session-Id"); sid != "" {
		t.Fatalf("无状态模式不应下发 session id: %q", sid)
	}
}
