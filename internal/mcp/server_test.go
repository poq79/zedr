package mcp

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

type fakeExec struct{ calls []string }

func (f *fakeExec) Call(_ context.Context, name string, args json.RawMessage) (any, error) {
	f.calls = append(f.calls, name)
	if name == "boom" {
		return nil, errBoom
	}
	return map[string]any{"echo": string(args)}, nil
}

var errBoom = &fakeErr{}

type fakeErr struct{}

func (fakeErr) Error() string { return "执行失败" }

func newTestServer() (*Server, *fakeExec) {
	ex := &fakeExec{}
	return &Server{
		Name: "test", Version: "0",
		Tools: []Tool{
			{Name: "alpha", Description: "第一个", InputSchema: json.RawMessage(`{"type":"object"}`)},
			{Name: "boom", Description: "失败工具", InputSchema: json.RawMessage(`{"type":"object"}`)},
		},
		Ex: ex,
	}, ex
}

func TestInitializeAndList(t *testing.T) {
	s, _ := newTestServer()
	out := s.Handle(context.Background(), []byte(`{"jsonrpc":"2.0","id":1,"method":"initialize"}`))
	var resp struct {
		Result struct {
			ProtocolVersion string         `json:"protocolVersion"`
			Capabilities    map[string]any `json:"capabilities"`
			ServerInfo      struct {
				Name string `json:"name"`
			} `json:"serverInfo"`
		} `json:"result"`
	}
	if err := json.Unmarshal(out, &resp); err != nil {
		t.Fatalf("initialize 响应不是 JSON: %v", err)
	}
	if resp.Result.ProtocolVersion == "" || resp.Result.ServerInfo.Name != "test" {
		t.Fatalf("initialize 字段缺失: %+v", resp.Result)
	}
	if _, ok := resp.Result.Capabilities["tools"]; !ok {
		t.Fatal("应声明 tools 能力")
	}

	out = s.Handle(context.Background(), []byte(`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`))
	if !strings.Contains(string(out), `"alpha"`) || !strings.Contains(string(out), `"inputSchema"`) {
		t.Fatalf("tools/list 应包含工具定义: %s", out)
	}
}

func TestNotificationNoResponse(t *testing.T) {
	s, _ := newTestServer()
	if out := s.Handle(context.Background(), []byte(`{"jsonrpc":"2.0","method":"notifications/initialized"}`)); out != nil {
		t.Fatalf("通知不应有响应体: %s", out)
	}
}

func TestToolCallAndError(t *testing.T) {
	s, ex := newTestServer()
	out := s.Handle(context.Background(), []byte(`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"alpha","arguments":{"x":1}}}`))
	if len(ex.calls) != 1 || ex.calls[0] != "alpha" {
		t.Fatalf("工具应被执行: %v", ex.calls)
	}
	if !strings.Contains(string(out), "echo") || !strings.Contains(string(out), `"content"`) {
		t.Fatalf("调用结果格式不对: %s", out)
	}

	out = s.Handle(context.Background(), []byte(`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"boom","arguments":{}}}`))
	if !strings.Contains(string(out), `"isError":true`) || !strings.Contains(string(out), "执行失败") {
		t.Fatalf("工具错误应按 isError 返回: %s", out)
	}

	out = s.Handle(context.Background(), []byte(`{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"nope"}}`))
	if !strings.Contains(string(out), "未知工具") {
		t.Fatalf("未知工具应报错: %s", out)
	}
}

func TestUnknownMethodAndBadJSON(t *testing.T) {
	s, _ := newTestServer()
	out := s.Handle(context.Background(), []byte(`{"jsonrpc":"2.0","id":6,"method":"x/y"}`))
	if !strings.Contains(string(out), "-32601") {
		t.Fatalf("未知方法应返回 -32601: %s", out)
	}
	out = s.Handle(context.Background(), []byte(`not json`))
	if !strings.Contains(string(out), "-32700") {
		t.Fatalf("坏 JSON 应返回 -32700: %s", out)
	}
}

func TestOnCallHook(t *testing.T) {
	s, _ := newTestServer()
	var seen []string
	s.OnCall = func(name string, err error) {
		seen = append(seen, name)
	}
	_ = s.Handle(context.Background(), []byte(`{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"alpha","arguments":{}}}`))
	if len(seen) != 1 || seen[0] != "alpha" {
		t.Fatalf("审计钩子应被调用: %v", seen)
	}
}
