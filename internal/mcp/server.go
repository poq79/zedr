// Package mcp 提供 MCP（Model Context Protocol）服务端的最小无状态子集：
// initialize / ping / tools/list / tools/call（JSON-RPC 2.0 over HTTP POST）。
//
// 为什么自研而不是引 SDK（2026-11 取证结论）：官方 Go SDK 对 2026-07-28
// 无状态规范的支持仍是 v1.7.0-pre.1（beta，MCP 官方博客 2026-06-29）；
// pre-release 依赖不进主干（AGENTS §3.6）。本包把协议面收在一个文件里，
// SDK 转正后只需替换 Handle 实现——上层（工具注册、审计、鉴权）不动。
//
// 安全口径：工具描述与结果都按不可信数据处理；只读工具白名单在服务层；
// 鉴权/审计在 HTTP 层（api/mcp.go）。
package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
)

// Tool 是一个对外暴露的工具定义。
type Tool struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"inputSchema"`
}

// Executor 执行一次工具调用；返回可 JSON 序列化的结果。
type Executor interface {
	Call(ctx context.Context, name string, args json.RawMessage) (any, error)
}

// Server 是 MCP 协议处理器。
type Server struct {
	Name    string
	Version string
	Tools   []Tool
	Ex      Executor
	// OnCall 是工具调用审计钩子（nil 表示不记录）。
	OnCall func(name string, err error)
}

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

// protocolVersion 声明兼容的稳定线版本（2025-11-25 是当前客户端普遍支持的
// 版本；2026-07-28 无状态线由后续 SDK 迁移时再协商）。
const protocolVersion = "2025-11-25"

// Handle 处理一个 JSON-RPC 请求体，返回响应体；通知类方法返回 nil。
func (s *Server) Handle(ctx context.Context, body []byte) []byte {
	var req rpcRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return mustJSON(rpcResponse{JSONRPC: "2.0", Error: &rpcError{Code: -32700, Message: "JSON 解析失败"}})
	}
	if req.JSONRPC != "2.0" || req.Method == "" {
		return mustJSON(rpcResponse{JSONRPC: "2.0", Result: nil,
			Error: &rpcError{Code: -32600, Message: "非法请求"}})
	}

	switch req.Method {
	case "initialize":
		return mustJSON(rpcResponse{JSONRPC: "2.0", ID: req.ID, Result: map[string]any{
			"protocolVersion": protocolVersion,
			"capabilities":    map[string]any{"tools": map[string]any{}},
			"serverInfo":      map[string]any{"name": s.Name, "version": s.Version},
		}})

	case "notifications/initialized", "notifications/cancelled":
		return nil // 通知无响应

	case "ping":
		return mustJSON(rpcResponse{JSONRPC: "2.0", ID: req.ID, Result: map[string]any{}})

	case "tools/list":
		tools := make([]Tool, len(s.Tools))
		copy(tools, s.Tools)
		sort.SliceStable(tools, func(i, j int) bool { return tools[i].Name < tools[j].Name })
		return mustJSON(rpcResponse{JSONRPC: "2.0", ID: req.ID, Result: map[string]any{"tools": tools}})

	case "tools/call":
		var p struct {
			Name      string          `json:"name"`
			Arguments json.RawMessage `json:"arguments"`
		}
		if err := json.Unmarshal(req.Params, &p); err != nil || p.Name == "" {
			return mustJSON(rpcResponse{JSONRPC: "2.0", ID: req.ID,
				Error: &rpcError{Code: -32602, Message: "缺少工具名"}})
		}
		res, err := s.call(ctx, p.Name, p.Arguments)
		if s.OnCall != nil {
			s.OnCall(p.Name, err)
		}
		if err != nil {
			// 工具错误按 MCP 语义放 result.isError（模型可见并可自我修正）
			return mustJSON(rpcResponse{JSONRPC: "2.0", ID: req.ID, Result: map[string]any{
				"content": []map[string]any{{"type": "text", "text": "工具错误：" + err.Error()}},
				"isError": true,
			}})
		}
		raw, _ := json.MarshalIndent(res, "", "  ")
		if len(raw) > 64*1024 {
			raw = raw[:64*1024] // 结果上限：防止单个工具调用撑爆客户端上下文
		}
		return mustJSON(rpcResponse{JSONRPC: "2.0", ID: req.ID, Result: map[string]any{
			"content": []map[string]any{{"type": "text", "text": string(raw)}},
		}})
	}

	return mustJSON(rpcResponse{JSONRPC: "2.0", ID: req.ID,
		Error: &rpcError{Code: -32601, Message: fmt.Sprintf("不支持的方法: %s", req.Method)}})
}

func (s *Server) call(ctx context.Context, name string, args json.RawMessage) (any, error) {
	for _, t := range s.Tools {
		if t.Name != name {
			continue
		}
		if s.Ex == nil {
			return nil, fmt.Errorf("没有可用的工具执行器")
		}
		if len(args) > 0 && !json.Valid(args) {
			return nil, fmt.Errorf("参数不是合法 JSON")
		}
		return s.Ex.Call(ctx, name, args)
	}
	return nil, fmt.Errorf("未知工具 %q", name)
}

func mustJSON(v any) []byte {
	raw, err := json.Marshal(v)
	if err != nil {
		return []byte(`{"jsonrpc":"2.0","error":{"code":-32603,"message":"内部错误"}}`)
	}
	return raw
}
