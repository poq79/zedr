// Package mcp 提供 MCP 工具服务的协议面——自 v1.8.0 起基于官方 Go SDK
// （github.com/modelcontextprotocol/go-sdk，Tier 1）实现。
//
// 迁移史（为什么是这个形状）：
//   - 2026-11 首版自研最小子集（2025-11-25 线），当时官方 SDK 对
//     2026-07-28 无状态规范还是 pre-release，依赖不进主干（AGENTS §3.6）；
//   - 2026-11-10 取证（pkg.go.dev / Go 官方博客 / MCP 官方博客）：SDK
//     v1.0.0 已于 2025-09 转正、v1.8.0（2026-09-04）升 Tier 1 并支持
//     2026-07-28 规范——TRADEOFFS §3.15 的替换触发条件达成，本包整体
//     换装 SDK，上层（工具注册/审计/鉴权/service 层）接口零改动。
//
// 协议能力（SDK 提供，本包不再手写）：无状态核心（无握手/无
// Mcp-Session-Id，每请求 _meta 自带协议版本，GET/DELETE 405）、
// server/discover 能力探测、resultType、serverInfo 身份、
// 2025-11-25 老客户端透明协商。ping 已在 2026-07-28 规范移除。
//
// 安全口径不变：工具描述与结果都按不可信数据处理；只读工具白名单在
// 服务层；鉴权/审计在 HTTP 层（api/mcp.go 的 Bearer 检查 + OnCall 钩子）。
package mcp

import (
	"context"
	"encoding/json"
	"net/http"
	"sort"
	"strings"
	"sync"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

// Tool 是一个对外暴露的工具定义（service 层产出，本包转换成 SDK 类型）。
// Annotations 是 ToolAnnotations 行为提示（readOnlyHint/openWorldHint/
// title 等）——规范明示它们是 UX 提示而非安全边界，客户端不得仅凭注解
// 做安全决策；松散 map 承载以跟随规范演进（本服务全部只读：readOnlyHint=true）。
type Tool struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"inputSchema"`
	Annotations map[string]any  `json:"annotations,omitempty"`
}

// Executor 执行一次工具调用；返回可 JSON 序列化的结果。
type Executor interface {
	Call(ctx context.Context, name string, args json.RawMessage) (any, error)
}

// Server 是 MCP 工具服务：service 层组装（Tools/Ex/OnCall），
// Handler() 输出官方 SDK 的 HTTP 协议面。
type Server struct {
	Name    string
	Version string
	Tools   []Tool
	Ex      Executor
	// OnCall 是工具调用审计钩子（nil 表示不记录）。
	OnCall func(name string, err error)

	once    sync.Once
	handler http.Handler
}

// mcpResultLimit 是单个工具结果回喂模型前的字节上限：防个别枚举端点
// 在异常大主机上撑爆客户端上下文（服务端 shapeForModel 已先把绝大多数
// 结果压进 48KB，这里是协议面最后防线）。
const mcpResultLimit = 64 << 10

// Handler 返回 MCP 协议的 HTTP 处理器（幂等，可并发）。
// Stateless 模式对齐 2026-07-28 规范：无握手、无 session、每请求自包含，
// 任意实例可挂普通轮询负载均衡——与本服务"POST /mcp 无状态"的原始
// 设计完全同构。
func (s *Server) Handler() http.Handler {
	s.once.Do(func() {
		sdk := sdkmcp.NewServer(&sdkmcp.Implementation{Name: s.Name, Version: s.Version},
			&sdkmcp.ServerOptions{
				// 可缓存列表（2026-07-28 SEP-2549）：工具集只在换装/重启时
				// 变化，5 分钟 TTL 让客户端缓存 tools/list，避免每次会话
				// 重复拉全量目录；scope public（无会话差异，stateless）。
				SetCacheable: func(_ context.Context, _ sdkmcp.Request, c *sdkmcp.Cacheable) {
					c.TTLMs = 5 * 60 * 1000
				},
			})
		tools := make([]Tool, len(s.Tools))
		copy(tools, s.Tools)
		sort.SliceStable(tools, func(i, j int) bool { return tools[i].Name < tools[j].Name })
		for _, t := range tools {
			sdk.AddTool(sdkTool(t), s.toolHandler(t.Name))
		}
		s.handler = sdkmcp.NewStreamableHTTPHandler(
			func(*http.Request) *sdkmcp.Server { return sdk },
			&sdkmcp.StreamableHTTPOptions{
				Stateless: true,
				// 纯 JSON 响应（规范 §2.1.5 允许服务端选择）：保持与自研版
				// 相同的线形态，curl 调试与现有客户端零迁移
				JSONResponse: true,
			})
	})
	return s.handler
}

// sdkTool 把本包 Tool 转成 SDK Tool。InputSchema 用 RawMessage 直传
// （方法版 AddTool 不做 schema 推断，参数校验由本包 executor 的
// json.Unmarshal 承担——service 层每个工具都是强类型入参）。
func sdkTool(t Tool) *sdkmcp.Tool {
	out := &sdkmcp.Tool{
		Name:        t.Name,
		Description: t.Description,
		InputSchema: json.RawMessage(t.InputSchema),
	}
	if len(t.Annotations) == 0 {
		return out
	}
	out.Annotations = &sdkmcp.ToolAnnotations{}
	for k, v := range t.Annotations {
		switch k {
		case "title":
			if s, ok := v.(string); ok {
				out.Annotations.Title = s
			}
		case "readOnlyHint":
			if b, ok := v.(bool); ok {
				out.Annotations.ReadOnlyHint = b
			}
		case "openWorldHint":
			if b, ok := v.(bool); ok {
				out.Annotations.OpenWorldHint = &b
			}
		case "destructiveHint", "idempotentHint":
			if b, ok := v.(bool); ok {
				if k == "destructiveHint" {
					out.Annotations.DestructiveHint = &b
				} else {
					out.Annotations.IdempotentHint = b
				}
			}
		}
	}
	return out
}

// toolHandler 包装 Executor 成 SDK 工具处理函数。工具错误按 MCP 语义
// 放 result.isError 回喂模型（模型可见并可自我修正），不转协议层错误。
func (s *Server) toolHandler(name string) sdkmcp.ToolHandler {
	return func(ctx context.Context, req *sdkmcp.CallToolRequest) (*sdkmcp.CallToolResult, error) {
		args, err := json.Marshal(req.Params.Arguments)
		if err != nil {
			args = nil
		}
		out, callErr := s.Ex.Call(ctx, name, args)
		if s.OnCall != nil {
			s.OnCall(name, callErr)
		}
		if callErr != nil {
			return &sdkmcp.CallToolResult{
				IsError: true,
				Content: []sdkmcp.Content{&sdkmcp.TextContent{Text: "工具错误：" + callErr.Error()}},
			}, nil
		}
		raw, mErr := json.MarshalIndent(out, "", "  ")
		if mErr != nil {
			return &sdkmcp.CallToolResult{
				IsError: true,
				Content: []sdkmcp.Content{&sdkmcp.TextContent{Text: "工具错误：结果序列化失败"}},
			}, nil
		}
		// 结果上限：防单个工具调用撑爆客户端上下文。截断后 JSON 不再合法，
		// StructuredContent 必须撤下（喂非法 JSON 给 SDK 会挂响应流）——
		// 文本形式本就是字符串包装，不受影响。service 层 shapeForModel
		// 正常会先整形到位，这里只是协议面最后防线。
		if len(raw) > mcpResultLimit {
			raw = raw[:mcpResultLimit]
			return &sdkmcp.CallToolResult{
				Content: []sdkmcp.Content{&sdkmcp.TextContent{Text: string(raw) + "\n...(结果超限已截断)"}},
			}, nil
		}
		// 规范建议：structuredContent 与文本形式同时返回——结构化给程序化
		// 客户端，文本给模型（两端各取所需）
		return &sdkmcp.CallToolResult{
			Content:           []sdkmcp.Content{&sdkmcp.TextContent{Text: string(raw)}},
			StructuredContent: json.RawMessage(raw),
		}, nil
	}
}

// toolNames 返回已注册工具名（测试与日志用）。
func (s *Server) toolNames() string {
	names := make([]string, 0, len(s.Tools))
	for _, t := range s.Tools {
		names = append(names, t.Name)
	}
	sort.Strings(names)
	return strings.Join(names, ",")
}
