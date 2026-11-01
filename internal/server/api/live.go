package api

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"zedr/internal/platform/apperr"
	"zedr/internal/platform/httpx"
	"zedr/internal/platform/logx"
	"zedr/internal/platform/redact"
)

// 实时查询代理：管理端 REST → 隧道内只读 REST 的薄转发层。
//
// 本层是实时查询体系唯一的安全执法点（docs/LIVE-TUNNEL.md §4）：
// RBAC 由路由包装（api.go）保证，这里负责总开关/子开关、端点白名单、
// 超时预算、审计。刻意不做盲转发——"透传任意 HTTP"等于把执法点搬空，
// 探针侧 mux 也只挂白名单 handler，两侧收口才是完整防线。

// liveEndpoint 描述一个隧道内只读端点的转发预算。
type liveEndpoint struct {
	timeout  time.Duration
	fileRead bool // 需要 HG_SERVER_LIVEQUERY_FILEREAD 子开关把门
}

// 预算表（契约 §5.1 / §11.3）：fs/hash 与 analyze 要扫全文件所以最长；
// fs/read 受 512KB 钳制且流式传输，20s 足够覆盖慢速盘；fs/search 探针侧
// 自带 30s 预算（超时返回 truncated 部分），代理给 35s 让 truncated 语义
// 有机会送达而不是被代理先掐；其余都是内存级枚举。
var liveEndpoints = map[string]liveEndpoint{
	"ping":      {timeout: 5 * time.Second},
	"fs":        {timeout: 15 * time.Second},
	"fs/stat":   {timeout: 10 * time.Second},
	"fs/read":   {timeout: 20 * time.Second, fileRead: true},
	"fs/hash":   {timeout: 30 * time.Second},
	"processes": {timeout: 10 * time.Second},
	"netstat":   {timeout: 10 * time.Second},
	"analyze":   {timeout: 30 * time.Second},
	"ads":       {timeout: 10 * time.Second},
	"fs/search": {timeout: 35 * time.Second},
	"procinfo":  {timeout: 10 * time.Second},
	"info":      {timeout: 5 * time.Second},
	// recon 含回环探测（40 次 × 2s 上限 + 30s 内部预算），代理给 40s：
	// 比探针内部预算宽，保证探针的 truncated 语义能送达而不是被代理先掐
	"recon":    {timeout: 40 * time.Second},
	"baseline": {timeout: 10 * time.Second},
	"accounts": {timeout: 10 * time.Second},
}

// errTunnelNotConnected 是前端据以渲染"隧道未连接"状态条的错误码。
// 探针离线、老版本探针、主机 ID 不存在三种情况都归入此码：
// 对操作员而言行动指引相同（检查探针在线状态/版本）。
func errTunnelNotConnected(msg string) *apperr.Error {
	return &apperr.Error{
		Code:    apperr.Code("tunnel_not_connected"),
		Message: msg,
		Status:  http.StatusServiceUnavailable,
		Public:  true, // 状态描述即行动指引，不属于需要脱敏的内部错误
	}
}

// livePing 是 viewer 可用的探活端点（RTT 参考 + 真·在线判定）。
func (h *adminHandler) livePing(w http.ResponseWriter, r *http.Request) {
	h.liveForward(w, r, "ping")
}

// liveQuery 是 analyst+ 的实时查询端点（{rest...} 匹配预算表全部路径）。
func (h *adminHandler) liveQuery(w http.ResponseWriter, r *http.Request) {
	rest := r.PathValue("rest")
	ep, ok := liveEndpoints[rest]
	if !ok {
		httpx.WriteError(w, r, apperr.NotFound("实时查询端点"))
		return
	}
	// 文件内容预览单独把门：这是该体系信息暴露面最大的端点，
	// 与处置类同纪律（默认关、现场显式开），不用总开关一并放过
	if ep.fileRead && !h.deps.LiveQueryFileRead {
		httpx.WriteError(w, r, apperr.Forbidden("文件内容预览未启用（HG_SERVER_LIVEQUERY_FILEREAD）"))
		return
	}
	h.liveForward(w, r, rest)
}

func (h *adminHandler) liveForward(w http.ResponseWriter, r *http.Request, rest string) {
	p := principal(r)
	if !h.deps.LiveQueryEnabled {
		httpx.WriteError(w, r, apperr.Forbidden("实时查询未启用（HG_SERVER_LIVEQUERY_ENABLED）"))
		return
	}
	ep := liveEndpoints[rest]
	hostID := r.PathValue("id")

	cli, ok := h.deps.Tunnel.Get(hostID)
	if !ok {
		httpx.WriteError(w, r, errTunnelNotConnected("探针隧道未连接（探针离线或版本不支持实时查询）"))
		return
	}
	if err := cli.Acquire(r.Context()); err != nil {
		// 超限立即拒绝而非排队：交互式操作排队只会让操作员以为界面卡死
		httpx.WriteError(w, r, err)
		return
	}
	defer cli.Release()

	ctx, cancel := context.WithTimeout(r.Context(), ep.timeout)
	defer cancel()

	// 隧道内 URL 的 host 段无意义（拨号恒指向本会话），约定 "http://tunnel/"
	treq, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"http://tunnel/"+rest+"?"+r.URL.RawQuery, nil)
	if err != nil {
		httpx.WriteError(w, r, apperr.Invalid("实时查询请求构造失败"))
		return
	}
	// 操作员身份透传给探针侧审计（探针端无鉴权概念——无监听面，
	// 物理上只有持凭证的服务端可达，但"谁在查"要跟着请求走）
	treq.Header.Set("X-ZEDR-Operator", p.Username)
	if rid := logx.RequestID(r.Context()); rid != "" {
		treq.Header.Set("X-ZEDR-Request-Id", rid)
	}

	started := time.Now()
	resp, err := cli.HTTP().Do(treq)
	ms := time.Since(started).Milliseconds()
	if err != nil {
		h.deps.Services.Audit.Record(r.Context(), p.UserID, p.Username, "host.live_query",
			hostID, fmt.Sprintf("%s transport_error %dms", rest, ms), httpx.ClientIP(r))
		if ctx.Err() != nil {
			httpx.WriteError(w, r, apperr.Unavailable(fmt.Sprintf("探针响应超时（预算 %s）", ep.timeout)))
			return
		}
		httpx.WriteError(w, r, errTunnelNotConnected("探针隧道已断开，请稍后重试"))
		return
	}
	defer resp.Body.Close()

	// 审计口径与 sendCommand 一致：记"发生了什么"（端点+查询参数+结果+耗时）。
	// v2 起带查询参数——v1 只记 "fs 200 2ms"，事后无法回答"当时看了哪个目录"，
	// 追责链断了半截；路径类参数非敏感但可能很长，过 redact 截断。
	h.deps.Services.Audit.Record(r.Context(), p.UserID, p.Username, "host.live_query",
		hostID, fmt.Sprintf("%s %d %dms %s", rest, resp.StatusCode, ms, liveQueryDetail(r.URL.Query())),
		httpx.ClientIP(r))

	// fs/read 是字节流直通（契约 §5.1）；其余 JSON 的 {data} 包装由探针侧
	// httpx.WriteJSON 完成，这里原样透传状态码与响应体
	if ct := resp.Header.Get("Content-Type"); ct != "" {
		w.Header().Set("Content-Type", ct)
	}
	for _, hd := range []string{"X-ZEDR-File-Size", "X-ZEDR-Truncated"} {
		if v := resp.Header.Get(hd); v != "" {
			w.Header().Set(hd, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

// liveQueryDetail 把查询参数整理成可读审计串（k=v 空格分隔，值过 redact）。
// 为什么不用 RawQuery 原文：URL 编码后的 C%3A%5C 在审计里不可读，
// 排查的人还要手动解码；逐值截断防超长路径撑爆 detail 字段。
func liveQueryDetail(q url.Values) string {
	keys := make([]string, 0, len(q))
	for k := range q {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for i, k := range keys {
		if i > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(redact.Path(q.Get(k)))
	}
	return b.String()
}
