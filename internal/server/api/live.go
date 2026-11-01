package api

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"

	"hostguard/internal/platform/apperr"
	"hostguard/internal/platform/httpx"
	"hostguard/internal/platform/logx"
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

// 预算表（契约 §5.1）：fs/hash 要扫全文件所以最长；fs/read 受 512KB
// 钳制且流式传输，20s 足够覆盖慢速盘；其余都是内存级枚举。
var liveEndpoints = map[string]liveEndpoint{
	"ping":      {timeout: 5 * time.Second},
	"fs":        {timeout: 15 * time.Second},
	"fs/stat":   {timeout: 10 * time.Second},
	"fs/read":   {timeout: 20 * time.Second, fileRead: true},
	"fs/hash":   {timeout: 30 * time.Second},
	"processes": {timeout: 10 * time.Second},
	"netstat":   {timeout: 10 * time.Second},
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
	treq.Header.Set("X-HG-Operator", p.Username)
	if rid := logx.RequestID(r.Context()); rid != "" {
		treq.Header.Set("X-HG-Request-Id", rid)
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

	// 审计口径与 sendCommand 一致：记"发生了什么"（端点+结果+耗时）。
	// 请求级粒度是本设计的隐私对价（TRADEOFFS §9.6），目录浏览与
	// 内容预览都必须可追责到操作员。
	h.deps.Services.Audit.Record(r.Context(), p.UserID, p.Username, "host.live_query",
		hostID, fmt.Sprintf("%s %d %dms", rest, resp.StatusCode, ms), httpx.ClientIP(r))

	// fs/read 是字节流直通（契约 §5.1）；其余 JSON 的 {data} 包装由探针侧
	// httpx.WriteJSON 完成，这里原样透传状态码与响应体
	if ct := resp.Header.Get("Content-Type"); ct != "" {
		w.Header().Set("Content-Type", ct)
	}
	for _, hd := range []string{"X-HG-File-Size", "X-HG-Truncated"} {
		if v := resp.Header.Get(hd); v != "" {
			w.Header().Set(hd, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}
