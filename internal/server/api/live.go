package api

import (
	"io"
	"net/http"

	"zedr/internal/platform/apperr"
	"zedr/internal/platform/httpx"
	"zedr/internal/server/service"
)

// 实时查询代理：管理端 REST → 隧道内只读 REST 的薄转发层。
//
// 白名单/超时预算/子开关/审计的业务核心在 service.LiveQueryService
// （唯一事实源，2026-11-09 从本文件迁出——MCP host_live 工具与
// 管理台共用同一执法点，杜绝两份白名单漂移）。本层只保留 HTTP 语义：
// RBAC 由路由包装（api.go）保证，这里做端点存在性校验与响应头透传，
// 刻意不做盲转发——"透传任意 HTTP"等于把执法点搬空。

// livePing 是 viewer 可用的探活端点（RTT 参考 + 真·在线判定）。
func (h *adminHandler) livePing(w http.ResponseWriter, r *http.Request) {
	h.liveForward(w, r, "ping")
}

// liveQuery 是 analyst+ 的实时查询端点（{rest...} 匹配预算表全部路径）。
func (h *adminHandler) liveQuery(w http.ResponseWriter, r *http.Request) {
	rest := r.PathValue("rest")
	if _, ok := service.LiveEndpoints[rest]; !ok {
		httpx.WriteError(w, r, apperr.NotFound("实时查询端点"))
		return
	}
	h.liveForward(w, r, rest)
}

func (h *adminHandler) liveForward(w http.ResponseWriter, r *http.Request, rest string) {
	p := principal(r)
	conn, err := h.deps.Live.Open(r.Context(), r.PathValue("id"), rest,
		r.URL.Query(), p.UserID, p.Username, httpx.ClientIP(r))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	defer conn.Close()

	// fs/read 与 collect 是字节流直通（契约 §5.1）；其余 JSON 的 {data}
	// 包装由探针侧 httpx.WriteJSON 完成，这里原样透传状态码与响应体
	if ct := conn.Header.Get("Content-Type"); ct != "" {
		w.Header().Set("Content-Type", ct)
	}
	for _, hd := range []string{"X-ZEDR-File-Size", "X-ZEDR-Truncated", "X-ZEDR-Collect-Files"} {
		if v := conn.Header.Get(hd); v != "" {
			w.Header().Set(hd, v)
		}
	}
	w.WriteHeader(conn.Status)
	_, _ = io.Copy(w, conn.Body)
}
