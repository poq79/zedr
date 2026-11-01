package api

import (
	"net/http"
	"time"

	"hostguard/internal/platform/apperr"
	"hostguard/internal/platform/httpx"
	"hostguard/internal/server/domain"
)

// issueStreamTicket 为当前会话签发一次性的 SSE 连接票据。
func (h *adminHandler) issueStreamTicket(w http.ResponseWriter, r *http.Request) {
	p := principal(r)
	if p == nil {
		httpx.WriteError(w, r, apperr.Unauthenticated(""))
		return
	}
	id := h.deps.Tickets.issue(p)
	httpx.WriteJSON(w, r, http.StatusOK, map[string]any{
		"ticket":     id,
		"expires_in": 60,
	})
}

// streamAlerts 通过 SSE 推送实时告警。
//
// 选择 SSE 而非 WebSocket：本场景是单向（服务端→浏览器）推送，
// SSE 自带断线重连（EventSource 自动重试）、可穿透大多数代理，
// 且服务端实现成本极低。
func (h *adminHandler) streamAlerts(w http.ResponseWriter, r *http.Request) {
	// EventSource 无法自定义请求头，因此用一次性票据鉴权（60s 有效、用后即焚）
	p, ok := h.deps.Tickets.consume(r.URL.Query().Get("ticket"))
	if !ok {
		httpx.WriteError(w, r, apperr.Unauthenticated("流票据无效或已过期"))
		return
	}
	_ = p

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}

	hdr := w.Header()
	hdr.Set("Content-Type", "text/event-stream; charset=utf-8")
	hdr.Set("Cache-Control", "no-cache, no-transform")
	hdr.Set("Connection", "keep-alive")
	hdr.Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)

	subID, ch := h.deps.Bus.Subscribe()
	defer h.deps.Bus.Unsubscribe(subID)

	// 首帧告知前端通道就绪
	writeSSE(w, flusher, "ready", `{"ts":`+itoa64(time.Now().UnixMilli())+`}`)

	heartbeat := time.NewTicker(20 * time.Second)
	defer heartbeat.Stop()

	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case a, open := <-ch:
			if !open {
				return
			}
			payload, err := marshalJSON(sseAlert(a))
			if err != nil {
				continue
			}
			writeSSE(w, flusher, "alert", payload)
		case <-heartbeat.C:
			// 注释帧用于保活，不触发前端事件
			if _, err := w.Write([]byte(": ping\n\n")); err != nil {
				return
			}
			flusher.Flush()
		}
	}
}

func writeSSE(w http.ResponseWriter, f http.Flusher, event, data string) {
	_, _ = w.Write([]byte("event: " + event + "\ndata: " + data + "\n\n"))
	f.Flush()
}

// sseAlert 精简字段，避免单条事件过大。
func sseAlert(a domain.Alert) map[string]any {
	return map[string]any{
		"id":           a.ID,
		"hostname":     a.Hostname,
		"title":        a.Title,
		"severity":     a.Severity,
		"verdict":      a.Verdict,
		"score":        a.Score,
		"process_name": a.ProcessName,
		"image_path":   a.ImagePath,
		"occurred_at":  a.OccurredAt,
		"rule_ids":     a.RuleIDs,
	}
}
