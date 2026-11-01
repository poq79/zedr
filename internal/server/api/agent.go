package api

import (
	"context"
	"net/http"

	"hostguard/internal/model"
	"hostguard/internal/platform/apperr"
	"hostguard/internal/platform/httpx"
	"hostguard/internal/platform/rulehash"
	"hostguard/internal/server/domain"
)

type agentHandler struct{ deps Deps }

type ctxKeyAgent struct{}

func withAgent(ctx context.Context, a *domain.Agent) context.Context {
	return context.WithValue(ctx, ctxKeyAgent{}, a)
}

func agentFrom(ctx context.Context) *domain.Agent {
	a, _ := ctx.Value(ctxKeyAgent{}).(*domain.Agent)
	return a
}

// enroll 终端注册。
func (h *agentHandler) enroll(w http.ResponseWriter, r *http.Request) {
	var req model.EnrollRequest
	if err := httpx.DecodeJSON(r, &req); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	res, err := h.deps.Services.Agent.Enroll(r.Context(), req, httpx.ClientIP(r))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, r, http.StatusOK, res)
}

// heartbeat 心跳 + 拉取指令。
func (h *agentHandler) heartbeat(w http.ResponseWriter, r *http.Request) {
	a := agentFrom(r.Context())
	var req model.HeartbeatRequest
	if err := httpx.DecodeJSON(r, &req); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	res, err := h.deps.Services.Agent.Heartbeat(r.Context(), a.ID, req, httpx.ClientIP(r))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, r, http.StatusOK, res)
}

// reportAlerts 批量上报告警。
func (h *agentHandler) reportAlerts(w http.ResponseWriter, r *http.Request) {
	a := agentFrom(r.Context())
	var req model.AlertBatchRequest
	if err := httpx.DecodeJSON(r, &req); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	res, err := h.deps.Services.Alert.Ingest(r.Context(), a, req)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, r, http.StatusOK, res)
}

// rules 下发规则整包。带 If-None-Match 且版本未变时返回 304。
func (h *agentHandler) rules(w http.ResponseWriter, r *http.Request) {
	bundle, err := h.deps.Services.Rule.Bundle(r.Context(), 0)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	etag := "\"" + itoa(bundle.Version) + "\""
	if r.Header.Get("If-None-Match") == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	// 下发前签名：终端据此判断规则包是否被篡改。
	// 放在 ETag 命中之后，避免 304 路径做无用计算。
	if err := rulehash.Sign(bundle, h.deps.RuleSignKey); err != nil {
		h.deps.Log.ErrorContext(r.Context(), "rule_sign_failed", "err", err)
		httpx.WriteError(w, r, apperr.Internal(err))
		return
	}

	w.Header().Set("ETag", etag)
	httpx.WriteJSON(w, r, http.StatusOK, bundle)
}

// commandResult 接收指令执行回执。
func (h *agentHandler) commandResult(w http.ResponseWriter, r *http.Request) {
	a := agentFrom(r.Context())
	var req struct {
		Results []model.CommandResult `json:"results"`
	}
	if err := httpx.DecodeJSON(r, &req); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.deps.Services.Agent.CompleteCommand(r.Context(), a.ID, req.Results); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteNoContent(w)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
