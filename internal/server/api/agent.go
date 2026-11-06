package api

import (
	"context"
	"net/http"

	"zedr/internal/model"
	"zedr/internal/platform/apperr"
	"zedr/internal/platform/httpx"
	"zedr/internal/platform/rulehash"
	"zedr/internal/server/domain"
	"zedr/internal/server/livetunnel"
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
	// 观察命中快照旁挂在心跳上：非 nil（含空 map）即整包替换该终端的
	// 计数行。失败已在服务层吞掉（只记日志），不影响心跳主流程。
	if req.RuleObserved != nil {
		h.deps.Services.Rule.IngestObserve(r.Context(), a.ID, req.RuleObserved)
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
	// 背压闸：先按"本批条数"扣每终端速率额度，再占一个在途批次槽。
	// 拒绝只是让终端退避重试（探针侧 spool 保留告警），不是丢弃。
	if h.deps.Ingest != nil {
		release, err := h.deps.Ingest.Admit(a.ID, len(req.Alerts))
		if err != nil {
			if apperr.From(err).Code == apperr.CodeTooManyRequests {
				w.Header().Set("Retry-After", "2")
			}
			httpx.WriteError(w, r, err)
			return
		}
		defer release()
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

// agentIOCs 下发威胁指标整包。带 If-None-Match 且版本未变时返回 304。
// 与规则包同密钥但独立签名（payload 前缀 iocv1），老探针不请求此端点。
func (h *agentHandler) agentIOCs(w http.ResponseWriter, r *http.Request) {
	bundle, n, err := h.deps.Services.Rule.IOCBundle(r.Context())
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	// 空包也带版本号：从有到无（清空 IOC）同样要能被终端感知。
	etag := "\"" + itoa(bundle.Version) + "\""
	if r.Header.Get("If-None-Match") == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	if err := rulehash.SignIOCBundle(bundle, h.deps.RuleSignKey); err != nil {
		h.deps.Log.ErrorContext(r.Context(), "ioc_sign_failed", "err", err)
		httpx.WriteError(w, r, apperr.Internal(err))
		return
	}
	w.Header().Set("ETag", etag)
	w.Header().Set("X-IOC-Count", itoa(n))
	httpx.WriteJSON(w, r, http.StatusOK, bundle)
}

// tunnelUpgrade 处理探针实时隧道升级请求（101 后连接交给 yamux）。
// 鉴权在本方法内组装（复用与心跳一致的 Authenticate+CheckSecret），
// 升级细节全部下沉在 livetunnel.UpgradeHandler。
func (h *agentHandler) tunnelUpgrade(w http.ResponseWriter, r *http.Request) {
	authFn := func(agentID, secret string) error {
		agent, err := h.deps.Services.Agent.Authenticate(r.Context(), agentID)
		if err != nil {
			return err
		}
		return h.deps.Services.Agent.CheckSecret(agent, secret)
	}
	livetunnel.UpgradeHandler(h.deps.Log, authFn, h.deps.Tunnel.Track).ServeHTTP(w, r)
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
