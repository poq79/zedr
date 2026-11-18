package api

import (
	"net/http"
	"time"

	"zedr/internal/platform/apperr"
	"zedr/internal/platform/httpx"
	"zedr/internal/server/service"
)

const refreshCookieName = "zedr_rt"

type authHandler struct{ deps Deps }

type loginReq struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type sessionResp struct {
	AccessToken string    `json:"access_token"`
	ExpiresAt   time.Time `json:"expires_at"`
	User        userBrief `json:"user"`
}

type userBrief struct {
	ID          string `json:"id"`
	Username    string `json:"username"`
	DisplayName string `json:"display_name"`
	Role        string `json:"role"`
}

func (h *authHandler) login(w http.ResponseWriter, r *http.Request) {
	var req loginReq
	if err := httpx.DecodeJSON(r, &req); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	res, err := h.deps.Services.Auth.Login(r.Context(), req.Username, req.Password,
		httpx.ClientIP(r), r.UserAgent())
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	// 双因素账号：密码已验、令牌未发——返回待验证票据，前端引导输入
	// 验证码后调 /auth/mfa/verify。老前端忽略未知字段会把这当登录失败，
	// 这是刻意行为：未适配 MFA 的前端不该绕过第二因子。
	if res.MfaRequired {
		httpx.WriteJSON(w, r, http.StatusOK, map[string]any{
			"mfa_required": true,
			"mfa_ticket":   res.MfaTicket,
			"expires_in":   180, // 与 service.mfaTicketTTL 对齐（3 分钟）
		})
		return
	}
	h.setRefreshCookie(w, res.RefreshToken, res.RefreshExp)
	writeSession(w, r, res)
}

func (h *authHandler) refresh(w http.ResponseWriter, r *http.Request) {
	raw := h.readRefreshCookie(r)
	if raw == "" {
		httpx.WriteError(w, r, apperr.Unauthenticated("缺少刷新令牌，请重新登录"))
		return
	}
	res, err := h.deps.Services.Auth.Refresh(r.Context(), raw, httpx.ClientIP(r), r.UserAgent())
	if err != nil {
		h.clearRefreshCookie(w)
		httpx.WriteError(w, r, err)
		return
	}
	h.setRefreshCookie(w, res.RefreshToken, res.RefreshExp)
	writeSession(w, r, res)
}

// writeSession 输出登录成功响应（login/refresh/mfaVerify 三处共用）。
func writeSession(w http.ResponseWriter, r *http.Request, res *service.LoginResult) {
	httpx.WriteJSON(w, r, http.StatusOK, sessionResp{
		AccessToken: res.AccessToken,
		ExpiresAt:   res.ExpiresAt,
		User: userBrief{
			ID: res.User.ID, Username: res.User.Username,
			DisplayName: res.User.DisplayName, Role: string(res.User.Role),
		},
	})
}

// ---------------------------------------------------------------- MFA（TOTP 双因素）

type mfaVerifyReq struct {
	Ticket string `json:"ticket"`
	Code   string `json:"code"`
}

// mfaVerify 预认证端点：凭 login 发放的 mfa_ticket + 验证码换令牌对。
// 响应与 login 成功形态一致（sessionResp + refresh cookie），前端同一套
// 处理；路由挂在登录独立限流桶上（与 login 同参）——verify 无需登录态，
// 必须防"绕过 login 限流单独暴破验证码"。
func (h *authHandler) mfaVerify(w http.ResponseWriter, r *http.Request) {
	var req mfaVerifyReq
	if err := httpx.DecodeJSON(r, &req); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	res, err := h.deps.Services.Auth.VerifyMFA(r.Context(), req.Ticket, req.Code,
		httpx.ClientIP(r), r.UserAgent())
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	h.setRefreshCookie(w, res.RefreshToken, res.RefreshExp)
	writeSession(w, r, res)
}

type mfaEnrollResp struct {
	Secret     string `json:"secret"`
	OtpauthURL string `json:"otpauth_url"`
}

// mfaEnroll 发起绑定：返回 base32 密钥与 otpauth URI（扫码/手录）。
// 幂等重入：未确认的重复 enroll 直接换新密钥。
func (h *authHandler) mfaEnroll(w http.ResponseWriter, r *http.Request) {
	p := principal(r)
	secret, uri, err := h.deps.Services.Auth.EnrollMFA(r.Context(), p.UserID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, r, http.StatusOK, mfaEnrollResp{Secret: secret, OtpauthURL: uri})
}

type mfaConfirmReq struct {
	Code string `json:"code"`
}

// mfaConfirm 确认绑定：验证码通过才启用。204 前端刷新 /me 即见 mfa_enabled。
func (h *authHandler) mfaConfirm(w http.ResponseWriter, r *http.Request) {
	p := principal(r)
	var req mfaConfirmReq
	if err := httpx.DecodeJSON(r, &req); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.deps.Services.Auth.ConfirmMFA(r.Context(), p.UserID, req.Code); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteNoContent(w)
}

type mfaDisableReq struct {
	Password string `json:"password"`
	Code     string `json:"code"`
}

// mfaDisable 解绑：密码 + 当前验证码双确认（降级为单因素是高危操作）。
func (h *authHandler) mfaDisable(w http.ResponseWriter, r *http.Request) {
	p := principal(r)
	var req mfaDisableReq
	if err := httpx.DecodeJSON(r, &req); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.deps.Services.Auth.DisableMFA(r.Context(), p.UserID, req.Password, req.Code); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteNoContent(w)
}

func (h *authHandler) logout(w http.ResponseWriter, r *http.Request) {
	raw := h.readRefreshCookie(r)
	if raw != "" {
		_ = h.deps.Services.Auth.Logout(r.Context(), raw)
	}
	h.clearRefreshCookie(w)
	httpx.WriteNoContent(w)
}

// readRefreshCookie 只从 HttpOnly Cookie 读取，绝不接受 URL 查询参数（防日志泄露）。
func (h *authHandler) readRefreshCookie(r *http.Request) string {
	c, err := r.Cookie(refreshCookieName)
	if err != nil {
		return ""
	}
	return c.Value
}

func (h *authHandler) setRefreshCookie(w http.ResponseWriter, token string, exp time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name:     refreshCookieName,
		Value:    token,
		Path:     "/api/v1/auth",
		Expires:  exp,
		MaxAge:   int(time.Until(exp).Seconds()),
		HttpOnly: true,
		Secure:   h.deps.CookieSecure,
		SameSite: http.SameSiteStrictMode,
	})
}

func (h *authHandler) clearRefreshCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     refreshCookieName,
		Value:    "",
		Path:     "/api/v1/auth",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   h.deps.CookieSecure,
		SameSite: http.SameSiteStrictMode,
	})
}

// changePasswordReq 是修改密码的请求体。
type changePasswordReq struct {
	OldPassword string `json:"old_password"`
	NewPassword string `json:"new_password"`
}

// changePassword 当前用户改密：成功后吊销全部刷新令牌，
// 前端应清除本地凭证并回到登录页。
func (h *authHandler) changePassword(w http.ResponseWriter, r *http.Request) {
	p := principal(r)
	var req changePasswordReq
	if err := httpx.DecodeJSON(r, &req); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.deps.Services.Auth.ChangePassword(r.Context(), p.UserID,
		req.OldPassword, req.NewPassword); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	h.deps.Services.Audit.Record(r.Context(), p.UserID, p.Username,
		"auth.change_password", p.UserID, "", httpx.ClientIP(r))
	httpx.WriteNoContent(w)
}
