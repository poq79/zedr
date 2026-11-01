package api

import (
	"net/http"
	"time"

	"zedr/internal/platform/apperr"
	"zedr/internal/platform/httpx"
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
	h.setRefreshCookie(w, res.RefreshToken, res.RefreshExp)
	httpx.WriteJSON(w, r, http.StatusOK, sessionResp{
		AccessToken: res.AccessToken,
		ExpiresAt:   res.ExpiresAt,
		User: userBrief{
			ID: res.User.ID, Username: res.User.Username,
			DisplayName: res.User.DisplayName, Role: string(res.User.Role),
		},
	})
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
	httpx.WriteJSON(w, r, http.StatusOK, sessionResp{
		AccessToken: res.AccessToken,
		ExpiresAt:   res.ExpiresAt,
		User: userBrief{
			ID: res.User.ID, Username: res.User.Username,
			DisplayName: res.User.DisplayName, Role: string(res.User.Role),
		},
	})
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
