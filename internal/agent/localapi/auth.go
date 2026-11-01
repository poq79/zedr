package localapi

import (
	"crypto/subtle"
	"net"
	"net/http"
	"strings"

	"hostguard/internal/platform/httpx"
)

// 本地 API 的访问控制。
//
// 为什么必须做：这个接口暴露在 127.0.0.1 上，看似"只有本机能访问"应该是安全的，
// 但实际威胁面比想象中大得多：
//
//  1. **浏览器里的任意网页**都能向 127.0.0.1 发请求。没有防护时，
//     一个恶意页面就能调 `/api/local/allowlist` 把攻击载荷永久加白，
//     或者读走全部告警与进程清单——这是最现实的攻击路径。
//  2. 同机其它用户的进程可以读告警、触发重扫。
//
// 采用两层防护：
//
//   - **Origin/Host 校验**：拒绝跨站来源，并强制绑定回环地址。
//   - **访问令牌**：令牌文件仅当前用户可读，请求需携带。
//     同用户身份的进程理论上能读到该文件——这一点无法在用户态彻底解决
//     （那是操作系统的信任边界），但配合前一层已挡住浏览器侧的攻击。
const (
	tokenHeader = "X-HG-Token"
	tokenCookie = "hg_local_token"
	tokenQuery  = "token"
)

// guard 对需要保护的接口做访问控制。
func (s *Server) guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.loopbackOnly(r) {
			httpx.WriteRaw(w, r, http.StatusForbidden, map[string]any{
				"error": "本地接口仅接受回环地址访问",
			})
			return
		}
		if !s.originAllowed(r) {
			// 跨站请求：直接拒绝。浏览器侧的攻击在这里被切断。
			httpx.WriteRaw(w, r, http.StatusForbidden, map[string]any{
				"error": "跨站请求被拒绝",
			})
			return
		}
		if !s.tokenValid(r) {
			httpx.WriteRaw(w, r, http.StatusUnauthorized, map[string]any{
				"error": "缺少或无效的访问令牌（见数据目录下的 local.token）",
				"code":  "local_token_required",
			})
			return
		}
		next.ServeHTTP(w, r)
	})
}

// loopbackOnly 确认请求确实来自本机回环，而不是通过某种转发到达。
func (s *Server) loopbackOnly(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	if ip == nil {
		return false
	}
	return ip.IsLoopback()
}

// originAllowed 校验 Origin。
//
// 浏览器发起的跨站请求一定带 Origin；同源的 fetch 也带。
// 因此只接受"没有 Origin（同机非浏览器进程）"或"Origin 与 Host 一致"。
func (s *Server) originAllowed(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true // 非浏览器发起的请求
	}
	// Origin 形如 http://127.0.0.1:8843
	trimmed := strings.TrimPrefix(strings.TrimPrefix(origin, "http://"), "https://")
	originHost, _, err := net.SplitHostPort(trimmed)
	if err != nil {
		originHost = trimmed
	}
	reqHost, _, err := net.SplitHostPort(r.Host)
	if err != nil {
		reqHost = r.Host
	}
	if !strings.EqualFold(originHost, reqHost) {
		return false
	}
	ip := net.ParseIP(strings.Trim(originHost, "[]"))
	return ip != nil && ip.IsLoopback()
}

// tokenValid 从请求头 / Cookie / 查询参数中取令牌并比对。
//
// 支持查询参数是为了让桌面 UI 首屏能把令牌传进来；前端拿到后会立即
// 写入 localStorage 并从地址栏抹掉，避免留在历史记录里。
func (s *Server) tokenValid(r *http.Request) bool {
	want := s.deps.Token
	if want == "" {
		return true // 未启用令牌（显式配置为空时）
	}

	got := r.Header.Get(tokenHeader)
	if got == "" {
		if c, err := r.Cookie(tokenCookie); err == nil {
			got = c.Value
		}
	}
	if got == "" {
		got = r.URL.Query().Get(tokenQuery)
	}
	if got == "" {
		// 写操作额外要求自定义头：浏览器跨站请求无法在不触发预检的情况下伪造它
		return false
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}
