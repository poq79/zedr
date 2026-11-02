// Package httpx 提供 HTTP 层通用能力：请求 ID、结构化访问日志、panic 恢复、
// 统一错误出口、CORS、安全头、限流、JSON 编解码与优雅停机。
package httpx

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"zedr/internal/platform/apperr"
	"zedr/internal/platform/logx"
)

// maxBodyBytes 限制请求体，防止内存耗尽。
const maxBodyBytes = 1 << 20 // 1 MiB

// ---------------------------------------------------------------- request id

type ctxKeyRequestID struct{}

func newRequestID() string {
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("rid-%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b[:])
}

// RequestIDMiddleware 保证每个请求都有 ID，并写回响应头。
func RequestIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get("X-Request-Id")
		if id == "" || len(id) > 64 {
			id = newRequestID()
		}
		w.Header().Set("X-Request-Id", id)
		next.ServeHTTP(w, r.WithContext(logx.WithRequestID(r.Context(), id)))
	})
}

// ---------------------------------------------------------------- access log

type statusRecorder struct {
	http.ResponseWriter
	status  int
	written int64
}

func (s *statusRecorder) WriteHeader(code int) {
	if s.status == 0 {
		s.status = code
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	if s.status == 0 {
		s.status = http.StatusOK
	}
	n, err := s.ResponseWriter.Write(b)
	s.written += int64(n)
	return n, err
}

// Flush 透传，保证 SSE 可用。
func (s *statusRecorder) Flush() {
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Hijack 透传，保证 101 协议升级（实时隧道）可用。
// 为什么必须显式转发：内嵌接口只提升接口自身的方法集，
// 动态类型的 Hijack 不会自动出现在包装器的方法集里——
// 这与上面 Flush 需要显式转发是同一个语言行为。
func (s *statusRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hj, ok := s.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, errors.New("response writer 不支持协议升级")
	}
	return hj.Hijack()
}

// AccessLogMiddleware 输出结构化访问日志（不含请求体、不含 Authorization）。
func AccessLogMiddleware(log *slog.Logger, skip func(*http.Request) bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if skip != nil && skip(r) {
				next.ServeHTTP(w, r)
				return
			}
			start := time.Now()
			rec := &statusRecorder{ResponseWriter: w}
			next.ServeHTTP(rec, r)
			if rec.status == 0 {
				rec.status = http.StatusOK
			}
			level := slog.LevelInfo
			if rec.status >= 500 {
				level = slog.LevelError
			} else if rec.status >= 400 {
				level = slog.LevelWarn
			}
			log.Log(r.Context(), level, "http_request",
				"method", r.Method,
				"path", r.URL.Path,
				"status", rec.status,
				"bytes", rec.written,
				"duration_ms", float64(time.Since(start).Microseconds())/1000.0,
				"remote", clientIP(r),
			)
		})
	}
}

// ---------------------------------------------------------------- recovery

// RecoverMiddleware 捕获 panic，输出统一 500，绝不把堆栈返回给客户端。
func RecoverMiddleware(log *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if rec := recover(); rec != nil {
					log.ErrorContext(r.Context(), "panic_recovered",
						"panic", fmt.Sprint(rec), "path", r.URL.Path)
					WriteError(w, r, apperr.Internal(errors.New(fmt.Sprint(rec))))
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}

// ---------------------------------------------------------------- responses

type envelope struct {
	Data any `json:"data,omitempty"`
}

type errorBody struct {
	Error errorPayload `json:"error"`
}

type errorPayload struct {
	Code      string         `json:"code"`
	Message   string         `json:"message"`
	RequestID string         `json:"request_id,omitempty"`
	Details   map[string]any `json:"details,omitempty"`
}

// WriteJSON 输出统一成功结构 {"data": ...}。
func WriteJSON(w http.ResponseWriter, r *http.Request, status int, data any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if data == nil {
		return
	}
	if err := json.NewEncoder(w).Encode(envelope{Data: data}); err != nil {
		// 响应已开始写出，只能记录
		_ = err
	}
}

// WriteRaw 输出不带 envelope 的 JSON（用于需要扁平结构的场景）。
func WriteRaw(w http.ResponseWriter, r *http.Request, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// WriteNoContent 返回 204。
func WriteNoContent(w http.ResponseWriter) {
	w.WriteHeader(http.StatusNoContent)
}

// WriteError 是全局唯一错误出口：任何错误都会被归一化成稳定结构。
func WriteError(w http.ResponseWriter, r *http.Request, err error) {
	e := apperr.From(err)
	if e.Status == 0 {
		e.Status = http.StatusInternalServerError
	}
	// 仅内部错误返回请求 ID，便于用户报障；细节不外泄
	body := errorBody{Error: errorPayload{
		Code:    string(e.Code),
		Message: e.Message,
		Details: e.Details,
	}}
	if e.Status >= 500 && !e.Public {
		body.Error.Message = "服务内部错误，请稍后重试"
		body.Error.RequestID = logx.RequestID(r.Context())
	}
	if e.Status >= 500 {
		// 请求 ID 无论如何都带上：5xx 报障时定位日志的唯一线索
		body.Error.RequestID = logx.RequestID(r.Context())
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(e.Status)
	_ = json.NewEncoder(w).Encode(body)
}

// DecodeJSON 严格解析 JSON：限制体积、拒绝未知字段、拒绝尾随内容。
func DecodeJSON(r *http.Request, dst any) error {
	if r.Body == nil {
		return apperr.Invalid("请求体不能为空")
	}
	limited := http.MaxBytesReader(nil, r.Body, maxBodyBytes)
	dec := json.NewDecoder(limited)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			return apperr.Invalid("请求体过大（上限 1MiB）")
		}
		if errors.Is(err, io.EOF) {
			return apperr.Invalid("请求体不能为空")
		}
		return apperr.Invalid("请求体格式错误: %v", err)
	}
	if dec.More() {
		return apperr.Invalid("请求体包含多余内容")
	}
	return nil
}

// ---------------------------------------------------------------- middleware

// SecurityHeaders 设置基础安全响应头。
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
		if r.TLS != nil {
			h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		next.ServeHTTP(w, r)
	})
}

// CORS 使用显式来源白名单，生产环境绝不使用通配符。
func CORS(origins []string, allowCredentials bool) func(http.Handler) http.Handler {
	allowed := make(map[string]struct{}, len(origins))
	for _, o := range origins {
		o = strings.TrimRight(strings.TrimSpace(o), "/")
		if o != "" && o != "*" {
			allowed[strings.ToLower(o)] = struct{}{}
		}
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := strings.TrimRight(r.Header.Get("Origin"), "/")
			if origin != "" {
				if _, ok := allowed[strings.ToLower(origin)]; ok {
					h := w.Header()
					h.Set("Access-Control-Allow-Origin", origin)
					h.Set("Vary", "Origin")
					if allowCredentials {
						h.Set("Access-Control-Allow-Credentials", "true")
					}
					h.Set("Access-Control-Allow-Methods", "GET,POST,PUT,PATCH,DELETE,OPTIONS")
					h.Set("Access-Control-Allow-Headers", "Content-Type,Authorization,X-Request-Id")
					h.Set("Access-Control-Max-Age", "600")
				}
			}
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// BodyLimit 限制请求体大小（默认 1MiB）。
func BodyLimit(max int64) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r.Body = http.MaxBytesReader(w, r.Body, max)
			next.ServeHTTP(w, r)
		})
	}
}

// ---------------------------------------------------------------- rate limit

// TokenBucket 是线程安全的令牌桶，用于按 key（IP / agent）限流。
type TokenBucket struct {
	mu      sync.Mutex
	buckets map[string]*bucket
	rps     float64
	burst   float64
}

type bucket struct {
	tokens float64
	last   time.Time
}

// NewTokenBucket 创建限流器；rps<=0 表示不限制。
func NewTokenBucket(rps, burst float64) *TokenBucket {
	if burst < 1 {
		burst = 1
	}
	return &TokenBucket{
		buckets: make(map[string]*bucket),
		rps:     rps,
		burst:   burst,
	}
}

// Allow 判断 key 是否放行（消耗 1 个令牌）。
func (t *TokenBucket) Allow(key string) bool {
	return t.AllowN(key, 1)
}

// AllowN 判断 key 是否可放行 n 个令牌。
//
// 告警上报限流按"条数"而不是"请求数"计费：一个请求带 500 条告警
// 与 1 条告警对服务端的压力完全不同，按请求数限流会放过真正的突发。
func (t *TokenBucket) AllowN(key string, n float64) bool {
	if t == nil || t.rps <= 0 {
		return true
	}
	if n < 0 {
		n = 0
	}
	now := time.Now()
	t.mu.Lock()
	defer t.mu.Unlock()

	// 轻量 GC：桶过多时清理空闲桶
	if len(t.buckets) > 20000 {
		for k, b := range t.buckets {
			if now.Sub(b.last) > 10*time.Minute {
				delete(t.buckets, k)
			}
		}
	}

	b, ok := t.buckets[key]
	if !ok {
		b = &bucket{tokens: t.burst, last: now}
		t.buckets[key] = b
	} else {
		elapsed := now.Sub(b.last).Seconds()
		b.tokens += elapsed * t.rps
		b.last = now
		if b.tokens > t.burst {
			b.tokens = t.burst
		}
	}
	if n > b.tokens {
		return false
	}
	b.tokens -= n
	return true
}

// RateLimitMiddleware 对超限请求返回 429。
func RateLimitMiddleware(tb *TokenBucket, keyFn func(*http.Request) string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !tb.Allow(keyFn(r)) {
				w.Header().Set("Retry-After", "1")
				WriteError(w, r, apperr.TooManyRequests(""))
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// clientIP 取真实客户端 IP（信任 X-Forwarded-For 首跳仅当直连为内网时）。
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if ip := net.ParseIP(host); ip != nil && (ip.IsLoopback() || ip.IsPrivate()) {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			first := strings.TrimSpace(strings.Split(xff, ",")[0])
			if net.ParseIP(first) != nil {
				return first
			}
		}
	}
	return host
}

// ClientIP 导出给上层（审计日志用）。
func ClientIP(r *http.Request) string { return clientIP(r) }

// Chain 顺序组合中间件（第一个最外层）。
func Chain(h http.Handler, mws ...func(http.Handler) http.Handler) http.Handler {
	for i := len(mws) - 1; i >= 0; i-- {
		h = mws[i](h)
	}
	return h
}
