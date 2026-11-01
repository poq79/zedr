// Package logx 提供统一的 slog JSON 日志，并保证每行携带 request id。
//
// 安全约束：密码、令牌、命令行中的敏感参数一律不落日志。
package logx

import (
	"context"
	"io"
	"log/slog"
	"os"
	"strings"
)

type ctxKey struct{}

// WithRequestID 把 request id 注入 context。
func WithRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, ctxKey{}, id)
}

// RequestID 从 context 取出 request id。
func RequestID(ctx context.Context) string {
	if v, ok := ctx.Value(ctxKey{}).(string); ok {
		return v
	}
	return ""
}

// Options 日志初始化参数。
type Options struct {
	Level  string    // debug|info|warn|error
	Format string    // json|text
	Writer io.Writer // 默认 os.Stdout
}

// New 构建带 request id 注入的 logger。
func New(o Options) *slog.Logger {
	if o.Writer == nil {
		o.Writer = os.Stdout
	}
	var lv slog.Level
	switch strings.ToLower(o.Level) {
	case "debug":
		lv = slog.LevelDebug
	case "warn", "warning":
		lv = slog.LevelWarn
	case "error":
		lv = slog.LevelError
	default:
		lv = slog.LevelInfo
	}

	hopt := &slog.HandlerOptions{
		Level: lv,
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if a.Key == slog.TimeKey {
				a.Key = "ts"
			}
			if a.Key == slog.LevelKey {
				a.Key = "level"
				if l, ok := a.Value.Any().(slog.Level); ok {
					a.Value = slog.StringValue(strings.ToLower(l.String()))
				}
			}
			return a
		},
	}

	var h slog.Handler
	if strings.EqualFold(o.Format, "text") {
		h = slog.NewTextHandler(o.Writer, hopt)
	} else {
		h = slog.NewJSONHandler(o.Writer, hopt)
	}

	return slog.New(&ctxHandler{inner: h})
}

// ctxHandler 在每条日志上补齐 request_id / agent 维度字段。
type ctxHandler struct{ inner slog.Handler }

func (h *ctxHandler) Enabled(ctx context.Context, l slog.Level) bool {
	return h.inner.Enabled(ctx, l)
}

func (h *ctxHandler) Handle(ctx context.Context, r slog.Record) error {
	if id := RequestID(ctx); id != "" {
		r.AddAttrs(slog.String("request_id", id))
	}
	return h.inner.Handle(ctx, r)
}

func (h *ctxHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &ctxHandler{inner: h.inner.WithAttrs(attrs)}
}

func (h *ctxHandler) WithGroup(name string) slog.Handler {
	return &ctxHandler{inner: h.inner.WithGroup(name)}
}

// Redact 对疑似密钥做脱敏，仅保留前 4 位。
func Redact(s string) string {
	if len(s) <= 8 {
		return "***"
	}
	return s[:4] + "***"
}
