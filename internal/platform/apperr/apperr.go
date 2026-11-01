// Package apperr 定义平台统一的类型化错误体系。
//
// 设计要点：
//   - 业务层只抛出 *Error，不再拼装 HTTP 状态码字符串；
//   - HTTP 层通过 From 把任意 error 归一化成对外错误结构；
//   - 对外只暴露 code / message，绝不泄露堆栈与内部细节。
package apperr

import (
	"errors"
	"fmt"
	"net/http"
)

// Code 是稳定的机器可读错误码，客户端据此做分支与文案映射。
type Code string

const (
	CodeInternal        Code = "internal_error"
	CodeInvalidArgument Code = "invalid_argument"
	CodeUnauthenticated Code = "unauthenticated"
	CodeForbidden       Code = "forbidden"
	CodeNotFound        Code = "not_found"
	CodeConflict        Code = "conflict"
	CodeTooManyRequests Code = "too_many_requests"
	CodeUnavailable     Code = "unavailable"
	CodeUpstream        Code = "upstream_error"
)

// Error 是平台唯一的业务错误类型。
type Error struct {
	Code    Code           // 机器可读错误码
	Message string         // 面向用户的可读文案（可安全对外）
	Status  int            // 建议的 HTTP 状态码
	Details map[string]any // 可选结构化细节（如字段级校验错误）
	cause   error          // 内部原因，仅日志记录
}

func (e *Error) Error() string {
	if e.cause != nil {
		return fmt.Sprintf("%s: %s: %v", e.Code, e.Message, e.cause)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

func (e *Error) Unwrap() error { return e.cause }

// WithCause 附加内部原因（不对外）。
func (e *Error) WithCause(err error) *Error {
	cp := *e
	cp.cause = err
	return &cp
}

// WithDetails 附加结构化细节。
func (e *Error) WithDetails(kv map[string]any) *Error {
	cp := *e
	cp.Details = kv
	return &cp
}

func newE(code Code, status int, msg string) *Error {
	return &Error{Code: code, Message: msg, Status: status}
}

func Invalid(format string, args ...any) *Error {
	return newE(CodeInvalidArgument, http.StatusBadRequest, sprintf(format, args...))
}

func Unauthenticated(msg string) *Error {
	if msg == "" {
		msg = "未认证或凭证已失效"
	}
	return newE(CodeUnauthenticated, http.StatusUnauthorized, msg)
}

func Forbidden(msg string) *Error {
	if msg == "" {
		msg = "当前角色无权执行该操作"
	}
	return newE(CodeForbidden, http.StatusForbidden, msg)
}

func NotFound(what string) *Error {
	return newE(CodeNotFound, http.StatusNotFound, what+" 不存在")
}

func Conflict(msg string) *Error {
	return newE(CodeConflict, http.StatusConflict, msg)
}

func TooManyRequests(msg string) *Error {
	if msg == "" {
		msg = "请求过于频繁，请稍后重试"
	}
	return newE(CodeTooManyRequests, http.StatusTooManyRequests, msg)
}

func Unavailable(msg string) *Error {
	return newE(CodeUnavailable, http.StatusServiceUnavailable, msg)
}

func Internal(err error) *Error {
	e := newE(CodeInternal, http.StatusInternalServerError, "服务内部错误")
	if err != nil {
		e.cause = err
	}
	return e
}

// From 把任意 error 归一化为 *Error；未识别的错误统一按 internal 处理。
func From(err error) *Error {
	if err == nil {
		return nil
	}
	var e *Error
	if errors.As(err, &e) {
		return e
	}
	return Internal(err)
}

func sprintf(format string, args ...any) string {
	if len(args) == 0 {
		return format
	}
	return fmt.Sprintf(format, args...)
}
