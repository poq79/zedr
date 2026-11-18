// Package totp 实现 RFC 6238 TOTP（时间一次性密码），供管理台 MFA 使用。
//
// 只用标准库（crypto/hmac + crypto/sha1 + encoding/base32）：RFC 6238
// 核心是"HMAC-SHA1 over 8 字节时间步 + 动态截断"约 30 行，不值得为它
// 引入第三方依赖（AGENTS §4 简洁性）。参数钉死为业界默认：
// SHA1 / 6 位 / 30s 步长——Google Authenticator、1Password、企业 IdP
// 的兼容基线，不需要可配置性。
package totp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// Secret 生成新的 base32 密钥（20 字节熵 = 160 位，RFC 4226 推荐上限）。
func Secret() (string, error) {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("生成 TOTP 密钥: %w", err)
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b), nil
}

// URL 生成 otpauth:// 迁移 URI（扫码/手动录入用）。
func URL(secret, account, issuer string) string {
	label := url.PathEscape(issuer) + ":" + url.PathEscape(account)
	q := url.Values{}
	q.Set("secret", secret)
	q.Set("issuer", issuer)
	q.Set("algorithm", "SHA1")
	q.Set("digits", "6")
	q.Set("period", "30")
	return "otpauth://totp/" + label + "?" + q.Encode()
}

// Verify 校验 6 位验证码。允许 ±1 个时间步（30s）的时钟漂移——
// 手机端时钟与服务端有秒级偏差是常态，这是所有 TOTP 实现的标配窗口。
// 恒定时间比较，防时序侧信道逐位猜码。
func Verify(code, secret string, at time.Time) bool {
	code = strings.TrimSpace(code)
	if len(code) != 6 {
		return false
	}
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil || len(key) == 0 {
		return false
	}
	step := at.Unix() / 30
	for _, d := range []int64{-1, 0, 1} {
		if gen := generate(key, step+d); subtle.ConstantTimeCompare([]byte(gen), []byte(code)) == 1 {
			return true
		}
	}
	return false
}

// Code 计算指定时刻的 6 位验证码。导出原因：E2E 验证与运维拨测脚本
// 需要"从密钥重算验证码"的能力（认证器不在服务器上），实现就是 Verify
// 的正向路径，放同一个包避免两份截断逻辑漂移。
func Code(secret string, at time.Time) (string, error) {
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.TrimSpace(secret))
	if err != nil || len(key) == 0 {
		return "", fmt.Errorf("无效的 base32 密钥")
	}
	return generate(key, at.Unix()/30), nil
}

// generate 按 RFC 4226 §5.3 动态截断生成 6 位码。
func generate(key []byte, step int64) string {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(step))
	mac := hmac.New(sha1.New, key)
	mac.Write(buf[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	v := (binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff) % 1000000
	return fmt.Sprintf("%06d", v)
}
