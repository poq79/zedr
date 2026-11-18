package totp

import (
	"encoding/base32"
	"strings"
	"testing"
	"time"
)

// rfSecret 是 RFC 6238 附录 B 的测试密钥（ASCII "12345678901234567890"）。
var rfSecret = base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte("12345678901234567890"))

// TestRFC6238Vector 用官方测试向量锁死实现正确性：
// SHA1 口径 T=59 → 94287082（8 位），6 位即 287082。
func TestRFC6238Vector(t *testing.T) {
	if got := generate(mustDecode(t, rfSecret), 59/30); got != "287082" {
		t.Fatalf("RFC 6238 向量不符: got %s want 287082", got)
	}
}

func TestVerifyAcceptsVectorAndDrift(t *testing.T) {
	at := time.Unix(59, 0)
	if !Verify("287082", rfSecret, at) {
		t.Fatal("同步码应通过")
	}
	// 前一/后一步（±30s 漂移窗口）
	if !Verify("287082", rfSecret, at.Add(30*time.Second)) {
		t.Fatal("±1 步窗口内的码应通过")
	}
}

func TestVerifyRejectsWrongAndGarbage(t *testing.T) {
	at := time.Unix(59, 0)
	if Verify("287083", rfSecret, at) {
		t.Fatal("错误码不应通过")
	}
	if Verify("28708", rfSecret, at) {
		t.Fatal("位数不足应拒绝")
	}
	if Verify("", rfSecret, at) {
		t.Fatal("空码应拒绝")
	}
	if Verify("287082", "not@base32!", at) {
		t.Fatal("坏密钥应拒绝而不是 panic")
	}
	// 相邻步之外的码（T=59+90s = 第 5 步，超出 ±1 窗口）
	if Verify(generate(mustDecode(t, rfSecret), (59+90)/30), rfSecret, at) {
		t.Fatal("超出 ±1 步窗口的码不应通过")
	}
}

func TestSecretAndURL(t *testing.T) {
	s1, err := Secret()
	if err != nil {
		t.Fatalf("Secret: %v", err)
	}
	s2, _ := Secret()
	if s1 == s2 {
		t.Fatal("两次生成的密钥不应相同")
	}
	if _, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(s1); err != nil {
		t.Fatalf("密钥必须是可解 base32: %v", err)
	}
	u := URL(s1, "ops@corp.local", "Z-EDR")
	if !strings.HasPrefix(u, "otpauth://totp/Z-EDR:ops@corp.local?") {
		t.Fatalf("otpauth URI 形态不对: %s", u)
	}
	if !strings.Contains(u, "secret="+s1) || !strings.Contains(u, "issuer=Z-EDR") {
		t.Fatalf("URI 缺少 secret/issuer 参数: %s", u)
	}
}

func mustDecode(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(s)
	if err != nil {
		t.Fatalf("解码测试密钥: %v", err)
	}
	return b
}
