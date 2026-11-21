package service

import (
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"zedr/internal/platform/totp"
	"zedr/internal/server/auth"
	"zedr/internal/server/domain"
	"zedr/internal/server/repository/sqlite"
)

// MFA 登录闭环纪律：密码通过≠登录成功（启用 MFA 后必须过第二因子）；
// 票据单次使用；verify 失败并入登录锁定；解绑要密码+验证码双确认。
// 走真实 SQLite 仓储（同 sensor_watch_test 基建）。

func newMFATestSvc(t *testing.T) (*Services, context.Context, *domain.User) {
	t.Helper()
	ctx := context.Background()
	store, repos, err := sqlite.Open(ctx, filepath.Join(t.TempDir(), "mfa.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	mgr, err := auth.NewManager("test-jwt-secret-must-be-32-bytes-long!!", 15*time.Minute, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	svc := New(repos, mgr, Config{}, log, nil)
	u, err := svc.Auth.CreateUser(ctx, "opsadmin", "运维管理员", "Str0ngPass!2026", domain.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	return svc, ctx, u
}

func TestMFATurnstileFlow(t *testing.T) {
	svc, ctx, u := newMFATestSvc(t)

	// ① 未启用 MFA：密码登录直接发令牌
	res, err := svc.Auth.Login(ctx, "opsadmin", "Str0ngPass!2026", "127.0.0.1", "test")
	if err != nil {
		t.Fatalf("未启用 MFA 的登录: %v", err)
	}
	if res.MfaRequired || res.AccessToken == "" {
		t.Fatalf("未启用 MFA 应直接发令牌: %+v", res)
	}

	// ② enroll：密钥落库但未启用，登录仍直接发令牌
	secret, uri, err := svc.Auth.EnrollMFA(ctx, u.ID)
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}
	if secret == "" || !strings.Contains(uri, "otpauth://totp/Z-EDR:opsadmin?") {
		t.Fatalf("enroll 返回异常: secret=%q uri=%q", secret, uri)
	}
	res2, _ := svc.Auth.Login(ctx, "opsadmin", "Str0ngPass!2026", "127.0.0.1", "test")
	if res2.MfaRequired {
		t.Fatal("未确认的 enroll 不应影响登录（半途而废的绑定不能拦人）")
	}

	// ③ confirm：错误码拒绝，正确码启用
	if err := svc.Auth.ConfirmMFA(ctx, u.ID, "000000"); err == nil {
		t.Fatal("错误验证码不应启用成功")
	}
	code, err := totp.Code(secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.Auth.ConfirmMFA(ctx, u.ID, code); err != nil {
		t.Fatalf("正确验证码应启用: %v", err)
	}

	// ④ 启用后登录：mfa_required + 票据，无令牌
	res3, err := svc.Auth.Login(ctx, "opsadmin", "Str0ngPass!2026", "127.0.0.1", "test")
	if err != nil {
		t.Fatalf("启用 MFA 后登录: %v", err)
	}
	if !res3.MfaRequired || res3.MfaTicket == "" || res3.AccessToken != "" {
		t.Fatalf("启用 MFA 应返回票据而非令牌: mfa=%v token=%q", res3.MfaRequired, res3.AccessToken)
	}

	// ⑤ verify：错误码拒绝；票据消费后不可复用
	if _, err := svc.Auth.VerifyMFA(ctx, res3.MfaTicket, "000000", "127.0.0.1", "test"); err == nil {
		t.Fatal("错误验证码不应通过")
	}
	if _, err := svc.Auth.VerifyMFA(ctx, res3.MfaTicket, code, "127.0.0.1", "test"); err == nil {
		t.Fatal("失败尝试后票据不可复用（单次使用）")
	}

	// ⑥ 完整流程重走：票据 + 正确码 → 令牌对
	res4, err := svc.Auth.Login(ctx, "opsadmin", "Str0ngPass!2026", "127.0.0.1", "test")
	if err != nil {
		t.Fatal(err)
	}
	code4, _ := totp.Code(secret, time.Now())
	res5, err := svc.Auth.VerifyMFA(ctx, res4.MfaTicket, code4, "127.0.0.1", "test")
	if err != nil {
		t.Fatalf("正确票据+验证码应发令牌: %v", err)
	}
	if res5.AccessToken == "" || res5.RefreshToken == "" || res5.User == nil {
		t.Fatalf("verify 结果缺凭证: %+v", res5)
	}
}

func TestMFALockoutOnVerifyBrute(t *testing.T) {
	svc, ctx, u := newMFATestSvc(t)
	secret, _, err := svc.Auth.EnrollMFA(ctx, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	code, err := totp.Code(secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.Auth.ConfirmMFA(ctx, u.ID, code); err != nil {
		t.Fatal(err)
	}

	res, err := svc.Auth.Login(ctx, "opsadmin", "Str0ngPass!2026", "127.0.0.1", "test")
	if err != nil || !res.MfaRequired {
		t.Fatalf("登录应到 MFA 阶段: %v", err)
	}
	// 票据在第一次失败即消费，所以每次失败都要重新走登录拿新票据
	for i := 0; i < maxLoginFails; i++ {
		res, err := svc.Auth.Login(ctx, "opsadmin", "Str0ngPass!2026", "127.0.0.1", "test")
		if err != nil {
			t.Fatalf("第 %d 轮登录不应被锁: %v", i+1, err)
		}
		if _, lastErr := svc.Auth.VerifyMFA(ctx, res.MfaTicket, "000000", "127.0.0.1", "test"); lastErr == nil {
			t.Fatal("错误码不应通过")
		}
	}
	// 第 6 轮：登录直接被锁（verify 失败并入 loginGuard）
	if _, err := svc.Auth.Login(ctx, "opsadmin", "Str0ngPass!2026", "127.0.0.1", "test"); err == nil || !strings.Contains(err.Error(), "临时锁定") {
		t.Fatalf("MFA 暴破应触发登录锁定, got: %v", err)
	}
}

func TestMFADisableRequiresPasswordAndCode(t *testing.T) {
	svc, ctx, u := newMFATestSvc(t)
	secret, _, err := svc.Auth.EnrollMFA(ctx, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	code, _ := totp.Code(secret, time.Now())
	if err := svc.Auth.ConfirmMFA(ctx, u.ID, code); err != nil {
		t.Fatal(err)
	}

	if err := svc.Auth.DisableMFA(ctx, u.ID, "WrongPass!2026x", code); err == nil {
		t.Fatal("密码错误不应允许解绑")
	}
	if err := svc.Auth.DisableMFA(ctx, u.ID, "Str0ngPass!2026", "000000"); err == nil {
		t.Fatal("验证码错误不应允许解绑")
	}
	if err := svc.Auth.DisableMFA(ctx, u.ID, "Str0ngPass!2026", code); err != nil {
		t.Fatalf("密码+验证码齐全应解绑: %v", err)
	}
	// 解绑后登录恢复单因素
	res, err := svc.Auth.Login(ctx, "opsadmin", "Str0ngPass!2026", "127.0.0.1", "test")
	if err != nil || res.MfaRequired || res.AccessToken == "" {
		t.Fatalf("解绑后应回到单因素登录: %v mfa=%v", err, res.MfaRequired)
	}
}

// 复现 E2E 发现的登录 500：策略命中分支的 nil 解引用。
func TestMFAPolicyEnrollRepro(t *testing.T) {
	svc, ctx, u := newMFATestSvc(t)

	// ① 设策略：管理员强制
	if err := svc.Auth.SetMFAPolicy(ctx, MFAPolicy{RequireAdmins: true}); err != nil {
		t.Fatalf("SetMFAPolicy: %v", err)
	}
	// ② 登录应改发待绑定票据（此步曾 panic）
	res, err := svc.Auth.Login(ctx, "opsadmin", "Str0ngPass!2026", "127.0.0.1", "test")
	if err != nil {
		t.Fatalf("策略命中登录: %v", err)
	}
	if !res.MfaEnrollRequired || res.MfaTicket == "" || res.AccessToken != "" {
		t.Fatalf("应返回待绑定票据: %+v", res)
	}
	// ③ pending-enroll 出密钥
	secret, uri, err := svc.Auth.PendingEnrollMFA(ctx, res.MfaTicket)
	if err != nil {
		t.Fatalf("pending-enroll: %v", err)
	}
	if secret == "" || uri == "" {
		t.Fatal("pending-enroll 应返回密钥与 URI")
	}
	_ = u
	// ④ pending-confirm 绑定即登录
	code, err := totp.Code(secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	res2, err := svc.Auth.PendingConfirmMFA(ctx, res.MfaTicket, code, "127.0.0.1", "test")
	if err != nil {
		t.Fatalf("pending-confirm: %v", err)
	}
	if res2.AccessToken == "" {
		t.Fatal("绑定后应直接签发令牌")
	}
}
