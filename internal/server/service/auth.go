package service

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"time"

	"zedr/internal/platform/apperr"
	"zedr/internal/platform/idgen"
	"zedr/internal/platform/totp"
	"zedr/internal/server/auth"
	"zedr/internal/server/domain"
	"zedr/internal/server/repository"
)

// AuthService 负责登录、刷新令牌轮转与登出。
type AuthService struct {
	repos  repository.Repos
	tokens *auth.Manager
	log    *slog.Logger
	guard  loginGuard

	mfaMu sync.Mutex
	mfa   map[string]mfaTicket
}

// audit 写审计（登录失败/锁定等安全事件）。尽力而为：审计写失败
// 不应放大成登录不可用。
func (s *AuthService) audit(ctx context.Context, userID, username, action, target, detail, ip string) {
	_ = s.repos.Audit.Add(ctx, &domain.AuditLog{
		UserID: userID, Username: username, Action: action,
		Target: target, Detail: truncate(detail, 2000),
		IP: ip, CreatedAt: time.Now(),
	})
}

// ---------------------------------------------------------------- 登录失败锁定
//
// 进程内状态而非数据库：锁定是短时（15 分钟）防御，服务重启即清零是可接受的
// ——它防的是在线暴力破解，不是持久攻击。按用户名锁定有一个已知代价：
// 攻击者可以故意锁死他人账号（拒绝服务）。之所以仍按用户名锁：
// 企业场景账号数有限、来源 IP 分散（NAT 后无法按 IP 锁），
// 锁定的骚扰远小于密码被撞开的损失；登录接口另有独立限流兜底。

const (
	maxLoginFails = 5
	loginLockDur  = 15 * time.Minute
)

type loginFail struct {
	count       int
	lockedUntil time.Time
}

type loginGuard struct {
	fails map[string]*loginFail
}

// checkLocked 返回是否处于锁定中（顺带懒清理过期条目）。
func (g *loginGuard) checkLocked(username string) (bool, time.Duration) {
	if g.fails == nil {
		return false, 0
	}
	e, ok := g.fails[username]
	if !ok {
		return false, 0
	}
	if remain := time.Until(e.lockedUntil); remain > 0 {
		return true, remain
	}
	// 锁定已过期：清零重来
	if !e.lockedUntil.IsZero() {
		delete(g.fails, username)
	}
	return false, 0
}

func (g *loginGuard) recordFail(username string) (locked bool, remain time.Duration) {
	if g.fails == nil {
		g.fails = make(map[string]*loginFail, 16)
	}
	e := g.fails[username]
	if e == nil {
		e = &loginFail{}
		g.fails[username] = e
	}
	// 锁定期间不计次数（锁定本身就是在惩罚，不需要无限延长）
	if time.Until(e.lockedUntil) > 0 {
		return true, time.Until(e.lockedUntil)
	}
	e.count++
	if e.count >= maxLoginFails {
		e.lockedUntil = time.Now().Add(loginLockDur)
		return true, loginLockDur
	}
	return false, 0
}

func (g *loginGuard) reset(username string) {
	if g.fails != nil {
		delete(g.fails, username)
	}
}

// ---------------------------------------------------------------- 密码策略

// ValidatePasswordStrength 校验密码强度：≥10 位且至少包含大小写/数字/符号中的三类。
// 企业环境下弱密码是最便宜的入侵通道；这条策略的成本是三行代码，收益远超成本。
func ValidatePasswordStrength(pw string) error {
	if len(pw) < 10 {
		return apperr.Invalid("密码至少 10 位")
	}
	var classes int
	for _, has := range []bool{
		strings.ContainsFunc(pw, func(r rune) bool { return r >= 'a' && r <= 'z' }),
		strings.ContainsFunc(pw, func(r rune) bool { return r >= 'A' && r <= 'Z' }),
		strings.ContainsFunc(pw, func(r rune) bool { return r >= '0' && r <= '9' }),
		strings.ContainsFunc(pw, func(r rune) bool {
			return !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9'))
		}),
	} {
		if has {
			classes++
		}
	}
	if classes < 3 {
		return apperr.Invalid("密码需包含大小写字母、数字、符号中的至少三类")
	}
	return nil
}

// LoginResult 是登录成功后的凭证集合。
//
// MfaRequired=true 表示密码已验但该账号启用了 TOTP：此时令牌字段全空，
// 携带 MfaTicket，凭码调 VerifyMFA 换取真正的令牌对。
type LoginResult struct {
	AccessToken  string
	ExpiresAt    time.Time
	RefreshToken string
	RefreshExp   time.Time
	User         *domain.User
	MfaRequired  bool
	// MfaEnrollRequired=true 表示 MFA 策略强制命中且账号未绑定：凭
	// MfaTicket 走 pending-enroll/confirm 完成绑定，绑定即登录
	MfaEnrollRequired bool
	MfaTicket         string
}

// ---------------------------------------------------------------- MFA（TOTP 双因素）
//
// 双因素 = 密码（所知）+ TOTP（所持）。密码通过且账号已启用 MFA 时不发
// 令牌，发 3 分钟一次性 mfa 票据；verify 凭票据+验证码换令牌对。
// 票据等价于"密码已验"，所以：短时效 + 单次使用 + verify 失败并入
// 登录失败锁定（同 loginGuard，防止对 verify 端点单独暴破验证码）。

const mfaTicketTTL = 3 * time.Minute

type mfaTicket struct {
	userID    string
	username  string
	expiresAt time.Time
}

// issueMFATicket 登录密码通过后签发待验证票据。
func (s *AuthService) issueMFATicket(u *domain.User) string {
	id := idgen.URLSafe(32)
	s.mfaMu.Lock()
	if s.mfa == nil {
		s.mfa = make(map[string]mfaTicket, 8)
	}
	// 顺手懒清理过期票据（登录频率低，不值得单独起清理协程）
	now := time.Now()
	for k, t := range s.mfa {
		if now.After(t.expiresAt) {
			delete(s.mfa, k)
		}
	}
	s.mfa[id] = mfaTicket{userID: u.ID, username: u.Username, expiresAt: now.Add(mfaTicketTTL)}
	s.mfaMu.Unlock()
	return id
}

// mfaSettingRequireAdmins / mfaSettingRequireAll 是 MFA 强制策略的
// settings KV 键（GitLab 形态：策略类进设置中心热更新，不进 env——
// 2026-11-21 调研口径，来源见 overview.md）。默认双关：本机测试零负担。
const (
	mfaSettingRequireAdmins = "mfa_require_admins"
	mfaSettingRequireAll    = "mfa_require_all"
)

// MFAPolicy 是 MFA 强制策略（settings KV 存储，每次登录热读取）。
type MFAPolicy struct {
	RequireAdmins bool `json:"require_admins"` // 管理员账号强制（CISA admin-first 口径）
	RequireAll    bool `json:"require_all"`    // 全员强制
}

func settingTrue(v string, ok bool) bool {
	return ok && strings.EqualFold(strings.TrimSpace(v), "true")
}

// GetMFAPolicy 读当前策略。
func (s *AuthService) GetMFAPolicy(ctx context.Context) MFAPolicy {
	va, oka, _ := s.repos.AIConfig.GetSetting(ctx, mfaSettingRequireAdmins)
	vl, okl, _ := s.repos.AIConfig.GetSetting(ctx, mfaSettingRequireAll)
	return MFAPolicy{
		RequireAdmins: settingTrue(va, oka),
		RequireAll:    settingTrue(vl, okl),
	}
}

// SetMFAPolicy 写策略（幂等，热生效——登录时实时读取，无需重启）。
func (s *AuthService) SetMFAPolicy(ctx context.Context, p MFAPolicy) error {
	for key, val := range map[string]string{
		mfaSettingRequireAdmins: strconv.FormatBool(p.RequireAdmins),
		mfaSettingRequireAll:    strconv.FormatBool(p.RequireAll),
	} {
		if err := s.repos.AIConfig.SetSetting(ctx, key, val); err != nil {
			return err
		}
	}
	return nil
}

// mfaPolicyHit 判定该账号是否命中强制策略（未启用双因素时）。
func (s *AuthService) mfaPolicyHit(ctx context.Context, role domain.Role) bool {
	p := s.GetMFAPolicy(ctx)
	if p.RequireAll {
		return true
	}
	return p.RequireAdmins && role == domain.RoleAdmin
}

// peekMFATicket 校验票据有效但不消费——pending-enroll（生成密钥）与
// pending-confirm（消费+签发令牌）是两步，票据必须在两步间保持有效。
func (s *AuthService) peekMFATicket(id string) (*mfaTicket, bool) {
	s.mfaMu.Lock()
	defer s.mfaMu.Unlock()
	t, ok := s.mfa[id]
	if !ok || time.Now().After(t.expiresAt) {
		return nil, false
	}
	return &t, true
}

// PendingEnrollMFA 凭"密码已验"票据发起 TOTP 绑定：返回密钥与 otpauth
// URI 供登录页渲染二维码/手录。票据不消费（confirm 时才消费）。
func (s *AuthService) PendingEnrollMFA(ctx context.Context, ticketID string) (secret, otpauthURL string, err error) {
	t, ok := s.peekMFATicket(ticketID)
	if !ok {
		return "", "", apperr.Unauthenticated("登录票据无效或已过期，请重新登录")
	}
	return s.EnrollMFA(ctx, t.userID)
}

// PendingConfirmMFA 凭票据完成绑定并签发令牌对——强制绑定流程在登录
// 环节闭环，无需已认证会话。
func (s *AuthService) PendingConfirmMFA(ctx context.Context, ticketID, code, ip, ua string) (*LoginResult, error) {
	t, ok := s.consumeMFATicket(strings.TrimSpace(ticketID))
	if !ok {
		return nil, apperr.Unauthenticated("登录票据无效或已过期，请重新登录")
	}
	if err := s.ConfirmMFA(ctx, t.userID, code); err != nil {
		return nil, err
	}
	u, err := s.repos.Users.ByID(ctx, t.userID)
	if err != nil || u == nil {
		return nil, apperr.NotFound("用户")
	}
	s.audit(ctx, u.ID, u.Username, "auth.mfa_pending_confirm", u.Username,
		"MFA 策略强制：登录环节完成绑定", ip)
	return s.newSession(ctx, u, ip, ua, true)
}

// consumeMFATicket 取走票据（单次使用：取走即删，防重放）。
func (s *AuthService) consumeMFATicket(id string) (*mfaTicket, bool) {
	s.mfaMu.Lock()
	defer s.mfaMu.Unlock()
	t, ok := s.mfa[id]
	if !ok {
		return nil, false
	}
	delete(s.mfa, id)
	if time.Now().After(t.expiresAt) {
		return nil, false
	}
	return &t, true
}

// EnrollMFA 生成本账号的 TOTP 绑定：密钥落库但 enabled=false，确认后才
// 翻转——半途而废的绑定不会拦住下次登录。重复 enroll 覆盖旧密钥。
func (s *AuthService) EnrollMFA(ctx context.Context, userID string) (secret, otpauthURL string, err error) {
	u, err := s.repos.Users.ByID(ctx, userID)
	if err != nil {
		return "", "", err
	}
	if u == nil {
		return "", "", apperr.NotFound("用户")
	}
	if u.TotpEnabled {
		return "", "", apperr.Conflict("已启用双因素验证，如需更换请先解绑")
	}
	secret, err = totp.Secret()
	if err != nil {
		return "", "", apperr.Internal(err)
	}
	if err := s.repos.Users.SetTotp(ctx, userID, secret, false); err != nil {
		return "", "", err
	}
	s.audit(ctx, u.ID, u.Username, "auth.mfa_enroll", u.Username, "", "")
	return secret, totp.URL(secret, u.Username, "Z-EDR"), nil
}

// ConfirmMFA 确认绑定：验证码通过才把 enroll 落库的密钥翻转为启用。
func (s *AuthService) ConfirmMFA(ctx context.Context, userID, code string) error {
	u, err := s.repos.Users.ByID(ctx, userID)
	if err != nil {
		return err
	}
	if u == nil {
		return apperr.NotFound("用户")
	}
	if u.TotpEnabled {
		return apperr.Conflict("已启用双因素验证")
	}
	if u.TotpSecret == "" {
		return apperr.Invalid("请先发起双因素绑定")
	}
	if !totp.Verify(code, u.TotpSecret, time.Now()) {
		return apperr.Invalid("验证码不正确（请确认认证器时间同步）")
	}
	if err := s.repos.Users.SetTotp(ctx, userID, u.TotpSecret, true); err != nil {
		return err
	}
	s.audit(ctx, u.ID, u.Username, "auth.mfa_enabled", u.Username, "", "")
	s.log.InfoContext(ctx, "mfa_enabled", "user_id", u.ID, "username", u.Username)
	return nil
}

// DisableMFA 解绑：要求密码 + 当前验证码双确认——解绑等于把双因素
// 账号降回单因素，必须是"本人 + 持有设备"双重在场才允许。
func (s *AuthService) DisableMFA(ctx context.Context, userID, password, code string) error {
	u, err := s.repos.Users.ByID(ctx, userID)
	if err != nil {
		return err
	}
	if u == nil {
		return apperr.NotFound("用户")
	}
	if !u.TotpEnabled {
		return apperr.Conflict("未启用双因素验证")
	}
	if !auth.ComparePassword(u.PasswordHash, password) {
		return apperr.Invalid("密码不正确")
	}
	if !totp.Verify(code, u.TotpSecret, time.Now()) {
		return apperr.Invalid("验证码不正确")
	}
	if err := s.repos.Users.SetTotp(ctx, userID, "", false); err != nil {
		return err
	}
	s.audit(ctx, u.ID, u.Username, "auth.mfa_disabled", u.Username, "", "")
	s.log.InfoContext(ctx, "mfa_disabled", "user_id", u.ID, "username", u.Username)
	return nil
}

// VerifyMFA 用登录票据 + TOTP 验证码换取令牌对。票据单次使用；
// 验证失败并入登录锁定（recordFail），防止绕过 /login 限流单独暴破码。
func (s *AuthService) VerifyMFA(ctx context.Context, ticketID, code, ip, ua string) (*LoginResult, error) {
	ticket, ok := s.consumeMFATicket(strings.TrimSpace(ticketID))
	if !ok {
		return nil, apperr.Unauthenticated("登录票据无效或已过期，请重新登录")
	}
	u, err := s.repos.Users.ByID(ctx, ticket.userID)
	if err != nil {
		return nil, err
	}
	if u == nil || u.Disabled {
		return nil, apperr.Unauthenticated("账号不可用")
	}
	if !u.TotpEnabled || !totp.Verify(code, u.TotpSecret, time.Now()) {
		// 票据已消费：失败后必须重新走完整登录（密码→票据→verify），
		// 攻击者拿不到可重试的"密码已验"状态
		if locked, remain := s.guard.recordFail(ticket.username); locked {
			s.audit(ctx, "", ticket.username, "auth.login_locked", ticket.username,
				fmt.Sprintf("MFA 连续失败触发锁定（剩余 %d 秒）", int(remain.Seconds())), ip)
			return nil, apperr.Invalid("该账号已临时锁定，请 %d 分钟后重试", int(remain.Minutes())+1)
		}
		s.audit(ctx, u.ID, ticket.username, "auth.mfa_failed", ticket.username, "", ip)
		s.log.WarnContext(ctx, "mfa_verify_failed", "username", ticket.username, "ip", ip)
		return nil, apperr.Unauthenticated("验证码不正确")
	}
	s.guard.reset(ticket.username)

	res, err := s.newSession(ctx, u, ip, ua, true)
	if err != nil {
		return nil, err
	}
	s.log.InfoContext(ctx, "login_success", "user_id", u.ID, "username", u.Username,
		"role", u.Role, "ip", ip, "mfa", true)
	return res, nil
}

// Login 校验账号密码并签发令牌对。
func (s *AuthService) Login(ctx context.Context, username, password, ip, ua string) (*LoginResult, error) {
	username = strings.TrimSpace(strings.ToLower(username))
	if username == "" || password == "" {
		return nil, apperr.Invalid("用户名与密码不能为空")
	}

	if locked, remain := s.guard.checkLocked(username); locked {
		s.audit(ctx, "", username, "auth.login_locked", username,
			fmt.Sprintf("锁定剩余 %d 秒", int(remain.Seconds())), ip)
		s.log.WarnContext(ctx, "login_locked", "username", username, "ip", ip,
			"remain_sec", int(remain.Seconds()))
		return nil, apperr.Invalid("该账号已临时锁定（连续登录失败），请 %d 分钟后重试",
			int(remain.Minutes())+1)
	}

	u, err := s.repos.Users.ByUsername(ctx, username)
	if err != nil {
		return nil, err
	}
	// 用户名不存在与密码错误返回同一文案，避免账号枚举
	if u == nil || u.Disabled || !auth.ComparePassword(u.PasswordHash, password) {
		if locked, remain := s.guard.recordFail(username); locked {
			s.audit(ctx, "", username, "auth.login_locked", username,
				fmt.Sprintf("连续失败触发锁定（剩余 %d 秒）", int(remain.Seconds())), ip)
			s.log.WarnContext(ctx, "login_locked", "username", username, "ip", ip,
				"remain_sec", int(remain.Seconds()))
			return nil, apperr.Invalid("该账号已临时锁定（连续登录失败），请 %d 分钟后重试",
				int(remain.Minutes())+1)
		}
		// 失败也进审计：暴力破解在 SIEM 侧的表现就是"同用户名大量
		// auth.login_failed"，只写日志不入库的话，运营在管理台看不到
		s.audit(ctx, "", username, "auth.login_failed", username, "", ip)
		s.log.WarnContext(ctx, "login_failed", "username", username, "ip", ip)
		return nil, apperr.Unauthenticated("用户名或密码错误")
	}
	// TOTP 双因素：密码已验但第二因子未验——不发令牌，发待验证票据。
	// 票据 3 分钟/单次使用，verify 失败并入登录锁定（见 VerifyMFA）。
	// 注意 reset 必须放在 MFA 分支之后：双因素账号在第二因子通过前
	// 不清失败计数，否则"密码正确+暴破验证码"每轮都被 reset，永远
	// 累积不到锁定阈值（测试 TestMFALockoutOnVerifyBrute 钉死此语义）。
	if u.TotpEnabled {
		s.audit(ctx, u.ID, u.Username, "auth.mfa_required", u.Username, "", ip)
		return &LoginResult{MfaRequired: true, MfaTicket: s.issueMFATicket(u)}, nil
	}
	// MFA 策略强制（GitLab 形态，2026-11-21 调研）：设置中心开关命中且
	// 账号未启用双因素 → 拒发令牌，改发"待绑定票据"（密码已验）——
	// 前端凭票据在登录页完成绑定（pending-enroll/confirm），绑定即登录。
	// 未命中策略的账号（含全部本机测试场景）登录流程零变化。
	if !u.TotpEnabled && s.mfaPolicyHit(ctx, u.Role) {
		s.audit(ctx, u.ID, u.Username, "auth.mfa_enroll_required", u.Username, "", ip)
		return &LoginResult{MfaEnrollRequired: true, MfaTicket: s.issueMFATicket(u)}, nil
	}
	s.guard.reset(username)

	res, err := s.newSession(ctx, u, ip, ua, true)
	if err != nil {
		return nil, err
	}
	s.log.InfoContext(ctx, "login_success", "user_id", u.ID, "username", u.Username, "role", u.Role, "ip", ip)
	return res, nil
}

// newSession 签发访问令牌并落刷新令牌行（Login/VerifyMFA/Refresh 共用）。
// touchLogin=false 用于 Refresh：刷新轮换是凭证续期不是新的登录事实，
// last_login_at 应保留为最近一次真实登录时间。
func (s *AuthService) newSession(ctx context.Context, u *domain.User, ip, ua string, touchLogin bool) (*LoginResult, error) {
	access, exp, err := s.tokens.IssueAccess(u, time.Now())
	if err != nil {
		return nil, apperr.Internal(err)
	}

	refreshRaw := idgen.URLSafe(32)
	refreshExp := time.Now().Add(s.tokens.RefreshTTL())
	if err := s.repos.Tokens.Create(ctx, &domain.RefreshToken{
		ID:        idgen.Hex(12),
		UserID:    u.ID,
		TokenHash: auth.HashRefreshToken(refreshRaw),
		ExpiresAt: refreshExp,
		CreatedAt: time.Now(),
		UserAgent: truncate(ua, 200),
		IP:        ip,
	}); err != nil {
		return nil, err
	}

	if touchLogin {
		_ = s.repos.Users.TouchLogin(ctx, u.ID, time.Now())
	}
	return &LoginResult{
		AccessToken:  access,
		ExpiresAt:    exp,
		RefreshToken: refreshRaw,
		RefreshExp:   refreshExp,
		User:         u,
	}, nil
}

// Refresh 用刷新令牌换取新访问令牌，并轮转刷新令牌（一次性使用）。
func (s *AuthService) Refresh(ctx context.Context, rawRefresh, ip, ua string) (*LoginResult, error) {
	if rawRefresh == "" {
		return nil, apperr.Unauthenticated("缺少刷新令牌")
	}
	hash := auth.HashRefreshToken(rawRefresh)
	t, err := s.repos.Tokens.ByHash(ctx, hash)
	if err != nil {
		return nil, err
	}
	if t == nil || t.Revoked || time.Now().After(t.ExpiresAt) {
		return nil, apperr.Unauthenticated("刷新令牌无效或已过期，请重新登录")
	}

	u, err := s.repos.Users.ByID(ctx, t.UserID)
	if err != nil {
		return nil, err
	}
	if u == nil || u.Disabled {
		return nil, apperr.Unauthenticated("账号不可用")
	}

	// 轮转：旧令牌立即失效
	if err := s.repos.Tokens.Revoke(ctx, t.ID); err != nil {
		return nil, err
	}

	// 刷新令牌轮换不带 touchLogin：续期不是新的登录事实
	return s.newSession(ctx, u, ip, ua, false)
}

// Logout 吊销指定刷新令牌。
func (s *AuthService) Logout(ctx context.Context, rawRefresh string) error {
	if rawRefresh == "" {
		return nil
	}
	t, err := s.repos.Tokens.ByHash(ctx, auth.HashRefreshToken(rawRefresh))
	if err != nil {
		return err
	}
	if t == nil {
		return nil
	}
	return s.repos.Tokens.Revoke(ctx, t.ID)
}

// Me 返回当前账号信息。
func (s *AuthService) Me(ctx context.Context, userID string) (*domain.User, error) {
	u, err := s.repos.Users.ByID(ctx, userID)
	if err != nil {
		return nil, err
	}
	if u == nil {
		return nil, apperr.NotFound("账号")
	}
	return u, nil
}

// BootstrapAdmin 在无任何账号时创建初始管理员，返回明文密码（仅首次打印）。
func (s *AuthService) BootstrapAdmin(ctx context.Context, username, password string) (string, string, error) {
	n, err := s.repos.Users.Count(ctx)
	if err != nil {
		return "", "", err
	}
	if n > 0 {
		return "", "", nil
	}
	if username == "" {
		username = "admin"
	}
	generated := false
	if password == "" {
		password = idgen.URLSafe(12)
		generated = true
	}
	hash, err := auth.HashPassword(password)
	if err != nil {
		return "", "", err
	}
	u := &domain.User{
		ID:           idgen.Hex(12),
		Username:     strings.ToLower(username),
		DisplayName:  "初始管理员",
		PasswordHash: hash,
		Role:         domain.RoleAdmin,
		CreatedAt:    time.Now(),
	}
	if err := s.repos.Users.Create(ctx, u); err != nil {
		return "", "", err
	}
	if generated {
		return username, password, nil
	}
	return username, "", nil
}

// ChangePassword 修改当前用户密码。
//
// 除常规校验外必须吊销该用户的全部刷新令牌：密码改了，
// "记住登录"的其它设备不能继续免密续期——这是密码轮换语义的一半，
// 漏掉它等于改了个寂寞。
func (s *AuthService) ChangePassword(ctx context.Context, userID, oldPw, newPw string) error {
	u, err := s.repos.Users.ByID(ctx, userID)
	if err != nil || u == nil {
		return apperr.NotFound("用户")
	}
	if !auth.ComparePassword(u.PasswordHash, oldPw) {
		return apperr.Invalid("原密码不正确")
	}
	if err := ValidatePasswordStrength(newPw); err != nil {
		return err
	}
	hash, err := auth.HashPassword(newPw)
	if err != nil {
		return apperr.Internal(err)
	}
	if err := s.repos.Users.UpdatePassword(ctx, userID, hash); err != nil {
		return err
	}
	if err := s.repos.Tokens.RevokeAllForUser(ctx, userID); err != nil {
		return err
	}
	s.log.InfoContext(ctx, "password_changed", "user_id", userID, "tokens_revoked", true)
	return nil
}

// CreateUser 创建后台账号（仅管理员）。
func (s *AuthService) CreateUser(ctx context.Context, username, displayName, password string, role domain.Role) (*domain.User, error) {
	if err := ValidatePasswordStrength(password); err != nil {
		return nil, err
	}
	username = strings.ToLower(strings.TrimSpace(username))
	if len(username) < 3 {
		return nil, apperr.Invalid("用户名至少 3 个字符")
	}
	if !role.Valid() {
		return nil, apperr.Invalid("角色非法，可选 admin/analyst/viewer")
	}
	exists, err := s.repos.Users.ByUsername(ctx, username)
	if err != nil {
		return nil, err
	}
	if exists != nil {
		return nil, apperr.Conflict("用户名已存在")
	}
	hash, err := auth.HashPassword(password)
	if err != nil {
		return nil, err
	}
	u := &domain.User{
		ID:           idgen.Hex(12),
		Username:     username,
		DisplayName:  displayName,
		PasswordHash: hash,
		Role:         role,
		CreatedAt:    time.Now(),
	}
	if err := s.repos.Users.Create(ctx, u); err != nil {
		return nil, err
	}
	return u, nil
}

// ListUsers 列出后台账号。
func (s *AuthService) ListUsers(ctx context.Context) ([]domain.User, error) {
	return s.repos.Users.List(ctx)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
