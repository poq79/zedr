package service

import (
	"fmt"
	"context"
	"log/slog"
	"strings"
	"time"

	"zedr/internal/platform/apperr"
	"zedr/internal/platform/idgen"
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
type LoginResult struct {
	AccessToken  string
	ExpiresAt    time.Time
	RefreshToken string
	RefreshExp   time.Time
	User         *domain.User
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
	s.guard.reset(username)

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

	_ = s.repos.Users.TouchLogin(ctx, u.ID, time.Now())
	s.log.InfoContext(ctx, "login_success", "user_id", u.ID, "username", u.Username, "role", u.Role, "ip", ip)

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

	access, exp, err := s.tokens.IssueAccess(u, time.Now())
	if err != nil {
		return nil, apperr.Internal(err)
	}
	newRaw := idgen.URLSafe(32)
	newExp := time.Now().Add(s.tokens.RefreshTTL())
	if err := s.repos.Tokens.Create(ctx, &domain.RefreshToken{
		ID:        idgen.Hex(12),
		UserID:    u.ID,
		TokenHash: auth.HashRefreshToken(newRaw),
		ExpiresAt: newExp,
		CreatedAt: time.Now(),
		UserAgent: truncate(ua, 200),
		IP:        ip,
	}); err != nil {
		return nil, err
	}

	return &LoginResult{
		AccessToken:  access,
		ExpiresAt:    exp,
		RefreshToken: newRaw,
		RefreshExp:   newExp,
		User:         u,
	}, nil
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
