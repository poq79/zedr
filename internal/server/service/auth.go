package service

import (
	"context"
	"log/slog"
	"strings"
	"time"

	"hostguard/internal/platform/apperr"
	"hostguard/internal/platform/idgen"
	"hostguard/internal/server/auth"
	"hostguard/internal/server/domain"
	"hostguard/internal/server/repository"
)

// AuthService 负责登录、刷新令牌轮转与登出。
type AuthService struct {
	repos  repository.Repos
	tokens *auth.Manager
	log    *slog.Logger
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

	u, err := s.repos.Users.ByUsername(ctx, username)
	if err != nil {
		return nil, err
	}
	// 用户名不存在与密码错误返回同一文案，避免账号枚举
	if u == nil || u.Disabled || !auth.ComparePassword(u.PasswordHash, password) {
		s.log.WarnContext(ctx, "login_failed", "username", username, "ip", ip)
		return nil, apperr.Unauthenticated("用户名或密码错误")
	}

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

// CreateUser 创建后台账号（仅管理员）。
func (s *AuthService) CreateUser(ctx context.Context, username, displayName, password string, role domain.Role) (*domain.User, error) {
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
