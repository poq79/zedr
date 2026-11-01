// Package auth 负责后台账号认证（JWT 访问令牌 + 服务端刷新令牌）、
// 角色鉴权，以及终端侧 HMAC 请求签名验证。
package auth

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"

	"hostguard/internal/platform/apperr"
	"hostguard/internal/server/domain"
)

// Claims 是访问令牌载荷。
type Claims struct {
	jwt.RegisteredClaims
	UserID   string      `json:"uid"`
	Username string      `json:"usr"`
	Role     domain.Role `json:"rol"`
}

// Manager 负责签发与校验令牌。
type Manager struct {
	secret     []byte
	issuer     string
	accessTTL  time.Duration
	refreshTTL time.Duration
}

// NewManager 构造令牌管理器。
func NewManager(secret string, accessTTL, refreshTTL time.Duration) (*Manager, error) {
	if len(secret) < 32 {
		return nil, errors.New("JWT secret 长度必须 >= 32 字节")
	}
	if accessTTL <= 0 || refreshTTL <= 0 {
		return nil, errors.New("令牌有效期必须为正数")
	}
	if refreshTTL <= accessTTL {
		return nil, errors.New("refresh TTL 必须大于 access TTL")
	}
	return &Manager{
		secret:     []byte(secret),
		issuer:     "hostguard-server",
		accessTTL:  accessTTL,
		refreshTTL: refreshTTL,
	}, nil
}

// AccessTTL 暴露访问令牌有效期。
func (m *Manager) AccessTTL() time.Duration { return m.accessTTL }

// RefreshTTL 暴露刷新令牌有效期。
func (m *Manager) RefreshTTL() time.Duration { return m.refreshTTL }

// IssueAccess 签发短时效访问令牌。
func (m *Manager) IssueAccess(u *domain.User, now time.Time) (string, time.Time, error) {
	exp := now.Add(m.accessTTL)
	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    m.issuer,
			Subject:   u.ID,
			Audience:  jwt.ClaimStrings{"hostguard-console"},
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now.Add(-5 * time.Second)),
			ExpiresAt: jwt.NewNumericDate(exp),
		},
		UserID:   u.ID,
		Username: u.Username,
		Role:     u.Role,
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	s, err := tok.SignedString(m.secret)
	if err != nil {
		return "", time.Time{}, err
	}
	return s, exp, nil
}

// ParseAccess 校验并解析访问令牌。
func (m *Manager) ParseAccess(raw string) (*Claims, error) {
	claims := &Claims{}
	_, err := jwt.ParseWithClaims(raw, claims, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("非预期的签名算法")
		}
		return m.secret, nil
	},
		jwt.WithIssuer(m.issuer),
		jwt.WithAudience("hostguard-console"),
		jwt.WithExpirationRequired(),
		jwt.WithLeeway(30*time.Second),
	)
	if err != nil {
		return nil, apperr.Unauthenticated("访问令牌无效或已过期")
	}
	if claims.UserID == "" || !claims.Role.Valid() {
		return nil, apperr.Unauthenticated("访问令牌载荷不完整")
	}
	return claims, nil
}

// ---------------------------------------------------------------- 密码

// HashPassword 使用 bcrypt 生成口令哈希。
func HashPassword(pw string) (string, error) {
	if len(pw) < 8 {
		return "", apperr.Invalid("密码长度至少 8 位")
	}
	if len(pw) > 72 {
		return "", apperr.Invalid("密码长度不能超过 72 字节")
	}
	b, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// ComparePassword 校验口令；恒定时间比较由 bcrypt 保证。
func ComparePassword(hash, pw string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(pw)) == nil
}

// HashRefreshToken 刷新令牌只存哈希，泄库不可直接冒用。
func HashRefreshToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// ---------------------------------------------------------------- 终端签名

// SignAgentRequest 计算终端请求签名：
// HMAC-SHA256(secret, agentID|timestamp|nonce|sha256(body))
func SignAgentRequest(secret, agentID, timestamp, nonce string, body []byte) string {
	bodySum := sha256.Sum256(body)
	payload := agentID + "|" + timestamp + "|" + nonce + "|" + hex.EncodeToString(bodySum[:])
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(payload))
	return hex.EncodeToString(mac.Sum(nil))
}

// VerifyAgentRequest 校验签名与时窗（默认 ±5 分钟防重放）。
func VerifyAgentRequest(secret, agentID, timestamp, nonce, signature string, body []byte, now time.Time) error {
	if secret == "" {
		return apperr.Unauthenticated("终端凭证无效")
	}
	ts, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil {
		return apperr.Unauthenticated("时间戳非法")
	}
	drift := now.Sub(time.Unix(ts, 0))
	if drift > 5*time.Minute || drift < -5*time.Minute {
		return apperr.Unauthenticated("请求时间戳超出允许窗口")
	}
	if len(nonce) < 8 || len(nonce) > 64 {
		return apperr.Unauthenticated("nonce 非法")
	}
	expect := SignAgentRequest(secret, agentID, timestamp, nonce, body)
	if subtle.ConstantTimeCompare([]byte(strings.ToLower(expect)), []byte(strings.ToLower(signature))) != 1 {
		return apperr.Unauthenticated("请求签名校验失败")
	}
	return nil
}

// ---------------------------------------------------------------- context

type ctxKeyPrincipal struct{}

// Principal 是已认证的后台用户。
type Principal struct {
	UserID   string
	Username string
	Role     domain.Role
}

// WithPrincipal 注入当前用户。
func WithPrincipal(ctx context.Context, p *Principal) context.Context {
	return context.WithValue(ctx, ctxKeyPrincipal{}, p)
}

// FromContext 取出当前用户。
func FromContext(ctx context.Context) (*Principal, bool) {
	p, ok := ctx.Value(ctxKeyPrincipal{}).(*Principal)
	return p, ok
}

// RequireRole 在中间件里做角色校验。
func RequireRole(p *Principal, roles ...domain.Role) error {
	if p == nil {
		return apperr.Unauthenticated("")
	}
	for _, r := range roles {
		if p.Role == r {
			return nil
		}
	}
	return apperr.Forbidden("")
}
