//go:build windows
// +build windows

package liveapi

// accounts.go：账户与会话 Tab 的只读枚举端点（契约 §13.3）。
//
// 数据来源全部是 winapi 的 NetAPI 封装（LocalUsers / Administrators /
// LocalPolicyInfo），本文件只做三件事：
//  1. 把管理员名单与用户表 join 出 is_admin；
//  2. 部分能力失败时不伪造数据（管理员列表为空、策略置 0，并写日志）；
//  3. 把 NetAPI 权限错误映射成规范 HTTP 错误。
//
// is_admin 的口径：LocalAdmins 返回的是 "域/计算机\账户" 形式的成员名，
// 而 NetUserEnum 只给账户名，因此比较前统一剥掉反斜杠前缀并转小写。
// 注意 NetLocalGroupGetMembers 不递归嵌套组：仅作为"直接成员"的用户
// 会被标记，嵌套组内的用户不会被展开（与资产清单口径一致）。

import (
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"golang.org/x/sys/windows"

	"zedr/internal/agent/winapi"
	"zedr/internal/platform/apperr"
	"zedr/internal/platform/httpx"
)

// accountsUser 是一条用户账户（契约 §13.3 users[]，含 join 出的 is_admin）。
type accountsUser struct {
	Name                 string `json:"name"`
	SID                  string `json:"sid"`
	Disabled             bool   `json:"disabled"`
	PasswordNeverExpires bool   `json:"password_never_expires"`
	PasswordAgeDays      int    `json:"password_age_days"`
	LastLogonUnix        int64  `json:"last_logon_unix"`
	Comment              string `json:"comment"`
	IsAdmin              bool   `json:"is_admin"`
}

// accountsPolicy 是密码策略卡（契约 §13.3 policy）。
type accountsPolicy struct {
	MinPasswordLength uint32 `json:"min_password_length"`
	MaxAgeDays        uint32 `json:"max_age_days"`
	LockoutThreshold  uint32 `json:"lockout_threshold"`
}

// accountsResult 是 /accounts 的完整响应（httpx.WriteJSON 会包进 data）。
type accountsResult struct {
	GeneratedAt    string         `json:"generated_at"`
	Users          []accountsUser `json:"users"`
	Administrators []string       `json:"administrators"`
	Policy         accountsPolicy `json:"policy"`
}

// HandleAccounts 返回 GET /accounts 的 handler。
//
// 与 HandleBaseline 同样不依赖 Deps，路由由主会话接线。
func HandleAccounts() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		users, err := winapi.LocalUsers()
		if err != nil {
			writeAccountsErr(w, r, err)
			return
		}

		// 管理员名单与策略是"锦上添花"：失败时保留用户表并降级为
		// 空名单/零策略，同时打日志留痕——整页 500 会让操作员连
		// 用户列表都看不到，反而降低排查效率。
		admins, adminErr := winapi.Administrators()
		if adminErr != nil {
			slog.Warn("liveapi_accounts_admins_failed", "err", adminErr)
			admins = nil
		}
		policy, policyErr := winapi.LocalPolicyInfo()
		if policyErr != nil {
			slog.Warn("liveapi_accounts_policy_failed", "err", policyErr)
			policy = winapi.LocalPolicy{}
		}

		adminSet := make(map[string]struct{}, len(admins))
		for _, a := range admins {
			if k := accountNameKey(a); k != "" {
				adminSet[k] = struct{}{}
			}
		}

		out := make([]accountsUser, 0, len(users))
		for _, u := range users {
			_, isAdmin := adminSet[accountNameKey(u.Name)]
			out = append(out, accountsUser{
				Name:                 u.Name,
				SID:                  u.SID,
				Disabled:             u.Disabled,
				PasswordNeverExpires: u.PasswordNeverExpires,
				PasswordAgeDays:      u.PasswordAgeDays,
				LastLogonUnix:        u.LastLogonUnix,
				Comment:              u.Comment,
				IsAdmin:              isAdmin,
			})
		}
		if admins == nil {
			admins = []string{}
		}

		httpx.WriteJSON(w, r, http.StatusOK, accountsResult{
			GeneratedAt:    time.Now().UTC().Format(time.RFC3339),
			Users:          out,
			Administrators: admins,
			Policy: accountsPolicy{
				MinPasswordLength: policy.MinPasswordLength,
				MaxAgeDays:        policy.MaxPasswordAgeDays,
				LockoutThreshold:  policy.LockoutThreshold,
			},
		})
	}
}

// accountNameKey 归一化账户名用于比较：去掉 "域\" / "计算机\" 前缀，
// trim 空白后转小写。NetAPI 的成员名与用户名大小写/前缀形式不保证一致。
func accountNameKey(name string) string {
	name = strings.TrimSpace(name)
	if i := strings.LastIndexByte(name, '\\'); i >= 0 {
		name = name[i+1:]
	}
	return strings.ToLower(strings.TrimSpace(name))
}

// writeAccountsErr 把账户枚举失败转成规范错误。
// 权限不足单独映射 403（与 fs 的 ErrPermission 口径一致），其余按内部
// 错误；错误详情只进日志/请求 ID，不把 NetAPI 状态码直接抛给前端。
func writeAccountsErr(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, windows.ERROR_ACCESS_DENIED),
		errors.Is(err, windows.ERROR_PRIVILEGE_NOT_HELD):
		slog.Warn("liveapi_accounts_denied", "err", err)
		httpx.WriteError(w, r, apperr.Forbidden("账户枚举被系统拒绝，探针需要本地管理员权限"))
	default:
		slog.Warn("liveapi_accounts_enum_failed", "err", err)
		httpx.WriteError(w, r, apperr.Internal(err))
	}
}
