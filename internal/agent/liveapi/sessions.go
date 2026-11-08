package liveapi

// sessions.go：GET /sessions —— 当前活动登录会话（LSA 只读枚举）。
//
// 与 /accounts 的分工（两页互不替代）：
//   - /accounts = 账户清单（NetUserEnum 本机账户表）：机器上"有哪些账户"，
//     静态目录，回答"攻击者可能用什么身份"；
//   - /sessions = 此刻的活动登录会话（LsaEnumerateLogonSessions）：谁登录着、
//     什么类型（RemoteInteractive=RDP / Network / Service / Batch…）、来自
//     哪个认证包——排查横向移动（pass-the-hash、RDP 落地、计划任务自带
//     凭据）的第一手登录痕迹，回答"攻击者现在是不是已经在里面"。

import (
	"net/http"

	"zedr/internal/agent/winapi"
	"zedr/internal/platform/apperr"
	"zedr/internal/platform/httpx"
)

// sessionItem 是一条登录会话（winapi.LogonSession 的线协议投影）。
// logon_time 口径与 /procinfo 的 started_at 一致：unix 秒；LSA 来源为零值
// （会话时间不可知）时置 null——0 会伪装成 1970 年的登录，污染时间线。
type sessionItem struct {
	LogonID       uint64 `json:"logon_id"`
	Username      string `json:"username"`
	Domain        string `json:"domain"`
	LogonType     uint32 `json:"logon_type"`
	LogonTypeName string `json:"logon_type_name"`
	Session       uint32 `json:"session"`
	LogonTime     *int64 `json:"logon_time"` // unix 秒；零值 → null
	AuthPackage   string `json:"auth_package"`
}

// sessionsResult 是 /sessions 的完整响应（httpx.WriteJSON 包进 data）。
// items 已按登录时间倒序（winapi.LogonSessions 的排序口径）。
type sessionsResult struct {
	Items []sessionItem `json:"items"`
	Total int           `json:"total"` // 等于 len(items)：读详情失败的会话被跳过，不虚报
}

// handleSessions 返回 GET /sessions（不依赖 Deps，路由由主会话接线）。
func (s *server) handleSessions(w http.ResponseWriter, r *http.Request) {
	sessions, err := winapi.LogonSessions()
	if err != nil {
		// LsaEnumerateLogonSessions 对普通用户可用（见 logonsession.go），
		// 失败属环境异常，按内部错误上报而非伪造空表。
		httpx.WriteError(w, r, apperr.Internal(err))
		return
	}
	items := make([]sessionItem, 0, len(sessions))
	for _, ss := range sessions {
		item := sessionItem{
			LogonID:       ss.LogonID,
			Username:      ss.Username,
			Domain:        ss.Domain,
			LogonType:     ss.LogonType,
			LogonTypeName: ss.LogonTypeName,
			Session:       ss.Session,
			AuthPackage:   ss.AuthPackage,
		}
		if !ss.LogonTime.IsZero() {
			ts := ss.LogonTime.Unix()
			item.LogonTime = &ts
		}
		items = append(items, item)
	}
	httpx.WriteJSON(w, r, http.StatusOK, sessionsResult{Items: items, Total: len(items)})
}
