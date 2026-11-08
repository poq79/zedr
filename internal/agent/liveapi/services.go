package liveapi

// services.go：/services 服务实时全量端点（隧道内只读调查）。
//
// 数据来源 winapi.ServiceList（EnumServicesStatusEx + 逐条
// QueryServiceConfig 富化）——**本列表刻意不含驱动**：该 API 只枚举
// SERVICE_WIN32，这是 winapi 侧的既定口径；驱动对入侵调查的价值集中在
// Rootkit 排查，属于 /drivers 端点的职责（后续补齐），不在这里混装两种
// 生命周期语义的对象。
//
// State/StartMode 已由 winapi 侧映射为可读文本（running/stopped、
// auto/manual/disabled），本文件只做过滤、截断与 JSON 形状收敛。
//
// 契约：total 是过滤前的全量服务数（与 /tasks 同口径——服务几百条，
// 调查页需要"本机共 N 个服务"的事实），truncated 表示匹配集超出 limit。
// filter 匹配服务名或显示名（操作员记得的往往是显示名，如
// "Windows Update" 而非 wuauserv），两者大小写不敏感子串匹配。

import (
	"log/slog"
	"net/http"
	"strings"

	"zedr/internal/agent/winapi"
	"zedr/internal/platform/apperr"
	"zedr/internal/platform/httpx"
)

const (
	svcDefaultLimit = 200
	svcMaxLimit     = 500
)

// serviceItem 是 items[] 的一行。不复用 winapi.ServiceInfo 直接序列化
// 的原因同 /tasks：其字段无 json tag，直接 Marshal 会输出大写字段名。
type serviceItem struct {
	Name        string `json:"name"`         // 服务键名，如 wuauserv
	DisplayName string `json:"display_name"` // 如 Windows Update
	State       string `json:"state"`        // running / stopped / ...（winapi 映射口径）
	StartMode   string `json:"start_mode"`   // auto / manual / disabled / boot / system
	PathName    string `json:"path_name"`    // 二进制命令行（含参数）
	Account     string `json:"account"`      // 运行账户（LocalSystem 等可显示为空）
}

func (s *server) handleServices(w http.ResponseWriter, r *http.Request) {
	filter := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("filter")))
	// state 传空/缺省即跳过该过滤（列全量）；传值则与服务状态精确匹配
	//（大小写不敏感），如 state=running
	state := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("state")))
	limit := queryInt(r, "limit", svcDefaultLimit, 1, svcMaxLimit)

	list, err := winapi.ServiceList()
	if err != nil {
		slog.Warn("liveapi_services_enum_failed", "err", err)
		httpx.WriteError(w, r, apperr.Internal(err))
		return
	}

	matched := make([]serviceItem, 0, len(list))
	for _, sv := range list {
		if filter != "" &&
			!strings.Contains(strings.ToLower(sv.Name), filter) &&
			!strings.Contains(strings.ToLower(sv.DisplayName), filter) {
			continue
		}
		if state != "" && !strings.EqualFold(sv.State, state) {
			continue
		}
		matched = append(matched, serviceItem{
			Name:        sv.Name,
			DisplayName: sv.DisplayName,
			State:       sv.State,
			StartMode:   sv.StartMode,
			PathName:    sv.PathName,
			Account:     sv.Account,
		})
	}

	truncated := len(matched) > limit
	if truncated {
		matched = matched[:limit]
	}
	httpx.WriteJSON(w, r, http.StatusOK, map[string]any{
		"items":     matched,
		"total":     len(list),
		"truncated": truncated,
	})
}
