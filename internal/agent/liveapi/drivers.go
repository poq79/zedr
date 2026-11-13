//go:build windows
// +build windows

package liveapi

// drivers.go：GET /drivers —— 已加载内核驱动列表（rootkit/驱动持久化画像）。
//
// 默认不验签的原因：本机典型加载 100~400 个驱动，WinVerifyTrust 逐个走
// 证书链是毫秒级/个，全量验证会把一次"看一眼驱动表"的调查操作拖成数秒
// 的批处理，拖垮隧道交互预算。所以 verify=0（默认）只出清单，verify=1 才
// 对前 50 个驱动做 Authenticode 校验——"前 50"= LoadedDrivers 按 Path 排序
// 后的字典序前段（覆盖多数系统驱动），50 是成本封顶（取值逻辑同 /procinfo
// 的 procModulesMax）。verify=1 是显式慢通道：调用方明确要签名面才付这个
// 成本，verified_count 如实回报实际验了多少（总量不足 50 时小于 50）。

import (
	"net/http"

	"zedr/internal/agent/winapi"
	"zedr/internal/platform/apperr"
	"zedr/internal/platform/httpx"
)

// driversVerifyMax verify=1 时的验签个数上限（成本封顶，见文件头）。
const driversVerifyMax = 50

// driverItem 是一条驱动（winapi.DriverInfo 的线协议投影）。
// size/mtime_unix 在 os.Stat 失败时为 null——DriverInfo 用 -1/零值表达
// "拿不到"，直接透传会让 -1 看起来像真实大小、1970 像真实时间。
// signed/signer 仅在 verify=1 时输出（nil 指针 + omitempty → 字段缺省，
// verify=0 的响应里不出现，避免"没验"被误读成"没签"）。
type driverItem struct {
	Name      string `json:"name"`
	Path      string `json:"path"`
	Size      *int64 `json:"size"` // 字节；stat 失败 → null
	MtimeUnix *int64 `json:"mtime_unix"`

	Signed *bool  `json:"signed,omitempty"` // verify=1 时输出
	Signer string `json:"signer,omitempty"` // 有签名但读不出主体时缺省（诚实留空）
}

// driversResult 是 /drivers 的完整响应（httpx.WriteJSON 包进 data）。
type driversResult struct {
	Items         []driverItem `json:"items"`
	Total         int          `json:"total"`
	VerifiedCount int          `json:"verified_count"` // verify=1 时实际验签个数（≤50），verify=0 恒 0
}

// handleDrivers 返回 GET /drivers（不依赖 Deps，路由由主会话接线）。
func (s *server) handleDrivers(w http.ResponseWriter, r *http.Request) {
	verify := queryInt(r, "verify", 0, 0, 1)
	drivers, err := winapi.LoadedDrivers()
	if err != nil {
		// EnumDeviceDrivers 普通用户可用（见 drivers.go），失败属环境异常。
		httpx.WriteError(w, r, apperr.Internal(err))
		return
	}
	items := make([]driverItem, 0, len(drivers))
	verified := 0
	for _, d := range drivers {
		item := driverItem{Name: d.Name, Path: d.Path}
		if d.Size >= 0 {
			size := d.Size
			item.Size = &size
		}
		if !d.MTime.IsZero() {
			ts := d.MTime.Unix()
			item.MtimeUnix = &ts
		}
		if verify == 1 && verified < driversVerifyMax {
			sig := winapi.VerifySignature(d.Path)
			signed := sig.Signed
			item.Signed = &signed
			item.Signer = sig.Signer
			verified++
		}
		items = append(items, item)
	}
	httpx.WriteJSON(w, r, http.StatusOK, driversResult{
		Items:         items,
		Total:         len(items),
		VerifiedCount: verified,
	})
}
