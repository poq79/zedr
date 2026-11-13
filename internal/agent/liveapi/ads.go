//go:build windows
// +build windows

package liveapi

// ads.go：/ads —— NTFS 备用数据流 + MotW 下载来源（契约 §11.1）。
// 流枚举与 Zone.Identifier 解析在 winapi 包，本文件只做 HTTP 编排与
// zone_id → 名称映射（契约：名称映射放 liveapi 层）。

import (
	"net/http"

	"zedr/internal/agent/winapi"
	"zedr/internal/platform/apperr"
	"zedr/internal/platform/httpx"
)

// zoneNames 是 MotW ZoneId 的展示名（映射表来自契约 §11.1）。
var zoneNames = map[int]string{
	0: "本机",
	1: "本地内网",
	2: "受信任",
	3: "Internet",
	4: "受限",
}

func zoneName(id int) string {
	if n, ok := zoneNames[id]; ok {
		return n
	}
	// 未知取值如实带出原始 ID，不猜
	return "未知"
}

func (s *server) handleADS(w http.ResponseWriter, r *http.Request) {
	path, err := validateFSPath(r.URL.Query().Get("path"))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	e, err := s.d.FS.Stat(path)
	if err != nil {
		writeFSErr(w, r, err)
		return
	}
	if e.IsDir {
		// 目录没有数据流语义，MotW 也只对可执行/文档有意义
		httpx.WriteError(w, r, apperr.Invalid("目录没有备用数据流"))
		return
	}

	streams, err := winapi.EnumerateStreams(path)
	if err != nil {
		// Stat 已确认存在，此处失败按内部错误呈现（不让它静默变空）
		httpx.WriteError(w, r, apperr.Internal(err))
		return
	}
	if streams == nil {
		streams = []winapi.Stream{} // 空列表输出 [] 而非 null，前端省一层判空
	}

	zone, err := winapi.ReadZoneIdentifier(path)
	if err != nil {
		zone = nil // 读流失败不放大成 500（winapi 层已尽力降级，双保险）
	}
	resp := map[string]any{
		"path":    path,
		"streams": streams,
		"zone":    nil,
	}
	if zone != nil {
		resp["zone"] = map[string]any{
			"zone_id":       zone.ZoneID,
			"zone_name":     zoneName(zone.ZoneID),
			"referrer_url":  zone.ReferrerURL,
			"host_url":      zone.HostURL,
			"download_time": zone.DownloadTime,
		}
	}
	httpx.WriteJSON(w, r, http.StatusOK, resp)
}
