package liveapi

// info.go：/info —— 探针实时运行时（契约 §11.1）。
// 数据源 state.RuntimeInfo（scan 循环回调统一维护，见 AGENTS.md §5.2
// "SetRuntime 只保留最后回调"的口径约束）。

import (
	"net/http"
	"time"

	"zedr/internal/platform/httpx"
)

func (s *server) handleInfo(w http.ResponseWriter, r *http.Request) {
	if s.d.Runtime == nil {
		httpx.WriteError(w, r, errNotImplemented("探针运行时状态"))
		return
	}
	rt := s.d.Runtime()

	version := rt.AgentVersion
	if version == "" {
		// RuntimeInfo 未维护版本时回退探针编译期注入的 Deps.Version
		version = s.d.Version
	}
	uptime := rt.UptimeSec
	if uptime == 0 && !s.d.StartTime.IsZero() {
		// scan 回调尚未跑过首轮时的兜底；两处都空才是真的未知（输出 0）
		uptime = int64(time.Since(s.d.StartTime).Seconds())
	}

	// cpu_percent/mem_mb 为 0 视为"尚未采样"照实输出 0（探针刚启动的
	// 瞬态），不猜测不插值
	httpx.WriteJSON(w, r, http.StatusOK, map[string]any{
		"version":       version,
		"hostname":      rt.Hostname,
		"uptime_sec":    uptime,
		"proc_count":    rt.ProcCount,
		"cpu_percent":   rt.CPUPercent,
		"mem_mb":        rt.MemMB,
		"scan_interval": rt.ScanInterval,
		"collector":     rt.Collector,
	})
}
