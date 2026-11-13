//go:build windows
// +build windows

package liveapi

// recon.go：资产侦查薄 handler（契约 §12.1/§12.2）。
//
// 本文件只做参数解析、Deps 适配与输出；六类检测/探测全部在
// internal/agent/recon。Deps 不新增字段：
//   - 进程快照复用 Snapshot（全量），未接线时退回 Procs(procMax)；
//   - 连接表复用 Netstat；
//   - probe 参数由请求决定；全局开关 HG_AGENT_RECON_PROBE=false 时
//     强制被动（这里读环境变量作为兜底，接线层也可用 Config 覆盖）。
//
// 注意：路由注册在 liveapi.New（本批不改 liveapi.go），接线时需加一行
// mux.HandleFunc("GET /recon", s.handleRecon)。

import (
	"net/http"
	"os"
	"strings"

	"zedr/internal/agent/recon"
	"zedr/internal/agent/state"
	"zedr/internal/platform/apperr"
	"zedr/internal/platform/httpx"
)

func (s *server) handleRecon(w http.ResponseWriter, r *http.Request) {
	cats, err := recon.ParseCategories(r.URL.Query().Get("categories"))
	if err != nil {
		httpx.WriteError(w, r, apperr.Invalid("%s", err.Error()))
		return
	}

	// probe 缺省 1（主动）；0=强制被动。只接受 0/1，避免 "?probe=false"
	// 这类含糊写法被静默当成 true。
	probe := true
	if raw := r.URL.Query().Get("probe"); raw != "" {
		switch raw {
		case "0":
			probe = false
		case "1":
			probe = true
		default:
			httpx.WriteError(w, r, apperr.Invalid("probe 只能是 0 或 1"))
			return
		}
	}
	// 全局开关 HG_AGENT_RECON_PROBE=false 时强制被动（契约 §12.1）。
	// 这里直接读环境变量只作为兜底：app 层已把它解析进 Config，接线时
	// 若新增 liveapi.Deps.ReconProbe 字段，应以配置值为准（见文件头注释）。
	if v, ok := reconEnvBool("HG_AGENT_RECON_PROBE"); ok && !v {
		probe = false
	}

	var procs func() []state.ProcRow
	switch {
	case s.d.Snapshot != nil:
		procs = s.d.Snapshot
	case s.d.Procs != nil:
		procs = func() []state.ProcRow { return s.d.Procs(procMax) }
	}

	res, err := recon.Run(r.Context(), recon.Deps{
		Procs:   procs,
		Netstat: s.d.Netstat,
		Probe:   probe,
	}, cats)
	if err != nil {
		// ParseCategories 已挡住非法参数；走到这里说明是内部约定破坏
		// （例如 detector 表被改坏），按 500 暴露给中心端日志。
		httpx.WriteError(w, r, apperr.Internal(err))
		return
	}
	httpx.WriteJSON(w, r, http.StatusOK, res)
}

// reconEnvBool 读取布尔环境变量，取值口径与 config.Loader.Bool 一致
// （1/true/yes/on 与 0/false/no/off）；未设置或非法时 ok=false。
// 命名为 reconEnvBool 避免与 liveapi 其他并行新增文件的 helper 冲突。
func reconEnvBool(key string) (val bool, ok bool) {
	raw := strings.ToLower(strings.TrimSpace(os.Getenv(key)))
	switch raw {
	case "1", "true", "yes", "on":
		return true, true
	case "0", "false", "no", "off":
		return false, true
	}
	return false, false
}
