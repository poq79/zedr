// 本文件 NEUTRAL：/procinfo 双平台编译。平台差异收敛为两个钩子：
//   - procRealtimeFields：快照没有的单 PID 实时字段（Windows：
//     session_id/elevated/started_at；Linux：仅 started_at，session/elevated
//     无对等语义，诚实省略）；
//   - execFileInfoExtra：exec_info 的平台扩展块（Windows：签名状态 + MotW；
//     Linux：无，返回 nil）。
//
// Modules 未接线（Linux v1 恒未接线）时 modules 块整体省略，端点其余照常。
package liveapi

// procinfo.go：/procinfo —— 单进程详情（契约 §11.1，进程↔文件↔网络交叉枢纽）。
//
// 数据来源分三层，口径各有注释：
//   - 基本信息 = 采集快照（Deps.Snapshot/Procs），无系统调用；
//   - procRealtimeFields = 对该 PID 的平台实时查询（单 PID 成本可控；
//     快照 ProcRow 不携带这些字段）；
//   - modules/exec_info = 按需调用（Modules 是 collector 的高成本接口，
//     只应在可疑进程上触发）。

import (
	"net/http"
	"strconv"

	"zedr/internal/agent/nettypes"
	"zedr/internal/agent/state"
	"zedr/internal/platform/apperr"
	"zedr/internal/platform/httpx"
	"zedr/internal/platform/redact"
)

const (
	// procModulesMax 模块数上限：正常进程模块 <300 但遍历签名一次
	// WinVerifyTrust 每个毫秒级，64 是"够定位注入"且成本封顶的取值，
	// 超出截断并在响应里如实标注
	procModulesMax = 64
)

func (s *server) handleProcInfo(w http.ResponseWriter, r *http.Request) {
	raw := r.URL.Query().Get("pid")
	pid64, err := strconv.ParseUint(raw, 10, 32)
	if err != nil || pid64 == 0 {
		httpx.WriteError(w, r, apperr.Invalid("pid 必须是正整数"))
		return
	}
	pid := uint32(pid64)

	row := s.findProcRow(pid)
	if row == nil {
		// 不存在是正常调查结论（200 exists:false），与参数错误(400)区分
		httpx.WriteJSON(w, r, http.StatusOK, map[string]any{
			"pid": pid, "exists": false,
		})
		return
	}

	out := map[string]any{
		"pid":    pid,
		"exists": true,
		"name":   row.Name,
		"path":   row.Path,
		// 命令行过脱敏：隧道调查面与告警库同级泄露风险（--password 等）
		"cmdline": redact.CmdLine(row.CmdLine),
		"user":    row.User,
		"ppid":    row.PPID,
		// FirstSeen 是"探针何时首次观测到"，不是进程创建时刻——
		// 两者语义不同，如实用 first_seen 命名，不冒充 started_at
		"first_seen_unix": row.FirstSeen.Unix(),
	}

	// 实时富化：快照没有的平台字段（session_id/elevated/started_at）。
	// 进程已退出时平台查询自然失败 → 对应字段省略
	for k, v := range procRealtimeFields(pid) {
		out[k] = v
	}
	// cpu_percent/mem_mb：快照 ProcRow 不携带，本端点不做单进程采样
	//（诚实省略，见包内 /info 的全机口径）

	if s.d.Netstat != nil {
		var mine []nettypes.NetRow
		for _, nr := range s.d.Netstat() {
			if nr.PID == pid {
				mine = append(mine, nr)
			}
		}
		if mine == nil {
			mine = []nettypes.NetRow{}
		}
		out["connections"] = s.enrichNetRows(mine, s.snapshotRows())
	}

	if s.d.Modules != nil {
		out["modules"], out["modules_truncated"], out["unsigned_module_count"] = s.moduleReport(pid)
	}

	if row.Path != "" {
		out["exec_info"] = s.execInfo(row.Path)
	}

	httpx.WriteJSON(w, r, http.StatusOK, out)
}

// findProcRow 在快照里找 PID；快照未接线返回 nil。
func (s *server) findProcRow(pid uint32) *state.ProcRow {
	rows := s.snapshotRows()
	for i := range rows {
		if rows[i].PID == pid {
			return &rows[i]
		}
	}
	return nil
}

// moduleReport 枚举模块 + 逐个验签（≤64 截断）。
// 返回 (modules JSON, truncated, unsigned 计数)。
func (s *server) moduleReport(pid uint32) ([]map[string]string, bool, int) {
	mods := s.d.Modules(pid)
	truncated := false
	if len(mods) > procModulesMax {
		mods = mods[:procModulesMax]
		truncated = true
	}
	out := make([]map[string]string, 0, len(mods))
	unsigned := 0
	for _, m := range mods {
		// 只取 name/path（契约口径）；base_addr/size 对模块级排查无增益
		out = append(out, map[string]string{"name": m.Name, "path": m.Path})
		// 未签名 = 签名钩子（Windows: Authenticode 内嵌+catalog 双通道）
		// 判定为 unsigned。注意：打不开文件/校验出错的状态是 error_*，
		// 不计入 unsigned（未知 ≠ 未签名，宁缺毋滥）
		if fileSignature(m.Path).State == "unsigned" {
			unsigned++
		}
	}
	return out, truncated, unsigned
}

// execInfo 可执行文件速览：存在性 + 平台扩展块（Windows: 签名状态 + MotW
// zone；Linux: 无对等语义，钩子返回 nil，只给 exists）。
func (s *server) execInfo(path string) map[string]any {
	info := map[string]any{"exists": false}
	e, err := s.d.FS.Stat(path)
	if err != nil {
		return info
	}
	info["exists"] = !e.IsDir
	if e.IsDir {
		return info
	}
	for k, v := range execFileInfoExtra(path) {
		info[k] = v
	}
	return info
}
