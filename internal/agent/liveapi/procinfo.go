//go:build windows
// +build windows

package liveapi

// procinfo.go：/procinfo —— 单进程详情（契约 §11.1，进程↔文件↔网络交叉枢纽）。
//
// 数据来源分三层，口径各有注释：
//   - 基本信息 = 采集快照（Deps.Snapshot/Procs），无系统调用；
//   - session_id/elevated/started_at = 对该 PID 的实时 winapi 查询（单
//     PID 成本可控；快照 ProcRow 不携带这三个字段）；
//   - modules/exec_info = 按需调用（Modules 是 collector 的高成本接口，
//     只应在可疑进程上触发）。

import (
	"net/http"
	"strconv"

	"zedr/internal/agent/state"
	"zedr/internal/agent/winapi"
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

	// 实时富化：快照没有的三个字段。进程已退出时查询自然失败 → 字段省略
	if sid, err := winapi.SessionID(pid); err == nil && sid > 0 {
		out["session_id"] = sid
	}
	// IsElevated 对打不开令牌的进程（权限不足/已退出）返回 false——
	// "非提权"与"未知"在此无法区分，是已知口径局限
	if winapi.IsElevated(pid) {
		out["elevated"] = true
	}
	if ts, err := winapi.ProcessStartTime(pid); err == nil && ts > 0 {
		out["started_at_unix"] = ts
	}
	// cpu_percent/mem_mb：快照 ProcRow 不携带，本端点不做单进程采样
	//（诚实省略，见包内 /info 的全机口径）

	if s.d.Netstat != nil {
		var mine []winapi.NetRow
		for _, nr := range s.d.Netstat() {
			if nr.PID == pid {
				mine = append(mine, nr)
			}
		}
		if mine == nil {
			mine = []winapi.NetRow{}
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
		// 未签名 = Authenticode 内嵌+catalog 双通道都无签名。
		// 注意：打不开文件/校验出错的状态是 error_*，不计入 unsigned
		//（未知 ≠ 未签名，宁缺毋滥）
		if winapi.VerifySignature(m.Path).State == "unsigned" {
			unsigned++
		}
	}
	return out, truncated, unsigned
}

// execInfo 可执行文件速览：存在性 + 签名状态 + MotW zone。
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
	sig := winapi.VerifySignature(path)
	info["signed_state"] = sig.State
	// 有 zone.identifier 流才读内容（MotW 存在性一次枚举即可判定）
	if streams, err := winapi.EnumerateStreams(path); err == nil {
		for _, st := range streams {
			if st.Name == "zone.identifier" {
				if zi, err := winapi.ReadZoneIdentifier(path); err == nil && zi != nil {
					info["ads_zone_id"] = zi.ZoneID
				}
				break
			}
		}
	}
	return info
}
