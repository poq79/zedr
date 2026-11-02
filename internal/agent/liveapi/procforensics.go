package liveapi

// procforensics.go：进程取证四端点（契约 §15）。
//
//	GET /handles?pid=&type=&limit=   单进程句柄表（类型直方图 + 安全类型名称）
//	GET /handleowners?path=          谁打开了这个文件（全系统 File 句柄反向查）
//	GET /threads?pid=                线程起始地址/模块归属/匿名执行线索
//	GET /memscan?pid=                地址空间元数据摘要（只读，不含内存内容）
//
// 四个端点全部只读、单 PID 人工触发、带预算；错误统一走 apperr。
// note 字段不是装饰：句柄表与全系统扫描都是**部分覆盖**（受保护进程打不开、
// NtQueryObject 超时、预算截断），前端必须把它展示给分析师，否则"没查到"
// 会被误读成"不存在"。

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"zedr/internal/agent/winapi"
	"zedr/internal/model"
	"zedr/internal/platform/apperr"
	"zedr/internal/platform/httpx"
)

const (
	// handleLimitDefault/handleLimitMax 与契约 §15.1 对齐（探针侧钳制；
	// 中心代理侧还有一道）。
	handleLimitDefault = 1000
	handleLimitMax     = 5000

	// memScanNote 是 /memscan 的固定说明（用户点名要求写死，避免前端
	// 或后续改动把"元数据"表述成"内存内容"）。
	memScanNote = "仅返回地址空间元数据；仅对可疑区域读取 2 字节判定 MZ，不读取/不传输任何内存内容；受保护进程打不开时跳过"
)

// parseForensicsPID 解析并校验 pid 参数：正整数，0 与 4（System）直接拒绝。
// 4 号进程的句柄表/地址空间在用户态不可访问，放行只会让调用方拿到一堆
// 空结果而不知道是权限问题。
func parseForensicsPID(r *http.Request) (uint32, error) {
	raw := strings.TrimSpace(r.URL.Query().Get("pid"))
	if raw == "" {
		return 0, apperr.Invalid("pid 参数必填")
	}
	n, err := strconv.ParseUint(raw, 10, 32)
	if err != nil || n == 0 {
		return 0, apperr.Invalid("pid 必须是正整数")
	}
	if n == 4 {
		return 0, apperr.Invalid("pid 4（System）不支持进程取证")
	}
	return uint32(n), nil
}

// handleHandles 实现 GET /handles。
func (s *server) handleHandles(w http.ResponseWriter, r *http.Request) {
	pid, err := parseForensicsPID(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	typeFilter := strings.TrimSpace(r.URL.Query().Get("type"))
	limit := queryInt(r, "limit", handleLimitDefault, 1, handleLimitMax)

	res, err := winapi.CollectHandles(pid, typeFilter, limit, 2*time.Second)
	if err != nil {
		httpx.WriteError(w, r, apperr.Internal(err))
		return
	}
	if res.Rows == nil {
		res.Rows = []winapi.HandleRow{}
	}
	if res.Types == nil {
		res.Types = map[string]int{}
	}

	parts := make([]string, 0, 4)
	switch {
	case res.Total == 0 && typeFilter != "":
		parts = append(parts, fmt.Sprintf("没有匹配类型 %q 的句柄", typeFilter))
	case res.Total == 0:
		parts = append(parts, "该进程没有可枚举的句柄（进程可能已退出，或为受保护进程）")
	default:
		parts = append(parts, fmt.Sprintf("共 %d 个句柄", res.Total))
		if res.Truncated {
			parts = append(parts, fmt.Sprintf("仅返回前 %d 条", len(res.Rows)))
		}
		switch {
		case !res.ProcessOpened:
			parts = append(parts, "无法打开目标进程（受保护或权限不足），句柄名称不可读")
		case res.NameAttempted == 0:
			parts = append(parts, "没有可解析名称的安全类型句柄（仅 File/Directory/Key/Section/Mutant/Semaphore/SymbolicLink 会解析）")
		default:
			parts = append(parts, fmt.Sprintf("已解析 %d/%d 个安全类型句柄名称", res.NameResolved, res.NameAttempted))
		}
		if res.NameBudgetHit {
			parts = append(parts, "名称解析超出 2s 预算，其余句柄名称留空（可缩小 limit 或按 type 过滤后重试）")
		}
	}
	if res.UnresolvedTypes > 0 {
		parts = append(parts, fmt.Sprintf("%d 个句柄的对象类型名无法解析（显示为 Type#N，多来自受保护进程）", res.UnresolvedTypes))
	}

	httpx.WriteJSON(w, r, http.StatusOK, map[string]any{
		"pid":   pid,
		"total": res.Total,
		// 契约把"整请求超 2s"也归入 truncated：列表没截断但名称解析
		// 被预算打断时，前端同样要显示"结果不完整"。细节看 note。
		"truncated": res.Truncated || res.NameBudgetHit,
		"types":     res.Types,
		"items":     res.Rows,
		"note":      strings.Join(parts, "；"),
	})
}

// ownerRow 是 /handleowners owners 的元素（契约 §15.2）。
type ownerRow struct {
	PID  uint32 `json:"pid"`
	Name string `json:"name"`
	Path string `json:"path"`
}

// handleHandleOwners 实现 GET /handleowners?path=。
func (s *server) handleHandleOwners(w http.ResponseWriter, r *http.Request) {
	target, err := validateFSPath(strings.TrimSpace(r.URL.Query().Get("path")))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}

	out := map[string]any{
		"path":      target,
		"scanned":   0,
		"resolved":  0,
		"owners":    []ownerRow{},
		"truncated": false,
		"note":      "",
	}

	devicePath, ok := winapi.NormalizeToDevicePath(target)
	if !ok {
		out["note"] = "无法把该路径映射为 NT 设备路径（网络共享/未挂载卷），本轮无法枚举占用者"
		httpx.WriteJSON(w, r, http.StatusOK, out)
		return
	}

	notePrefix := ""
	if _, err := s.d.FS.Stat(target); err != nil {
		notePrefix = "目标路径当前不可访问（可能已删除或权限不足）；"
	}

	scan, err := winapi.ScanFileHandles(5 * time.Second)
	if err != nil {
		httpx.WriteError(w, r, apperr.Internal(err))
		return
	}

	// 同一进程可能对同一文件持有多个句柄，owners 按 PID 去重（前端列的是
	// "占用进程"而不是"句柄"）。
	seen := make(map[uint32]bool, 8)
	owners := make([]ownerRow, 0, 8)
	for _, h := range scan.Handles {
		if seen[h.PID] || !strings.EqualFold(h.Name, devicePath) {
			continue
		}
		seen[h.PID] = true
		owners = append(owners, ownerRow{PID: h.PID, Name: "(未知)", Path: ""})
	}

	// join 快照补进程名/镜像路径。快照在扫描之后取，尽量覆盖新出现的进程。
	byPID := make(map[uint32]int, len(owners))
	if len(owners) > 0 {
		for i := range owners {
			byPID[owners[i].PID] = i
		}
		for _, p := range s.snapshotRows() {
			if i, ok := byPID[p.PID]; ok {
				owners[i].Name = p.Name
				owners[i].Path = p.Path
			}
		}
	}

	parts := []string{fmt.Sprintf("仅扫描了 %d 个文件句柄（名称解析成功 %d 个），可能不完整", scan.FileScanned, scan.Resolved)}
	if notePrefix != "" {
		parts = append([]string{strings.TrimSuffix(notePrefix, "；")}, parts...)
	}
	if scan.Truncated {
		parts = append(parts, "扫描达到 5s 预算，仍有未检查的 File 句柄")
	}
	if scan.UnresolvedTypes > 0 {
		parts = append(parts, fmt.Sprintf("%d 个句柄的类型名无法解析（多来自受保护进程）", scan.UnresolvedTypes))
	}
	if len(owners) == 0 {
		parts = append(parts, "当前未见持有该文件句柄的进程")
	}
	// 目录句柄的对象类型是 Directory，不在 File 扫描范围；用户查目录时
	// 必须知道这个口径，否则会把"没查到"误判为"没被占用"。
	parts = append(parts, "目录句柄类型为 Directory，不在 File 扫描范围内")

	out["path"] = target
	out["scanned"] = scan.FileScanned
	out["resolved"] = scan.Resolved
	out["owners"] = owners
	out["truncated"] = scan.Truncated
	out["note"] = strings.Join(parts, "；")
	httpx.WriteJSON(w, r, http.StatusOK, out)
}

// handleThreads 实现 GET /threads?pid=。
func (s *server) handleThreads(w http.ResponseWriter, r *http.Request) {
	pid, err := parseForensicsPID(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}

	var mods []model.ModuleInfo
	if s.d.Modules != nil {
		mods = s.d.Modules(pid)
	}
	res, err := winapi.ScanThreads(pid, mods)
	if err != nil {
		httpx.WriteError(w, r, apperr.Internal(err))
		return
	}
	if res.Rows == nil {
		res.Rows = []winapi.ThreadRow{}
	}

	parts := make([]string, 0, 4)
	if res.Total == 0 {
		parts = append(parts, "未找到该进程的线程（进程可能已退出）")
	} else {
		parts = append(parts, fmt.Sprintf("共 %d 个线程", res.Total))
	}
	if res.Skipped > 0 {
		parts = append(parts, fmt.Sprintf("%d 个线程无法打开（受保护或已退出），仅列出 TID", res.Skipped))
	}
	if res.QueryFailed > 0 {
		parts = append(parts, fmt.Sprintf("%d 个线程起始地址查询失败", res.QueryFailed))
	}
	if !res.ProcessOpened && res.Total > 0 {
		parts = append(parts, "无法打开进程（受保护或权限不足），in_anonymous_exec 无法判定，统一为 false")
	}
	if !res.ModulesKnown && res.Total > 0 {
		parts = append(parts, "模块表不可用，module 字段全空")
	}

	httpx.WriteJSON(w, r, http.StatusOK, map[string]any{
		"pid":   pid,
		"items": res.Rows,
		"note":  strings.Join(parts, "；"),
	})
}

// handleMemScan 实现 GET /memscan?pid=。
//
// 入口先看 HG_AGENT_MEMSCAN_ENABLED：只有显式 "false" 才禁用（与
// HG_AGENT_RECON_PROBE 同模式），未设置=启用，便于旧部署升级后行为不变。
func (s *server) handleMemScan(w http.ResponseWriter, r *http.Request) {
	if strings.EqualFold(os.Getenv("HG_AGENT_MEMSCAN_ENABLED"), "false") {
		httpx.WriteError(w, r, apperr.Forbidden("内存扫描已在探针侧禁用（HG_AGENT_MEMSCAN_ENABLED=false）"))
		return
	}
	pid, err := parseForensicsPID(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}

	res, err := winapi.ScanMemory(pid)
	if err != nil {
		switch {
		case errors.Is(err, winapi.ErrMemScanAccessDenied):
			// 受保护进程打不开是正常调查结论：200 + 空结果 + 固定 note，
			// 不做重试（重试只会重复撞权限，放大探针开销）。
			httpx.WriteJSON(w, r, http.StatusOK, map[string]any{
				"pid":        pid,
				"counts":     map[string]int{"regions": 0, "private_exec": 0, "suspicious": 0},
				"regions":    []winapi.MemRegion{},
				"suspicious": []winapi.SuspiciousRegion{},
				"truncated":  false,
				"note":       "无法打开进程（受保护或权限不足），已跳过；" + memScanNote,
			})
			return
		case errors.Is(err, winapi.ErrMemScanProcessGone):
			httpx.WriteError(w, r, apperr.NotFound("进程"))
			return
		default:
			httpx.WriteError(w, r, apperr.Internal(err))
			return
		}
	}
	if res.Regions == nil {
		res.Regions = []winapi.MemRegion{}
	}
	if res.Suspicious == nil {
		res.Suspicious = []winapi.SuspiciousRegion{}
	}

	parts := []string{memScanNote}
	if res.Truncated {
		parts = append(parts, "regions 仅输出前 200 个或循环达到 2000 次上限，结果可能不完整")
	}
	if res.SuspiciousTruncated {
		parts = append(parts, fmt.Sprintf("suspicious 仅输出前 20 条（共命中 %d 条）", res.SuspiciousTotal))
	}
	if res.Committed == 0 {
		parts = append(parts, "该进程没有可读的提交区域（可能刚启动或已退出）")
	}

	httpx.WriteJSON(w, r, http.StatusOK, map[string]any{
		"pid": pid,
		"counts": map[string]int{
			"regions":      res.Committed,
			"private_exec": res.PrivateExec,
			"suspicious":   res.SuspiciousTotal,
		},
		"regions":    res.Regions,
		"suspicious": res.Suspicious,
		"truncated":  res.Truncated,
		"note":       strings.Join(parts, "；"),
	})
}
