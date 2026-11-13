//go:build windows
// +build windows

package liveapi

// platform_windows.go：liveapi 的全部平台钩子 Windows 实现。
//
// 中性代码（liveapi.go/fs.go/fsys.go/netstat.go/procinfo.go/search.go/
// collect.go/info.go）只依赖本文件与 platform_linux.go 提供的同名钩子，
// 保证"中性形状 + 平台实现"的分治；Windows 实现全部是对既有 winapi
// 只读函数的直通适配，行为与拆分前逐字一致（validateFSPath/splitPathSegs
// 自 fs.go 原样搬移，拆分原因见 fs.go 头注释）。

import (
	"path/filepath"
	"strings"

	"zedr/internal/agent/winapi"
	"zedr/internal/platform/apperr"
)

// relPathSep 是 /fs/search 相对路径的分隔符（Windows 线协议历史上就是
// `\`，保持不变让前端拼路径行为稳定）。
const relPathSep = `\`

// validateFSPath 校验 fs* 端点共用的 path 参数（Windows 规则）。
//
// 规则（契约 §5.2 逐条）：
//   - 非空（空 = 400）；
//   - 拒绝 `\\.\` 与 `\\?\` 前缀（设备命名空间——`\\.\PhysicalDrive0` 能把
//     整块物理盘当文件读，风险面 v1 明确不收）；
//   - filepath.IsAbs 且 VolumeName 非空（拒绝 `\foo` 这类盘符相对路径，
//     它实际落在"进程当前盘"，语义随 cwd 漂移）；
//   - 不允许出现 `..` 路径段。
//
// `..` 检查必须看原始输入：filepath.Clean 会把 `C:\a\..\b` 解析成 `C:\b`，
// 绝对路径经 Clean 后理论上不可能残留 ".."，对 Clean 结果检查恒为假。
// （Linux 侧对应规则在 platform_linux.go + linuxpath.go，两套规则各自的
// 语义差异是真实的平台差异，不是偷懒。）
func validateFSPath(raw string) (string, error) {
	if raw == "" {
		return "", apperr.Invalid("path 参数必填")
	}
	if strings.HasPrefix(raw, `\\.\`) || strings.HasPrefix(raw, `\\?\`) {
		return "", apperr.Invalid("不支持设备命名空间路径")
	}
	if !filepath.IsAbs(raw) {
		return "", apperr.Invalid("path 必须是绝对路径")
	}
	if filepath.VolumeName(raw) == "" {
		return "", apperr.Invalid("path 缺少盘符/卷名")
	}
	for _, seg := range splitPathSegs(raw) {
		if seg == ".." {
			return "", apperr.Invalid("path 不允许包含 ..")
		}
	}
	return filepath.Clean(raw), nil
}

// splitPathSegs 按 Windows 两种分隔符切分路径段（空段丢弃）。
func splitPathSegs(p string) []string {
	return strings.FieldsFunc(p, func(r rune) bool {
		return r == '\\' || r == '/'
	})
}

// fsPathKey 是 /collect 路径去重键：Windows 路径大小写不敏感，
// Clean 后 casefold 才能挡住 `C:\a\f` 与 `C:\A\F` 的重复采集。
func fsPathKey(clean string) string {
	return strings.ToLower(clean)
}

// fileSignature 直通 winapi.VerifySignature（Authenticode）。
func fileSignature(path string) signatureInfo {
	sig := winapi.VerifySignature(path)
	return signatureInfo{State: sig.State, Signer: sig.Signer, Signed: sig.Signed}
}

// fileAttrs 直通 winapi.GetFileAttrs（原始属性位）。
func fileAttrs(path string) fileAttrFlags {
	a := winapi.GetFileAttrs(path)
	return fileAttrFlags{Hidden: a.Hidden, System: a.System, Readonly: a.Readonly, Reparse: a.Reparse}
}

// hasAltStreams 判定文件是否有 NTFS 备用数据流（quick.ads 标志）。
func hasAltStreams(path string) bool {
	streams, err := winapi.EnumerateStreams(path)
	return err == nil && len(streams) > 0
}

// netRealtime 对快照内唯一 PID 做实时富化：启动时刻（GetProcessTimes）
// 与提权态（令牌完整性）。IsElevated 对打不开令牌的进程返回 false——
// "非提权"与"未知"在此无法区分，是已知口径局限（与 /procinfo 一致）。
func netRealtime(pids []uint32) (map[uint32]int64, map[uint32]bool) {
	startedAt := make(map[uint32]int64, len(pids))
	elevated := make(map[uint32]bool, len(pids))
	for _, pid := range pids {
		if ts, err := winapi.ProcessStartTime(pid); err == nil && ts > 0 {
			startedAt[pid] = ts
		}
		elevated[pid] = winapi.IsElevated(pid)
	}
	return startedAt, elevated
}

// procRealtimeFields 是 /procinfo 的单 PID 实时字段（快照 ProcRow 不携带）。
// 进程已退出时查询自然失败 → 对应字段省略。
func procRealtimeFields(pid uint32) map[string]any {
	out := map[string]any{}
	if sid, err := winapi.SessionID(pid); err == nil && sid > 0 {
		out["session_id"] = sid
	}
	if winapi.IsElevated(pid) {
		out["elevated"] = true
	}
	if ts, err := winapi.ProcessStartTime(pid); err == nil && ts > 0 {
		out["started_at_unix"] = ts
	}
	return out
}

// execFileInfoExtra 是 /procinfo exec_info 的 Windows 扩展块：签名状态 +
// MotW zone（有 zone.identifier 流才读内容，MotW 存在性一次枚举即可判定）。
func execFileInfoExtra(path string) map[string]any {
	out := map[string]any{}
	sig := winapi.VerifySignature(path)
	out["signed_state"] = sig.State
	if streams, err := winapi.EnumerateStreams(path); err == nil {
		for _, st := range streams {
			if st.Name == "zone.identifier" {
				if zi, err := winapi.ReadZoneIdentifier(path); err == nil && zi != nil {
					out["ads_zone_id"] = zi.ZoneID
				}
				break
			}
		}
	}
	return out
}

// enrichInfo 是 /info 的平台扩展（Windows：no-op——RuntimeInfo 已覆盖全部
// Windows 关心字段，保持既有输出零变化）。
func (s *server) enrichInfo(out map[string]any) {}
