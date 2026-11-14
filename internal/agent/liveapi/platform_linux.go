//go:build linux

// platform_linux.go：liveapi 平台钩子的 Linux 实现。
//
// 未在 Linux 实机验证（本机无 Linux 测试环境）；验证口径 = GOOS=linux
// 交叉编译 + 纯逻辑单测（linuxpath.go / linuxproc.go，Windows 上跑）。
//
// Linux 版能力矩阵（与 Windows 同一路由路径，能力按平台诚实分层）：
//
//	✅ /processes  /netstat  /procinfo  /fs  /fs/stat  /fs/read  /fs/hash
//	   /fs/search  /fs/grep  /collect  /info  /peers  /persistence  /recon
//	   /ping  /_catalog
//	   /accounts（passwd/group/shadow/login.defs）  /sessions（utmp）
//	   /services（systemd unit）  /tasks（cron + systemd timer）
//	   /netinfo（/proc/net/arp·route + resolv.conf）  /baseline（Linux 十项）
//	❌ 501（Windows 专属语义，见 unsupported_linux.go）：/registry /evtlog
//	   /drivers /usn /ads /analyze /handles /handleowners /threads /memscan
//
// 数据源接线（组合根职责，本文件只提供能力）：
//   - Deps.Netstat = liveapi.ProcfsNetstat（/proc/net/tcp 投影）；
//   - Deps.Procs/Snapshot/Runtime 由 state.Store 直通；
//   - Deps.FS 留空用 OSFS（本文件的 fileAttrs 提供属性映射）。
package liveapi

import (
	"os"
	"runtime"
	"time"
)

// relPathSep 是 /fs/search 相对路径的分隔符（Linux 线协议用 `/`，与
// 平台原生路径形态一致）。
const relPathSep = "/"

// validateFSPath 是 Linux 版路径校验：绝对路径 + 防目录穿越。规则与实现
// 见 linuxpath.go（中性纯逻辑，单测锁口径）；本文件只做直通。
func validateFSPath(raw string) (string, error) {
	return validateLinuxAbsPath(raw)
}

// fsPathKey 是 /collect 路径去重键：Linux 大小写敏感，/tmp/A 与 /tmp/a
// 是两个文件，原样作键（Windows 侧才 casefold）。
func fsPathKey(clean string) string {
	return clean
}

// fileSignature：Linux 无 Authenticode 语义。State="unsupported" 诚实
// 表达"本平台不做签名判定"，绝不冒充 unsigned（那是"验证过且无签名"）。
func fileSignature(path string) signatureInfo {
	return signatureInfo{State: "unsupported"}
}

// fileAttrs 把 stat 信息映射成 Entry 属性位（口径见 attrsFromStat）。
// 用 Lstat：symlink 条目自身要标 Reparse，跟随目标会丢这个信息。
// 读失败返回零值（与 Windows GetFileAttrs 的降级口径一致）。
func fileAttrs(path string) fileAttrFlags {
	info, err := os.Lstat(path)
	if err != nil {
		return fileAttrFlags{}
	}
	return attrsFromStat(info.Name(), info.Mode())
}

// hasAltStreams：Linux 无 NTFS ADS 语义，恒 false（quick.ads 不出现，
// 前端徽标自然缺席，不伪造）。
func hasAltStreams(path string) bool { return false }

// netRealtime 是 /netstat 的单 PID 实时富化（Linux 口径）：
//   - started_at：/proc/[pid]/stat starttime 锚定 boot 时刻（同 collect
//     口径，锚定用"墙钟 - uptime"反推，不读 btime）；
//   - elevated：real uid == 0（root 即提权；读不到按 false——"非 root"
//     与"未知"不可区分，与 Windows IsElevated 同一已知局限）。
//
// 失败的 PID 字段缺省（省略），不放大成端点失败。
func netRealtime(pids []uint32) (map[uint32]int64, map[uint32]bool) {
	now := time.Now()
	startedAt := make(map[uint32]int64, len(pids))
	elevated := make(map[uint32]bool, len(pids))
	for _, pid := range pids {
		if ts := procStarttimeUnix(pid, now); ts > 0 {
			startedAt[pid] = ts
		}
		elevated[pid] = procIsRootEuid(pid)
	}
	return startedAt, elevated
}

// procRealtimeFields 是 /procinfo 的单 PID 实时字段。Linux 只给
// started_at_unix；session_id/elevated 无对等语义（/proc 无会话概念、
// root 判定已由快照 User 列表达），诚实省略。
func procRealtimeFields(pid uint32) map[string]any {
	out := map[string]any{}
	if ts := procStarttimeUnix(pid, time.Now()); ts > 0 {
		out["started_at_unix"] = ts
	}
	return out
}

// execFileInfoExtra：Linux 无签名校验与 MotW，exec_info 只保留中性层的
// exists（返回 nil = 无平台扩展键）。
func execFileInfoExtra(path string) map[string]any { return nil }

// enrichInfo 是 /info 的平台扩展：os/arch 从 /etc/os-release + 内核版本 +
// runtime.GOARCH 现取；hostname 在 RuntimeInfo 未跑过首轮回调时兜底
// （os.Hostname 一次系统调用，成本可忽略）。Windows 侧对应实现为 no-op，
// 输出零变化。
func (s *server) enrichInfo(out map[string]any) {
	out["os"] = linuxOSName()
	out["arch"] = runtime.GOARCH
	if hn, ok := out["hostname"].(string); !ok || hn == "" {
		if name, err := os.Hostname(); err == nil && name != "" {
			out["hostname"] = name
		}
	}
}
