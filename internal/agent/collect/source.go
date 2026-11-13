// Package collect 实现进程采集（跨平台）。
//
// 采集策略（对应报告第 5 章"性能工程"）：
//   - 用"进程表来源"(Source) 做增量比对，只对"新出现的 PID"做昂贵富化；
//   - 网络连接用单次全量拉取（Windows: GetExtendedTcpTable；
//     Linux: /proc/net/tcp + inode→PID 映射），避免每进程一次系统调用；
//   - 已退出进程保留在历史表中，用于还原"父进程已退出"的孤儿链路；
//   - 定期做一次全量深度扫描（补模块信息），频率远低于增量轮询。
//
// 来源可插拔（AGENTS §3.3 纪律）：Windows 有 ntquery/toolhelp 两实现，
// Linux 是 procfs——按 GOOS 各自提供 NewSource 分派，检测层消费同一
// Table/ProcessInfo 形状，零分叉。
package collect

import (
	"time"

	"zedr/internal/agent/nettypes"
)

// Source 是"进程表来源"的抽象。
//
// 之所以做成可插拔：进程采集是整个探针里最依赖操作系统实现细节的一层，
// 不同 OS 版本、不同安全软件干预下，某一种枚举方式可能失效。
// 保留多个实现并支持运行时切换，可以在出问题时立刻退回已验证的旧引擎，
// 而不必重新发版——这对需要覆盖大量异构终端的场景很关键。
type Source interface {
	// Name 返回实现名，用于日志与 UI 展示。
	Name() string
	// Table 返回当前进程表与网络连接表。
	Table() (*Table, error)
}

// Table 是一轮采集的原始结果。
type Table struct {
	Procs   map[uint32]rawProc
	Conns   map[uint32][]nettypes.TCPConn
	TakenAt time.Time
	Count   int
}

// rawProc 是采集层内部的进程摘要。
type rawProc struct {
	PID  uint32
	PPID uint32
	Name string
	// CreateTime 是进程创建时刻（Unix 纳秒；0 表示该来源不提供）。
	// 有它就能准确识别 PID 复用：同名但创建时间不同 = 新进程。
	// Windows 的 NtQuery 来源把 FILETIME 在采集层换算成本口径；
	// Linux 的 procfs 来源由 /proc/[pid]/stat 的 btime 换算。
	CreateTime int64
}

// 采集源名称。Windows：auto（ntquery 优先、失败回退 toolhelp）/ntquery/
// toolhelp；Linux：auto/procfs。
const (
	SourceAuto = "auto"
	// SourceNTQuery 强制使用 NtQuerySystemInformation（仅 Windows）。
	SourceNTQuery = "ntquery"
	// SourceToolhelp 强制使用 Toolhelp32（兼容性最好，旧引擎，仅 Windows）。
	SourceToolhelp = "toolhelp"
	// SourceProcfs 是 Linux 的 procfs 采集源。
	SourceProcfs = "procfs"
)
