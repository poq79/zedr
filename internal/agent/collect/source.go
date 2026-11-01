package collect

import (
	"fmt"
	"time"

	"zedr/internal/agent/winapi"
)

// Source 是"进程表来源"的抽象。
//
// 之所以做成可插拔：进程采集是整个探针里最依赖操作系统实现细节的一层，
// 不同 Windows 版本、不同安全软件干预下，某一种枚举方式可能失效。
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
	Conns   map[uint32][]winapi.TCPConn
	TakenAt time.Time
	Count   int
}

// rawProc 是采集层内部的进程摘要。
type rawProc struct {
	PID   uint32
	PPID  uint32
	Name  string
	// CreateTime 为 FILETIME 计数，0 表示该来源不提供（Toolhelp32 就没有）。
	// 有它就能准确识别 PID 复用：同名但创建时间不同 = 新进程。
	CreateTime int64
}

const (
	// SourceAuto 优先使用 NtQuerySystemInformation，失败自动回退 Toolhelp32。
	SourceAuto = "auto"
	// SourceNTQuery 强制使用 NtQuerySystemInformation。
	SourceNTQuery = "ntquery"
	// SourceToolhelp 强制使用 Toolhelp32（兼容性最好，旧引擎）。
	SourceToolhelp = "toolhelp"
)

// NewSource 按名字构造采集源；auto 会做一次可用性探测后择优。
func NewSource(name string) (Source, string, error) {
	switch name {
	case SourceToolhelp:
		return toolhelpSource{}, "显式指定 Toolhelp32 采集", nil

	case SourceNTQuery:
		if err := winapi.ProbeNT(); err != nil {
			return nil, "", fmt.Errorf("NtQuerySystemInformation 不可用: %w", err)
		}
		return ntSource{}, "显式指定 NtQuerySystemInformation 采集", nil

	case "", SourceAuto:
		if err := winapi.ProbeNT(); err == nil {
			return ntSource{}, "自动选择：NtQuerySystemInformation 探测通过", nil
		} else {
			return toolhelpSource{}, "自动回退：NtQuerySystemInformation 不可用（" + err.Error() + "），改用 Toolhelp32", nil
		}

	default:
		return nil, "", fmt.Errorf("未知的采集源 %q，可选 auto/ntquery/toolhelp", name)
	}
}

// ---------------------------------------------------------------- Toolhelp32

type toolhelpSource struct{}

func (toolhelpSource) Name() string { return SourceToolhelp }

func (toolhelpSource) Table() (*Table, error) {
	start := time.Now()
	list, err := winapi.SnapshotProcesses()
	if err != nil {
		return nil, err
	}
	conns, err := winapi.TCPConnections()
	if err != nil {
		conns = map[uint32][]winapi.TCPConn{} // 网络信息失败不影响进程采集
	}

	t := &Table{
		Procs:   make(map[uint32]rawProc, len(list)),
		Conns:   conns,
		TakenAt: start,
		Count:   len(list),
	}
	for _, p := range list {
		t.Procs[p.PID] = rawProc{PID: p.PID, PPID: p.PPID, Name: p.Name}
	}
	return t, nil
}

// ---------------------------------------------------------------- NtQuery

type ntSource struct{}

func (ntSource) Name() string { return SourceNTQuery }

func (ntSource) Table() (*Table, error) {
	start := time.Now()
	list, err := winapi.SnapshotProcessesNT()
	if err != nil {
		return nil, err
	}
	conns, err := winapi.TCPConnections()
	if err != nil {
		conns = map[uint32][]winapi.TCPConn{}
	}

	t := &Table{
		Procs:   make(map[uint32]rawProc, len(list)),
		Conns:   conns,
		TakenAt: start,
		Count:   len(list),
	}
	for _, p := range list {
		t.Procs[p.PID] = rawProc{
			PID: p.PID, PPID: p.PPID, Name: p.Name, CreateTime: p.CreateTime,
		}
	}
	return t, nil
}
