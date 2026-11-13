//go:build windows

package collect

import (
	"fmt"
	"time"

	"zedr/internal/agent/winapi"
)

// NewSource 按名字构造采集源（Windows）；auto 会做一次可用性探测后择优。
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
			PID: p.PID, PPID: p.PPID, Name: p.Name,
			// FILETIME（1601 起 100ns）→ Unix 纳秒：rawProc.CreateTime
			// 是平台无关口径，中性代码不再感知 FILETIME 语义。
			CreateTime: filetimeToUnixNanos(p.CreateTime),
		}
	}
	return t, nil
}

// filetimeToTime 把 FILETIME 计数（1601 起 100ns）转换为 UTC 时间。
func filetimeToTime(ft int64) time.Time {
	if ns := filetimeToUnixNanos(ft); ns > 0 {
		return time.Unix(0, ns).UTC()
	}
	return time.Time{}
}

// filetimeToUnixNanos 把 FILETIME 计数转换为 Unix 纳秒（<=0 原样返回 0）。
func filetimeToUnixNanos(ft int64) int64 {
	const epochDiff = 116444736000000000
	ns := (ft - epochDiff) * 100
	if ns <= 0 {
		return 0
	}
	return ns
}
