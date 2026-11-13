//go:build windows
// +build windows

package winapi

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// 本文件实现基于 NtQuerySystemInformation(SystemProcessInformation) 的进程枚举。
//
// 与 Toolhelp32 的差异（也是引入它的原因）：
//   - 一次系统调用返回全部进程，避免"快照 + 每进程多次调用"的开销；
//   - 每条记录自带 CreateTime，可以准确识别 PID 复用
//     （Toolhelp32 只能靠进程名比对，同名进程换代会漏判）；
//   - 单次调用约 1–2ms，比 Toolhelp32 更便宜，因此可以用更短的轮询间隔，
//     缩短"短命进程"的观测盲区。
//
// 兼容性：该 API 自 Windows NT 起就存在，但不同版本的结构体字段有增补，
// 因此这里只读取前若干个稳定字段（CreateTime / ImageName / PID / PPID），
// 且一旦调用失败，调用方会回退到 Toolhelp32 实现。

const systemProcessInformation = 5

// statusInfoLengthMismatch 表示缓冲区不足，需要按返回长度重试。
const statusInfoLengthMismatch = 0xC0000004

var procNtQuerySystemInformation = modNtdll.NewProc("NtQuerySystemInformation")

// unicodeStr 对应 UNICODE_STRING。
type unicodeStr struct {
	Length        uint16
	MaximumLength uint16
	_             uint32
	Buffer        *uint16
}

// ntProcessEntry 是 SYSTEM_PROCESS_INFORMATION 的稳定前缀。
// 只声明到 InheritedFromUniqueProcessId，后续字段在不同 Windows 版本上有差异，
// 我们不需要它们。
type ntProcessEntry struct {
	NextEntryOffset              uint32
	NumberOfThreads              uint32
	WorkingSetPrivateSize        int64
	HardFaultCount               uint32
	NumberOfThreadsHighWatermark uint32
	CycleTime                    uint64
	CreateTime                   int64
	UserTime                     int64
	KernelTime                   int64
	ImageName                    unicodeStr
	BasePriority                 int32
	UniqueProcessID              uintptr
	InheritedFromUniqueProcessID uintptr
}

// NtProcessEntry 是从内核结构解析出的进程条目。
type NtProcessEntry struct {
	PID        uint32
	PPID       uint32
	Name       string
	CreateTime int64 // FILETIME 计数，0 表示未知
}

// SnapshotProcessesNT 用一次系统调用枚举全部进程。
func SnapshotProcessesNT() ([]NtProcessEntry, error) {
	// 初始缓冲区：进程数 × 约 1.2KB，留足余量避免频繁重试
	size := uintptr(1024 * 1024)
	var buf []byte

	for attempt := 0; attempt < 6; attempt++ {
		buf = make([]byte, size)
		var retLen uint32
		status, _, _ := procNtQuerySystemInformation.Call(
			systemProcessInformation,
			uintptr(unsafe.Pointer(&buf[0])),
			size,
			uintptr(unsafe.Pointer(&retLen)),
		)

		if uint32(status) == statusInfoLengthMismatch {
			// 缓冲区不够：按返回长度（再留 25% 余量）重试
			if retLen > 0 {
				size = uintptr(retLen) + uintptr(retLen)/4
			} else {
				size *= 2
			}
			continue
		}
		if status != 0 {
			return nil, fmt.Errorf("NtQuerySystemInformation 失败: status=0x%x", uint32(status))
		}

		return parseProcessList(buf), nil
	}
	return nil, fmt.Errorf("NtQuerySystemInformation 缓冲区多次不足，放弃")
}

func parseProcessList(buf []byte) []NtProcessEntry {
	out := make([]NtProcessEntry, 0, 512)
	base := unsafe.Pointer(&buf[0])
	limit := uintptr(len(buf))
	var off uintptr

	for off < limit {
		if off+unsafe.Sizeof(ntProcessEntry{}) > limit {
			break
		}
		e := (*ntProcessEntry)(unsafe.Add(base, off))

		pid := uint32(e.UniqueProcessID)
		ppid := uint32(e.InheritedFromUniqueProcessID)
		name := ""
		if e.ImageName.Buffer != nil && e.ImageName.Length > 0 && e.ImageName.Length <= 520 {
			name = windows.UTF16ToString(unsafe.Slice(e.ImageName.Buffer, e.ImageName.Length/2))
		}

		out = append(out, NtProcessEntry{
			PID:        pid,
			PPID:       ppid,
			Name:       name,
			CreateTime: e.CreateTime,
		})

		if e.NextEntryOffset == 0 {
			break
		}
		off += uintptr(e.NextEntryOffset)
	}
	return out
}

// ProbeNT 探测该 API 是否可用（用于采集器自动选择）。
func ProbeNT() error {
	entries, err := SnapshotProcessesNT()
	if err != nil {
		return err
	}
	if len(entries) < 4 {
		return fmt.Errorf("NtQuerySystemInformation 返回进程数异常: %d", len(entries))
	}
	return nil
}
