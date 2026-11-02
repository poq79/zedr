package winapi

// memscan.go：进程地址空间元数据扫描（liveapi /memscan 的数据源）。
//
// 设计前提（必须连同实现一起理解，任何对外文档不得把它宣传成"内存取证"）：
//   - 只服务**单 PID 的人工触发**调查，不提供批量扫描、定时扫描、自动扫描
//     入口；调用方一次只查一个进程；
//   - 只返回 VirtualQueryEx 给出的**地址空间元数据**（基址/大小/保护位/类型/
//     映射文件名），不是内存内容；
//   - 对可疑区域只读**前 2 字节**判定 "MZ"（PE 头线索），随后立即丢弃，
//     不读取、不缓存、不传输任何其他内存内容；
//   - 不修改目标进程，不注入、不挂起线程，全部是只读查询；
//   - 受保护进程（PPL/System）OpenProcess 会失败，此时整体返回空结果 +
//     note 说明，不做重试、不降权反复尝试。
//
// 风险与性能护栏（与契约 §15.4 一致）：VirtualQueryEx 循环上限 2000 次、
// regions 输出上限 200、suspicious 上限 20；预算是为了"控制探针自身开销"
// 而不是"扫描深度"，超出即 truncated，绝不为了凑全量而放大调用次数。

import (
	"errors"
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	memScanMaxIterations = 2000 // VirtualQueryEx 调用上限，防失控
	memScanRegionMax     = 200  // regions 输出上限
	memScanSuspiciousMax = 20   // suspicious 输出上限

	// minSuspiciousSize：小于 4KB 的私有可执行页多为运行时跳板/分配器
	// 元数据，噪声远大于线索；4KB 正好是一个页，与契约口径一致。
	minSuspiciousSize = 4096

	memMapped = 0x00040000 // MEM_MAPPED（x/sys 未导出）
	memImage  = 0x01000000 // MEM_IMAGE（x/sys 未导出）
)

var (
	// ErrMemScanAccessDenied 表示目标进程受保护或权限不足。handler 据此
	// 返回 200 + 空结果 + note（"打不开"是正常调查结论，不是服务器错误）。
	ErrMemScanAccessDenied = errors.New("内存扫描：无法打开进程（受保护或权限不足）")
	// ErrMemScanProcessGone 表示 PID 不存在/已退出（OpenProcess 返回
	// ERROR_INVALID_PARAMETER）。handler 映射为 404。
	ErrMemScanProcessGone = errors.New("内存扫描：进程不存在或已退出")

	// GetMappedFileNameW 属于 psapi.dll（部分精简版 Windows 的 kernel32
	// 没有转发导出，直接绑 kernel32 会在 Call 时 panic）。psapi.dll 自
	// NT4 起就是系统组件，兼容性比 kernel32 转发更稳。
	procGetMappedFileNameW = windows.NewLazySystemDLL("psapi.dll").NewProc("GetMappedFileNameW")
)

// MemRegion 是 /memscan regions 的元素（契约 §15.4）。
type MemRegion struct {
	Base       uint64 `json:"base"`
	Size       uint64 `json:"size"`
	Protect    string `json:"protect"`
	Type       string `json:"type"`
	MappedFile string `json:"mapped_file,omitempty"`
}

// SuspiciousRegion 是 /memscan suspicious 的元素。pe_header 三态：
//
//	true  = 前两字节是 MZ
//	false = 能读但不是 MZ
//	null  = ReadProcessMemory 失败（无法判定，不冒充 false）
type SuspiciousRegion struct {
	Base     uint64 `json:"base"`
	Size     uint64 `json:"size"`
	Protect  string `json:"protect"`
	PEHeader *bool  `json:"pe_header"`
}

// MemScanResult 是一次内存元数据扫描的完整结果。
type MemScanResult struct {
	Regions             []MemRegion
	Suspicious          []SuspiciousRegion
	Iterations          int  // VirtualQueryEx 实际调用次数
	Committed           int  // 提交状态区域数（含未输出的）
	PrivateExec         int  // 私有可执行区域数（Suspicious 的判定集合）
	SuspiciousTotal     int  // 命中的可疑区域总数（可能大于输出的 20）
	Truncated           bool // regions 超 200 或循环触顶
	SuspiciousTruncated bool // suspicious 超 20
}

// ScanMemory 遍历 pid 的地址空间并返回元数据摘要。
//
// 权限：PROCESS_QUERY_INFORMATION | PROCESS_VM_READ。前者用于
// VirtualQueryEx，后者用于读 MZ 两字节——两者缺一不可，所以受保护进程
// 会在 OpenProcess 这一步整体失败（而不是扫描到一半）。
func ScanMemory(pid uint32) (MemScanResult, error) {
	out := MemScanResult{
		Regions:    []MemRegion{},
		Suspicious: []SuspiciousRegion{},
	}
	if pid == 0 {
		return out, ErrMemScanProcessGone
	}

	h, err := windows.OpenProcess(processQueryInformation|processVMRead, false, pid)
	if err != nil {
		switch {
		case errors.Is(err, windows.ERROR_ACCESS_DENIED):
			return out, fmt.Errorf("%w: %v", ErrMemScanAccessDenied, err)
		case errors.Is(err, windows.ERROR_INVALID_PARAMETER):
			return out, fmt.Errorf("%w: %v", ErrMemScanProcessGone, err)
		default:
			return out, err
		}
	}
	defer windows.CloseHandle(h)

	var addr uintptr
	exhausted := true
	for i := 0; i < memScanMaxIterations; i++ {
		var mbi windows.MemoryBasicInformation
		if err := windows.VirtualQueryEx(h, addr, &mbi, unsafe.Sizeof(mbi)); err != nil {
			exhausted = false
			break
		}
		if mbi.RegionSize == 0 {
			exhausted = false
			break
		}
		next := addr + mbi.RegionSize
		if next <= addr { // 地址回绕/异常区域，停止避免死循环
			exhausted = false
			break
		}
		out.Iterations++

		if mbi.State == windows.MEM_COMMIT {
			out.Committed++
			exec := isExecutableProtect(mbi.Protect)
			if mbi.Type == memPrivate && exec {
				out.PrivateExec++
			}
			if len(out.Regions) < memScanRegionMax {
				region := MemRegion{
					Base:    uint64(mbi.BaseAddress),
					Size:    uint64(mbi.RegionSize),
					Protect: protectString(mbi.Protect),
					Type:    memTypeString(mbi.Type),
				}
				// 只有映射/镜像区域才有文件名；再对私有区域调用
				// GetMappedFileName 是纯浪费（必然失败）。
				if mbi.Type == memMapped || mbi.Type == memImage {
					region.MappedFile = mappedFileName(h, mbi.BaseAddress)
				}
				out.Regions = append(out.Regions, region)
			} else {
				out.Truncated = true
			}
			if mbi.Type == memPrivate && exec && mbi.RegionSize >= minSuspiciousSize {
				out.SuspiciousTotal++
				if len(out.Suspicious) < memScanSuspiciousMax {
					out.Suspicious = append(out.Suspicious, SuspiciousRegion{
						Base:     uint64(mbi.BaseAddress),
						Size:     uint64(mbi.RegionSize),
						Protect:  protectString(mbi.Protect),
						PEHeader: probeMZ(h, mbi.BaseAddress),
					})
				} else {
					out.SuspiciousTruncated = true
				}
			}
		}
		addr = next
	}
	if exhausted {
		// 2000 次还没走到地址空间末尾：后面的区域没看，必须标注截断。
		out.Truncated = true
	}
	return out, nil
}

// isExecutableProtect 判断保护位是否含执行权限。
// 0x10/0x20/0x40/0x80 四个基保护都对应"可执行"，高字节是 GUARD/NOCACHE
// 等修饰位，不影响执行属性。
func isExecutableProtect(protect uint32) bool {
	return protect&(windows.PAGE_EXECUTE|windows.PAGE_EXECUTE_READ|
		windows.PAGE_EXECUTE_READWRITE|windows.PAGE_EXECUTE_WRITECOPY) != 0
}

// protectString 把保护位转成可读串（ERW/R/RW/...），修饰位追加 +G/+NC/+WC。
// 不用数字直出的原因：前端要一眼区分"可读可写可执行"和"只读"。
func protectString(protect uint32) string {
	var s string
	switch protect & 0xFF {
	case windows.PAGE_NOACCESS:
		s = "NO"
	case windows.PAGE_READONLY:
		s = "R"
	case windows.PAGE_READWRITE:
		s = "RW"
	case windows.PAGE_WRITECOPY:
		s = "WC"
	case windows.PAGE_EXECUTE:
		s = "E"
	case windows.PAGE_EXECUTE_READ:
		s = "ER"
	case windows.PAGE_EXECUTE_READWRITE:
		s = "ERW"
	case windows.PAGE_EXECUTE_WRITECOPY:
		s = "EWC"
	default:
		s = fmt.Sprintf("0x%x", protect)
	}
	if protect&windows.PAGE_GUARD != 0 {
		s += "+G"
	}
	if protect&windows.PAGE_NOCACHE != 0 {
		s += "+NC"
	}
	if protect&windows.PAGE_WRITECOMBINE != 0 {
		s += "+WC"
	}
	return s
}

func memTypeString(t uint32) string {
	switch t {
	case memImage:
		return "image"
	case memMapped:
		return "mapped"
	case memPrivate:
		return "private"
	default:
		return ""
	}
}

// mappedFileName 用 GetMappedFileNameW 取映射文件名（返回 NT 设备路径）。
// 失败返回空串——"没有映射"与"查询失败"在输出上无法区分，但对调查而言
// 都是"没有可信文件名"，不虚构占位符。
func mappedFileName(h windows.Handle, base uintptr) string {
	// Find 失败（极老/被裁剪的系统）时返回空串而不是让 Call panic：
	// 映射文件名只是富化字段，不值得为它中断整个扫描。
	if err := procGetMappedFileNameW.Find(); err != nil {
		return ""
	}
	buf := make([]uint16, 1024)
	n, _, _ := procGetMappedFileNameW.Call(
		uintptr(h),
		base,
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
	)
	if n == 0 {
		return ""
	}
	if int(n) > len(buf) {
		n = uintptr(len(buf))
	}
	return windows.UTF16ToString(buf[:n])
}

// probeMZ 只读前 2 字节判 PE 头，这是本文件唯一读取内存内容的位置。
// n != 2（短读）同样按"无法判定"处理，避免把半截数据当成结论。
func probeMZ(h windows.Handle, base uintptr) *bool {
	var buf [2]byte
	var read uintptr
	if err := windows.ReadProcessMemory(h, base, &buf[0], 2, &read); err != nil || read != 2 {
		return nil
	}
	mz := buf[0] == 'M' && buf[1] == 'Z'
	return &mz
}
