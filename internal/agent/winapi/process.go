// Package winapi 封装探针所需的 Win32 / NT 原生接口。
//
// 全部通过 syscall 动态调用，不依赖 CGO，编译产物是单文件静态 exe，
// 便于在受管终端上直接分发。
package winapi

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modKernel32 = windows.NewLazySystemDLL("kernel32.dll")
	modAdvapi32 = windows.NewLazySystemDLL("advapi32.dll")
	modNtdll    = windows.NewLazySystemDLL("ntdll.dll")

	procCreateToolhelp32Snapshot = modKernel32.NewProc("CreateToolhelp32Snapshot")
	procProcess32FirstW          = modKernel32.NewProc("Process32FirstW")
	procProcess32NextW           = modKernel32.NewProc("Process32NextW")
	procModule32FirstW           = modKernel32.NewProc("Module32FirstW")
	procModule32NextW            = modKernel32.NewProc("Module32NextW")
	procOpenProcess              = modKernel32.NewProc("OpenProcess")
	procCloseHandle              = modKernel32.NewProc("CloseHandle")
	procQueryFullProcessImage    = modKernel32.NewProc("QueryFullProcessImageNameW")
	procProcessIdToSessionId     = modKernel32.NewProc("ProcessIdToSessionId")
	procIsWow64Process           = modKernel32.NewProc("IsWow64Process")
	procGetProcessTimes          = modKernel32.NewProc("GetProcessTimes")
	procGetSystemTimes           = modKernel32.NewProc("GetSystemTimes")

	procOpenProcessToken   = modAdvapi32.NewProc("OpenProcessToken")
	procGetTokenInformation = modAdvapi32.NewProc("GetTokenInformation")
	procLookupAccountSidW  = modAdvapi32.NewProc("LookupAccountSidW")

	procNtQueryInformationProcess = modNtdll.NewProc("NtQueryInformationProcess")
)

const (
	th32csSnapProcess     = 0x00000002
	th32csSnapModule      = 0x00000008
	th32csSnapModule32    = 0x00000010
	invalidHandleValue    = ^uintptr(0)

	processQueryLimitedInformation = 0x1000
	processQueryInformation        = 0x0400
	processVMRead                  = 0x0010

	tokenQuery = 0x0008
	tokenDup   = 0x0002

	maxPath = 260
)

// ProcessEntry 是 Toolhelp32 快照中的一条进程记录。
type ProcessEntry struct {
	PID       uint32
	PPID      uint32
	Name      string
	Threads   uint32
	PriClass  int32
}

type processEntry32 struct {
	Size            uint32
	CntUsage        uint32
	ProcessID       uint32
	DefaultHeapID   uintptr
	ModuleID        uint32
	CntThreads      uint32
	ParentProcessID uint32
	PriClassBase    int32
	Flags           uint32
	ExeFile         [maxPath]uint16
}

// ModuleEntry 是某个进程加载的模块。
type ModuleEntry struct {
	Name     string
	Path     string
	BaseAddr uint64
	Size     uint32
}

type moduleEntry32 struct {
	Size         uint32
	ModuleID     uint32
	ProcessID    uint32
	GlblcntUsage uint32
	ProccntUsage uint32
	ModBaseAddr  uintptr
	ModBaseSize  uint32
	HModule      uintptr
	SzModule     [256]uint16
	SzExePath    [maxPath]uint16
}

func openProcess(pid uint32, access uint32) (windows.Handle, error) {
	h, _, err := procOpenProcess.Call(uintptr(access), 0, uintptr(pid))
	if h == 0 {
		return 0, fmt.Errorf("OpenProcess(%d) 失败: %w", pid, err)
	}
	return windows.Handle(h), nil
}

func closeHandle(h windows.Handle) {
	if h != 0 && h != windows.InvalidHandle {
		_, _, _ = procCloseHandle.Call(uintptr(h))
	}
}

// SnapshotProcesses 一次性枚举全部进程（约 300-800 条，耗时通常 < 5ms）。
func SnapshotProcesses() ([]ProcessEntry, error) {
	h, _, err := procCreateToolhelp32Snapshot.Call(th32csSnapProcess, 0)
	if uintptr(h) == invalidHandleValue || h == 0 {
		return nil, fmt.Errorf("进程快照失败: %w", err)
	}
	defer closeHandle(windows.Handle(h))

	var entry processEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))

	ret, _, errFirst := procProcess32FirstW.Call(h, uintptr(unsafe.Pointer(&entry)))
	if ret == 0 {
		return nil, fmt.Errorf("Process32FirstW 失败: %w", errFirst)
	}

	out := make([]ProcessEntry, 0, 512)
	for {
		out = append(out, ProcessEntry{
			PID:      entry.ProcessID,
			PPID:     entry.ParentProcessID,
			Name:     windows.UTF16ToString(entry.ExeFile[:]),
			Threads:  entry.CntThreads,
			PriClass: entry.PriClassBase,
		})
		entry.Size = uint32(unsafe.Sizeof(entry))
		ret, _, _ = procProcess32NextW.Call(h, uintptr(unsafe.Pointer(&entry)))
		if ret == 0 {
			break
		}
	}
	return out, nil
}

// ImagePath 取进程镜像的完整路径。
func ImagePath(pid uint32) (string, error) {
	h, err := openProcess(pid, processQueryLimitedInformation)
	if err != nil {
		return "", err
	}
	defer closeHandle(h)

	var buf [maxPath * 2]uint16
	size := uint32(len(buf))
	ret, _, e := procQueryFullProcessImage.Call(uintptr(h), 0,
		uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)))
	if ret == 0 {
		return "", fmt.Errorf("QueryFullProcessImageName 失败: %w", e)
	}
	return windows.UTF16ToString(buf[:size]), nil
}

// ---------------------------------------------------------------- 命令行（PEB）

type processBasicInformation struct {
	ExitStatus                   int32
	PebBaseAddress               uintptr
	AffinityMask                 uintptr
	BasePriority                 int32
	UniqueProcessID              uintptr
	InheritedFromUniqueProcessID uintptr
}

type unicodeString struct {
	Length        uint16
	MaximumLength uint16
	_             uint32
	Buffer        uintptr
}

// 目标进程为 64 位时的固定偏移。
const (
	pebProcessParametersOffset = 0x20 // PEB.ProcessParameters
	rpCommandLineOffset        = 0x70 // RTL_USER_PROCESS_PARAMETERS.CommandLine
)

// CommandLine 通过读取目标进程 PEB 获取完整命令行。
//
// 这是 ETW 之外的常规手段：需要 PROCESS_VM_READ，受保护进程（如 PPL 保护的安全软件）
// 会读取失败，此时返回空串属于预期行为。
func CommandLine(pid uint32) (string, error) {
	h, err := openProcess(pid, processQueryInformation|processVMRead)
	if err != nil {
		return "", err
	}
	defer closeHandle(h)

	var pbi processBasicInformation
	var retLen uint32
	status, _, _ := procNtQueryInformationProcess.Call(
		uintptr(h), 0, uintptr(unsafe.Pointer(&pbi)),
		uintptr(unsafe.Sizeof(pbi)), uintptr(unsafe.Pointer(&retLen)))
	if status != 0 || pbi.PebBaseAddress == 0 {
		return "", fmt.Errorf("NtQueryInformationProcess 失败: status=0x%x", status)
	}

	var paramsAddr uintptr
	if err := readMemory(h, pbi.PebBaseAddress+pebProcessParametersOffset, unsafe.Pointer(&paramsAddr), 8); err != nil {
		return "", err
	}
	if paramsAddr == 0 {
		return "", fmt.Errorf("ProcessParameters 为空")
	}

	var us unicodeString
	if err := readMemory(h, paramsAddr+rpCommandLineOffset, unsafe.Pointer(&us), unsafe.Sizeof(us)); err != nil {
		return "", err
	}
	if us.Buffer == 0 || us.Length == 0 || us.Length > 32767 {
		return "", nil
	}

	buf := make([]uint16, us.Length/2+1)
	if err := readMemory(h, us.Buffer, unsafe.Pointer(&buf[0]), uintptr(us.Length)); err != nil {
		return "", err
	}
	return windows.UTF16ToString(buf), nil
}

func readMemory(h windows.Handle, addr uintptr, dst unsafe.Pointer, size uintptr) error {
	var read uintptr
	ret, _, e := windows.NewLazySystemDLL("kernel32.dll").NewProc("ReadProcessMemory").Call(
		uintptr(h), addr, uintptr(dst), size, uintptr(unsafe.Pointer(&read)))
	if ret == 0 {
		return fmt.Errorf("ReadProcessMemory(0x%x) 失败: %w", addr, e)
	}
	return nil
}

// ---------------------------------------------------------------- 令牌信息

// ProcessUser 解析进程所属账号（DOMAIN\user）。
func ProcessUser(pid uint32) (string, error) {
	h, err := openProcess(pid, processQueryLimitedInformation)
	if err != nil {
		return "", err
	}
	defer closeHandle(h)

	var token windows.Handle
	ret, _, e := procOpenProcessToken.Call(uintptr(h), tokenQuery, uintptr(unsafe.Pointer(&token)))
	if ret == 0 {
		return "", fmt.Errorf("OpenProcessToken 失败: %w", e)
	}
	defer closeHandle(token)

	// TokenUser = 1
	var size uint32
	_, _, _ = procGetTokenInformation.Call(uintptr(token), 1, 0, 0, uintptr(unsafe.Pointer(&size)))
	if size == 0 {
		return "", fmt.Errorf("获取令牌信息长度失败")
	}
	buf := make([]byte, size)
	ret, _, e = procGetTokenInformation.Call(uintptr(token), 1,
		uintptr(unsafe.Pointer(&buf[0])), uintptr(size), uintptr(unsafe.Pointer(&size)))
	if ret == 0 {
		return "", fmt.Errorf("GetTokenInformation(TokenUser) 失败: %w", e)
	}

	// TOKEN_USER 的第一个字段是 SID_AND_ATTRIBUTES{SID 指针, DWORD}
	sid := *(**windows.SID)(unsafe.Pointer(&buf[0]))
	if sid == nil {
		return "", fmt.Errorf("SID 为空")
	}

	var nameBuf [256]uint16
	var domainBuf [256]uint16
	nameLen := uint32(len(nameBuf))
	domainLen := uint32(len(domainBuf))
	var sidType uint32
	ret, _, _ = procLookupAccountSidW.Call(0,
		uintptr(unsafe.Pointer(sid)),
		uintptr(unsafe.Pointer(&nameBuf[0])), uintptr(unsafe.Pointer(&nameLen)),
		uintptr(unsafe.Pointer(&domainBuf[0])), uintptr(unsafe.Pointer(&domainLen)),
		uintptr(unsafe.Pointer(&sidType)))
	if ret == 0 {
		// 解析失败时退化成 SID 字符串，仍可用于区分不同账号
		if s := sid.String(); s != "" {
			return s, nil
		}
		return "", fmt.Errorf("LookupAccountSid 失败")
	}
	name := windows.UTF16ToString(nameBuf[:nameLen])
	domain := windows.UTF16ToString(domainBuf[:domainLen])
	if domain != "" {
		return domain + `\` + name, nil
	}
	return name, nil
}

// IsElevated 判断进程令牌是否为提升状态（TokenElevation = 20）。
func IsElevated(pid uint32) bool {
	h, err := openProcess(pid, processQueryLimitedInformation)
	if err != nil {
		return false
	}
	defer closeHandle(h)

	var token windows.Handle
	ret, _, _ := procOpenProcessToken.Call(uintptr(h), tokenQuery, uintptr(unsafe.Pointer(&token)))
	if ret == 0 {
		return false
	}
	defer closeHandle(token)

	var elevated uint32
	var size uint32
	ret, _, _ = procGetTokenInformation.Call(uintptr(token), 20,
		uintptr(unsafe.Pointer(&elevated)), 4, uintptr(unsafe.Pointer(&size)))
	return ret != 0 && elevated != 0
}

// SessionID 返回进程所在会话。
func SessionID(pid uint32) (uint32, error) {
	var sid uint32
	ret, _, e := procProcessIdToSessionId.Call(uintptr(pid), uintptr(unsafe.Pointer(&sid)))
	if ret == 0 {
		return 0, fmt.Errorf("ProcessIdToSessionId 失败: %w", e)
	}
	return sid, nil
}

// IsWow64 判断 32 位进程运行在 64 位系统上。
func IsWow64(pid uint32) bool {
	h, err := openProcess(pid, processQueryLimitedInformation)
	if err != nil {
		return false
	}
	defer closeHandle(h)
	var wow bool
	var out uint32
	ret, _, _ := procIsWow64Process.Call(uintptr(h), uintptr(unsafe.Pointer(&out)))
	if ret == 0 {
		return false
	}
	wow = out != 0
	return wow
}

// ---------------------------------------------------------------- 模块

// ProcessModules 枚举进程加载的所有模块。
func ProcessModules(pid uint32) ([]ModuleEntry, error) {
	h, _, err := procCreateToolhelp32Snapshot.Call(th32csSnapModule|th32csSnapModule32, uintptr(pid))
	if uintptr(h) == invalidHandleValue || h == 0 {
		return nil, fmt.Errorf("模块快照失败: %w", err)
	}
	defer closeHandle(windows.Handle(h))

	var entry moduleEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))
	ret, _, errFirst := procModule32FirstW.Call(h, uintptr(unsafe.Pointer(&entry)))
	if ret == 0 {
		return nil, fmt.Errorf("Module32FirstW 失败: %w", errFirst)
	}

	out := make([]ModuleEntry, 0, 64)
	for {
		out = append(out, ModuleEntry{
			Name:     windows.UTF16ToString(entry.SzModule[:]),
			Path:     windows.UTF16ToString(entry.SzExePath[:]),
			BaseAddr: uint64(entry.ModBaseAddr),
			Size:     entry.ModBaseSize,
		})
		entry.Size = uint32(unsafe.Sizeof(entry))
		ret, _, _ = procModule32NextW.Call(h, uintptr(unsafe.Pointer(&entry)))
		if ret == 0 {
			break
		}
	}
	return out, nil
}

// ---------------------------------------------------------------- CPU 占用

// CPUPercent 采样本进程 CPU 占用（两次调用之间计算差值）。
type CPUSampler struct {
	lastProc   uint64
	lastSystem uint64
	primed     bool
}

// Sample 返回最近一次采样区间的 CPU 百分比（0-100 * 核数上限内）。
func (c *CPUSampler) Sample() float64 {
	var creation, exit, kernel, user windows.Filetime
	h, err := windows.GetCurrentProcess()
	if err != nil {
		return 0
	}
	ret, _, _ := procGetProcessTimes.Call(uintptr(h),
		uintptr(unsafe.Pointer(&creation)), uintptr(unsafe.Pointer(&exit)),
		uintptr(unsafe.Pointer(&kernel)), uintptr(unsafe.Pointer(&user)))
	if ret == 0 {
		return 0
	}
	procTicks := filetimeTicks(kernel) + filetimeTicks(user)

	var idle, k, u windows.Filetime
	ret, _, _ = procGetSystemTimes.Call(uintptr(unsafe.Pointer(&idle)),
		uintptr(unsafe.Pointer(&k)), uintptr(unsafe.Pointer(&u)))
	if ret == 0 {
		return 0
	}
	sysTicks := filetimeTicks(k) + filetimeTicks(u)

	if !c.primed {
		c.lastProc, c.lastSystem, c.primed = procTicks, sysTicks, true
		return 0
	}
	dProc := procTicks - c.lastProc
	dSys := sysTicks - c.lastSystem
	c.lastProc, c.lastSystem = procTicks, sysTicks
	if dSys == 0 {
		return 0
	}
	pct := float64(dProc) / float64(dSys) * 100
	if pct < 0 {
		pct = 0
	}
	return pct
}

func filetimeTicks(ft windows.Filetime) uint64 {
	return uint64(ft.HighDateTime)<<32 | uint64(ft.LowDateTime)
}

// ProcessStartTime 取进程启动时间（UTC）。
func ProcessStartTime(pid uint32) (int64, error) {
	h, err := openProcess(pid, processQueryLimitedInformation)
	if err != nil {
		return 0, err
	}
	defer closeHandle(h)

	var creation, exit, kernel, user windows.Filetime
	ret, _, e := procGetProcessTimes.Call(uintptr(h),
		uintptr(unsafe.Pointer(&creation)), uintptr(unsafe.Pointer(&exit)),
		uintptr(unsafe.Pointer(&kernel)), uintptr(unsafe.Pointer(&user)))
	if ret == 0 {
		return 0, fmt.Errorf("GetProcessTimes 失败: %w", e)
	}
	// FILETIME: 1601-01-01 起的 100ns 计数 → Unix 秒
	ticks := int64(filetimeTicks(creation))
	const epochDiff = 116444736000000000
	return (ticks - epochDiff) / 10000000, nil
}
