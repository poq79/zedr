//go:build windows
// +build windows

// Package winapi 的资产盘点采集（inventory）。
//
// 为什么需要它：告警只有进程上下文时研判空间有限——"svchost.exe 连公网"
// 是否正常，取决于这台机器有没有服务在跑、有没有异常监听端口、磁盘/内存
// 是什么量级。资产快照提供这些"环境事实"，供管理台资产页与 AI 研判使用。
//
// 成本纪律：每个函数都是一次系统调用级别的快照（无回调、无 COM、无网络 IO），
// 单次调用目标 <50ms；失败一律返回 error，不 panic、不吞错。
// 本文件仅 Windows（文件名后缀约束，与包内其他文件"无显式 build tag"的
// 约定一致——本包整体只面向 Windows）。
package winapi

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

var (
	procGetExtendedUdpTable = modIphlpapi.NewProc("GetExtendedUdpTable")

	procGetLogicalDrives     = modKernel32.NewProc("GetLogicalDrives")
	procGetDriveTypeW        = modKernel32.NewProc("GetDriveTypeW")
	procGetDiskFreeSpaceExW  = modKernel32.NewProc("GetDiskFreeSpaceExW")
	procGlobalMemoryStatusEx = modKernel32.NewProc("GlobalMemoryStatusEx")
	procGetSystemInfo        = modKernel32.NewProc("GetSystemInfo")
	procGetTickCount64       = modKernel32.NewProc("GetTickCount64")

	procOpenSCManagerW        = modAdvapi32.NewProc("OpenSCManagerW")
	procEnumServicesStatusExW = modAdvapi32.NewProc("EnumServicesStatusExW")
	procOpenServiceW          = modAdvapi32.NewProc("OpenServiceW")
	procQueryServiceConfigW   = modAdvapi32.NewProc("QueryServiceConfigW")
	procCloseServiceHandle    = modAdvapi32.NewProc("CloseServiceHandle")
)

const (
	afUnspec = 0

	udpTableOwnerPID = 1 // UDP_TABLE_OWNER_PID：带归属 PID 的 UDP 表

	// GetAdaptersAddresses 标志：网关默认不返回，必须显式要；
	// anycast/multicast 列表对资产盘点无判别力，跳过以减小缓冲压力。
	gaaIncludeGateways = 0x40
	gaaSkipAnycast     = 0x02
	gaaSkipMulticast   = 0x04

	driveFixed = 3 // DRIVE_FIXED

	scmConnect   = 0x0001 // SC_MANAGER_CONNECT（OpenService 需要）
	scmEnumerate = 0x0004 // SC_MANAGER_ENUMERATE_SERVICE

	svcQueryConfig = 0x0001 // SERVICE_QUERY_CONFIG
	svcWin32       = 0x30   // SERVICE_WIN32：只列普通服务，不含驱动
	// （驱动数量大、变化少，且 persist.go 的自启动服务基线已排除驱动，口径对齐）
	svcStateAll   = 3 // SERVICE_STATE_ALL
	svcStatusInfo = 0 // SC_ENUM_PROCESS_INFO（EnumServicesStatusEx 的 InfoLevel，唯一合法值）
)

// ---------------------------------------------------------------- UDP 监听

// UDPEntry 是一条 UDP 监听端点（UDP 无连接，"监听"即已绑定的端口）。
type UDPEntry struct {
	Port uint16
	PID  uint32
}

// UDPListeners 一次拉取全系统 UDP 监听表（IPv4 + IPv6）。
//
// 与 TCP 表同一套"两次调用"模式：先探长度再取表，缓冲多留 1KB，
// 规避两次调用之间表增长导致的截断。
func UDPListeners() ([]UDPEntry, error) {
	out, err := udpTable(afInet)
	if err != nil {
		return nil, err
	}
	// IPv6 失败不影响 IPv4 结果（与 network.go 的 TCPConnections 同一口径）
	v6, err6 := udpTable(afInet6)
	if err6 == nil {
		out = append(out, v6...)
	}
	return out, nil
}

// udpTable 读一种地址族的 MIB_UDP*_ROW_OWNER_PID 表。
// v4 行 12 字节（Addr4/Port/PID），v6 行 28 字节（Addr16/ScopeId/Port/PID）；
// 端口与 TCP 表一样以网络序存在低 16 位，复用 ntohs 还原。
// PID 0 的行保留：通常是内核/驱动占用的绑定端点，对资产盘点是真实存在。
func udpTable(family uint32) ([]UDPEntry, error) {
	rowSize, portOff, pidOff := 12, 4, 8
	if family == afInet6 {
		rowSize, portOff, pidOff = 28, 20, 24
	}

	var size uint32
	ret, _, _ := procGetExtendedUdpTable.Call(0, uintptr(unsafe.Pointer(&size)), 0,
		uintptr(family), udpTableOwnerPID, 0)
	if ret != 0 && size == 0 {
		return nil, fmt.Errorf("GetExtendedUdpTable 获取长度失败: family=%d ret=%d", family, ret)
	}

	buf := make([]byte, size+1024)
	ret, _, _ = procGetExtendedUdpTable.Call(uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)), 0, uintptr(family), udpTableOwnerPID, 0)
	if ret != 0 {
		return nil, fmt.Errorf("GetExtendedUdpTable 失败: family=%d ret=%d", family, ret)
	}

	count := *(*uint32)(unsafe.Pointer(&buf[0]))
	if int(4+int(count)*rowSize) > len(buf) {
		return nil, fmt.Errorf("UDP 表长度异常: count=%d rowSize=%d", count, rowSize)
	}
	base := unsafe.Pointer(&buf[0])

	out := make([]UDPEntry, 0, count)
	for i := 0; i < int(count); i++ {
		row := unsafe.Add(base, 4+i*rowSize)
		out = append(out, UDPEntry{
			Port: ntohs(*(*uint32)(unsafe.Add(row, portOff))),
			PID:  *(*uint32)(unsafe.Add(row, pidOff)),
		})
	}
	return out, nil
}

// ---------------------------------------------------------------- 网卡

// AdapterInfo 是一块网卡的资产视图。
type AdapterInfo struct {
	Name      string
	MAC       string
	IPs       []string
	Gateway   string
	DNS       []string
	OperState string
}

// Adapters 枚举全部网卡（IPv4/IPv6 地址一次拿全）。
//
// GetAdaptersAddresses 的表在两次调用之间可能增长，缓冲溢出时按系统
// 给出的所需大小重试（上限 3 次，正常机器首轮 16KB 就够）。
func Adapters() ([]AdapterInfo, error) {
	buf, err := adapterTable()
	if err != nil {
		return nil, err
	}

	var out []AdapterInfo
	for aa := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0])); aa != nil; aa = aa.Next {
		ai := AdapterInfo{
			Name:      windows.UTF16PtrToString(aa.FriendlyName),
			OperState: ifOperStateName(aa.OperStatus),
			IPs:       []string{},
			DNS:       []string{},
		}
		if aa.PhysicalAddressLength > 0 {
			parts := make([]string, 0, int(aa.PhysicalAddressLength))
			for _, b := range aa.PhysicalAddress[:aa.PhysicalAddressLength] {
				parts = append(parts, fmt.Sprintf("%02x", b))
			}
			ai.MAC = strings.Join(parts, "-")
		}
		for u := aa.FirstUnicastAddress; u != nil; u = u.Next {
			if ip := u.Address.IP(); ip != nil {
				ai.IPs = append(ai.IPs, ip.String())
			}
		}
		// 网关通常只有一个；多网关并列时用逗号拼接，保序
		var gw []string
		for g := aa.FirstGatewayAddress; g != nil; g = g.Next {
			if ip := g.Address.IP(); ip != nil {
				gw = append(gw, ip.String())
			}
		}
		ai.Gateway = strings.Join(gw, ",")
		for d := aa.FirstDnsServerAddress; d != nil; d = d.Next {
			if ip := d.Address.IP(); ip != nil {
				ai.DNS = append(ai.DNS, ip.String())
			}
		}
		out = append(out, ai)
	}
	return out, nil
}

// adapterTable 调 GetAdaptersAddresses 取原始表缓冲。
func adapterTable() ([]byte, error) {
	buf := make([]byte, 16*1024)
	for try := 0; try < 3; try++ {
		size := uint32(len(buf))
		err := windows.GetAdaptersAddresses(afUnspec, gaaIncludeGateways|gaaSkipAnycast|gaaSkipMulticast,
			0, (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0])), &size)
		if err == nil {
			return buf, nil
		}
		if err != windows.ERROR_BUFFER_OVERFLOW {
			return nil, fmt.Errorf("GetAdaptersAddresses 失败: %w", err)
		}
		buf = make([]byte, size)
	}
	return nil, fmt.Errorf("GetAdaptersAddresses 缓冲区重试 3 次仍溢出")
}

// ifOperStateName 把 IfOperStatus 转成可读文本。
func ifOperStateName(v uint32) string {
	switch v {
	case windows.IfOperStatusUp:
		return "up"
	case windows.IfOperStatusDown:
		return "down"
	case windows.IfOperStatusTesting:
		return "testing"
	case windows.IfOperStatusUnknown:
		return "unknown"
	case windows.IfOperStatusDormant:
		return "dormant"
	case windows.IfOperStatusNotPresent:
		return "not_present"
	case windows.IfOperStatusLowerLayerDown:
		return "lower_layer_down"
	}
	return fmt.Sprintf("unknown_%d", v)
}

// ---------------------------------------------------------------- 服务

// ServiceInfo 是一个 Windows 服务的资产视图。
type ServiceInfo struct {
	Name        string
	DisplayName string
	State       string
	StartMode   string
	PathName    string
	Account     string
}

// svcStateNames 把 SERVICE_STATUS_PROCESS.dwCurrentState 转成可读文本。
var svcStateNames = map[uint32]string{
	1: "stopped", 2: "start_pending", 3: "stop_pending", 4: "running",
	5: "continue_pending", 6: "pause_pending", 7: "paused",
}

// svcStartModeNames 把 QUERY_SERVICE_CONFIG.dwStartType 转成可读文本。
var svcStartModeNames = map[uint32]string{
	0: "boot", 1: "system", 2: "auto", 3: "manual", 4: "disabled",
}

func svcStateName(v uint32) string {
	if n, ok := svcStateNames[v]; ok {
		return n
	}
	return fmt.Sprintf("state_%d", v)
}

func svcStartModeName(v uint32) string {
	if n, ok := svcStartModeNames[v]; ok {
		return n
	}
	return fmt.Sprintf("mode_%d", v)
}

// ServiceList 枚举全部普通服务（不含驱动）。
//
// EnumServicesStatusEx 一次拿名字 + 运行状态；PathName/Account/StartMode
// 需要逐个 QueryServiceConfig 补齐（见 enrichServiceConfigs 的并行化原因）。
// 单个服务查询失败（受保护服务等）不中断整体，三个字段留空——
// 枚举是 best-effort，列表完整性优先于单条完整性。
func ServiceList() ([]ServiceInfo, error) {
	h, _, callErr := procOpenSCManagerW.Call(0, 0, uintptr(scmConnect|scmEnumerate))
	if h == 0 {
		return nil, fmt.Errorf("OpenSCManager 失败: %v", callErr)
	}
	defer func() { _, _, _ = procCloseServiceHandle.Call(h) }()

	out := make([]ServiceInfo, 0, 256)
	buf := make([]byte, 64*1024) // 首轮 64KB，约可容 1100 条
	var resume uint32
	for {
		var needed, returned uint32
		ret, _, callErr := procEnumServicesStatusExW.Call(
			h, svcStatusInfo, svcWin32, svcStateAll,
			uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)),
			uintptr(unsafe.Pointer(&needed)), uintptr(unsafe.Pointer(&returned)),
			uintptr(unsafe.Pointer(&resume)), 0)
		if ret == 0 {
			if callErr != windows.ERROR_MORE_DATA {
				return nil, fmt.Errorf("EnumServicesStatusEx 失败: %v", callErr)
			}
			if int(needed) > len(buf) {
				buf = make([]byte, needed)
			}
		}
		if returned == 0 {
			break
		}

		// ENUM_SERVICE_STATUS_PROCESSW（x64）：两个指针 + SERVICE_STATUS_PROCESS(36B)，
		// 按最大对齐补到 56 字节；dwCurrentState 在第 3 个 DWORD。
		base := unsafe.Pointer(&buf[0])
		for i := 0; i < int(returned); i++ {
			entry := unsafe.Add(base, i*56)
			out = append(out, ServiceInfo{
				Name:        windows.UTF16PtrToString(*(**uint16)(entry)),
				DisplayName: windows.UTF16PtrToString(*(**uint16)(unsafe.Add(entry, 8))),
				State:       svcStateName(*(*uint32)(unsafe.Add(entry, 20))),
			})
		}
		if ret != 0 {
			break // 本批成功且没有 MORE_DATA，说明枚举完成
		}
	}
	enrichServiceConfigs(h, out)
	return out, nil
}

// enrichServiceConfigs 并行为每个服务补 PathName/Account/StartMode。
//
// 为什么并行：QueryServiceConfig 每条要走 OpenService→Query→Close 三次
// ALPC 往返，单线程实测约 0.45ms/条，几百条服务就会超过 <50ms 预算；
// 8 个 worker 把整段压回几十毫秒。纯读操作、条目分片互不重叠，无需加锁；
// append 阶段已结束，底层数组不再增长，切片并发安全。
func enrichServiceConfigs(scm uintptr, out []ServiceInfo) {
	const workers = 8
	n := len(out)
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		lo, hi := n*w/workers, n*(w+1)/workers
		if lo >= hi {
			continue
		}
		wg.Add(1)
		go func(lo, hi int) {
			defer wg.Done()
			for i := lo; i < hi; i++ {
				fillServiceConfig(scm, out[i].Name, &out[i])
			}
		}(lo, hi)
	}
	wg.Wait()
}

// fillServiceConfig 补 PathName/Account/StartMode（QUERY_SERVICE_CONFIGW）。
// 任何失败静默返回，字段留空：调用方按 best-effort 语义处理。
func fillServiceConfig(scm uintptr, name string, info *ServiceInfo) {
	namePtr, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return // 名字含 NUL 等异常情况，字段留空
	}
	hSvc, _, _ := procOpenServiceW.Call(scm, uintptr(unsafe.Pointer(namePtr)), svcQueryConfig)
	if hSvc == 0 {
		return
	}
	defer func() { _, _, _ = procCloseServiceHandle.Call(hSvc) }()

	var needed uint32
	ret, _, _ := procQueryServiceConfigW.Call(hSvc, 0, 0, uintptr(unsafe.Pointer(&needed)))
	if ret == 0 && needed == 0 {
		return
	}
	cfg := make([]byte, needed)
	ret, _, _ = procQueryServiceConfigW.Call(hSvc,
		uintptr(unsafe.Pointer(&cfg[0])), uintptr(needed), uintptr(unsafe.Pointer(&needed)))
	if ret == 0 {
		return
	}
	// QUERY_SERVICE_CONFIGW（x64）：3 个 DWORD + 补齐，随后 6 个指针。
	base := unsafe.Pointer(&cfg[0])
	info.PathName = windows.UTF16PtrToString(*(**uint16)(unsafe.Add(base, 16)))
	info.Account = windows.UTF16PtrToString(*(**uint16)(unsafe.Add(base, 48)))
	info.StartMode = svcStartModeName(*(*uint32)(unsafe.Add(base, 4)))
}

// ---------------------------------------------------------------- 计划任务

// TaskInfo 是一个计划任务的资产视图。
//
// 前三个字段来自文件级枚举（是否"已注册"）；后五个字段由任务定义 XML
// 补充（见 taskxml.go）。追加而非替换：既有消费方按 Path/Name/State
// 取值的契约不变，新字段解析失败时保持零值。
type TaskInfo struct {
	Path  string
	Name  string
	State string

	// 以下为 v0.9.8.1 追加的富字段（JSON 名与前端契约对齐）。
	Author   string        `json:"author"`
	Enabled  bool          `json:"enabled"`
	RunLevel string        `json:"run_level"`
	Triggers []TaskTrigger `json:"triggers"`
	Actions  []TaskAction  `json:"actions"`
}

// TaskList 枚举全部已注册计划任务。
//
// 直接复用 persist.go 的 enumerateScheduledTasks（同包内共享实现，
// 避免"两处各走一遍文件树"的成本与口径漂移）。State 固定 unknown：
// 计划任务的运行态需要 Task Scheduler COM 查询，成本与失败面都超出
// "便宜"纪律，文件级枚举只能证明"已注册"——语义缺口如实留白，
// 待有真实需求再评估 COM 路径（届时应改在 persist 侧抽公共实现）。
func TaskList() ([]TaskInfo, error) {
	items, err := enumerateScheduledTasks()
	if err != nil {
		return nil, err
	}

	// 富字段单独走一轮定义文件枚举，按统一命名口径（'\'+相对路径）join。
	// 不复用 enumerateScheduledTasks 内部的解析结果：那条路径为了基线稳定
	// 刻意"零值退化"，拿不到触发器的完整列表与启用状态；这里多走一次
	// 文件树是几十毫秒量级，换来的是字段语义完整。整轮枚举失败时只丢
	// 富字段，基础列表照常返回——资产节不能因为一个坏目录整体消失。
	details := taskXMLDetails()

	out := make([]TaskInfo, 0, len(items))
	for _, it := range items {
		// persist 侧的 Name 即完整任务路径（\Microsoft\Windows\...），叶子名自己截
		name := it.Name
		leaf := name
		if i := strings.LastIndexByte(name, '\\'); i >= 0 {
			leaf = name[i+1:]
		}
		ti := TaskInfo{
			Path:  name,
			Name:  leaf,
			State: "unknown",
			// 解析不到定义时按"启用"处理：文件级枚举只能证明任务已注册，
			// 把未知误报成"已禁用"会让资产页低估风险（与 persist 侧
			// 对全部计划任务置 Enabled=true 的口径一致）。
			Enabled: true,
		}
		if info := details[name]; info != nil {
			ti.Author = info.Author
			ti.Enabled = info.Enabled
			ti.RunLevel = info.RunLevel
			ti.Triggers = info.Triggers
			ti.Actions = info.Actions
		}
		out = append(out, ti)
	}
	return out, nil
}

// taskXMLDetails 建立"任务完整路径 → 解析结果"的索引。
//
// 坏文件（Err 非空）不进入索引：调用方保持零值富字段，与"解析失败的文件
// 跳过并计数"的契约一致（不在这里打日志——本包是纯采集层，日志由
// inventory 上报侧统一记录，避免每 30s 刷一遍同样的坏文件）。
func taskXMLDetails() map[string]*TaskXMLInfo {
	root := filepath.Join(os.Getenv("SystemRoot"), "System32", "Tasks")
	defs, err := EnumerateTaskXML(root)
	if err != nil {
		return nil
	}
	m := make(map[string]*TaskXMLInfo, len(defs))
	for _, d := range defs {
		if d.Err != nil || d.Info == nil {
			continue
		}
		m[d.Name] = d.Info
	}
	return m
}

// ---------------------------------------------------------------- 磁盘

// DiskInfo 是一个固定磁盘卷的容量视图。
type DiskInfo struct {
	Drive   string
	TotalMB uint64
	FreeMB  uint64
}

// DiskVolumes 枚举固定磁盘卷容量。
//
// 只统计 DRIVE_FIXED：可移动介质/光驱价值低，网络盘的容量探测可能秒级
// 阻塞，是"便宜"纪律明确要避开的。单卷查询失败（BitLocker 锁定等）
// 跳过该卷，不影响其他卷。FreeMB 取物理剩余（而非配额内可用），资产口径更直观。
func DiskVolumes() ([]DiskInfo, error) {
	mask, err := windows.GetLogicalDrives()
	if err != nil {
		return nil, fmt.Errorf("GetLogicalDrives 失败: %w", err)
	}

	const mb = 1024 * 1024
	var out []DiskInfo
	for i := 0; i < 26; i++ {
		if mask&(1<<uint(i)) == 0 {
			continue
		}
		drive := string(rune('A'+i)) + ":"
		root, err := windows.UTF16PtrFromString(drive + `\`)
		if err != nil {
			continue // 纯 ASCII 路径不可能失败，防御性跳过
		}
		typ, _, _ := procGetDriveTypeW.Call(uintptr(unsafe.Pointer(root)))
		if typ != driveFixed {
			continue
		}
		var quotaFree, total, physFree uint64
		ret, _, _ := procGetDiskFreeSpaceExW.Call(
			uintptr(unsafe.Pointer(root)),
			uintptr(unsafe.Pointer(&quotaFree)),
			uintptr(unsafe.Pointer(&total)),
			uintptr(unsafe.Pointer(&physFree)))
		if ret == 0 {
			continue
		}
		out = append(out, DiskInfo{
			Drive:   drive,
			TotalMB: total / mb,
			FreeMB:  physFree / mb,
		})
	}
	return out, nil
}

// ---------------------------------------------------------------- 内存 / CPU / 开机时间

// memoryStatusEx 对齐 MEMORYSTATUSEX（x/sys 未封装，自备结构）。
type memoryStatusEx struct {
	Length               uint32
	MemoryLoad           uint32
	TotalPhys            uint64
	AvailPhys            uint64
	TotalPageFile        uint64
	AvailPageFile        uint64
	TotalVirtual         uint64
	AvailVirtual         uint64
	AvailExtendedVirtual uint64
}

// MemoryStats 返回物理内存总量/剩余（MB）。
func MemoryStats() (totalMB uint64, freeMB uint64, err error) {
	var m memoryStatusEx
	m.Length = uint32(unsafe.Sizeof(m))
	ret, _, callErr := procGlobalMemoryStatusEx.Call(uintptr(unsafe.Pointer(&m)))
	if ret == 0 {
		return 0, 0, fmt.Errorf("GlobalMemoryStatusEx 失败: %v", callErr)
	}
	const mb = 1024 * 1024
	return m.TotalPhys / mb, m.AvailPhys / mb, nil
}

// systemInfoNative 对齐 SYSTEM_INFO（x64），只关心核数字段。
// 不用 x/sys 的 GetSystemInfo 封装是为了让结构布局由本包固定，
// 不随依赖版本的结构体字段增减漂移。
type systemInfoNative struct {
	Arch                      uint32
	PageSize                  uint32
	MinimumApplicationAddress uintptr
	MaximumApplicationAddress uintptr
	ActiveProcessorMask       uintptr
	NumberOfProcessors        uint32
	ProcessorType             uint32
	AllocationGranularity     uint32
	ProcessorLevel            uint16
	ProcessorRevision         uint16
}

// CPUInfo 返回 CPU 型号与逻辑核数。
//
// 型号只在注册表里有（HKLM\HARDWARE\DESCRIPTION\System\CentralProcessor\0，
// 读一个值）；GetSystemInfo 无返回值恒成功，失败面在注册表读取。
func CPUInfo() (name string, cores int, err error) {
	var si systemInfoNative
	_, _, _ = procGetSystemInfo.Call(uintptr(unsafe.Pointer(&si)))
	cores = int(si.NumberOfProcessors)
	if cores <= 0 {
		return "", 0, fmt.Errorf("GetSystemInfo 返回核数异常: %d", si.NumberOfProcessors)
	}

	k, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`HARDWARE\DESCRIPTION\System\CentralProcessor\0`, registry.QUERY_VALUE)
	if err != nil {
		return "", cores, fmt.Errorf("打开 CentralProcessor 注册表键失败: %w", err)
	}
	defer k.Close()

	name, _, err = k.GetStringValue("ProcessorNameString")
	if err != nil {
		return "", cores, fmt.Errorf("读取 ProcessorNameString 失败: %w", err)
	}
	return strings.TrimSpace(name), cores, nil
}

// BootTime 用 GetTickCount64 反推开机时间。
//
// 时间源与系统时钟独立，开机后用户改系统时钟会造成偏差——
// 资产盘点口径下可接受，不做 NTP 级校正。
func BootTime() (bootedAt time.Time, err error) {
	ms, _, _ := procGetTickCount64.Call()
	if ms == 0 {
		return time.Time{}, fmt.Errorf("GetTickCount64 返回 0，无法反推开机时间")
	}
	// tick 实际更新粒度约 15ms，秒级对齐足够且便于跨周期比较
	return time.Now().Add(-time.Duration(ms) * time.Millisecond).Truncate(time.Second), nil
}
