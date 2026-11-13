//go:build windows
// +build windows

package winapi

// netinfo.go：ARP 表 / IPv4 路由表 / DNS 解析缓存（只读快照）。
//
// 采集定位：横向移动画像的基础面——谁在 ARP/路由层可达、本机最近解析过
// 哪些域名（C2 域名回连前必然先过本机缓存）。全部是快照式读取，
// 无句柄、无订阅、无释放义务。
//
// 为什么 DNS 缓存用未文档化的 DnsGetCacheDataTable：这是 Windows 上
// 唯一不需要服务端提权/COM/WMI 就能拿到解析缓存的导出接口
// （Get-DnsClientCache 底层也是它）。它不在 SDK 文档里但 dnsapi.dll
// 按名字导出，头部 5 字段布局多年稳定；union Data 布局未文档化，
// 因此 Data 解析全部经 ReadProcessMemory 自校验，读不动就留空，
// 绝不让坏偏移变成野指针解引用（见 dnsEntryData 注释）。

import (
	"fmt"
	"net"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modDnsapi = windows.NewLazySystemDLL("dnsapi.dll")

	procGetIpNetTable        = modIphlpapi.NewProc("GetIpNetTable")
	procGetIpForwardTable    = modIphlpapi.NewProc("GetIpForwardTable")
	procDnsGetCacheDataTable = modDnsapi.NewProc("DnsGetCacheDataTable")
	procReadProcessMemory    = modKernel32.NewProc("ReadProcessMemory")
)

const (
	// Windows 套接字错误码（winerror.h）。
	errInsufficientBuffer = 122
	errNoData             = 232
)

// ---------------------------------------------------------------- ARP 表

// ArpEntry 是一条 ARP/邻居缓存记录。
type ArpEntry struct {
	IP      string
	MAC     string // aa:bb:cc:dd:ee:ff；长度异常时留空
	IfIndex uint32
	State   string // MIB_IPNET_TYPE 可读名，越界给 unknown_N
}

// arpTypeNames 按 MIB_IPNET_TYPE 真实枚举值映射。
// 为什么不用需求口径的 1-7（broken/probing/incomplete/...）：那组名字
// 属于 GetIpNetTable2 的 NL_NEIGHBOR_STATE（且真实顺序也不是这样），
// 而这里明确用 GetIpNetTable，其 dwType 语义是 MIB_IPNET_TYPE
// （1 other / 2 invalid / 3 dynamic / 4 static）。按错误口径命名会把
// 普通 dynamic 邻居标成 "reachable"，直接误导横向移动判定。
var arpTypeNames = map[uint32]string{
	1: "other",
	2: "invalid",
	3: "dynamic",
	4: "static",
}

func arpTypeName(t uint32) string {
	if n, ok := arpTypeNames[t]; ok {
		return n
	}
	return fmt.Sprintf("unknown_%d", t)
}

// ArpTable 一次快照读取全系统 IPv4 ARP/邻居表（按 IP 排序返回）。
// 表 0 条（如刚清过缓存）返回空切片而不是错误；API 失败才是 error。
func ArpTable() ([]ArpEntry, error) {
	// 先给足缓冲一次到位：1024 条 × 24B ≈ 24KB，ARP 表正常远小于此；
	// 不走"NULL 探长度"两段式是因为该 API 对 NULL 缓冲的返回码在
	// 文档里含糊（可能直接 ERROR_NO_DATA），一次给足更可控。
	size := uint32(4 + 1024*24)
	buf := make([]byte, size)
	ret, _, _ := procGetIpNetTable.Call(
		uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 1)
	if ret == errInsufficientBuffer {
		// size 已被回填为所需字节数，扩容重试一次
		buf = make([]byte, size+64)
		ret, _, _ = procGetIpNetTable.Call(
			uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 1)
	}
	if ret == errNoData {
		return nil, nil // 表空不是错误
	}
	if ret != 0 {
		return nil, fmt.Errorf("GetIpNetTable 失败: errno=%d", ret)
	}

	count := *(*uint32)(unsafe.Pointer(&buf[0]))
	const rowSize = 24 // MIB_IPNETROW：dwIndex/dwPhysAddrLen/bPhysAddr[8]/dwAddr/dwType
	if int(4+count*rowSize) > len(buf) {
		return nil, fmt.Errorf("ARP 表长度异常: entries=%d buf=%d", count, len(buf))
	}
	base := unsafe.Pointer(&buf[0])

	out := make([]ArpEntry, 0, count)
	for i := 0; i < int(count); i++ {
		row := (*[6]uint32)(unsafe.Add(base, 4+i*rowSize))
		// row[0]=dwIndex, row[1]=dwPhysAddrLen, row[2..3]=bPhysAddr[8],
		// row[4]=dwAddr（网络字节序，与 network.go 同口径转点分）,
		// row[5]=dwType
		macLen := row[1]
		if macLen > 8 {
			macLen = 8
		}
		mac := ""
		if macLen > 0 {
			raw := (*[8]byte)(unsafe.Pointer(&row[2]))[:macLen:macLen]
			mac = fmt.Sprintf("%02x", raw[0])
			for _, b := range raw[1:] {
				mac += fmt.Sprintf(":%02x", b)
			}
		}
		out = append(out, ArpEntry{
			IP:      uint32ToIP(row[4]),
			MAC:     mac,
			IfIndex: row[0],
			State:   arpTypeName(row[5]),
		})
	}
	return out, nil
}

// ---------------------------------------------------------------- 路由表

// RouteEntry 是一条 IPv4 路由。
type RouteEntry struct {
	Dest    string
	Mask    string
	Gateway string // 0.0.0.0 = on-link（直连）
	IfIndex uint32
	Metric  int32 // dwForwardMetric1
}

// ipForwardRow 对应 MIB_IPFORWARDROW：14 个连续 DWORD，无对齐填充，
// x86/x64 布局一致（每行 56 字节）。
type ipForwardRow struct {
	Dest      uint32 // dwForwardDest（网络字节序）
	Mask      uint32 // dwForwardMask
	Policy    uint32 // dwForwardPolicy（DSCP/策略路由，未消费）
	NextHop   uint32 // dwForwardNextHop
	IfIndex   uint32 // dwForwardIfIndex
	Type      uint32 // dwForwardType
	Proto     uint32 // dwForwardProto
	Age       uint32 // dwForwardAge
	NextHopAS uint32 // dwForwardNextHopAS
	Metric1   uint32
	Metric2   uint32
	Metric3   uint32
	Metric4   uint32
	Metric5   uint32
}

// RouteTable 一次快照读取全系统 IPv4 路由表（按目的地址排序返回）。
// 表 0 条不是错误；API 失败才是 error。
func RouteTable() ([]RouteEntry, error) {
	size := uint32(4 + 1024*56)
	buf := make([]byte, size)
	ret, _, _ := procGetIpForwardTable.Call(
		uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 1)
	if ret == errInsufficientBuffer {
		buf = make([]byte, size+64)
		ret, _, _ = procGetIpForwardTable.Call(
			uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 1)
	}
	if ret == errNoData {
		return nil, nil
	}
	if ret != 0 {
		return nil, fmt.Errorf("GetIpForwardTable 失败: errno=%d", ret)
	}

	count := *(*uint32)(unsafe.Pointer(&buf[0]))
	const rowSize = 56
	if int(4+count*rowSize) > len(buf) {
		return nil, fmt.Errorf("路由表长度异常: entries=%d buf=%d", count, len(buf))
	}
	base := unsafe.Pointer(&buf[0])

	out := make([]RouteEntry, 0, count)
	for i := 0; i < int(count); i++ {
		row := (*ipForwardRow)(unsafe.Add(base, 4+i*rowSize))
		out = append(out, RouteEntry{
			Dest:    uint32ToIP(row.Dest),
			Mask:    uint32ToIP(row.Mask),
			Gateway: uint32ToIP(row.NextHop),
			IfIndex: row.IfIndex,
			Metric:  int32(row.Metric1),
		})
	}
	return out, nil
}

// ---------------------------------------------------------------- DNS 缓存

// dnsTypeName 按 RFC 1035/3596 记录类型映射（需求口径），其他给 T_N。
var dnsTypeNames = map[uint16]string{
	1:  "A",
	28: "AAAA",
	5:  "CNAME",
	12: "PTR",
	16: "TXT",
	33: "SRV",
}

func dnsTypeName(t uint16) string {
	if n, ok := dnsTypeNames[t]; ok {
		return n
	}
	return fmt.Sprintf("T_%d", t)
}

// DnsCacheEntry 是一条 DNS 解析缓存记录。
type DnsCacheEntry struct {
	Name string
	Type string // A/AAAA/CNAME/PTR/TXT/SRV，其他 T_N
	Data string // 解析值；解析不出（布局异常/类型不支持）留空
	TTL  uint32 // 见下方"TTL 为什么恒 0"
}

// dnsCacheEntry 对应 DNS_CACHE_ENTRY 的头部 5 字段（windns.h 口径，
// 这部分布局稳定且有大量公开实现背书）。x64：pNext@0 pszName@8
// wType@16 wDataLength@18 dwFlags@20，union Data 文档口径里紧随其后 @24。
//
// 真机实测（2026-11-09，Windows Server 20348 x64）：条目分配只有 24 字节
// 头部本身——@24 起就是下一个堆块的分配头（固定 magic 'LMEM' +
// 长度 0x18），且全部条目 wDataLength 恒为 0。即这个 API 在该版本上
// 只给 Name+Type：记录数据不在条目里，也没有指向它的指针字段。
// 因此 Data 在实测环境恒为空（dnsEntryData 的解析分支全部被
// wDataLength=0 拦下）；要拿 Data 得改成逐条 DnsQuery_W(cache-only)
// 的 N 次查询设计，超出本文件"一次遍历快照"的定位，未实施。
//
// TTL 为什么恒 0：头部 5 字段里没有 TTL，Get-DnsClientCache 的 TTL
// 来自内部更深结构，偏移未文档化也未核实。按"查不到就写未核实、
// 不许猜测"的仓库纪律，诚实给 0 而不是编一个偏移去猜；
// Name+Type 已足够识别 C2 域名线索。
type dnsCacheEntry struct {
	Next       *dnsCacheEntry
	Name       *uint16
	Type       uint16
	DataLength uint16
	Flags      uint32
}

// dnsDataOffset 是 union Data 相对条目起始的偏移（x64）。
const dnsDataOffset = 24

// dnsMaxEntries 防环上限：缓存正常几十到几百条；链表是 dnsapi 内部
// 数据结构，理论上可能因为并发淘汰出现环，不设上限就是死循环。
const dnsMaxEntries = 512

// DnsCache 读取 Windows DNS 解析缓存（dnsapi DnsGetCacheDataTable）。
// 缓存空返回空切片；调用失败才是 error。
//
// 不做 free：条目缓冲由 dnsapi 持有，没有导出的逐条释放接口，公开实现
// 一律不释放（KB 级、进程生命周期一次性按需调用）。缓存是活数据，
// 遍历期间可能被 dnsapi 并发淘汰——这是所有公开实现共同接受的固有
// 竞态；本函数快速遍历、立即拷贝字符串、不驻留句柄，把窗口压到最小。
func DnsCache() ([]DnsCacheEntry, error) {
	var first *dnsCacheEntry
	ret, _, _ := procDnsGetCacheDataTable.Call(uintptr(unsafe.Pointer(&first)))
	if ret == 0 {
		return nil, fmt.Errorf("DnsGetCacheDataTable 失败")
	}
	if first == nil {
		return nil, nil
	}

	out := make([]DnsCacheEntry, 0, 64)
	for e := first; e != nil && len(out) < dnsMaxEntries; e = e.Next {
		out = append(out, DnsCacheEntry{
			Name: utf16PtrToStr(e.Name),
			Type: dnsTypeName(e.Type),
			Data: dnsEntryData(e),
			TTL:  0, // 未核实到稳定偏移，诚实留 0（见 DnsCacheEntry 注释）
		})
	}
	return out, nil
}

// dnsEntryData 解析 union Data（条目起始偏移 24 起）。
//
// 布局诚实声明：windns.h 只给出前 5 字段，union Data 从未文档化；
// 且实测（20348，见 dnsCacheEntry 注释）条目分配只有 24 字节头部、
// wDataLength 恒 0，所以本函数在实测环境所有分支都会被 wDataLength
// 门槛拦下、恒返回 ""。解析分支仍然保留：万一其他版本真的内联数据
// 且回填了 wDataLength，这里能直接出结果。所有读取一律经 dnsSafeRead
// （ReadProcessMemory 自校验）——偏移一旦失效读到的是内部字段或相邻
// 堆块，安全读让它降级为"留空"而不是野指针解引用让进程直接 AV。
// Name+Type 恒可用，Data 缺失只损失细节不损失线索。
func dnsEntryData(e *dnsCacheEntry) string {
	if e == nil {
		return ""
	}
	base := uintptr(unsafe.Pointer(e))
	switch e.Type {
	case 1: // A：DNS_A_DATA { IP4_ADDRESS IpAddress; }
		if e.DataLength < 4 {
			return ""
		}
		b, ok := dnsSafeRead(base+dnsDataOffset, 4)
		if !ok {
			return ""
		}
		return net.IPv4(b[0], b[1], b[2], b[3]).String()
	case 28: // AAAA：DNS_AAAA_DATA { IP6_ADDRESS IpAddress; } 16 字节
		if e.DataLength < 16 {
			return ""
		}
		b, ok := dnsSafeRead(base+dnsDataOffset, 16)
		if !ok {
			return ""
		}
		return net.IP(b).String()
	case 5, 12, 33: // CNAME/PTR：pNameHost；SRV：pNameTarget——都是 union+0 的 PWSTR
		if e.DataLength < 8 {
			return ""
		}
		b, ok := dnsSafeRead(base+dnsDataOffset, 8)
		if !ok {
			return ""
		}
		return dnsReadUTF16At(*(*uintptr)(unsafe.Pointer(&b[0])))
	case 16: // TXT：DNS_TXT_DATA { DWORD dwStringCount; PWSTR pStringArray[1]; }
		// 数组在 8 字节对齐处，取第一条串
		if e.DataLength < 16 {
			return ""
		}
		b, ok := dnsSafeRead(base+dnsDataOffset, 16)
		if !ok {
			return ""
		}
		if *(*uint32)(unsafe.Pointer(&b[0])) == 0 {
			return ""
		}
		return dnsReadUTF16At(*(*uintptr)(unsafe.Pointer(&b[8])))
	}
	return "" // 其他类型按口径留空
}

// dnsSafeRead 从自身进程地址空间安全读 size 字节。
//
// 为什么不用直接解引用：union 偏移未文档化，一旦读到非法地址，
// 直接解引用是不可恢复的 AV（整个探针进程挂掉）；ReadProcessMemory
// 对坏地址只是返回失败（内核 MmCopyVirtualMemory 校验），把
// "布局认知失效"从崩溃降级成 Data 留空。伪句柄读自身，开销每条几微秒。
func dnsSafeRead(addr uintptr, size int) ([]byte, bool) {
	if addr < 0x10000 || addr > 1<<47 {
		return nil, false // 用户态指针合理区间外的值一律不碰
	}
	buf := make([]byte, size)
	var got uintptr
	ret, _, _ := procReadProcessMemory.Call(
		uintptr(windows.CurrentProcess()), addr,
		uintptr(unsafe.Pointer(&buf[0])), uintptr(size),
		uintptr(unsafe.Pointer(&got)))
	if ret == 0 || got != uintptr(size) {
		return nil, false
	}
	return buf, true
}

// dnsReadUTF16At 安全读取一个 NUL 结尾的 UTF16 串（DNS 域名上限 255
// 字节，读 512 字节封顶）。目标串由 dnsapi 堆持有，与缓存条目同生命周期。
func dnsReadUTF16At(p uintptr) string {
	if p == 0 {
		return ""
	}
	raw, ok := dnsSafeRead(p, 512)
	if !ok {
		return ""
	}
	u16 := unsafe.Slice((*uint16)(unsafe.Pointer(&raw[0])), 256)
	return windows.UTF16ToString(u16) // 遇 NUL 自然截断
}

// utf16PtrToStr 从 *uint16 读 NUL 结尾串（pszName）。
// DNS 全名 ≤255 字符，256 单位封顶扫描，不做无界扫（防坏指针拖长读距）。
func utf16PtrToStr(p *uint16) string {
	if p == nil {
		return ""
	}
	buf := unsafe.Slice(p, 256)
	n := 0
	for n < len(buf) && buf[n] != 0 {
		n++
	}
	return windows.UTF16ToString(buf[:n])
}
