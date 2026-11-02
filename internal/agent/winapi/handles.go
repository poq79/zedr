package winapi

// handles.go：系统句柄表枚举、对象类型名缓存、句柄名解析、盘符→设备路径映射。
//
// 数据源是 NtQuerySystemInformation(SystemExtendedHandleInformation=64)：一次
// 系统调用拿到全系统"对象 + 属主 PID + 句柄值 + 类型索引"四元组，供 liveapi
// /handles（单进程句柄列表）与 /handleowners（谁打开了这个文件）使用。
//
// 为什么不用 EnumProcessHandles 之类的公开 API：Win32 没有跨进程枚举句柄的
// 接口，只有内核态的 NtQuerySystemInformation 能给出全量表；对象名称还必须
// DuplicateHandle 到本进程后用 NtQueryObject 查询（对象名属于内核对象，不能
// 直接读目标进程内存拿到）。
//
// 已知限制（必须如实向调用方传达）：
//   - 打开目标进程需要 PROCESS_DUP_HANDLE，受保护进程（PPL/System）拿不到，
//     这类进程的句柄只能给类型索引，给不出名称；
//   - NtQueryObject(ObjectNameInformation) 在坏网络文件/同步设备句柄上会
//     无限期阻塞（Process Explorer 同样受此限制），因此名称解析放在独立
//     goroutine 里跑，300ms 不返回就放弃。放弃时**故意不关闭已复制的句柄、
//     也不回收 goroutine**：NtQueryObject 仍在用该句柄，关闭会造成句柄值复用
//     竞态（可能读到别的对象名甚至崩溃）。代价是极端情况下泄漏一个句柄与一个
//     goroutine，这与 Process Explorer 的既有取舍一致；
//   - ObjectTypeIndex 在一次开机内稳定，但跨重启可能变化，所以类型名缓存只在
//     探针进程生命周期内有效（进程内缓存，不落盘）。

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// procNtQueryObject 是对象名称/类型查询的唯一切入点。ntdll 未在 x/sys 中
// 导出，只能动态取址。
var procNtQueryObject = modNtdll.NewProc("NtQueryObject")

const (
	// systemExtendedHandleInformation 是 SYSTEM_INFORMATION_CLASS 的
	// SystemExtendedHandleInformation 取值（Vista+）。
	systemExtendedHandleInformation = 64

	// processDupHandle 是 PROCESS_DUP_HANDLE；跨进程复制句柄的最小权限。
	processDupHandle = 0x0040

	// duplicateSameAccess 对应 DUPLICATE_SAME_ACCESS。
	duplicateSameAccess = 0x00000002

	// OBJECT_INFORMATION_CLASS
	objectNameInformation = 1
	objectTypeInformation = 2

	// statusBufferOverflow：NtQueryObject 在缓冲不够时仍返回了截断数据，
	// 属于"可用但不完整"，按成功处理（长度字段会小于真实值）。
	statusBufferOverflow = 0x80000005

	// handleNameTimeout 是单个对象名解析的上限。取 300ms 的依据：正常对象
	// 名称查询是微秒级，超过 300ms 基本只剩"坏网络文件/同步设备"这一类
	// 会永久阻塞的句柄，继续等没有意义（契约 §15.1 同一口径）。
	handleNameTimeout = 300 * time.Millisecond

	// handleListDefaultLimit / handleListMaxLimit 与契约 §15.1 对齐：
	// 默认 1000，上限 5000（前端一次渲染的合理上限，再大也看不过来）。
	handleListDefaultLimit = 1000
	handleListMaxLimit     = 5000

	// handleNameBudget 是 /handles 整请求的名称解析预算（契约 §15.1 "整请求
	// ≤2s，超出 truncated"）。句柄表枚举本身是毫秒级，预算只花在名称上。
	handleNameBudget = 2 * time.Second

	// handleOwnersBudget 是 /handleowners 全系统扫描预算（契约 §15.2 5s）。
	// 全系统 File 句柄可能上千，逐个 300ms 上限不现实，靠总预算兜底。
	handleOwnersBudget = 5 * time.Second

	// typeResolveMaxAttempts：同一类型索引在**单次扫描**里最多尝试几次
	// 类型名解析。不缓存失败结果（否则第一个受保护进程的失败会让后续所有
	// 可访问进程的同类句柄都显示 Type#N），改为每次扫描重试有限次数。
	typeResolveMaxAttempts = 6

	// maxHandleTableBytes 防止内核返回异常长度时做出超大分配（全系统句柄
	// 表在服务器上可达数百万条，40B/条 ≈ 40MB，256MB 留足余量）。
	maxHandleTableBytes = 256 << 20
)

// sysHandleEntry 是 SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX 的 Go 映射。
//
// 64 位布局：Object(8) UniqueProcessId(8) HandleValue(8) GrantedAccess(4)
// CreatorBackTraceIndex(2) ObjectTypeIndex(2) HandleAttributes(4) Reserved(4)
// = 40 字节；32 位下 uintptr 收窄为 4 字节，总长 28 字节。用 uintptr 声明
// 而不是固定 uint64，让 wOw64 场景下 unsafe.Sizeof 自动给出正确跨度。
type sysHandleEntry struct {
	Object                uintptr
	UniqueProcessID       uintptr
	HandleValue           uintptr
	GrantedAccess         uint32
	CreatorBackTraceIndex uint16
	ObjectTypeIndex       uint16
	HandleAttributes      uint32
	Reserved              uint32
}

// HandleRow 是 /handles 的线协议行（契约 §15.1 items 元素）。
// Value 用 uint64：句柄值本质是 32 位，但 JSON number 用 uint64 避免
// 前端在 32/64 位间做有符号解析。
type HandleRow struct {
	Value uint64 `json:"value"`
	Type  string `json:"type"`
	Name  string `json:"name"`
}

// HandleList 是一次单进程句柄枚举的完整结果（含覆盖度统计）。
//
// 为什么返回结构体而不是裸 []HandleRow：/handles 的 note 必须如实说明
// "名称解析了多少、有没有被预算截断"，裸切片会把这些信息丢掉。
type HandleList struct {
	Rows      []HandleRow    // 已按 typeFilter 过滤并截断到 limit
	Types     map[string]int // 过滤后全量类型直方图（截断前）
	Total     int            // 过滤后的句柄总数（截断前）
	Truncated bool           // Total > limit，列表被截断
	// NameAttempted/NameResolved 只统计安全类型且访问权限非 0 的句柄；
	// NameBudgetHit 表示预算耗尽导致后续行 name 为空（缩短每次 300ms 上限
	// 没有意义，直接停下比给半截数据更诚实）。
	NameAttempted int
	NameResolved  int
	NameBudgetHit bool
	// ProcessOpened 表示目标进程能否以 PROCESS_DUP_HANDLE 打开（句柄名称
	// 解析的前提）。false 时名称全空，且这不是"超时"而是"权限不足"，
	// note 必须区分这两种情况。
	ProcessOpened bool
	// UnresolvedTypes 是类型名没能解析（显示为 Type#N）的句柄数。它们不影响
	// 列表展示，但意味着 type 过滤可能不精确。
	UnresolvedTypes int
}

// SysHandle 是全系统扫描（/handleowners）命中的一条句柄。
type SysHandle struct {
	PID   uint32 `json:"pid"`
	Value uint64 `json:"value"`
	Type  string `json:"type"`
	Name  string `json:"name"`
}

// FileHandleScan 是全系统 File 句柄扫描的结果。
type FileHandleScan struct {
	Handles         []SysHandle // 已解析出名称的 File 句柄
	TotalHandles    int         // 系统句柄表条目总数（诊断覆盖度）
	FileScanned     int         // 实际检查过的 File 类型句柄数
	Resolved        int         // 其中名称解析成功的数量
	Truncated       bool        // 预算耗尽，扫描提前结束
	UnresolvedTypes int         // 类型名未解析的句柄数
}

// ---------------------------------------------------------------- 类型名缓存

var (
	typeNameMu    sync.RWMutex
	typeNameCache = map[uint16]string{}
)

func cachedTypeName(index uint16) (string, bool) {
	typeNameMu.RLock()
	name, ok := typeNameCache[index]
	typeNameMu.RUnlock()
	return name, ok
}

func storeTypeName(index uint16, name string) {
	typeNameMu.Lock()
	typeNameCache[index] = name
	typeNameMu.Unlock()
}

// cachedTypeNameCount 仅供单测断言"缓存确实建立"。
func cachedTypeNameCount() int {
	typeNameMu.RLock()
	n := len(typeNameCache)
	typeNameMu.RUnlock()
	return n
}

// ---------------------------------------------------------------- 进程句柄缓存

// dupSourceCache 在一次扫描内缓存"目标 PID → 可复制句柄的进程句柄"。
//
// 为什么需要：全系统扫描时同一条目所属 PID 会反复出现（一个进程几百个
// 句柄），每个句柄都 OpenProcess 一次既慢又浪费句柄配额；失败结果也缓存，
// 避免对几百个受保护句柄反复撞 ACCESS_DENIED。
type dupSourceCache struct {
	handles map[uint32]windows.Handle
	failed  map[uint32]bool
}

func newDupSourceCache() *dupSourceCache {
	return &dupSourceCache{
		handles: make(map[uint32]windows.Handle, 64),
		failed:  make(map[uint32]bool, 64),
	}
}

func (c *dupSourceCache) get(pid uint32) (windows.Handle, bool) {
	// PID 0 不是真实进程；PID 4 是 System，用户态永远拿不到
	// PROCESS_DUP_HANDLE，直接归入失败避免无谓调用。
	if pid == 0 || pid == 4 {
		return 0, false
	}
	if h, ok := c.handles[pid]; ok {
		return h, true
	}
	if c.failed[pid] {
		return 0, false
	}
	h, err := openProcess(pid, processDupHandle)
	if err != nil {
		c.failed[pid] = true
		return 0, false
	}
	c.handles[pid] = h
	return h, true
}

func (c *dupSourceCache) closeAll() {
	for _, h := range c.handles {
		closeHandle(h)
	}
	c.handles = nil
	c.failed = nil
}

// ---------------------------------------------------------------- 句柄表查询

// queryHandleTable 读取全系统扩展句柄表。
//
// 两次调用模式与 netproc/netstat 一致：先拿 STATUS_INFO_LENGTH_MISMATCH
// 返回的所需长度，再按"所需 + 25%"重试（句柄表在两次调用之间仍会增长，
// 留余量比精确分配少一轮重试）。真实调用偶发仍不够时继续重试，最多 5 轮。
func queryHandleTable() ([]sysHandleEntry, error) {
	size := uintptr(1 << 20)
	for attempt := 0; attempt < 5; attempt++ {
		if size > maxHandleTableBytes {
			return nil, fmt.Errorf("句柄表所需缓冲异常: %d 字节", size)
		}
		buf := make([]byte, size)
		var retLen uint32
		status, _, _ := procNtQuerySystemInformation.Call(
			systemExtendedHandleInformation,
			uintptr(unsafe.Pointer(&buf[0])),
			size,
			uintptr(unsafe.Pointer(&retLen)),
		)
		if uint32(status) == statusInfoLengthMismatch {
			if retLen > 0 {
				size = uintptr(retLen) + uintptr(retLen)/4
			} else {
				size *= 2
			}
			continue
		}
		if status != 0 {
			return nil, fmt.Errorf("NtQuerySystemInformation(SystemExtendedHandleInformation) 失败: status=0x%x", uint32(status))
		}
		return parseHandleTable(buf), nil
	}
	return nil, fmt.Errorf("句柄表缓冲区多次不足，放弃")
}

// parseHandleTable 解析 SYSTEM_HANDLE_INFORMATION_EX：
//
//	{ ULONG_PTR NumberOfHandles; ULONG_PTR Reserved; Entry Handles[]; }
//
// 计数与缓冲不一致时按缓冲能容纳的条数截断，绝不越界读。
func parseHandleTable(buf []byte) []sysHandleEntry {
	headerSize := unsafe.Sizeof(uintptr(0)) * 2
	entrySize := unsafe.Sizeof(sysHandleEntry{})
	if uintptr(len(buf)) < headerSize+entrySize {
		return nil
	}
	count := *(*uintptr)(unsafe.Pointer(&buf[0]))
	if count == 0 {
		return nil
	}
	maxCount := (uintptr(len(buf)) - headerSize) / entrySize
	if count > maxCount {
		count = maxCount
	}

	base := unsafe.Pointer(&buf[0])
	out := make([]sysHandleEntry, 0, count)
	for i := uintptr(0); i < count; i++ {
		e := (*sysHandleEntry)(unsafe.Add(base, headerSize+i*entrySize))
		out = append(out, *e)
	}
	return out
}

// ---------------------------------------------------------------- 类型名解析

// typeNameResolver 在一次扫描内解析 ObjectTypeIndex → 类型名。
//
// 成功结果进全局缓存（类型索引开机内稳定）；失败只在本次扫描内记
// Type#N，并允许换一个进程重试，避免第一个受保护进程把整类句柄带偏。
type typeNameResolver struct {
	sources  *dupSourceCache
	attempts map[uint16]int
	fallback map[uint16]string
}

func newTypeNameResolver(sources *dupSourceCache) *typeNameResolver {
	return &typeNameResolver{
		sources:  sources,
		attempts: map[uint16]int{},
		fallback: map[uint16]string{},
	}
}

// seedSelf 用本进程的句柄预热类型名缓存（每种类型索引只取第一个样本）。
//
// 为什么必须预热：类型索引是系统级的，但"能不能 DuplicateHandle"取决于
// 目标进程权限。全系统扫描按句柄表顺序前进时，某个类型的前几个条目可能全
// 属于 SYSTEM/受保护进程，连续失败会把该类型记成 Type#N，进而导致 File
// 整类被跳过——实测首次 /handleowners 出现 scanned=0。本进程的句柄永远
// 可复制，用它预热最可靠；预热后即使目标进程打不开，类型名依旧正确。
func (r *typeNameResolver) seedSelf(entries []sysHandleEntry) {
	self := uint32(os.Getpid())
	seen := make(map[uint16]bool, 16)
	for i := range entries {
		e := &entries[i]
		if uint32(e.UniqueProcessID) != self || seen[e.ObjectTypeIndex] {
			continue
		}
		seen[e.ObjectTypeIndex] = true
		r.name(e.ObjectTypeIndex, self, e.HandleValue)
	}
}

func (r *typeNameResolver) name(index uint16, pid uint32, handle uintptr) string {
	if n, ok := cachedTypeName(index); ok {
		return n
	}
	fallbackName := fmt.Sprintf("Type#%d", index)
	if r.attempts[index] >= typeResolveMaxAttempts {
		return fallbackName
	}
	r.attempts[index]++

	hProc, ok := r.sources.get(pid)
	if !ok || handle == 0 {
		r.fallback[index] = fallbackName
		return fallbackName
	}
	self, err := windows.GetCurrentProcess()
	if err != nil {
		return fallbackName
	}
	var dup windows.Handle
	if err := windows.DuplicateHandle(hProc, windows.Handle(handle), self,
		&dup, 0, false, duplicateSameAccess); err != nil {
		if f, ok := r.fallback[index]; ok {
			return f
		}
		return fallbackName
	}
	// ObjectTypeInformation 只读对象类型元数据，不触碰设备/网络，不会像
	// ObjectNameInformation 那样阻塞，可以同步调用。
	name, ok := queryObjectString(dup, objectTypeInformation)
	closeHandle(dup)
	if !ok || name == "" {
		r.fallback[index] = fallbackName
		return fallbackName
	}
	storeTypeName(index, name)
	return name
}

// ---------------------------------------------------------------- 名称解析

// safeHandleTypes 是允许查询对象名的类型白名单。
//
// 为什么只查这几类：File/Directory/Key/Section/Mutant/Semaphore/SymbolicLink
// 的名称是调查价值最高的（文件占用、注册表键、节对象、互斥体），且
// NtQueryObject 对它们的行为可预期。Process/Thread/Token 等类型不查——
// 名称要么无意义，要么查询本身会触碰敏感路径。
var safeHandleTypes = map[string]struct{}{
	"File":         {},
	"Directory":    {},
	"Key":          {},
	"Section":      {},
	"Mutant":       {},
	"Semaphore":    {},
	"SymbolicLink": {},
}

func isSafeHandleType(t string) bool {
	_, ok := safeHandleTypes[t]
	return ok
}

// resolveHandleName 解析单个句柄的对象名（独立入口，单次开进程）。
//
// 枚举路径不要直接调用它——那会为每个句柄 OpenProcess 一次；用
// resolveHandleNameWithProc 复用已打开的进程句柄。
func resolveHandleName(pid uint32, handle uintptr, typeName string) (string, bool) {
	if handle == 0 || !isSafeHandleType(typeName) {
		return "", false
	}
	hProc, err := openProcess(pid, processDupHandle)
	if err != nil {
		return "", false
	}
	defer closeHandle(hProc)
	return resolveHandleNameWithProc(hProc, handle, handleNameTimeout)
}

// resolveHandleNameWithProc 把句柄复制到本进程，再在 goroutine 里查询名称。
//
// 超时语义见文件头注释：放弃时故意泄漏 dup 句柄与 goroutine，换取"不会
// 在 NtQueryObject 仍在使用句柄时关闭它"的安全性。调用方必须把 handle 的
// 访问权限为 0 的条目提前跳过——`GrantedAccess == 0` 的句柄 DuplicateHandle
// 能成功但 NtQueryObject 必然 ACCESS_DENIED，纯属浪费一次 300ms 预算。
func resolveHandleNameWithProc(hProc windows.Handle, handle uintptr, timeout time.Duration) (string, bool) {
	if hProc == 0 || handle == 0 || timeout <= 0 {
		return "", false
	}
	self, err := windows.GetCurrentProcess()
	if err != nil {
		return "", false
	}
	var dup windows.Handle
	if err := windows.DuplicateHandle(hProc, windows.Handle(handle), self,
		&dup, 0, false, duplicateSameAccess); err != nil {
		return "", false
	}

	type nameResult struct {
		name string
		ok   bool
	}
	// 带缓冲的 channel：超时后 goroutine 若最终返回，可以无阻塞写入并退出，
	// 不会因为没人接收而永久阻塞（虽然句柄/缓冲仍被它持有直到返回）。
	ch := make(chan nameResult, 1)
	go func() {
		name, ok := queryObjectString(dup, objectNameInformation)
		ch <- nameResult{name: name, ok: ok}
	}()

	// 用 NewTimer 而不是 time.After：名称查询大多在微秒级返回，After 的
	// 定时器要等 300ms 才释放；一次 5000 条枚举会留下几千个待触发定时器。
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case r := <-ch:
		closeHandle(dup)
		return r.name, r.ok
	case <-timer.C:
		// 不 closeHandle(dup)：NtQueryObject 可能仍在内核里引用该句柄。
		return "", false
	}
}

// queryObjectString 同步调用 NtQueryObject 取对象名/类型名。
//
// 返回的 UNICODE_STRING.Buffer 指向同一块输出缓冲内部，必须做区间校验后
// 再转 UTF-16；直接信任内核指针会在异常驱动/回调场景下读到任意地址。
func queryObjectString(h windows.Handle, class uint32) (string, bool) {
	buf := make([]byte, 4096)
	var ret uint32
	status, _, _ := procNtQueryObject.Call(
		uintptr(h),
		uintptr(class),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
		uintptr(unsafe.Pointer(&ret)),
	)
	if uint32(status) != 0 && uint32(status) != statusBufferOverflow {
		return "", false
	}
	return unicodeStringFromBuffer(buf)
}

// unicodeStringFromBuffer 从 NtQueryObject 输出缓冲解析前导 UNICODE_STRING。
func unicodeStringFromBuffer(buf []byte) (string, bool) {
	if len(buf) < int(unsafe.Sizeof(unicodeStr{})) {
		return "", false
	}
	us := (*unicodeStr)(unsafe.Pointer(&buf[0]))
	if us.Buffer == nil || us.Length == 0 || us.Length%2 != 0 {
		return "", false
	}
	base := uintptr(unsafe.Pointer(&buf[0]))
	ptr := uintptr(unsafe.Pointer(us.Buffer))
	n := uintptr(us.Length)
	if ptr < base || ptr+n > base+uintptr(len(buf)) {
		return "", false
	}
	return windows.UTF16ToString(unsafe.Slice(us.Buffer, us.Length/2)), true
}

// ---------------------------------------------------------------- 单进程枚举

// EnumerateHandles 枚举指定进程的句柄（默认上限 1000、名称预算 2s）。
//
// 只为"最终会返回的行"解析名称：类型直方图不依赖名称，先过滤/截断再解析
// 可以把 NtQueryObject 的次数从"进程全部句柄"压到"实际展示的 ≤1000 条"。
func EnumerateHandles(pid uint32) ([]HandleRow, error) {
	res, err := CollectHandles(pid, "", handleListDefaultLimit, handleNameBudget)
	if err != nil {
		return nil, err
	}
	return res.Rows, nil
}

// CollectHandles 是 /handles handler 的完整入口：
// 枚举 → 按类型过滤 → 截断 → 只为展示行解析名称。
func CollectHandles(pid uint32, typeFilter string, limit int, nameBudget time.Duration) (HandleList, error) {
	out := HandleList{Types: map[string]int{}}
	if limit <= 0 {
		limit = handleListDefaultLimit
	}
	if limit > handleListMaxLimit {
		limit = handleListMaxLimit
	}

	entries, err := queryHandleTable()
	if err != nil {
		return out, err
	}

	sources := newDupSourceCache()
	defer sources.closeAll()
	resolver := newTypeNameResolver(sources)
	resolver.seedSelf(entries)

	type matchedEntry struct {
		entry    sysHandleEntry
		typeName string
	}
	matched := make([]matchedEntry, 0, 64)
	for i := range entries {
		e := &entries[i]
		if uint32(e.UniqueProcessID) != pid {
			continue
		}
		tname := resolver.name(e.ObjectTypeIndex, pid, e.HandleValue)
		if strings.HasPrefix(tname, "Type#") {
			out.UnresolvedTypes++
		}
		if typeFilter != "" && !strings.EqualFold(tname, typeFilter) {
			continue
		}
		out.Types[tname]++
		matched = append(matched, matchedEntry{entry: *e, typeName: tname})
	}

	out.Total = len(matched)
	if len(matched) > limit {
		matched = matched[:limit]
		out.Truncated = true
	}

	deadline := time.Now().Add(nameBudget)
	namesExhausted := false
	out.Rows = make([]HandleRow, 0, len(matched))
	// 打开目标进程一次供所有名称解析复用；打不开时句柄名不可读，
	// 直接跳过解析（不是超时，不许计入 NameBudgetHit）。
	var hProc windows.Handle
	canResolve := false
	if len(matched) > 0 {
		hProc, canResolve = sources.get(pid)
		out.ProcessOpened = canResolve
	}
	for _, m := range matched {
		row := HandleRow{Value: uint64(m.entry.HandleValue), Type: m.typeName}
		if canResolve && !namesExhausted && isSafeHandleType(m.typeName) && m.entry.GrantedAccess != 0 {
			timeout := handleNameTimeout
			if rem := time.Until(deadline); rem < timeout {
				timeout = rem
			}
			if timeout <= 0 {
				out.NameBudgetHit = true
				namesExhausted = true
			} else {
				out.NameAttempted++
				if name, ok := resolveHandleNameWithProc(hProc, m.entry.HandleValue, timeout); ok {
					row.Name = name
					out.NameResolved++
				}
				// 预算在单次查询后被耗尽时，下一轮循环会置 namesExhausted，
				// 这里不提前 break，保证剩余行仍然完整返回（只是 name 为空）。
				if time.Now().After(deadline) {
					out.NameBudgetHit = true
					namesExhausted = true
				}
			}
		}
		out.Rows = append(out.Rows, row)
	}
	return out, nil
}

// ---------------------------------------------------------------- 全系统 File 扫描

// EnumerateAllFileHandles 扫描全系统 File 类型句柄并解析名称（默认 5s 预算）。
// 供 /handleowners 使用；需要覆盖度统计的调用方用 ScanFileHandles。
func EnumerateAllFileHandles() ([]SysHandle, error) {
	res, err := ScanFileHandles(handleOwnersBudget)
	if err != nil {
		return nil, err
	}
	return res.Handles, nil
}

// ScanFileHandles 是全系统 File 句柄扫描的完整入口。
//
// 语义是**部分覆盖**：预算内能解析多少算多少，Truncated=true 表示还有
// 未检查的 File 句柄。调用方必须把这一点写进 note（契约 §15.2）。
func ScanFileHandles(budget time.Duration) (FileHandleScan, error) {
	out := FileHandleScan{Handles: []SysHandle{}}
	entries, err := queryHandleTable()
	if err != nil {
		return out, err
	}
	out.TotalHandles = len(entries)
	if budget <= 0 {
		budget = handleOwnersBudget
	}
	deadline := time.Now().Add(budget)

	sources := newDupSourceCache()
	defer sources.closeAll()
	resolver := newTypeNameResolver(sources)
	resolver.seedSelf(entries)

	for i := range entries {
		e := &entries[i]
		pid := uint32(e.UniqueProcessID)
		if pid == 0 {
			continue
		}
		tname := resolver.name(e.ObjectTypeIndex, pid, e.HandleValue)
		if strings.HasPrefix(tname, "Type#") {
			out.UnresolvedTypes++
		}
		if tname != "File" {
			continue
		}
		if time.Now().After(deadline) {
			out.Truncated = true
			break
		}
		out.FileScanned++
		timeout := handleNameTimeout
		if rem := time.Until(deadline); rem < timeout {
			timeout = rem
		}
		hProc, ok := sources.get(pid)
		if !ok || timeout <= 0 || e.GrantedAccess == 0 {
			if timeout <= 0 {
				out.Truncated = true
				break
			}
			continue
		}
		name, ok := resolveHandleNameWithProc(hProc, e.HandleValue, timeout)
		if !ok {
			continue
		}
		out.Resolved++
		out.Handles = append(out.Handles, SysHandle{
			PID:   pid,
			Value: uint64(e.HandleValue),
			Type:  tname,
			Name:  name,
		})
	}
	// 循环自然跑完但最后一次解析用完了预算，也按截断标注（后面可能还有
	// File 句柄没检查到）。
	if !out.Truncated && time.Now().After(deadline) {
		out.Truncated = true
	}
	return out, nil
}

// ---------------------------------------------------------------- 设备路径映射

// DevicePathForDriveLetter 把盘符（"C:" 或 "C"）映射为 NT 设备路径。
//
// 为什么要这层映射：NtQueryObject 返回的文件对象名是
// `\Device\HarddiskVolume2\Windows\notepad.exe`，而用户输入的是
// `C:\Windows\notepad.exe`；两者只能通过 QueryDosDevice 的卷映射对齐。
// 不匹配的盘符（subst/网络映射）返回错误，调用方按"无法覆盖"处理。
func DevicePathForDriveLetter(drive string) (string, error) {
	d := strings.TrimSpace(drive)
	if len(d) == 1 {
		d += ":"
	}
	if len(d) != 2 || d[1] != ':' {
		return "", fmt.Errorf("非法盘符: %q", drive)
	}
	letter := d[0]
	if letter >= 'a' && letter <= 'z' {
		letter -= 'a' - 'A'
	}
	if letter < 'A' || letter > 'Z' {
		return "", fmt.Errorf("非法盘符: %q", drive)
	}
	query := string([]byte{letter, ':'})
	queryPtr, err := windows.UTF16PtrFromString(query)
	if err != nil {
		return "", err
	}
	buf := make([]uint16, 1024)
	n, err := windows.QueryDosDevice(queryPtr, &buf[0], uint32(len(buf)))
	if err != nil {
		return "", fmt.Errorf("QueryDosDevice(%s) 失败: %w", query, err)
	}
	if n == 0 {
		return "", fmt.Errorf("QueryDosDevice(%s) 返回空映射", query)
	}
	// 一个盘符可能映射到多个目标（subst 等），返回的是 NUL 分隔多字符串；
	// UTF16ToString 在第一个 NUL 处停止，正好取主目标。
	target := windows.UTF16ToString(buf[:n])
	if target == "" {
		return "", fmt.Errorf("盘符 %s 没有设备映射", query)
	}
	return target, nil
}

// NormalizeToDevicePath 把 Win32 路径规范化为 NT 设备路径。
//
// 支持三种输入：
//   - 已经是 `\Device\...`（NtQueryObject 原生格式）→ 原样返回；
//   - `\\?\C:\...` / `\??\C:\...` → 剥前缀后按盘符处理；
//   - `C:\...` → QueryDosDevice 映射到 `\Device\HarddiskVolumeN\...`。
//
// UNC 路径（`\\server\share\...`）返回 false：网络重定向器没有稳定的
// QueryDosDevice 映射，硬猜一个 `\Device\Mup\...` 会带来误匹配。
func NormalizeToDevicePath(path string) (string, bool) {
	p := strings.TrimSpace(path)
	if p == "" {
		return "", false
	}
	// 统一分隔符，避免前端/命令行传入正斜杠时匹配失败。
	p = strings.ReplaceAll(p, "/", `\`)
	if strings.HasPrefix(p, `\\?\`) {
		p = p[len(`\\?\`):]
	}
	if strings.HasPrefix(p, `\??\`) {
		p = p[len(`\??\`):]
	}
	if len(p) >= len(`\Device\`) && strings.EqualFold(p[:len(`\Device\`)], `\Device\`) {
		return p, true
	}
	vol := "" // filepath.VolumeName 在这里不引入额外依赖，手动取盘符
	if len(p) >= 2 && p[1] == ':' {
		vol = p[:2]
	}
	if vol == "" {
		return "", false
	}
	dev, err := DevicePathForDriveLetter(vol)
	if err != nil {
		return "", false
	}
	rest := strings.TrimPrefix(p[len(vol):], `\`)
	if rest == "" {
		return dev, true
	}
	return dev + `\` + rest, true
}
