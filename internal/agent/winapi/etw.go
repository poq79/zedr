//go:build windows && etw

// Package winapi 的 ETW 实时进程事件采集。
//
// 本文件通过 `etw` 构建标签隔离，默认不参与编译：
//   - ETW 回调必须把 syscall 传入的 uintptr 还原成结构体指针，
//     `go vet` 的 unsafeptr 检查无法认可这种固有模式（这是误报，
//     指针在回调期间由 ETW 保证有效），带进主构建会让 vet 不再干净；
//   - 该实现已在 Windows Server 2022 上实测：StartTrace / EnableTraceEx2 均成功，
//     但 OpenTrace 对所有参数组合都返回 ERROR_INVALID_NAME，未能跑通，
//     不能作为默认采集路径。
//
// 需要验证时：go build -tags etw ./cmd/hgdiag && ./hgdiag -etw 10s
//
// 为什么需要它：用户态轮询（无论 Toolhelp32 还是 NtQuery）都存在固有的
// TOCTOU 盲区——存活时间短于一个轮询周期的进程永远采集不到，
// 而"落地即执行、执行即退出"恰恰是恶意样本最常见的形态。
// 解决这个问题的唯一办法是不再"看快照"，而是"收事件"。
//
// 实现方式：直接调用 advapi32 的 ETW API 订阅
// Microsoft-Windows-Kernel-Process provider 的 ProcessStart 事件，
// 实时拿到每一次进程创建（含 ImageFileName 与 CommandLine）。
//
// 稳定性设计：
//   - 该实现只依赖 advapi32 的稳定导出符号，不 hook、不打补丁；
//   - 任何一步失败都返回明确错误，由上层决定是否回退到快照采集；
//   - provider 不存在（极老版本系统）时 EnableTraceEx2 会失败，同样走回退。
package winapi

import (
	"encoding/binary"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unicode/utf16"
	"unsafe"
)

var (
	procStartTraceW     = modAdvapi32.NewProc("StartTraceW")
	procControlTraceW   = modAdvapi32.NewProc("ControlTraceW")
	procEnableTraceEx2  = modAdvapi32.NewProc("EnableTraceEx2")
	procOpenTraceW      = modAdvapi32.NewProc("OpenTraceW")
	procProcessTrace    = modAdvapi32.NewProc("ProcessTrace")
	procCloseTrace      = modAdvapi32.NewProc("CloseTrace")
	procTraceSetInfo    = modAdvapi32.NewProc("TraceSetInformation")
)

const (
	eventTraceControlStop   = 0
	eventControlCodeEnable  = 1
	eventTraceRealTimeMode  = 0x00000100
	processTraceModeRealTime    = 0x00000100
	processTraceModeEventRecord = 0x10000000
	traceLevelInformation       = 4
	wnodeFlagTracedGUID         = 0x00020000
)

// kernelProcessGUID 是 Microsoft-Windows-Kernel-Process 的 provider GUID：
// {22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}
var kernelProcessGUID = guid{
	Data1: 0x22FB2CD6,
	Data2: 0x0E7B,
	Data3: 0x422B,
	Data4: [8]byte{0xA0, 0xC7, 0x2F, 0xAD, 0x1F, 0xD0, 0xE7, 0x16},
}

// wnodeHeader 对应 WNODE_HEADER（x64 为 48 字节）。
type wnodeHeader struct {
	BufferSize    uint32
	ProviderID    uint32
	HistoricalCtx uint64
	TimeStamp     int64
	Guid          guid
	ClientContext uint32
	Flags         uint32
}

// eventTraceProperties 对应 EVENT_TRACE_PROPERTIES（x64 为 120 字节，不含后续字符串区）。
type eventTraceProperties struct {
	Wnode               wnodeHeader
	BufferSize          uint32
	MinimumBuffers      uint32
	MaximumBuffers      uint32
	MaximumFileSize     uint32
	LogFileMode         uint32
	FlushTimer          uint32
	EnableFlags         uint32
	AgeLimit            uint32
	NumberOfBuffers     uint32
	FreeBuffers         uint32
	EventsLost          uint32
	BuffersWritten      uint32
	LogBuffersLost      uint32
	RealTimeBuffersLost uint32
	LoggerThreadID      uintptr
	LogFileNameOffset   uint32
	LoggerNameOffset    uint32
}

// eventTraceLogfileW 对应 EVENT_TRACE_LOGFILEW。
//
// 其中 CurrentEvent(EVENT_TRACE) 与 LogfileHeader(TRACE_LOGFILE_HEADER)
// 我们完全不需要读取，因此用定长字节数组占位——避免把两个横跨数十个
// 字段的 C 结构体照搬一遍，减少出错面（大小按 x64 ABI 固定）。
type eventTraceLogfileW struct {
	LoggerName          *uint16
	LogFileName         *uint16
	CurrentTime         int64
	BuffersRead         uint32
	ProcessTraceMode    uint32
	CurrentEvent        [48]byte  // EVENT_TRACE
	LogfileHeader       [296]byte // TRACE_LOGFILE_HEADER
	BufferCallback      uintptr
	BufferSize          uint32
	Filled              uint32
	EventsLost          uint32
	_                   uint32
	EventRecordCallback uintptr
	IsKernelTrace       uint32
	_                   uint32
	Context             uintptr
}

// eventHeader 对应 EVENT_HEADER（x64 为 80 字节）。
type eventHeader struct {
	Size          uint16
	HeaderType    uint16
	Flags         uint16
	EventProperty uint16
	ThreadID      uint32
	ProcessID     uint32
	TimeStamp     int64
	ProviderID    guid
	EventID       uint16
	Version       uint8
	Channel       uint8
	Level         uint8
	Opcode        uint8
	Task          uint16
	Keyword       uint64
	ProcessorTime int64
	ActivityID    guid
}

// eventRecord 对应 EVENT_RECORD（x64 为 104 字节）。
type eventRecord struct {
	EventHeader       eventHeader
	BufferContext     uint32
	ExtendedDataCount uint16
	UserDataLength    uint16
	UserData          unsafe.Pointer
	UserContext       unsafe.Pointer
}

// ProcEvent 是一条进程创建事件。
type ProcEvent struct {
	PID      uint32
	PPID     uint32
	Image    string // 完整镜像路径
	CmdLine  string
	Time     time.Time
	EventsLostOnStart uint64
}

// ETWProcessWatcher 订阅内核进程创建事件。
type ETWProcessWatcher struct {
	name  string
	ch    chan ProcEvent
	done  chan struct{}

	traceHandle uint64 // StartTrace 得到的控制句柄
	consumeHandle uint64 // OpenTrace 得到的消费句柄

	closeOnce sync.Once
	closed    atomic.Bool
	lostCount uint64
	errOnce   sync.Once
	lastErr   error
}

// NewETWProcessWatcher 创建并启动实时订阅。
//
// sessionName 用于标识 ETW 会话；同名会话重复创建会失败，
// 因此调用前会先尝试停止同名残留会话（探针崩溃后重启是常见场景）。
func NewETWProcessWatcher(sessionName string) (*ETWProcessWatcher, error) {
	if sessionName == "" {
		sessionName = "HostGuard-ProcessTrace"
	}
	w := &ETWProcessWatcher{
		name: sessionName,
		ch:   make(chan ProcEvent, 2048),
		done: make(chan struct{}),
	}

	// 清理同名残留会话，避免二次启动失败
	w.stopLeftover(sessionName)

	if err := w.startSession(sessionName); err != nil {
		return nil, err
	}
	if err := w.enableProvider(); err != nil {
		w.stopSession()
		return nil, err
	}

	// OpenTrace 与 ProcessTrace 必须在同一个 OS 线程上调用，
	// 因此整个消费过程放在一个 locked goroutine 里完成，
	// 通过 ready 通道把"是否打开成功"同步回构造函数。
	ready := make(chan error, 1)
	go w.consume(sessionName, ready)
	if err := <-ready; err != nil {
		w.stopSession()
		return nil, err
	}
	return w, nil
}

// Name 返回实现名。
func (w *ETWProcessWatcher) Name() string { return "etw-kernel-process" }

// Events 返回事件通道。通道在 Close 后关闭。
func (w *ETWProcessWatcher) Events() <-chan ProcEvent { return w.ch }

// Err 返回记录到的首个错误（用于 UI 展示降级原因）。
func (w *ETWProcessWatcher) Err() error { return w.lastErr }

// Close 停止订阅并释放资源。
func (w *ETWProcessWatcher) Close() error {
	w.closeOnce.Do(func() {
		w.closed.Store(true)
		if w.consumeHandle != 0 {
			// CloseTrace 会让阻塞中的 ProcessTrace 返回
			_, _, _ = procCloseTrace.Call(uintptr(w.consumeHandle))
		}
		w.stopSession()
	})
	return nil
}

func (w *ETWProcessWatcher) stopLeftover(name string) {
	namePtr, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return
	}
	// 只传名字、属性用最小缓冲即可完成 STOP
	buf := make([]byte, unsafe.Sizeof(eventTraceProperties{})+1024)
	props := (*eventTraceProperties)(unsafe.Pointer(&buf[0]))
	props.Wnode.BufferSize = uint32(len(buf))
	props.LoggerNameOffset = uint32(unsafe.Sizeof(eventTraceProperties{}))
	_, _, _ = procControlTraceW.Call(0, uintptr(unsafe.Pointer(namePtr)),
		uintptr(unsafe.Pointer(props)), eventTraceControlStop)
}

func (w *ETWProcessWatcher) startSession(name string) error {
	namePtr, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return err
	}
	buf := make([]byte, unsafe.Sizeof(eventTraceProperties{})+1024)
	props := (*eventTraceProperties)(unsafe.Pointer(&buf[0]))
	props.Wnode.BufferSize = uint32(len(buf))
	props.Wnode.Flags = wnodeFlagTracedGUID
	props.Wnode.ClientContext = 1 // QPC 时间戳
	props.LogFileMode = eventTraceRealTimeMode
	props.FlushTimer = 1
	props.LoggerNameOffset = uint32(unsafe.Sizeof(eventTraceProperties{}))

	r, _, _ := procStartTraceW.Call(
		uintptr(unsafe.Pointer(&w.traceHandle)),
		uintptr(unsafe.Pointer(namePtr)),
		uintptr(unsafe.Pointer(props)),
	)
	if r != 0 {
		return fmt.Errorf("StartTraceW 失败(code=%d)，通常需要在管理员权限下运行", r)
	}
	if w.traceHandle == 0 {
		return fmt.Errorf("StartTraceW 返回空句柄")
	}
	return nil
}

func (w *ETWProcessWatcher) enableProvider() error {
	r, _, _ := procEnableTraceEx2.Call(
		uintptr(w.traceHandle),
		uintptr(unsafe.Pointer(&kernelProcessGUID)),
		eventControlCodeEnable,
		traceLevelInformation,
		^uintptr(0), // MatchAnyKeyword 全开
		0,
		0,
		0, // EnableParameters 传 NULL：keyword 已在函数参数里
	)
	if r != 0 {
		return fmt.Errorf("EnableTraceEx2 失败(code=%d)，该 provider 可能不可用", r)
	}
	return nil
}

// openConsumerLocked 打开实时消费句柄。必须在将调用 ProcessTrace 的同一线程上执行。
func (w *ETWProcessWatcher) openConsumerLocked(name string) error {
	namePtr, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return err
	}
	lf := &eventTraceLogfileW{
		LoggerName:       namePtr,
		ProcessTraceMode: processTraceModeRealTime | processTraceModeEventRecord,
		EventRecordCallback: syscall.NewCallback(func(ptr uintptr) uintptr {
			w.onEvent(ptr)
			return 0
		}),
	}
	h, _, e := procOpenTraceW.Call(uintptr(unsafe.Pointer(lf)))
	if h == ^uintptr(0) || h == 0 {
		return fmt.Errorf("OpenTraceW 失败(%v)", e)
	}
	w.consumeHandle = uint64(h)
	return nil
}

func (w *ETWProcessWatcher) stopSession() {
	namePtr, err := syscall.UTF16PtrFromString(w.name)
	if err != nil {
		return
	}
	buf := make([]byte, unsafe.Sizeof(eventTraceProperties{})+1024)
	props := (*eventTraceProperties)(unsafe.Pointer(&buf[0]))
	props.Wnode.BufferSize = uint32(len(buf))
	props.LoggerNameOffset = uint32(unsafe.Sizeof(eventTraceProperties{}))
	_, _, _ = procControlTraceW.Call(uintptr(w.traceHandle), uintptr(unsafe.Pointer(namePtr)),
		uintptr(unsafe.Pointer(props)), eventTraceControlStop)
}

// consume 阻塞消费事件，直到会话被关闭。
// 调用前已 LockOSThread：OpenTrace 与 ProcessTrace 必须同线程。
func (w *ETWProcessWatcher) consume(name string, ready chan<- error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	defer close(w.ch)

	if err := w.openConsumerLocked(name); err != nil {
		ready <- err
		return
	}
	ready <- nil

	r, _, e := procProcessTrace.Call(
		uintptr(unsafe.Pointer(&w.consumeHandle)), 1, 0, 0)
	// ProcessTrace 正常返回时 r==0（会话被停止）
	if r != 0 && !w.closed.Load() {
		w.errOnce.Do(func() { w.lastErr = fmt.Errorf("ProcessTrace 异常退出(code=%d, %v)", r, e) })
	}
}

// onEvent 是 ETW 回调（运行在 ETW 自己的线程上，必须极其克制：
// 只做最小解析后投递到带缓冲通道，绝不做 IO 或加锁等待）。
func (w *ETWProcessWatcher) onEvent(ptr uintptr) {
	if w.closed.Load() || ptr == 0 {
		return
	}
	rec := (*eventRecord)(unsafe.Pointer(ptr))

	// 只关心 Kernel-Process 的 ProcessStart（EventID=1）
	if rec.EventHeader.ProviderID != kernelProcessGUID {
		return
	}
	if rec.EventHeader.EventID != 1 || rec.UserDataLength == 0 || rec.UserData == nil {
		return
	}

	payload := unsafe.Slice((*byte)(rec.UserData), int(rec.UserDataLength))
	ev, ok := parseProcessStart(payload)
	if !ok || ev.PID == 0 {
		return
	}
	if rec.EventHeader.TimeStamp > 0 {
		ev.Time = time.Unix(0, rec.EventHeader.TimeStamp)
	} else {
		ev.Time = time.Now()
	}

	select {
	case w.ch <- ev:
	default:
		// 通道满说明下游处理不过来。计数后丢弃：宁可丢事件也不阻塞 ETW 线程，
		// 阻塞会导致 ETW 缓冲区耗尽并丢更多事件。
		atomic.AddUint64(&w.lostCount, 1)
	}
}

// parseProcessStart 解析 ProcessStart 事件负载。
//
// 字段顺序（Microsoft-Windows-Kernel-Process manifest）：
//
//	ProcessID(u32) CreateTime(u64) ParentProcessID(u32) SessionID(u32)
//	Flags(u32) ImageFileName(unicode_string) CommandLine(unicode_string) ...
func parseProcessStart(b []byte) (ProcEvent, bool) {
	const headerLen = 20 // 4 + 8 + 4 + 4
	if len(b) < headerLen {
		return ProcEvent{}, false
	}
	ev := ProcEvent{
		PID:  binary.LittleEndian.Uint32(b[0:]),
		PPID: binary.LittleEndian.Uint32(b[12:]),
	}

	off := headerLen
	img, off := readUnicodeString(b, off)
	cmd, _ := readUnicodeString(b, off)

	ev.Image = img
	ev.CmdLine = cmd
	return ev, img != ""
}

// readUnicodeString 读取 ETW 的 UNICODE_STRING 编码：
// USHORT 字节长度 + WCHAR 数组（无结束符），随后按 4 字节对齐。
func readUnicodeString(b []byte, off int) (string, int) {
	if off+2 > len(b) {
		return "", len(b)
	}
	n := int(binary.LittleEndian.Uint16(b[off:]))
	off += 2
	if n <= 0 {
		return "", align4(off)
	}
	if off+n > len(b) {
		n = len(b) - off
		if n <= 0 {
			return "", len(b)
		}
	}
	s := decodeUTF16LE(b[off : off+n])
	return s, align4(off + n)
}

func align4(n int) int {
	if r := n % 4; r != 0 {
		return n + (4 - r)
	}
	return n
}

func decodeUTF16LE(raw []byte) string {
	if len(raw) < 2 {
		return ""
	}
	u := make([]uint16, 0, len(raw)/2)
	for i := 0; i+1 < len(raw); i += 2 {
		u = append(u, binary.LittleEndian.Uint16(raw[i:]))
	}
	return strings.TrimRight(string(utf16.Decode(u)), "\x00")
}

// ProbeETW 做一次轻量可用性探测：能建会话、能启用 provider 即为可用。
// 探测后立即清理，不留残留会话。
func ProbeETW() error {
	w, err := NewETWProcessWatcher("HostGuard-Probe")
	if err != nil {
		return err
	}
	return w.Close()
}
