//go:build windows && etw2

package main

// ETW 消费端对照实验（TRADEOFFS §3.1 重启专项的 spike）。
//
// 背景：旧实现（-tags etw）的两个卡点记录互相矛盾（文件头说 OpenTrace
// 返回 ERROR_INVALID_NAME；TRADEOFFS 说回调不触发）。本实验按
// 0xrawsec/golang-etw（纯 Go 生产验证骨架）从零重写消费端，每一步返回值
// 全部打印，给出四条新假设的实测判定。
//
// 与旧实现的关键差异（刻意做的对照项）：
//   - 回调只计数+解析头部，不做 UserData 解析（排除解析干扰）
//   - ProcessTraceMode = REAL_TIME | EVENT_RECORD(0x10000000)
//   - NewCallbackCDecl 注册
//   - 启动前 KillSession 同名残留（Velociraptor 同款强抢占）
//   - Wnode 按 Velocidex 口径：Flags 占 ProviderId 槽（0x20000）、
//     ClientContext 在偏移 40
//
// 判定：回调总数>0 = 消费端通（批次三解锁）；Id=1（ProcessStart）出现 =
// 进程创建捕获成立。
//
// 需要验证时：go build -tags etw2 -o bin/zedr-diag-etw2.exe ./cmd/diag
//           && bin/zedr-diag-etw2.exe -etw2 30s

import (
	"encoding/binary"
	"fmt"
	"os/exec"
	"runtime"
	"sort"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modAdvapi32E2 = windows.NewLazySystemDLL("advapi32.dll")

	procStartTraceW2   = modAdvapi32E2.NewProc("StartTraceW")
	procControlTraceW2 = modAdvapi32E2.NewProc("ControlTraceW")
	procEnableTraceEx2 = modAdvapi32E2.NewProc("EnableTraceEx2")
	procOpenTraceW2    = modAdvapi32E2.NewProc("OpenTraceW")
	procProcessTrace2  = modAdvapi32E2.NewProc("ProcessTrace")
)

const (
	etw2Session     = "ZEDR-Etw2-Diag"
	etw2RealTime    = 0x00000100
	etw2EventRecord = 0x20000000 // MSDN: EVENT_TRACE_EVENT_RECORD（0x10000000 是别的 flag，写错则 Windows 退回旧式 EventCallback——回调静默不触发）
	etw2TracedGUID  = 0x00020000 // WNODE_FLAG_TRACED_GUID（占 ProviderId 槽，Velocidex 口径）
	etw2ControlStop = 1
	etw2LevelVerbose = 5
)

// kernelProcessProvider 是 Microsoft-Windows-Kernel-Process
//（GUID 与 winapi/etw.go 的旧实现一致）。
var kernelProcessProvider = windows.GUID{
	Data1: 0x22FB2CD6, Data2: 0x0E7B, Data3: 0x422B,
	Data4: [8]byte{0xA0, 0xC7, 0x2F, 0xAD, 0x1F, 0xD0, 0xE7, 0x16},
}

// etw2Properties 对应 EVENT_TRACE_PROPERTIES 的定长区（x64 128 字节），
// 变长区（LoggerName）从结构体尺寸起内联在缓冲里。
type etw2Properties struct {
	Wnode               [48]byte
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

// etw2Logfile 对应 EVENT_TRACE_LOGFILEW（x64 总 424 字节）。
//
// 字段序按 MSDN 原文：... CurrentEvent(EVENT_TRACE, 152B) →
// LogfileHeader(TRACE_LOGFILE_HEADER, 192B) → BufferCallback → BufferSize
// → Filled → EventsLost → IsKernelTrace → Context → EventCallback(旧式)
// → EventRecordCallback(新式)。
// **旧实现的错误就出在这里**：它把 EventRecordCallback 放在了
// EventsLost 之后、IsKernelTrace 之前——回调指针写进错误偏移，
// OpenTrace 读到垃圾指针，这就是"回调不触发"的根因（假设②实锤）。
type etw2Logfile struct {
	LogFileName   *uint16
	LoggerName    *uint16
	CurrentTime   int64
	BuffersRead   uint32
	ProcessTraceMode uint32
	CurrentEvent  etw2EventTrace
	LogfileHeader etw2TraceLogfileHeader
	BufferCallback uintptr
	BufferSize     uint32
	Filled         uint32
	EventsLost     uint32
	// Callback 是 union 槽：EventRecordCallback（带 EVENT_RECORD 位）或
	// EventCallback（旧式）共用同一偏移
	Callback       uintptr
	IsKernelTrace  uint32
	Context        uintptr
}

// etw2EventTrace 对应 EVENT_TRACE（x64 88 字节：Header 48 + 实例字段 40）。
// **旧实现的根因（假设②实锤）**：CurrentEvent 只用 48 字节占位、
// LogfileHeader 用 296 —— 整个结构体 416 ≠ 424，回调槽前移 40 字节
// 写到 LogfileHeader 内，OpenTrace 读到垃圾指针 → "回调不触发"。
// 本定义照抄 0xrawsec/golang-etw（advapi32_header.go，生产验证）：
// LogFileName 在前、LoggerName 在后（winnt.h 真序，MSDN 网页顺序误导），
// Callback(union) 在 EventsLost 后、IsKernelTrace 前。
type etw2EventTrace struct {
	Header           [48]byte
	InstanceId       uint32
	ParentInstanceId uint32
	ParentGuid       [16]byte
	MofData          uintptr
	MofLength        uint32
	UnionCtx         uint32
}

// etw2TraceLogfileHeader 对应 TRACE_LOGFILE_HEADER（x64 264 字节）。
type etw2TraceLogfileHeader struct {
	BufferSize         uint32
	VersionUnion       uint32
	ProviderVersion    uint32
	NumberOfProcessors uint32
	EndTime            int64
	TimerResolution    uint32
	MaximumFileSize    uint32
	LogFileMode        uint32
	BuffersWritten     uint32
	Union1             [16]byte
	LoggerName         *uint16
	LogFileName        *uint16
	TimeZone           etw2TimeZone
	BootTime           int64
	PerfFreq           int64
	StartTime          int64
	ReservedFlags      uint32
	BuffersLost        uint32
}

// etw2TimeZone 对应 TIME_ZONE_INFORMATION（x64 176 字节）。
type etw2TimeZone struct {
	Bias         int32
	StandardName [32]uint16
	StandardDate [16]byte
	StandardBias int32
	DaylightName [32]uint16
	DaylightDate [16]byte
	DaylightBias int32
}

var (
	etw2Buffers  atomic.Int64 // BufferCallback 计数（判别器）
	etw2Total    atomic.Int64
	etw2IDs      = map[uint32]int64{}
	etw2FirstPID atomic.Int64
	etw2KeepLF   *etw2Logfile
	etw2KeepName *uint16
	etw2KeepProps []byte
)

func etw2U16(b []byte, off int, v uint16) { binary.LittleEndian.PutUint16(b[off:], v) }
func etw2U32(b []byte, off int, v uint32) { binary.LittleEndian.PutUint32(b[off:], v) }

// etw2FillProps 按 WNODE_HEADER 真实偏移填会话属性。
// Velocidex 口径：Flags 放 ProviderId 槽（偏移 4），ClientContext 在 40，
// 自定义会话 GUID 在 24-39。
func etw2FillProps(buf []byte) {
	props := (*etw2Properties)(unsafe.Pointer(&buf[0]))
	etw2U32(props.Wnode[0:], 0, uint32(len(buf))) // Wnode.BufferSize
	etw2U32(props.Wnode[4:], 0, etw2TracedGUID)
	// Guid（偏移 24）：会话自定义 GUID
	etw2U32(props.Wnode[24:], 0, 0x5A454452) // "ZEDR"
	etw2U16(props.Wnode[28:], 0, 0x4E44)
	etw2U16(props.Wnode[30:], 0, 0x4E44)
	props.Wnode[32] = 0x44 // 随意可辨的固定尾
	etw2U32(props.Wnode[40:], 0, 1) // ClientContext = QPC
	props.LoggerNameOffset = uint32(unsafe.Sizeof(etw2Properties{}))
	for i, u := range syscall.StringToUTF16(etw2Session) {
		etw2U16(buf[int(props.LoggerNameOffset)+i*2:], i, u)
	}
}

// testETW2Attach 只做消费者 attach（配合 logman 创建的会话）：
// 判别"消费者代码错"还是"StartTrace 同进程路径错"的决定性实验。
func testETW2Attach(name string, d time.Duration) {
	if name == "" {
		name = etw2Session
	}
	fmt.Printf("\n--- ETW attach 实验（消费者挂到已存在会话 %q）---\n", name)
	lf := &etw2Logfile{}
	namePtr, _ := syscall.UTF16PtrFromString(name)
	lf.LoggerName = namePtr
	// 旧实现的"反直觉结论"在正确布局下复验：LogFileName 也指向会话名
	//（realtime 不写文件，但缺了它 OpenTrace 似乎不真正绑定会话）
	lf.LogFileName = namePtr
	lf.ProcessTraceMode = etw2RealTime | etw2EventRecord
	lf.Callback = windows.NewCallbackCDecl(etw2OnEvent)
	etw2KeepLF = lf
	etw2KeepName = namePtr
	handle, _, otErr := procOpenTraceW2.Call(uintptr(unsafe.Pointer(lf)))
	fmt.Printf("OpenTraceW: handle=0x%x err=%v\n", handle, otErr)
	if handle == ^uintptr(0) {
		return
	}
	done := make(chan struct{})
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		ret, _, _ := procProcessTrace2.Call(uintptr(unsafe.Pointer(&handle)), 1, 0, 0)
		fmt.Printf("ProcessTrace 返回: ret=%d\n", ret)
		// 布局探针：消费期间 Windows 会回写 LogfileHeader（BuffersWritten/
		// LoggerName 指针等）。回写值与 QUERY 一致 = 偏移对齐；全零 =
		// 我们的结构体基准解释不对。
		fmt.Printf("[探针] lf.LogfileHeader.BuffersWritten=%d (offset=%d)\n",
			lf.LogfileHeader.BuffersWritten,
			unsafe.Offsetof(lf.LogfileHeader)+unsafe.Offsetof(lf.LogfileHeader.BuffersWritten))
		fmt.Printf("[探针] lf.LogfileHeader.LoggerName nil=%v (offset=%d)\n",
			lf.LogfileHeader.LoggerName == nil,
			unsafe.Offsetof(lf.LogfileHeader)+unsafe.Offsetof(lf.LogfileHeader.LoggerName))
		fmt.Printf("[探针] lf.EventsLost=%d (offset=%d) EventRecordCallback(offset=%d)\n",
			lf.EventsLost, unsafe.Offsetof(lf.EventsLost), unsafe.Offsetof(lf.Callback))
		h := &lf.LogfileHeader
		fmt.Printf("[LH 全字段偏移] BufferSize=%d VersionUnion=%d ProviderVersion=%d NumProc=%d\n",
			unsafe.Offsetof(h.BufferSize), unsafe.Offsetof(h.VersionUnion),
			unsafe.Offsetof(h.ProviderVersion), unsafe.Offsetof(h.NumberOfProcessors))
		fmt.Printf("[LH 续] EndTime=%d TimerRes=%d MaxFileSize=%d LogFileMode=%d BuffersWritten=%d\n",
			unsafe.Offsetof(h.EndTime), unsafe.Offsetof(h.TimerResolution),
			unsafe.Offsetof(h.MaximumFileSize), unsafe.Offsetof(h.LogFileMode),
			unsafe.Offsetof(h.BuffersWritten))
		fmt.Printf("[LH 续] Union1=%d LoggerName=%d LogFileName=%d TimeZone=%d BootTime=%d\n",
			unsafe.Offsetof(h.Union1), unsafe.Offsetof(h.LoggerName),
			unsafe.Offsetof(h.LogFileName), unsafe.Offsetof(h.TimeZone),
			unsafe.Offsetof(h.BootTime))
		fmt.Printf("[LH 续] PerfFreq=%d StartTime=%d ReservedFlags=%d BuffersLost=%d sizeof(LH)=%d\n",
			unsafe.Offsetof(h.PerfFreq), unsafe.Offsetof(h.StartTime),
			unsafe.Offsetof(h.ReservedFlags), unsafe.Offsetof(h.BuffersLost),
			unsafe.Sizeof(*h))
		fmt.Printf("[LH 续] sizeof(TimeZone)=%d sizeof(EventTrace)=%d\n",
			unsafe.Sizeof(h.TimeZone), unsafe.Sizeof(lf.CurrentEvent))
		close(done)
	}()
	// 窗口期拉起进程，制造 ProcessStart
	for i := 0; i < int(d.Seconds())/8 + 1; i++ {
		time.Sleep(8 * time.Second)
		cmd := exec.Command("notepad.exe")
		if err := cmd.Start(); err != nil {
			break
		}
		select {
		case <-done:
			goto finish
		default:
		}
		select {
		case <-done:
			goto finish
		default:
		}
		_ = cmd.Process.Kill()
	}
finish:
	fmt.Printf("\n=== attach 实验判定 ===\n回调总数=%d Buffer回调=%d\n", etw2Total.Load(), etw2Buffers.Load())
	if etw2IDs[1] > 0 {
		fmt.Println("Id=1（ProcessStart）已捕获")
	}
	// 停掉 logman 会话
	if out, err := exec.Command("logman", "stop", name, "-ets").CombinedOutput(); err == nil {
		fmt.Printf("logman stop: %s", strings.TrimSpace(string(out))[:min(80, len(strings.TrimSpace(string(out))))])
	}
}

// testETW2 跑一轮对照实验。
func testETW2(d time.Duration) {
	if d <= 0 {
		d = 30 * time.Second
	}
	fmt.Println("\n--- ETW 消费端对照实验（0xrawsec 骨架，每步返回值全打印）---")

	// ① KillSession 同名残留（强抢占）
	kill := make([]byte, 1024)
	etw2FillProps(kill)
	killName, _ := syscall.UTF16PtrFromString(etw2Session)
	r, _, _ := procControlTraceW2.Call(0, uintptr(unsafe.Pointer(killName)),
		uintptr(unsafe.Pointer(&kill[0])), etw2ControlStop)
	fmt.Printf("① KillSession 残留: ret=%d（非零=无残留）\n", r)

	// ② StartTraceW
	props := make([]byte, 1024)
	etw2FillProps(props)
	p := (*etw2Properties)(unsafe.Pointer(&props[0]))
	p.LogFileMode = etw2RealTime
	p.BufferSize = 64 // KB：0xrawsec 注释——缓冲不得小于单事件上限
	p.MinimumBuffers = 4
	p.MaximumBuffers = 16
	p.FlushTimer = 1 // 每秒冲刷：不设则事件堆在缓冲直到满，实时消费者感知不到
	etw2KeepProps = props
	startName, _ := syscall.UTF16PtrFromString(etw2Session)
	var traceHandle uintptr
	ret, _, startErr := procStartTraceW2.Call(uintptr(unsafe.Pointer(&traceHandle)),
		uintptr(unsafe.Pointer(startName)), uintptr(unsafe.Pointer(&props[0])))
	fmt.Printf("② StartTraceW: ret=%d errno=%v handle=0x%x（0=成功）\n", ret, startErr, traceHandle)
	if ret != 0 {
		fmt.Println("   实验终止：会话建立失败（权限/同名/参数）")
		return
	}

	// ④ OpenTraceW（消费端；只设 LoggerName——0xrawsec 生产口径，
	// LogFileName 留空，realtime 不写文件）
	lf := &etw2Logfile{}
	namePtr, _ := syscall.UTF16PtrFromString(etw2Session)
	lf.LoggerName = namePtr
	// 旧式 PEVENT_TRACE 回调对照：去掉 EVENT_RECORD 位、union 同槽放旧式
	// 回调——判定"EVENT_RECORD 路径问题"还是"thunk 绑定层问题"
	lf.ProcessTraceMode = etw2RealTime
	lf.Callback = windows.NewCallbackCDecl(etw2OnTrace)
	fmt.Println("[对照] 模式=REAL_TIME only，旧式 EventCallback 注册")
	etw2KeepLF = lf
	etw2KeepName = namePtr
	handle, _, otErr := procOpenTraceW2.Call(uintptr(unsafe.Pointer(lf)))
	fmt.Printf("④ OpenTraceW: handle=0x%x err=%v（全 1 = 失败）\n", handle, otErr)
	if handle == ^uintptr(0) {
		procControlTraceW2.Call(0, uintptr(unsafe.Pointer(startName)),
			uintptr(unsafe.Pointer(&props[0])), etw2ControlStop)
		return
	}

	// ⑤ ProcessTrace（单 handle，独立 OS 线程）
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		ret, _, _ := procProcessTrace2.Call(uintptr(unsafe.Pointer(&handle)), 1, 0, 0)
		fmt.Printf("⑤ ProcessTrace 返回: ret=%d\n", ret)
	}()

	// ③ EnableTraceEx2（放在消费者挂上之后——Velocidex 生产顺序）
	guid := kernelProcessProvider
	ret, _, _ = procEnableTraceEx2.Call(traceHandle,
		uintptr(unsafe.Pointer(&guid)), 1, // EVENT_CONTROL_CODE_ENABLE_PROVIDER
		etw2LevelVerbose, 0xFFFFFFFFFFFFFFFF, 0, 0, 0)
	fmt.Printf("③ EnableTraceEx2(Kernel-Process, verbose, keyword=all): ret=%d\n", ret)

	// ⑤b 外部视图对照：logman 看内核眼里的会话状态与实时消费者数
	if out, err := exec.Command("logman", "query", "-ets", etw2Session).CombinedOutput(); err == nil {
		for _, l := range strings.Split(string(out), "\n") {
			if strings.Contains(l, "Status") || strings.Contains(l, "状态") ||
				strings.Contains(l, "Consumer") || strings.Contains(l, "消费者") ||
				strings.Contains(l, "Name") || strings.Contains(l, "名字") {
				fmt.Println("⑤b logman:", strings.TrimSpace(l))
			}
		}
	} else {
		fmt.Println("⑤b logman 查询失败:", err)
	}

	// ⑥ 采样窗口：拉起进程制造 ProcessStart 事件
	fmt.Printf("⑥ 采样窗口 %s（自动拉起 notepad 两次制造 ProcessStart）\n", d)
	for i := 0; i < 2; i++ {
		time.Sleep(d / 4)
		cmd := exec.Command("notepad.exe")
		if err := cmd.Start(); err != nil {
			fmt.Printf("   notepad 拉起失败: %v\n", err)
		} else {
			time.AfterFunc(2*time.Second, func() { _ = cmd.Process.Kill() })
		}
	}
	time.Sleep(d / 4)

	// ⑦ STOP + QUERY（EventsLost/BuffersWritten）
	query := make([]byte, 1024)
	etw2FillProps(query)
	procControlTraceW2.Call(0, uintptr(unsafe.Pointer(startName)),
		uintptr(unsafe.Pointer(&query[0])), etw2ControlStop)
	time.Sleep(500 * time.Millisecond)
	q := (*etw2Properties)(unsafe.Pointer(&query[0]))
	fmt.Printf("⑦ QUERY: EventsLost=%d BuffersWritten=%d\n", q.EventsLost, q.BuffersWritten)

	// ⑧ 判定
	total := etw2Total.Load()
	fmt.Printf("\n=== 判定 ===\n回调总数=%d Buffer回调=%d（Buffer>0=消费者已绑定，=0=绑定失败）\n",
		total, etw2Buffers.Load())
	if total > 0 {
		ids := make([]int, 0, len(etw2IDs))
		for id := range etw2IDs {
			ids = append(ids, int(id))
		}
		sort.Ints(ids)
		fmt.Printf("EventID 直方图: ")
		for _, id := range ids {
			fmt.Printf("[%d]=%d ", id, etw2IDs[uint32(id)])
		}
		fmt.Println()
		if etw2IDs[1] > 0 {
			fmt.Println("判定: Id=1（ProcessStart）已捕获 → 批次三（文件归因/网络事件流/DNS）解锁")
		} else {
			fmt.Println("判定: 消费端通但未见 Id=1——需查 keyword/级别/provider 过滤")
		}
	} else {
		fmt.Println("判定: 回调仍不触发——对照骨架仍不通，差异需继续收敛")
	}
}

// etw2OnTrace 是旧式 PEVENT_TRACE 回调（对照实验用）。
func etw2OnTrace(et uintptr) uintptr {
	etw2Total.Add(1)
	etw2Buffers.Add(1) // 复用判别计数：触发即证明回调链路通
	return 0
}

// etw2OnBuffer 是缓冲回调判别器：被调 = 消费者已在内核侧绑定。
func etw2OnBuffer(lf uintptr) uintptr {
	etw2Buffers.Add(1)
	return 1 // 继续处理
}

// etw2OnEvent 是 EVENT_RECORD 回调：只解析头部（不做 UserData），计数。
// EVENT_HEADER 偏移（x64）：ThreadId(8) ProcessId(12) TimeStamp(16)
// ProviderId(24) EventDescriptor(40：Id=40, Version=42, Channel=44,
// Level=45, Opcode=46)。
func etw2OnEvent(rec uintptr) uintptr {
	etw2Total.Add(1)
	pid := *(*int32)(unsafe.Pointer(rec + 12))
	id := *(*uint16)(unsafe.Pointer(rec + 40))
	etw2IDs[uint32(id)]++
	if pid > 0 && etw2FirstPID.Load() == 0 {
		etw2FirstPID.Store(int64(pid))
	}
	return 0
}
