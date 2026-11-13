//go:build windows
// +build windows

// evtlog.go：Windows 事件日志读取层（wevtapi.dll，轮询模式，E1 骨架）。
//
// 为什么是轮询而不是 EvtSubscribe 推模式：推模式的回调绑定发起线程，
// 本仓 regwatch 已实锤"阻塞注册 + Close"的挂死路径（见 regnotify.go
// 文件头），不重蹈覆辙。30s 轮询频率下单次查询成本（毫秒级）可忽略，
// 换来零回调线程、零生命周期管理——每次调用自管理句柄（打开→用→Close），
// 不做长连接。
//
// 方向口径（2026-11 Windows Server 2022 10.0.20348 实测，wevtutil 对照
// Get-WinEvent 交叉印证）：EvtQuery 默认方向（不带 EvtQueryReverseDirection，
// 即"正序"）按 RecordID 从最旧到最新返回；带 ReverseDirection 才是新→旧。
// 因此：
//   - EvtReadBatch 用正序，收集 RecordID > sinceID 的新事件，返回前再排序
//     一次（防御性：不依赖系统返回顺序的内部实现细节，契约保证升序）；
//   - EvtChannelOldestRecordID 用正序拿第一条即最旧记录。
//
// 成本模型（诚实边界）：正序意味着游标之前的旧匹配事件每轮都会被重新
// 扫描+渲染（成本 O(本次查询全部匹配事件数)），缓解靠调用方用窄 XPath
// （只查精选 EventID）。刻意不做"扫描预算"截断：正序下预算截断会让
// 新事件永久饿死（旧积压填满预算、游标不推进、下一轮从同一个最旧位置
// 重新开始）——宁可慢，不可丢。maxEvents 封顶只作用于"新事件收集数"，
// 到顶即停是安全的：未交付的匹配下一轮会重新查到（查询无服务端游标，
// 每次从头按同一 XPath 重算，天然幂等）。
//
// 绑定方式：x/sys/windows 只封装了旧式 ReportEvent API（无 Evt*），
// 走 NewLazySystemDLL + LazyProc，对齐包内先例。LazyProc.Call 的 err
// 恒非 nil（残留 LastErr）——判错只看返回码，err 只当 errno 用
// （见 evtErrno，AGENTS.md §5.3 同源教训）。
//
// 诚实边界：
//   - EvtNext 的 Timeout 按上限处理并容忍 ERROR_TIMEOUT（视为本批结束，
//     下轮续读）。本地通道查询是文件背书、即刻返回，该分支处于休眠
//     防御状态（防挂死保险），未在真机触发过——如实标注，不当作已验证路径。
//   - 单条事件渲染/解析失败只跳过该条、不推进游标：下一轮会再次读到并
//     再次跳过（幂等），不会卡死批处理；本层无日志器，跳过不产生噪音，
//     上层如需观测可在拿到批次后比对游标推进量。
//   - XPath 语法错误只体现为 EvtQuery 的失败错误码，本层不做错误分类；
//     调用方按"通道不可用"降级即可满足契约。
//   - Data 元素内含子元素的复杂嵌套载荷只取 chardata，子元素丢弃
//     （精选的三类事件——7045/4625/1149——均为简单值，够用）。
//   - 未覆盖：远程会话（Session 恒 NULL=本地）、EvtQueryLogFile 文件
//     模式、EvtRenderEventValues/System 值模式渲染（绑定已备，见
//     procEvtCreateRenderContext 注释）。
//   - 空通道的 EvtChannelOldestRecordID 返回 (0, nil)——调用方不能把 0
//     当合法游标基线，"检查点 < 最旧记录"的失效判定对 0 同样成立。
package winapi

import (
	"encoding/xml"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var modWevtapi = windows.NewLazySystemDLL("wevtapi.dll")

var (
	procEvtQuery = modWevtapi.NewProc("EvtQuery")
	procEvtNext  = modWevtapi.NewProc("EvtNext")
	// EvtCreateRenderContext：XML 渲染（evtRenderEventXml）传 NULL 上下文即可
	// （2026-11 真机实测），渲染上下文只在 EvtRenderEventValues/System 的
	// 结构化取值时需要——本骨架不用值模式，绑定先备着，供后续"系统属性
	// 直读免 XML"优化时使用。
	procEvtCreateRenderContext = modWevtapi.NewProc("EvtCreateRenderContext")
	procEvtRender              = modWevtapi.NewProc("EvtRender")
	procEvtClose               = modWevtapi.NewProc("EvtClose")
)

// winevt.h 的标志位与错误码口径（x/sys 已有 errno 常量，flags 本地定义）。
const (
	evtQueryChannelPath = 0x00000001 // EvtQuery 的 Query 参数是通道路径

	// EVT_RENDER_FLAGS 的真机口径（2026-11 Server 2022 10.0.20348 探针实测；
	// 本机无 SDK 头文件比对，且常见资料凭 enum 排序把 Xml 记成 0）：
	// EvtRenderEventValues=0（须配 EvtCreateRenderContext 上下文）/
	// EvtRenderEventXml=1（NULL 上下文即可）/ EvtRenderEventUserData=2。
	// 实测证据：flag=1+NULL 上下文返回 "<Event xmlns=..."；flag=0+System
	// 上下文返回 416 字节 EVT_SYSTEM_PROPERTIES 结构，与文档中
	// "EvtRenderContextSystem + EvtRenderEventValues 渲染系统属性"的配对
	// 完全吻合；flag=0+NULL 上下文恒 ERROR_INVALID_PARAMETER。
	evtRenderEventXml = 1

	// 单次 EvtNext 拉取的事件句柄数。64 是官方样例口径，再大也省不了
	// 渲染成本（每条仍要 EvtRender），只是摊薄调用次数。
	evtNextBatchSize = 64
	// maxEvents 的默认值与上限（契约口径）。
	evtMaxEventsCap = 512
	// EvtNext 等待上限（毫秒）。本地通道查询即刻返回，带超时只为"绝不
	// 依赖阻塞调用按时返回"的仓内纪律（regwatch 教训）。
	evtNextTimeoutMs = 1000
)

// EvtEvent 是一条渲染后的 Windows 事件。
type EvtEvent struct {
	Channel     string
	RecordID    uint64
	EventID     uint16 // 不含 qualifier 位
	Level       uint8
	TimeCreated time.Time
	// Data 是 EventData/UserData 里的命名值（XML 解析所得；键为元素名小写）。
	// 安全事件的 EventData 是 Name 属性型 <Data Name='SubjectUserName'>，
	// System 事件是无名 <Data>（键为 "data[0]".."data[n]"）——两种都要支持。
	Data map[string]string
}

// EvtReadBatch 从通道拉取一批新事件（RecordID > sinceID，升序）。
//
// channel 形如 "System"；xpath 是查询过滤（形如
// "*[System[(EventID=7045) or (EventID=104)]]"），空串表示不过滤（全事件）。
// 返回本批事件与推进后的游标（批内最大 RecordID，不低于 sinceID）。
//
// 错误语义（契约）：
//   - 通道不存在/被禁用/无权限：返回包装 windows 错误码的可判错误
//     （errors.Is 可比对 windows.Errno），调用方降级；
//   - 无新事件：返回空切片 + sinceID 原值，不算错误；
//   - 中途硬错误（渲染/系统调用失败）：丢弃本批、游标不动（返回 sinceID），
//     下轮重查天然补齐——查询无状态，丢弃不等于丢失。
//
// 可并发调用（无共享状态，句柄自管理）。
func EvtReadBatch(channel, xpath string, sinceID uint64, maxEvents int) ([]EvtEvent, uint64, error) {
	if maxEvents <= 0 || maxEvents > evtMaxEventsCap {
		maxEvents = evtMaxEventsCap // 契约：默认/钳制 512
	}
	chPtr, err := windows.UTF16PtrFromString(channel)
	if err != nil {
		return nil, sinceID, fmt.Errorf("evtlog: 通道名非法 %q: %w", channel, err)
	}
	var xpathArg uintptr
	if xpath != "" {
		xp, err := windows.UTF16PtrFromString(xpath)
		if err != nil {
			return nil, sinceID, fmt.Errorf("evtlog: XPath 非法 %q: %w", xpath, err)
		}
		xpathArg = uintptr(unsafe.Pointer(xp))
	}

	qh, _, e := procEvtQuery.Call(0, uintptr(unsafe.Pointer(chPtr)), xpathArg, evtQueryChannelPath)
	if qh == 0 {
		return nil, sinceID, fmt.Errorf("evtlog: EvtQuery(%q) 打开失败: %w", channel, evtErrno(e))
	}
	defer evtClose(qh)

	events := make([]EvtEvent, 0, min(maxEvents, evtNextBatchSize))
	cursor := sinceID
	var batch [evtNextBatchSize]uintptr

scan:
	for len(events) < maxEvents {
		var returned uint32
		r, _, e := procEvtNext.Call(qh, evtNextBatchSize, uintptr(unsafe.Pointer(&batch[0])),
			evtNextTimeoutMs, 0, uintptr(unsafe.Pointer(&returned)))
		if r == 0 {
			en := evtErrno(e)
			switch en {
			case windows.ERROR_NO_MORE_ITEMS, windows.ERROR_TIMEOUT:
				break scan // 正常耗尽 / 暂无更多（防挂死：视为本批结束，下轮续读）
			default:
				return nil, sinceID, fmt.Errorf("evtlog: EvtNext(%q) 失败: %w", channel, en)
			}
		}
		if returned == 0 {
			break scan // 防御：成功但零条，避免外层空转
		}

		hs := batch[:returned]
		for i := range hs {
			xmlText, rerr := evtRenderXML(hs[i])
			evtClose(hs[i]) // 事件句柄用完即关，无论渲染成败
			if rerr != nil {
				evtCloseBatch(hs, i+1)
				return nil, sinceID, fmt.Errorf("evtlog: 渲染事件失败(%q): %w", channel, rerr)
			}
			ev, perr := ParseEvtXML(channel, xmlText)
			if perr != nil {
				// 单条畸形事件只跳过：该条下一轮会被再次读到并再次跳过（幂
				// 等），游标不推进也不会卡死批处理。
				continue
			}
			if ev.RecordID > cursor {
				cursor = ev.RecordID
			}
			if ev.RecordID > sinceID {
				events = append(events, *ev)
				if len(events) >= maxEvents {
					// 封顶即停：本批剩余句柄先全部关掉再退出（防句柄泄漏）。
					// 未交付的匹配下一轮重新查到，不丢。
					evtCloseBatch(hs, i+1)
					break scan
				}
			}
		}
	}

	sort.Slice(events, func(i, j int) bool { return events[i].RecordID < events[j].RecordID })
	return events, cursor, nil
}

// EvtChannelOldestRecordID 返回通道当前最旧记录的 RecordID（游标合法性检查
// 用：检查点落后于最旧记录 = 日志被清/滚动，游标失效需重置基线）。
// 空通道返回 (0, nil)；通道不可读返回错误。
func EvtChannelOldestRecordID(channel string) (uint64, error) {
	chPtr, err := windows.UTF16PtrFromString(channel)
	if err != nil {
		return 0, fmt.Errorf("evtlog: 通道名非法 %q: %w", channel, err)
	}
	// "*" 匹配全部事件（wevtutil /q:"*" 同口径，2026-11 实测有效）。
	xp, err := windows.UTF16PtrFromString("*")
	if err != nil {
		return 0, fmt.Errorf("evtlog: XPath 非法: %w", err)
	}
	// 正序（默认方向）的第一条就是最旧记录（2026-11 实测：默认方向为
	// 最旧→最新；带 ReverseDirection 才是新→旧）。不用 ReverseDirection
	// 反着拿，避免再引入一个方向语义记忆点。
	qh, _, e := procEvtQuery.Call(0, uintptr(unsafe.Pointer(chPtr)),
		uintptr(unsafe.Pointer(xp)), evtQueryChannelPath)
	if qh == 0 {
		return 0, fmt.Errorf("evtlog: EvtQuery(%q) 打开失败: %w", channel, evtErrno(e))
	}
	defer evtClose(qh)

	var h uintptr
	var returned uint32
	r, _, e := procEvtNext.Call(qh, 1, uintptr(unsafe.Pointer(&h)),
		evtNextTimeoutMs, 0, uintptr(unsafe.Pointer(&returned)))
	if r == 0 {
		en := evtErrno(e)
		if en == windows.ERROR_NO_MORE_ITEMS || en == windows.ERROR_TIMEOUT {
			return 0, nil // 空通道：契约返回 0,nil
		}
		return 0, fmt.Errorf("evtlog: EvtNext(%q) 失败: %w", channel, en)
	}
	if returned == 0 {
		return 0, nil // 防御：成功但零条按空通道处理
	}

	xmlText, err := evtRenderXML(h)
	evtClose(h)
	if err != nil {
		return 0, fmt.Errorf("evtlog: 渲染最旧事件失败(%q): %w", channel, err)
	}
	ev, err := ParseEvtXML(channel, xmlText)
	if err != nil {
		return 0, fmt.Errorf("evtlog: 解析最旧事件失败(%q): %w", channel, err)
	}
	return ev.RecordID, nil
}

// evtRenderBufBytes 是首选渲染缓冲的字节数。精选事件（7045/4625/1149）的
// XML 实测在 1-4KB 量级，16KB 覆盖绝大多数；超出走精确重取，不影响正确性。
const evtRenderBufBytes = 16 * 1024

// evtRenderXML 渲染一条事件为 UTF-16 XML 文本（每次调用自管理中间缓冲）。
//
// 2026-11 真机实测（Windows Server 2022 10.0.20348）：EvtRender 不支持
// "Buffer=NULL + BufferSize=0" 的先查尺寸手法——直接返回
// ERROR_INVALID_PARAMETER，与 EvtFormatMessage 系 API 的惯例不同。官方
// C 样本的口径是先给固定大缓冲、失败于 ERROR_INSUFFICIENT_BUFFER 时按
// BufferUsed 带回的所需字节数精确重取，此处照做。
func evtRenderXML(h uintptr) (string, error) {
	buf := make([]uint16, evtRenderBufBytes/2)
	used := uint32(len(buf) * 2)
	r, _, e := procEvtRender.Call(0, h, evtRenderEventXml, uintptr(used),
		uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&used)), 0)
	if r == 0 {
		en := evtErrno(e)
		if en != windows.ERROR_INSUFFICIENT_BUFFER {
			return "", fmt.Errorf("evtlog: EvtRender 取 XML 失败: %w", en)
		}
		if used == 0 {
			return "", errors.New("evtlog: EvtRender 缓冲不足且未带回所需尺寸")
		}
		big := make([]uint16, used/2)
		r, _, e = procEvtRender.Call(0, h, evtRenderEventXml, uintptr(used),
			uintptr(unsafe.Pointer(&big[0])), uintptr(unsafe.Pointer(&used)), 0)
		if r == 0 {
			return "", fmt.Errorf("evtlog: EvtRender 精确重取失败: %w", evtErrno(e))
		}
		buf = big
	}
	// used 含结尾 NUL；UTF16ToString 在第一个 NUL 处截断，含/不含 NUL 两种
	// 返回口径都安全。
	return windows.UTF16ToString(buf[:used/2]), nil
}

// evtCloseBatch 关闭 handles[from:] 的剩余事件句柄——错误/封顶提前退出时
// 必须显式收尾，否则每次提前退出都漏 64 个以内的句柄。
func evtCloseBatch(handles []uintptr, from int) {
	for i := from; i < len(handles); i++ {
		evtClose(handles[i])
	}
}

// evtClose 关闭任意 Evt* 句柄。EvtClose 对合法句柄不失败，失败亦无补救手段。
func evtClose(h uintptr) {
	_, _, _ = procEvtClose.Call(h)
}

// evtErrno 从 LazyProc.Call 的第三返回值取出真实错误码。Call 的 err 恒非
// nil（残留 LastErr），判错只能看返回码——err 只当 errno 用。
func evtErrno(e error) syscall.Errno {
	if en, ok := e.(syscall.Errno); ok {
		return en
	}
	return 0
}

// ---- XML 解析（纯函数，无 Win32 依赖；导出供上层单测复用） ----

// ParseEvtXML 解析 EvtRender(EvtRenderEventXml) 产出的事件 XML。
//
// 解析口径（宽松 struct + 显式转换，坏字段不拖垮整条）：
//   - RecordID 取 <System><EventRecordID>；缺失/非法返回错误（结构性字段）；
//   - EventID 只取元素文本转 uint16，Qualifiers 属性剥离（契约）；
//     缺失/非法返回错误；
//   - Level 缺失/非法给 0 不报错（辅助字段）；
//   - TimeCreated/SystemTime 为 ISO8601（Windows 实际是 7 位小数秒，
//     time.RFC3339Nano 兼容）：失败给零值不报错（契约）；
//   - Data 恒非 nil map；键口径见 collectEvtData。
func ParseEvtXML(channel, xmlText string) (*EvtEvent, error) {
	var doc evtDocXML
	if err := xml.Unmarshal([]byte(xmlText), &doc); err != nil {
		return nil, fmt.Errorf("evtlog: 事件 XML 解析失败: %w", err)
	}

	id, err := strconv.ParseUint(strings.TrimSpace(doc.System.EventID.Text), 10, 16)
	if err != nil {
		return nil, fmt.Errorf("evtlog: EventID 非法 %q: %w", doc.System.EventID.Text, err)
	}
	rid, err := strconv.ParseUint(strings.TrimSpace(doc.System.EventRecordID), 10, 64)
	if err != nil {
		return nil, fmt.Errorf("evtlog: EventRecordID 非法 %q: %w", doc.System.EventRecordID, err)
	}

	level := uint8(0)
	if lv, lerr := strconv.ParseUint(strings.TrimSpace(doc.System.Level), 10, 8); lerr == nil {
		level = uint8(lv)
	}

	var when time.Time
	if st := strings.TrimSpace(doc.System.TimeCreated.SystemTime); st != "" {
		if t, terr := time.Parse(time.RFC3339Nano, st); terr == nil {
			when = t
		} // 失败给零值不报错（契约）：时间坏了不拖垮整条事件
	}

	data := make(map[string]string)
	unnamed := 0 // 无名 Data 的递增计数器跨 EventData/UserData 共享，杜绝 data[i] 撞键
	collectEvtData(doc.EventData.Kids, data, &unnamed)
	collectEvtData(doc.UserData.Kids, data, &unnamed)

	return &EvtEvent{
		Channel:     channel,
		RecordID:    rid,
		EventID:     uint16(id),
		Level:       level,
		TimeCreated: when,
		Data:        data,
	}, nil
}

// evtDocXML / evtSystemXML 是对事件 XML 的宽松映射：未声明的元素（Correlation/
// Execution/Provider 等及其属性）由 encoding/xml 自动忽略。
type evtDocXML struct {
	XMLName   xml.Name     `xml:"Event"`
	System    evtSystemXML `xml:"System"`
	EventData evtXMLNode   `xml:"EventData"`
	UserData  evtXMLNode   `xml:"UserData"`
}

type evtSystemXML struct {
	EventID       evtEventIDXML `xml:"EventID"`
	Level         string        `xml:"Level"`
	EventRecordID string        `xml:"EventRecordID"`
	TimeCreated   struct {
		SystemTime string `xml:"SystemTime,attr"`
	} `xml:"TimeCreated"`
}

type evtEventIDXML struct {
	// Qualifiers 只为把属性"吃掉"而不参与解析：事件 ID 只取元素文本（契约）。
	Qualifiers string `xml:"Qualifiers,attr"`
	Text       string `xml:",chardata"`
}

// evtXMLNode 是递归节点：既当 EventData/UserData 的容器，也当其子元素。
// encoding/xml 的 ",any" 只匹配直接子元素，嵌套包装（如 1149 的
// UserData/EventXML）靠 collectEvtData 递归下钻。
type evtXMLNode struct {
	XMLName xml.Name
	Name    string       `xml:"Name,attr"`
	Value   string       `xml:",chardata"`
	Kids    []evtXMLNode `xml:",any"`
}

// collectEvtData 把节点列表按契约口径收进 out：
//   - <Data Name='X'>v</Data>          → 键 "x"（Name 小写，安全事件口径）；
//   - <Data>v</Data>（无名）           → 键 "data[i]"（i 跨调用递增，System 通道
//     全无名时即契约的 data[0]..data[n]）；
//   - 有子元素的包装元素                → 下钻（TSLSM 1149 的 UserData/EventXML）；
//   - 其他叶子元素（<User>、<Address>…）→ 键 = 元素名小写（UserData 口径）。
//
// 值保持原文不做 Trim：渲染 XML 是紧凑单行，原文即真实值。
func collectEvtData(nodes []evtXMLNode, out map[string]string, unnamed *int) {
	for _, n := range nodes {
		local := n.XMLName.Local
		if strings.EqualFold(local, "Data") {
			if n.Name != "" {
				out[strings.ToLower(n.Name)] = n.Value
			} else {
				out["data["+strconv.Itoa(*unnamed)+"]"] = n.Value
				*unnamed++
			}
			continue
		}
		if len(n.Kids) > 0 {
			collectEvtData(n.Kids, out, unnamed)
			continue
		}
		out[strings.ToLower(local)] = n.Value
	}
}
