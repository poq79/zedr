//go:build windows
// +build windows

package winapi

// evtquery.go：反向事件查询原语（"取某通道最近 N 条"，交互式调查用）。
//
// 为什么不复用 EvtReadBatch：那是正向游标语义（RecordID > sinceID，升序，
// 服务采集层断点续传），要拿"最新一批"只能从最旧端扫全通道再取尾部，大
// 通道上成本差一个数量级。这里直接用 EvtQueryReverseDirection (0x200) 让
// 事件服务从最新端反向迭代，取满即停。全部复用 evtlog.go 的包内 unexported
// 绑定（procEvtQuery/procEvtNext/evtRenderXML/evtClose*/ParseEvtXML），
// 零新增系统调用面。
//
// 方向口径同 evtlog.go 文件头（2026-11 真机实测）：默认方向=最旧→最新；
// ReverseDirection=最新→最旧。返回顺序保留反向读的天然"新→旧"，只做一次
// 防御性降序排序（同 EvtReadBatch 对升序的防御姿态：不依赖系统返回顺序
// 的内部实现细节）。

import (
	"fmt"
	"sort"
	"unsafe"

	"golang.org/x/sys/windows"
)

// evtQueryReverseDirection 是 EvtQuery 的反向迭代标志（winevt.h 的
// EvtQueryReverseDirection = 0x200）。x/sys 未封装 Evt* API，标志位与
// evtlog.go 的 evtQueryChannelPath 一并在本地定义。
const evtQueryReverseDirection = 0x00000200

// EvtReadLatest 从通道按"最新→最旧"取最多 maxEvents 条事件。
//
// channel 形如 "System"；xpath 是查询过滤（Windows 事件日志 XPath 1.0
// 子集，形如 "*[System[(EventID=7045)]]"），空串按 "*"（全事件）处理。
// 返回值口径与 EvtReadBatch 对齐：
//   - []EvtEvent：ParseEvtXML 的产物，顺序为新→旧（RecordID 严格递减，
//     契约保证）；单条渲染/解析失败跳过该条继续（宁少一条不丢整批）；
//   - uint64：批内最大 RecordID（即新→旧的首条），可直接作为后续
//     EvtReadBatch 的 sinceID 游标基线；空结果为 0；
//   - error：通道不存在/无权限/查询非法——包装 windows 错误码的可判错误
//     （errors.Is 可比对 windows.Errno，如 ERROR_ACCESS_DENIED /
//     ERROR_EVT_CHANNEL_NOT_FOUND），调用方可区分降级。
//
// maxEvents <= 0 或超过 evtMaxEventsCap 时按 evtMaxEventsCap 钳制（同
// EvtReadBatch 契约）。可并发调用（无共享状态，句柄自管理）。
func EvtReadLatest(channel, xpath string, maxEvents int) ([]EvtEvent, uint64, error) {
	if maxEvents <= 0 || maxEvents > evtMaxEventsCap {
		maxEvents = evtMaxEventsCap // 契约：默认/钳制 512
	}
	chPtr, err := windows.UTF16PtrFromString(channel)
	if err != nil {
		return nil, 0, fmt.Errorf("evtquery: 通道名非法 %q: %w", channel, err)
	}
	if xpath == "" {
		xpath = "*" // 空过滤 = 全事件（wevtutil /q:"*" 同口径）
	}
	xp, err := windows.UTF16PtrFromString(xpath)
	if err != nil {
		return nil, 0, fmt.Errorf("evtquery: XPath 非法 %q: %w", xpath, err)
	}

	// EvtQuery 本身是惰性的（只建查询句柄），真正的遍历成本在 EvtNext；
	// "最新在前"意味着取满即停、不扫旧数据。
	qh, _, e := procEvtQuery.Call(0, uintptr(unsafe.Pointer(chPtr)),
		uintptr(unsafe.Pointer(xp)), evtQueryChannelPath|evtQueryReverseDirection)
	if qh == 0 {
		// errno 原样包装保持可判：调用方按 ERROR_ACCESS_DENIED /
		// ERROR_EVT_CHANNEL_NOT_FOUND 区分"无权限"与"没有这个通道"。
		return nil, 0, fmt.Errorf("evtquery: EvtQuery(%q) 打开失败: %w", channel, evtErrno(e))
	}
	defer evtClose(qh)

	events := make([]EvtEvent, 0, min(maxEvents, evtNextBatchSize))
	var maxRecordID uint64
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
				break scan // 反向走到头 / 暂无更多（同 EvtReadBatch 防挂死口径）
			default:
				return nil, 0, fmt.Errorf("evtquery: EvtNext(%q) 失败: %w", channel, en)
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
				return nil, 0, fmt.Errorf("evtquery: 渲染事件失败(%q): %w", channel, rerr)
			}
			ev, perr := ParseEvtXML(channel, xmlText)
			if perr != nil {
				continue // 单条畸形只跳过，不拖垮整批（同 EvtReadBatch）
			}
			if ev.RecordID > maxRecordID {
				maxRecordID = ev.RecordID
			}
			events = append(events, *ev)
			if len(events) >= maxEvents {
				// 封顶即停：本批剩余句柄先全部关掉再退出（防句柄泄漏）。
				evtCloseBatch(hs, i+1)
				break scan
			}
		}
	}

	sort.Slice(events, func(i, j int) bool { return events[i].RecordID > events[j].RecordID })
	return events, maxRecordID, nil
}
