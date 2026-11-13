//go:build windows
// +build windows

package winapi

// usnsnapshot.go：USN journal 定点回溯扫描（liveapi /usn 调查端点专用）。
//
// 与 usn.go 的 ReadUSNJournal（断点补采）的分工：补采面向增量消费，输出
// 按 Kind 归类的五类事件、不带记录 USN 值（USNEvent 无此字段）；本文件
// 面向"从 journal 最旧可用位置向前、带资源硬顶的有界回溯"，逐条保留
// 原始 reason 位与记录 USN，供调查端点自行过滤与展示。两处记录布局
// 解析（parseUSNBuffer / parseUSNSnapshot）偏移必须同步维护——
// USN_RECORD_V2 布局认知变更时两个解析器都要改（文件头互相引用）。
//
// 只读：只开卷句柄 + DeviceIoControl 查询/读取，不写 journal、不碰
// app 层检查点；与补采轮询的读可并发（各自独立句柄，FSCTL 读取不互斥）。
// 预算三项（时间/记录数/字节）在批量循环内逐轮检查，任一达到即停——
// 时间检查必须放在循环内而不是循环外（单块 256KB 读取 + 解析在大
// journal 上也会积少成多）。

import (
	"encoding/binary"
	"errors"
	"time"

	"golang.org/x/sys/windows"
)

// usnReasonClose 是 usn.go 位定义里缺的 CLOSE 位（0x80000000）。
// 这里只用于"剔除纯 CLOSE 记录"的判断，不参与事件归类。
const usnReasonClose = 0x80000000

// USNRecord 是一条 USN journal 原始记录（快照口径，reason 位不归类）。
type USNRecord struct {
	USN    uint64
	FRN    uint64
	Name   string // 叶子文件名，不含目录（USN 固有限制）
	When   time.Time
	Reason uint32
}

// USNScanBudget 是一次扫描的资源硬顶，三项同时生效、任一达到即停。
// 零值表示该项不设限（调用方应始终显式给齐，快照端点不允许无预算扫描）。
type USNScanBudget struct {
	Timeout    time.Duration // 墙钟硬顶；0 = 不限时
	MaxRecords int           // 扫描记录数硬顶（含被跳过的目录/元数据/窗口外记录）；0 = 不限
	MaxBytes   int64         // DeviceIoControl 实读字节硬顶；0 = 不限
}

// USNScanResult 是一次扫描的产出。
type USNScanResult struct {
	Records   []USNRecord // 窗口内（When >= cutoff）且可保留的记录，按 USN 升序
	FirstUSN  uint64
	NextUSN   uint64
	JournalID uint64
	// Scanned 是实际扫过的记录总数：含目录、纯元数据、窗口外与纯 CLOSE
	// 记录——"扫描成本"与"保留结果"分开报，调用方才能如实展示覆盖面。
	Scanned   int
	BytesRead int64
	// StoppedBy 说明扫描为何停止：
	//   end     = 读到 journal 当前末尾（正常结束）；
	//   timeout/records/bytes = 对应预算用尽；
	//   error   = 中途读取失败（Records 保留已取得部分）；
	//   journal = journal 查询失败（被禁用/不存在/非 NTFS）；
	//   volume  = 卷打不开（权限/卷消失）。
	StoppedBy string
	Err       error
}

// USNScan 从 fromUSN 起向前扫描某卷 USN journal，逐块读取并在批量循环内
// 检查预算。fromUSN=0 表示从 journal 最旧可用位置（FirstUSN）开始；
// 早于 FirstUSN 的起点一律收敛到 FirstUSN（journal 保留窗口之外的
// 历史不可恢复，调用方按"覆盖从最旧可用记录开始"理解）。
//
// cutoff 之前的记录计入 Scanned 但不保留（时间过滤在解析处做，避免
// 长 journal 场景把几十年前的记录原样塞给调用方再丢）。
func USNScan(volume string, fromUSN uint64, cutoff time.Time, budget USNScanBudget) USNScanResult {
	res := USNScanResult{StoppedBy: "end"}

	h, err := openVolume(volume)
	if err != nil {
		res.StoppedBy = "volume"
		res.Err = err
		return res
	}
	defer windows.CloseHandle(h)

	first, next, id, err := queryUSNJournal(h)
	if err != nil {
		res.StoppedBy = "journal"
		res.Err = err
		return res
	}
	res.FirstUSN, res.NextUSN, res.JournalID = first, next, id

	if fromUSN < first {
		fromUSN = first
	}
	if fromUSN > next {
		// 起点越过当前末尾（并发消费把位置推过去了）：无事可扫，不是错误
		return res
	}

	var deadline time.Time
	if budget.Timeout > 0 {
		deadline = time.Now().Add(budget.Timeout)
	}
	out := make([]byte, 256<<10)
	progress := fromUSN
	for {
		// 预算检查在每轮批量开头：单块读取 + 解析不可中断，硬顶的
		// 精度就是"一块"，(256KB / ~60B) ≈ 4400 条以内的过冲被
		// parseUSNSnapshot 的剩余配额参数压到精确。
		if budget.MaxRecords > 0 && res.Scanned >= budget.MaxRecords {
			res.StoppedBy = "records"
			return res
		}
		if budget.MaxBytes > 0 && res.BytesRead >= budget.MaxBytes {
			res.StoppedBy = "bytes"
			return res
		}
		if !deadline.IsZero() && !time.Now().Before(deadline) {
			res.StoppedBy = "timeout"
			return res
		}

		got, ioErr := readUSNJournalChunk(h, progress, id, out)
		if ioErr != nil {
			if errors.Is(ioErr, windows.ERROR_HANDLE_EOF) {
				return res // StoppedBy 保持 "end"
			}
			res.StoppedBy = "error"
			res.Err = ioErr
			return res
		}
		if got <= 8 {
			return res // 只剩 8 字节 next USN 头 = 已到末尾
		}
		res.BytesRead += int64(got)

		remaining := -1
		if budget.MaxRecords > 0 {
			remaining = budget.MaxRecords - res.Scanned
		}
		kept, chunkNext, scanned, hitCap := parseUSNSnapshot(out[:got], cutoff, remaining)
		res.Records = append(res.Records, kept...)
		res.Scanned += scanned
		progress = chunkNext
		if hitCap {
			// 记录数预算在块中间用尽：下一轮循环顶部的检查会以
			// "records" 收口，未扫的尾部不算 scanned（诚实口径）。
			continue
		}
		if progress >= next {
			return res
		}
	}
}

// parseUSNSnapshot 解析一块读取缓冲（布局偏移与 parseUSNBuffer 完全一致，
// 两处必须同步维护）。保留口径：major=2、非目录、叶子名合法、除 CLOSE 外
// 还有其他 reason 位（纯 CLOSE = 打开未改，无调查价值）、时间在窗口内。
// maxScan <= 0 表示不限；达到时停在记录边界，chunkNext 指向第一条未处理
// 记录的 USN（与 parseUSNBuffer 截断语义相同，从该位置重读不会漏）。
func parseUSNSnapshot(buf []byte, cutoff time.Time, maxScan int) (
	kept []USNRecord, chunkNext uint64, scanned int, hitCap bool,
) {
	if len(buf) < 8 {
		return nil, 0, 0, false
	}
	chunkNext = binary.LittleEndian.Uint64(buf[0:8])
	payload := buf[8:]
	for len(payload) >= 60 {
		recLen := int(binary.LittleEndian.Uint32(payload[0:4]))
		if recLen < 60 || recLen > len(payload) {
			break
		}
		if maxScan > 0 && scanned >= maxScan {
			// 这条不处理：chunkNext 停在它的 USN 上（同 parseUSNBuffer，
			// 用 usn 本身而非 +1——FSCTL 语义是 "USN >= StartUsn"）
			return kept, binary.LittleEndian.Uint64(payload[24:32]), scanned, true
		}
		scanned++
		major := binary.LittleEndian.Uint16(payload[4:6])
		reason := binary.LittleEndian.Uint32(payload[40:44])
		attrs := binary.LittleEndian.Uint32(payload[52:56])
		nameLen := int(binary.LittleEndian.Uint16(payload[56:58]))
		nameOff := int(binary.LittleEndian.Uint16(payload[58:60]))

		if major == 2 && attrs&fileAttributeDirectory == 0 &&
			nameOff >= 60 && nameLen > 0 && nameOff+nameLen <= recLen &&
			reason&^usnReasonClose != 0 {
			name := decodeUSNName(payload[nameOff : nameOff+nameLen])
			if name != "" && name != "." && name != ".." {
				when := usnTime(int64(binary.LittleEndian.Uint64(payload[32:40])))
				if !when.Before(cutoff) {
					kept = append(kept, USNRecord{
						USN:    binary.LittleEndian.Uint64(payload[24:32]),
						FRN:    binary.LittleEndian.Uint64(payload[8:16]),
						Name:   name,
						When:   when,
						Reason: reason,
					})
				}
			}
		}
		payload = payload[recLen:]
	}
	return kept, chunkNext, scanned, false
}
