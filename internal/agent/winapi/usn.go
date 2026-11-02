// Package winapi 的 USN Journal 断点补采。
//
// 解决什么问题：ReadDirectoryChangesW 只在进程存活时收事件。探针升级、
// 服务重启、崩溃恢复期间落地的文件完全漏掉——攻击者恰好可以利用这个窗口
// "先停安全软件再投放载荷"。USN Journal 是 NTFS 自带的变更日志，用户态
// 通过 FSCTL_READ_USN_JOURNAL 就能读到停机期间的创建/改名/写入记录，
// 不需要驱动、不需要 Hook。
//
// 诚实边界：
//   - USN 记录只带 leaf name 与父目录 FRN，不带完整路径。解析完整路径需要
//     OpenFileById + 提权遍历，成本高；这里只取 leaf name，交给现有
//     FileWatcher 的 byBase 兜底索引（与"路径解析不完整"时的既有兜底同口径）。
//   - 只有 NTFS 卷有 USN；FAT/网络盘/非管理员句柄会失败，失败即降级。
//   - 补采有记录数上限，超出部分推进到已处理位置并在日志中如实报告，
//     不假装全量。
package winapi

import (
	"encoding/binary"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf16"

	"golang.org/x/sys/windows"
)

const (
	fsctlQueryUSNJournal = 0x000900f4
	fsctlReadUSNJournal  = 0x000900bb

	usnReasonDataOverwrite = 0x00000001
	usnReasonDataExtend    = 0x00000002
	usnReasonDataTruncation = 0x00000004
	usnReasonFileCreate    = 0x00000100
	usnReasonRenameNewName = 0x00002000

	fileAttributeDirectory = 0x00000010
)

// USNEvent 是一条补采到的文件变更（只保留与"落地"相关的 reason）。
type USNEvent struct {
	Name   string    // 文件名（leaf name，不含目录）
	When   time.Time // 变更发生时间（来自 USN 记录，不是采集时刻）
	Reason uint32
}

// USNVolumeOf 返回目录所在卷（形如 "C:"）；UNC/非盘符路径返回 false。
func USNVolumeOf(dir string) (string, bool) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return "", false
	}
	vol := filepath.VolumeName(abs)
	if len(vol) != 2 || vol[1] != ':' {
		return "", false
	}
	return strings.ToUpper(vol), true
}

// ReadUSNJournal 从 startUSN 开始读取某卷的 USN 变更。
//
// 返回：
//   - events：过滤后的文件落地事件（目录、删除、纯元数据变更已剔除）；
//   - nextUSN：下次应从哪个 USN 继续（已准确推进到最后一条已处理记录之后）；
//   - journalID：当前卷的 journal ID（用于检测日志被重建）；
//   - reset：journal ID 不匹配/检查点越界，调用方应把它当作新基线；
//   - err：打不开卷/无权限等，调用方降级即可。
//
// startUSN=0 或 journalID=0 表示首次运行：不回溯历史，直接把基线
// 推到当前 NextUSN（否则第一次启动会把整段 journal 历史当成"刚落地的文件"）。
func ReadUSNJournal(volume string, startUSN, journalID uint64, maxRecords int) (
	events []USNEvent, nextUSN uint64, curJournalID uint64, reset bool, err error,
) {
	if maxRecords <= 0 {
		maxRecords = 5000
	}
	if maxRecords > 20000 {
		maxRecords = 20000
	}

	h, err := openVolume(volume)
	if err != nil {
		return nil, 0, 0, false, err
	}
	defer windows.CloseHandle(h)

	first, next, curID, err := queryUSNJournal(h)
	if err != nil {
		return nil, 0, 0, false, err
	}
	curJournalID = curID

	if journalID == 0 || startUSN == 0 {
		return nil, next, curID, false, nil
	}
	if curID != journalID {
		return nil, next, curID, true, nil
	}
	start := startUSN
	if start < first {
		// 检查点早于 journal 保留窗口：最旧可用位置开始，reset 如实上报。
		start = first
		reset = true
	}
	if start > next {
		return nil, next, curID, true, nil
	}

	const outSize = 256 << 10
	out := make([]byte, outSize)
	progress := start
	for iter := 0; iter < 64; iter++ {
		if len(events) >= maxRecords {
			break
		}
		got, ioErr := readUSNJournalChunk(h, progress, curID, out)
		if ioErr != nil {
			if errors.Is(ioErr, windows.ERROR_HANDLE_EOF) {
				break
			}
			return events, progress, curID, reset, ioErr
		}
		if got <= 8 {
			progress = next
			break
		}
		parsed, chunkNext, truncated := parseUSNBuffer(out[:got], maxRecords-len(events))
		events = append(events, parsed...)
		progress = chunkNext
		if truncated {
			break
		}
		if progress >= next {
			break
		}
	}
	return events, progress, curID, reset, nil
}

func openVolume(volume string) (windows.Handle, error) {
	// volume 形如 "C:"；CreateFile 需要 \\.\C: 形式。
	v := strings.TrimSuffix(volume, ":")
	path := `\\.\` + v + ":"
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return windows.InvalidHandle, err
	}
	h, err := windows.CreateFile(p, windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		return windows.InvalidHandle, fmt.Errorf("打开卷 %s 失败（USN 补采需要管理员权限）: %w", volume, err)
	}
	return h, nil
}

// queryUSNJournal 返回 (FirstUsn, NextUsn, JournalID)。
func queryUSNJournal(h windows.Handle) (first, next, id uint64, err error) {
	// USN_JOURNAL_DATA_V0 是 7 个 DWORDLONG = 56 字节，不是 40！
	// V1 再追加 Min/MaxSupportedMajorVersion + Flags = 64 字节。
	// 缓冲区给小了内核直接返回 ERROR_INVALID_USER_BUFFER（实测踩过）。
	buf := make([]byte, 64)
	var returned uint32
	if err := windows.DeviceIoControl(h, fsctlQueryUSNJournal, nil, 0,
		&buf[0], uint32(len(buf)), &returned, nil); err != nil {
		return 0, 0, 0, fmt.Errorf("查询 USN Journal 失败: %w", err)
	}
	if returned < 56 {
		return 0, 0, 0, fmt.Errorf("USN Journal 响应过短: %d", returned)
	}
	id = binary.LittleEndian.Uint64(buf[0:8])
	first = binary.LittleEndian.Uint64(buf[8:16])
	next = binary.LittleEndian.Uint64(buf[16:24])
	return first, next, id, nil
}

// readUSNJournalChunk 读取一段。返回值包含 8 字节 next USN + 若干记录。
func readUSNJournalChunk(h windows.Handle, start, journalID uint64, out []byte) (int, error) {
	in := make([]byte, 40) // READ_USN_JOURNAL_DATA_V0
	binary.LittleEndian.PutUint64(in[0:8], start)
	binary.LittleEndian.PutUint32(in[8:12], 0xFFFFFFFF) // ReasonMask：全部原因，Go 侧过滤
	binary.LittleEndian.PutUint32(in[12:16], 0)         // ReturnOnlyOnClose=0，避免漏掉仍打开的文件
	binary.LittleEndian.PutUint64(in[16:24], 0)         // Timeout
	binary.LittleEndian.PutUint64(in[24:32], 0)         // BytesToWaitFor
	binary.LittleEndian.PutUint64(in[32:40], journalID)

	var returned uint32
	err := windows.DeviceIoControl(h, fsctlReadUSNJournal,
		&in[0], uint32(len(in)), &out[0], uint32(len(out)), &returned, nil)
	if err != nil {
		return 0, err
	}
	return int(returned), nil
}

// parseUSNBuffer 解析 DeviceIoControl 的输出缓冲。
//
// 纯函数，便于用合成缓冲做单测（不需要管理员权限/真实卷）。
// truncated=true 表示因 max 条数上限在记录中间停止，chunkNext 指向
// 第一条未处理记录的 USN，下次从这里继续不会漏。
func parseUSNBuffer(buf []byte, max int) (events []USNEvent, chunkNext uint64, truncated bool) {
	if len(buf) < 8 {
		return nil, 0, false
	}
	chunkNext = binary.LittleEndian.Uint64(buf[0:8])
	payload := buf[8:]
	for len(payload) >= 60 {
		recLen := int(binary.LittleEndian.Uint32(payload[0:4]))
		if recLen < 60 || recLen > len(payload) {
			break
		}
		major := binary.LittleEndian.Uint16(payload[4:6])
		reason := binary.LittleEndian.Uint32(payload[40:44])
		attrs := binary.LittleEndian.Uint32(payload[52:56])
		nameLen := int(binary.LittleEndian.Uint16(payload[56:58]))
		nameOff := int(binary.LittleEndian.Uint16(payload[58:60]))
		usn := binary.LittleEndian.Uint64(payload[24:32])
		ts := int64(binary.LittleEndian.Uint64(payload[32:40]))

		if max > 0 && len(events) >= max {
			// 这条记录不处理，下次从它的 USN 继续。用 usn 而不是 usn+1：
			// FSCTL_READ_USN_JOURNAL 的语义是"USN >= StartUsn"，+1 会
			// 把这条未处理的记录永久跳过。
			return events, usn, true
		}

		if major == 2 && isDropReason(reason) && attrs&fileAttributeDirectory == 0 &&
			nameOff >= 60 && nameLen > 0 && nameOff+nameLen <= recLen {
			name := decodeUSNName(payload[nameOff : nameOff+nameLen])
			if name != "" && name != "." && name != ".." {
				events = append(events, USNEvent{
					Name: name, When: usnTime(ts), Reason: reason,
				})
			}
		}
		payload = payload[recLen:]
	}
	return events, chunkNext, false
}

func isDropReason(reason uint32) bool {
	return reason&(usnReasonFileCreate|usnReasonRenameNewName|
		usnReasonDataOverwrite|usnReasonDataExtend|usnReasonDataTruncation) != 0
}

func decodeUSNName(raw []byte) string {
	if len(raw) < 2 || len(raw)%2 != 0 {
		return ""
	}
	u := make([]uint16, 0, len(raw)/2)
	for i := 0; i+1 < len(raw); i += 2 {
		u = append(u, uint16(raw[i])|uint16(raw[i+1])<<8)
	}
	return string(utf16.Decode(u))
}

func usnTime(ft int64) time.Time {
	const epochDiff = 116444736000000000
	ns := (ft - epochDiff) * 100
	if ns <= 0 {
		return time.Time{}
	}
	return time.Unix(0, ns).UTC()
}
