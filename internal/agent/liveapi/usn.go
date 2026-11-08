package liveapi

// usn.go：/usn 卷级最近文件活动（USN journal 定点回溯扫描）。
//
// 调查价值：落地痕迹回溯——样本投放、勒索批量加密/改名、持久化文件写入
// 都在 journal 里留记录；USN 是 NTFS 自带的变更日志，覆盖探针停机/重启
// 窗口，补"文件监控只在探针存活时收事件"的盲区。
//
// 诚实边界（响应字段与注释双重声明，调查输出不许含糊）：
//   - USN 记录只有叶子文件名、没有目录信息（与 winapi/filewatch.go 及
//     补采管线同口径）：name 过滤是全卷叶子名匹配，不同目录的同名文件
//     无法区分；ext 过滤同理按叶子扩展名；
//   - 目录对象记录、纯 CLOSE（打开未改）记录不返回；
//   - 扫描从 journal 最旧可用位置向前、带三项预算硬顶（时间/记录数/
//     字节），任一达到即停并置 truncated=true + budget_note——长 journal
//     的卷返回的是"预算内能扫到的范围"，不是全量历史；scanned 含窗口外
//     与被跳过的记录，是真实扫描成本；
//   - matched 可大于 len(items)：环形截取只保留最近 max 条匹配。

import (
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"zedr/internal/agent/winapi"
	"zedr/internal/platform/apperr"
	"zedr/internal/platform/httpx"
)

const (
	usnDefaultMinutes = 10
	usnMaxMinutes     = 120

	usnDefaultMax = 200
	usnMaxItems   = 1000

	// 扫描预算硬顶。15s 与包内 /peers 的 5s 预算同量级偏松——USN 读取
	// 是逐块 DeviceIoControl，长 journal 的卷要扫到窗口位置；三项预算
	// 在 winapi.USNScan 的批量循环内逐轮检查，不是只在外层看一次。
	usnScanTimeout    = 15 * time.Second
	usnScanMaxRecords = 500000
	usnScanMaxBytes   = 128 << 20
)

// usnItem 是 items[] 的一行。
type usnItem struct {
	USN     uint64   `json:"usn"`
	TsUnix  int64    `json:"ts_unix"` // 变更时刻（USN 记录时间戳，非采集时刻）
	Name    string   `json:"name"`    // 叶子文件名，无目录信息（见文件头诚实边界）
	Reasons []string `json:"reasons"` // reason 位可读名，非空
}

// usnReasonBits 对照 Windows 文档 USN_REASON_* 常量（USN_RECORD_V2）。
// winapi/usn.go 有一组未导出的同值位定义（事件归类用），跨包取不到，
// 这里按位值独立成表——两处值需同步维护，改位先改 winapi。
var usnReasonBits = []struct {
	bit  uint32
	name string
}{
	{0x00000001, "data_overwrite"},
	{0x00000002, "data_extend"},
	{0x00000004, "data_truncation"},
	{0x00000010, "named_data_overwrite"},
	{0x00000020, "named_data_extend"},
	{0x00000040, "named_data_truncation"},
	{0x00000100, "file_create"},
	{0x00000200, "file_delete"},
	{0x00000400, "ea_change"},
	{0x00000800, "security_change"},
	{0x00001000, "rename_old_name"},
	{0x00002000, "rename_new_name"},
	{0x00004000, "indexable_change"},
	{0x00008000, "basic_info_change"},
	{0x00010000, "hard_link_change"},
	{0x00020000, "compression_change"},
	{0x00040000, "encryption_change"},
	{0x00080000, "object_id_change"},
	{0x00100000, "reparse_point_change"},
	{0x00200000, "stream_change"},
	{0x00400000, "transacted_change"},
	{0x00800000, "integrity_change"},
	{0x80000000, "close"},
}

// usnReasonNames 把 reason 位映射成可读名列表。未识别的位不静默吞掉：
// 拼成一条 unknown_0x... 残段，证据完整性优先于展示整洁。
func usnReasonNames(reason uint32) []string {
	names := make([]string, 0, 4)
	rest := reason
	for _, b := range usnReasonBits {
		if reason&b.bit != 0 {
			names = append(names, b.name)
			rest &^= b.bit
		}
	}
	if rest != 0 {
		names = append(names, fmt.Sprintf("unknown_0x%08x", rest))
	}
	return names
}

// normalizeUSNVolume 归一盘符参数："C:" / "C" / "C:\" / "c:/" 全收，
// 空串默认 "C:"；其余形态拒绝。
//
// 为什么不用 winapi.USNVolumeOf 归一：它把入参当目录走 filepath.Abs——
// 裸 "C" 会被解析成"进程当前盘上名为 C 的路径"再取卷名，调查员要查 Q:
// 却拿到 cwd 所在卷的数据属于误导性输出。这里按字面解析盘符，语义只有
// 一种，解析不了就 400。
func normalizeUSNVolume(raw string) (string, bool) {
	v := strings.TrimSpace(raw)
	if v == "" {
		return "C:", true
	}
	v = strings.TrimRight(v, `\/`)
	switch len(v) {
	case 1:
		v += ":"
	case 2:
		if v[1] != ':' {
			return "", false
		}
	default:
		return "", false
	}
	c := v[0]
	if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z') {
		return "", false
	}
	return strings.ToUpper(v), true
}

// usnVolumeValid 以 FixedNTFSVolumes 为卷合法性的唯一权威：它同时验证了
// 固定磁盘（可移动盘卷号漂移）与 journal 可查询（NTFS + 管理员句柄），
// 任何一项不满足本端点都扫不出东西，直接 400 比扫一半失败更诚实。
func usnVolumeValid(vol string) bool {
	for _, v := range winapi.FixedNTFSVolumes() {
		if v == vol {
			return true
		}
	}
	return false
}

// normalizeUSNExt 扩展名过滤归一：补点、小写；空串 = 不过滤。
func normalizeUSNExt(raw string) string {
	e := strings.ToLower(strings.TrimSpace(raw))
	if e == "" {
		return ""
	}
	if !strings.HasPrefix(e, ".") {
		e = "." + e
	}
	return e
}

// handleUSN 返回 GET /usn。
// 响应契约：
//
//	{
//	  "volume": "C:",
//	  "journal": {"first_usn": N, "next_usn": N} | null,  // null = journal 不可用
//	  "scanned": N,          // 实际扫过的记录数（含窗口外/目录/元数据记录）
//	  "matched": N,          // 窗口内 + name/ext 过滤后的匹配总数
//	  "items": [{usn, ts_unix, name, reasons:[...]}],     // 最多 max 条，保留最近
//	  "truncated": bool,     // 预算提前停止 或 matched > len(items)
//	  "budget_note?": "...", // 仅预算停止时出现
//	  "note?": "..."         // 仅 journal 不可用/中途失败时出现
//	}
func (s *server) handleUSN(w http.ResponseWriter, r *http.Request) {
	vol, ok := normalizeUSNVolume(r.URL.Query().Get("volume"))
	if !ok {
		httpx.WriteError(w, r, apperr.Invalid(`volume 必须是盘符形态（"C:" / "C" / "C:\"）`))
		return
	}
	if !usnVolumeValid(vol) {
		httpx.WriteError(w, r, apperr.Invalid("卷 %s 不是固定磁盘的 NTFS 卷，或 USN journal 不可用", vol))
		return
	}
	minutes := queryInt(r, "minutes", usnDefaultMinutes, 1, usnMaxMinutes)
	max := queryInt(r, "max", usnDefaultMax, 1, usnMaxItems)
	nameFilter := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("name")))
	extFilter := normalizeUSNExt(r.URL.Query().Get("ext"))

	cutoff := time.Now().Add(-time.Duration(minutes) * time.Minute)
	res := winapi.USNScan(vol, 0, cutoff, winapi.USNScanBudget{
		Timeout:    usnScanTimeout,
		MaxRecords: usnScanMaxRecords,
		MaxBytes:   usnScanMaxBytes,
	})

	out := map[string]any{
		"volume":  vol,
		"scanned": res.Scanned,
	}
	switch res.StoppedBy {
	case "volume", "journal":
		// 卷合法性刚验证过仍打不开/journal 查不到：被禁用、刚被删除或
		// 卷被移除的竞态。按"journal 在不在"是调查结论的口径给
		// 200 + journal:null，不 500；底层错误进日志不进响应（文案契约固定）。
		slog.Warn("liveapi_usn_journal_unavailable", "volume", vol,
			"stopped_by", res.StoppedBy, "err", res.Err)
		httpx.WriteJSON(w, r, http.StatusOK, map[string]any{
			"volume":    vol,
			"journal":   nil,
			"note":      "USN journal 不可用",
			"scanned":   0,
			"matched":   0,
			"items":     []usnItem{},
			"truncated": false,
		})
		return
	}
	out["journal"] = map[string]uint64{"first_usn": res.FirstUSN, "next_usn": res.NextUSN}

	items, matched := filterUSNRecords(res.Records, nameFilter, extFilter, max)
	out["matched"] = matched
	out["items"] = items

	// truncated 两个来源：扫描没覆盖全部 journal（预算/中途失败），
	// 或匹配数超出 max 被环形截取——任一发生都表示响应不完整。
	truncated := false
	switch res.StoppedBy {
	case "timeout":
		truncated = true
		out["budget_note"] = "达到 15s 扫描时间预算，未覆盖全部 journal"
	case "records":
		truncated = true
		out["budget_note"] = "达到 500000 条扫描记录预算，未覆盖全部 journal"
	case "bytes":
		truncated = true
		out["budget_note"] = "达到 128MB 读取预算，未覆盖全部 journal"
	case "error":
		truncated = true
		out["note"] = "扫描中途读取失败: " + errBrief(res.Err)
	}
	if matched > len(items) {
		truncated = true
	}
	out["truncated"] = truncated
	httpx.WriteJSON(w, r, http.StatusOK, out)
}

// filterUSNRecords 逐条应用 name/ext 过滤并用环形缓冲保留最近 max 条
// 匹配。记录按 USN 升序到达（journal 顺序 = 时间近似升序），"保留最近"
// 即保留序列尾部：环形覆盖后按 pos 旋回时间序，O(1) 每条，不做
// "命中即前移"的 O(n·max) 位移。
func filterUSNRecords(recs []winapi.USNRecord, nameFilter, extFilter string, max int) ([]usnItem, int) {
	items := make([]usnItem, 0, max)
	pos := 0
	matched := 0
	for _, rec := range recs {
		lname := strings.ToLower(rec.Name)
		if nameFilter != "" && !strings.Contains(lname, nameFilter) {
			continue
		}
		if extFilter != "" && !strings.HasSuffix(lname, extFilter) {
			continue
		}
		matched++
		item := usnItem{
			USN:     rec.USN,
			TsUnix:  rec.When.Unix(),
			Name:    rec.Name,
			Reasons: usnReasonNames(rec.Reason),
		}
		if len(items) < max {
			items = append(items, item)
			continue
		}
		items[pos] = item
		pos = (pos + 1) % max
	}
	// 环绕过且 pos≠0 时数组是"新→旧"接"旧→新"的旋转态，旋回时间序；
	// pos==0（未环绕或恰好整圈）时数组本来就是时间序。
	if len(items) == max && pos != 0 {
		rotated := make([]usnItem, 0, max)
		rotated = append(rotated, items[pos:]...)
		rotated = append(rotated, items[:pos]...)
		items = rotated
	}
	return items, matched
}
