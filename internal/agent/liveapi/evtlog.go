package liveapi

// evtlog.go：GET /evtlog —— 事件日志按需查询（隧道调查面）。
//
// 与探针常驻采集（HG_AGENT_EVTLOG 的 E1 订阅面）分工：那是"持续盯梢精选
// 事件喂检测管线"，这里是"分析师按通道/时间窗/事件 ID 即席取数"。走
// winapi.EvtReadLatest 反向读（最新→最旧），取满即停，不扫全通道。
//
// XPath 组装口径：Windows 事件日志查询是 XPath 1.0 的窄子集（wevtutil /q
// 与 Get-WinEvent -FilterXml 同语法）——顶层必须是 *[*] 选择器；System 节
// 点下 EventID=N 做相等比较（与 ParseEvtXML 剥离 Qualifiers 后的口径一致）；
// TimeCreated[timediff(@SystemTime) <= N] 过滤"距今 N 毫秒内"的事件，
// timediff 只接受非负整数毫秒（负值/表达式会被服务端拒绝），因此时间窗
// 统一换算 minutes*60000 拼进去。多 ID 用 or 连接（该子集无 in 语义，
// or 连接是 wevtutil 实测可用的保守形态）。
//
// 错误语义（契约）：
//   - ERROR_ACCESS_DENIED → 403（权限不足是环境问题，要报给操作员）；
//   - 通道不存在/打不开（15006/15007/15036 族）→ 200 + count:0——"此通道
//     没有可读事件"是调查结论（与 /fs/stat 的 exists:false 同语义），
//     打成 5xx 会让前端把"没有数据"误当"查询坏了"；
//   - 其余错误 → 500 内部错误，不吞。
//
// 输出字段映射（诚实边界）：items 是 ParseEvtXML 产物 EvtEvent 的最小投影，
// 只映射其真实导出字段（record_id/time_created/event_id/level/data）——
// EvtEvent 不携带 provider（evtSystemXML 未解析 Provider，evtlog.go 冻结
// 不可改），这里省略而非输出恒空串；主线扩展 ParseEvtXML 后在此补映射。

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/windows"

	"zedr/internal/agent/winapi"
	"zedr/internal/platform/apperr"
	"zedr/internal/platform/httpx"
)

const (
	evtlogChannelMaxLen = 200
	// evtlogIDsMax 事件 ID 上限：ID 列表拼进 XPath，过长会触发
	// ERROR_EVT_FILTER_TOO_COMPLEX，是服务端硬约束，不是拍脑袋的数。
	evtlogIDsMax = 32
	// evtlogMinutesMax 时间窗上限 24h：调查场景要的是"刚刚发生了什么"，
	// 更久远的历史让分析师去服务端事件库翻（那里有索引）。
	evtlogMinutesMax = 1440
	evtlogMax        = 200
	evtlogDefault    = 20
	evtlogBudget     = 15 * time.Second
)

// evtItem 是一条事件的最小投影（winapi.EvtEvent 的线协议形态）。
// time_created 为 unix 秒；解析失败（EvtEvent 零值）为 null——0 会伪装成
// 1970 年的事件，污染时间线。data 原样透传（键口径见 winapi.collectEvtData：
// Name 属性小写化 / 无名 Data 为 data[i]），恒非 null。
type evtItem struct {
	RecordID    uint64            `json:"record_id"`
	TimeCreated *int64            `json:"time_created"`
	EventID     uint16            `json:"event_id"`
	Level       uint8             `json:"level"`
	Data        map[string]string `json:"data"`
}

// evtResult 是 /evtlog 的完整响应（httpx.WriteJSON 包进 data）。
// items 按 RecordID 递减（新→旧，反向读的天然顺序，契约保证）。
type evtResult struct {
	Channel   string    `json:"channel"`
	XPath     string    `json:"xpath"` // 回显实际生效的查询，调查可复现
	Count     int       `json:"count"`
	Items     []evtItem `json:"items"`
	Truncated bool      `json:"truncated"` // 时间窗内命中超过 max（精确判定，见 handler 的 max+1 手法）
}

// handleEvtLog 返回 GET /evtlog（不依赖 Deps，路由由主会话接线）。
func (s *server) handleEvtLog(w http.ResponseWriter, r *http.Request) {
	channel := strings.TrimSpace(r.URL.Query().Get("channel"))
	if channel == "" {
		httpx.WriteError(w, r, apperr.Invalid("channel 必填"))
		return
	}
	if len(channel) > evtlogChannelMaxLen {
		httpx.WriteError(w, r, apperr.Invalid("channel 长度不得超过 %d", evtlogChannelMaxLen))
		return
	}
	ids := parseEvtIDs(r.URL.Query().Get("ids"))
	minutes := queryInt(r, "minutes", 60, 1, evtlogMinutesMax)
	max := queryInt(r, "max", evtlogDefault, 1, evtlogMax)
	xpath := buildEvtXPath(ids, minutes)

	// 15s 预算：EvtReadLatest 是 Win32 同步调用，不接受 context（无中途
	// 取消路径），deadline 检查在单次调用前形同虚设，因此用"后台执行 +
	// time.After 抢答"真实封顶。结果通道带 1 缓冲：超时抢答后内部调用
	// 自然结束、结果落缓冲被 GC，goroutine 不泄漏。内部 EvtNext 本身带
	// 1s 单批超时、64 条/批，max<=200 自然上界远低于预算，本分支是防挂
	// 死保险（regwatch 教训：绝不依赖阻塞调用按时返回）。
	type evtQueryResult struct {
		events []winapi.EvtEvent
		err    error
	}
	done := make(chan evtQueryResult, 1)
	go func() {
		defer func() {
			if rec := recover(); rec != nil {
				// recoverWrap 接不到别的 goroutine 的 panic，进程级
				// 崩溃必须在这里就地兜住
				done <- evtQueryResult{err: fmt.Errorf("evtlog: 查询 panic: %v", rec)}
			}
		}()
		evs, _, err := winapi.EvtReadLatest(channel, xpath, max+1)
		done <- evtQueryResult{events: evs, err: err}
	}()

	timer := time.NewTimer(evtlogBudget)
	defer timer.Stop()
	select {
	case <-timer.C:
		httpx.WriteError(w, r, apperr.Unavailable("事件查询超出 15s 预算，可缩小 minutes/max 后重试"))
		return
	case res := <-done:
		if res.err != nil {
			writeEvtLogErr(w, r, channel, xpath, res.err)
			return
		}
		// truncated 精确判定：多取一条（max+1），拿满 max+1 条说明窗内
		// 命中确实超过 max；恰好 max 条则不算截断。
		events := res.events
		truncated := false
		if len(events) > max {
			truncated = true
			events = events[:max]
		}
		items := make([]evtItem, 0, len(events))
		for i := range events {
			ev := &events[i]
			item := evtItem{
				RecordID: ev.RecordID,
				EventID:  ev.EventID,
				Level:    ev.Level,
				Data:     ev.Data,
			}
			if !ev.TimeCreated.IsZero() {
				ts := ev.TimeCreated.Unix()
				item.TimeCreated = &ts
			}
			items = append(items, item)
		}
		httpx.WriteJSON(w, r, http.StatusOK, evtResult{
			Channel:   channel,
			XPath:     xpath,
			Count:     len(items),
			Items:     items,
			Truncated: truncated,
		})
	}
}

// buildEvtXPath 组装通道查询 XPath（语法口径见文件头注释）。
func buildEvtXPath(ids []uint16, minutes int) string {
	ms := minutes * 60000
	if len(ids) == 0 {
		return fmt.Sprintf("*[System[TimeCreated[timediff(@SystemTime) <= %d]]]", ms)
	}
	parts := make([]string, 0, len(ids))
	for _, id := range ids {
		parts = append(parts, fmt.Sprintf("EventID=%d", id))
	}
	return fmt.Sprintf("*[System[(%s) and TimeCreated[timediff(@SystemTime) <= %d]]]",
		strings.Join(parts, " or "), ms)
}

// parseEvtIDs 解析逗号分隔的事件 ID：非法 token 忽略（手敲 ID 混入空格/
// 杂字符不该 400 打断调查），去重后按出现顺序截到 evtlogIDsMax（钳制哲学
// 同 queryInt；上限是 XPath 复杂度硬约束，见 evtlogIDsMax 注释）。
func parseEvtIDs(raw string) []uint16 {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	seen := make(map[uint16]struct{}, evtlogIDsMax)
	ids := make([]uint16, 0, evtlogIDsMax)
	for _, tok := range strings.Split(raw, ",") {
		v, err := strconv.ParseUint(strings.TrimSpace(tok), 10, 16)
		if err != nil {
			continue
		}
		id := uint16(v)
		if _, dup := seen[id]; dup {
			continue
		}
		seen[id] = struct{}{}
		ids = append(ids, id)
		if len(ids) >= evtlogIDsMax {
			break
		}
	}
	return ids
}

// writeEvtLogErr 把 EvtReadLatest 的错误转成规范 HTTP 语义（口径见文件头）。
func writeEvtLogErr(w http.ResponseWriter, r *http.Request, channel, xpath string, err error) {
	switch {
	case errors.Is(err, windows.ERROR_ACCESS_DENIED):
		httpx.WriteError(w, r, apperr.Forbidden(
			"事件通道 \""+channel+"\" 读取被系统拒绝（需要本地管理员或事件日志读者权限）"))
	case errors.Is(err, windows.ERROR_EVT_CHANNEL_NOT_FOUND), // 15007 找不到通道
		errors.Is(err, windows.ERROR_EVT_INVALID_CHANNEL_PATH),         // 15006 通道路径非法
		errors.Is(err, windows.ERROR_EVT_CANNOT_OPEN_CHANNEL_OF_QUERY): // 15036 查询内通道打不开
		// "没有这个通道"是调查结论，200 + 空结果（与 /fs/stat 同语义）
		httpx.WriteJSON(w, r, http.StatusOK, evtResult{
			Channel: channel,
			XPath:   xpath,
			Items:   []evtItem{},
		})
	default:
		httpx.WriteError(w, r, apperr.Internal(err))
	}
}
