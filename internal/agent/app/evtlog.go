// evtlog 接线层（E1）：Windows 事件日志 → 精选事件 → 统一告警出口。
//
// 与 USN 轮询同哲学：轮询式只读消费（30s/tick，游标增量），不用
// EvtSubscribe 推模式——回调线程绑定坑在 regwatch 已实锤过。
// 精选首批事件（低噪声高信号，定义见 evtChannels）：
//   - 7045 服务安装（持久化 T1543.003 的 OS 权威证据，秒级补 persist 轮询）
//   - 104  事件日志服务停止并清日志（反取证 T1070.001）
//   - 4625 登录失败（暴破 T1110）——量大，窗口聚合后才告警
//   - 1149 RDP 入站会话（横向 T1021.001）
//
// 诚实边界（同步 DETECTION §3.6.3）：
//   - 只读订阅，不改任何审核策略：4625 需要"审核登录失败"开启，未开启
//     的机器该通道无事件（不是故障也不告警）；
//   - 游标存 evt.json（per-channel RecordID）；通道日志被清/滚动导致
//     游标悬空时按最旧记录重置基线——清空场景的旧事件本就不在了，
//     104 自身若被一并清掉也如实接受；
//   - 首次运行只推进游标不告警（与 persist 首轮建基线同款哲学）；
//   - 4625 聚合窗口是内存态，重启清零——重启恰是攻击窗口，但离线告警
//     队列已保证"重启前"的告警不丢。
package agentapp

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"zedr/internal/agent/winapi"
	"zedr/internal/model"
)

const (
	evtCursorFile     = "evt.json"
	evtBatchSize      = 512         // 单通道单 tick 上限：事件源按 ID 过滤后量很小
	evtMaxCatchUp     = 16          // 首次基线推进循环上限（过滤后结果集小，很快拉空）
	evtBruteWindow    = time.Minute // 登录失败聚合窗口
	evtBruteThreshold = 10          // 窗口内次数阈值
	evtBruteCap       = 256         // 聚合窗口样本上限（防内存无界）
)

// evtChannelDef 是订阅的通道定义。
type evtChannelDef struct {
	name  string
	xpath string
}

// evtChannels 是首批订阅清单。System 通道事件是无名 Data（data[0..]），
// Security/TSLSM 是 Name 属性型——两种口径 winapi.parseEvtXML 都归一成
// map。XPath 在查询层过滤（通道全量不进探针），这是 4625 量级可控的前提。
// 1102（Security 日志清空）需"审核策略变更"审计开启；4698 需对象访问审计
// 子类——未开启的机器上对应事件缺失（诚实边界，见 DETECTION §3.6.3）。
var evtChannels = []evtChannelDef{
	{"System", "*[System[(EventID=7045) or (EventID=104)]]"},
	{"Security", "*[System[(EventID=4624) or (EventID=4625) or (EventID=4698) or (EventID=1102) " +
		"or (EventID=4720) or (EventID=4726) or (EventID=4728) or (EventID=4732) or (EventID=4719)]]"},
	{"Microsoft-Windows-TerminalServices-LocalSessionManager/Operational", "*[System[(EventID=1149)]]"},
	{"Microsoft-Windows-PowerShell/Operational", "*[System[(EventID=4104)]]"},
}

type evtCursor struct {
	Channels map[string]uint64 `json:"channels"`
}

// evtBruteRec 是聚合窗口内的一条登录失败样本。
type evtBruteRec struct {
	at   time.Time
	ip   string
	user string
}

// evtBruteAgg 是 4625 的滑动窗口聚合器（evtlogLoop 单 goroutine 访问，
// 锁是防御性的——与未来多消费者隔离）。
type evtBruteAgg struct {
	mu      sync.Mutex
	window  []evtBruteRec
	lastHit time.Time // 冷却
}

// startEvtLog 启动事件日志轮询循环（开关关闭时不启动）。
func (a *Agent) startEvtLog(ctx context.Context) {
	if !a.cfg.EvtLog {
		return
	}
	go a.evtlogLoop(ctx)
}

func (a *Agent) evtlogLoop(ctx context.Context) {
	cp := a.loadEvtCursor()
	if cp.Channels == nil {
		cp.Channels = map[string]uint64{}
	}

	// 错峰：首 tick 推迟 20s（与 USN 轮询 10s、清单 30s 相位错开）
	select {
	case <-ctx.Done():
		return
	case <-time.After(20 * time.Second):
	}
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	first := true
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		changed := false
		alive := 0
		for _, ch := range evtChannels {
			since := cp.Channels[ch.name]
			if first {
				// 首轮基线：把过滤后的存量拉空，只推进游标不告警
				since = a.evtBaseline(ch, since)
				cp.Channels[ch.name] = since
				changed = true
				alive++
				continue
			}
			events, last, err := winapi.EvtReadBatch(ch.name, ch.xpath, since, evtBatchSize)
			if err != nil {
				a.log.Warn("evtlog_read_failed", "channel", ch.name, "err", err)
				continue
			}
			alive++
			// 游标悬空检测：空批且检查点已低于通道最旧记录 = 日志被清/滚动。
			// 不处理的话 RecordID 从头重新计数，所有新事件都 < sinceID 被
			// 过滤——通道永久失明，而"日志被清"恰是 104 要抓的场景。
			// 重置为最旧记录之前一格（被清掉的旧事件如实接受）。
			if len(events) == 0 && since > 0 {
				if oldest, oerr := winapi.EvtChannelOldestRecordID(ch.name); oerr == nil &&
					oldest > 0 && oldest > since+1 {
					a.log.Warn("evtlog_cursor_reset", "channel", ch.name,
						"old_cursor", since, "new_baseline", oldest-1)
					cp.Channels[ch.name] = oldest - 1
					changed = true
				}
				continue
			}
			a.dispatchEvtEvents(ch.name, events)
			if last != since {
				cp.Channels[ch.name] = last
				changed = true
			}
		}
		a.evtChannels.Store(int64(alive))
		first = false
		if changed {
			a.saveEvtCursor(cp)
		}
	}
}

// evtBaseline 把通道过滤后的存量拉空，返回最终游标（首次运行不告警）。
func (a *Agent) evtBaseline(ch evtChannelDef, since uint64) uint64 {
	for i := 0; i < evtMaxCatchUp; i++ {
		_, last, err := winapi.EvtReadBatch(ch.name, ch.xpath, since, evtBatchSize)
		if err != nil {
			a.log.Warn("evtlog_baseline_failed", "channel", ch.name, "err", err)
			return since
		}
		if last == since {
			break
		}
		since = last
	}
	return since
}

// dispatchEvtEvents 把一批事件映射到告警策略（机制在 winapi，策略在此）。
func (a *Agent) dispatchEvtEvents(channel string, events []winapi.EvtEvent) {
	for _, ev := range events {
		switch {
		case channel == "System" && ev.EventID == 7045:
			a.emitEvtServiceInstall(ev)
		case channel == "System" && ev.EventID == 104:
			a.emitEvtLogCleared(ev, channel)
		case channel == "Security" && ev.EventID == 1102:
			// Security 通道清空（T1070.001）：与 104 同语义不同通道，
			// 前提是"审核策略变更"审计开启
			a.emitEvtLogCleared(ev, channel)
		case channel == "Security" && ev.EventID == 4624:
			a.evtLogonWatch(ev)
		case channel == "Security" && ev.EventID == 4625:
			a.evtBrutePush(ev)
		case channel == "Security" && ev.EventID == 4698:
			a.emitEvtSchTask(ev)
		case channel == "Security" && ev.EventID == 4720, channel == "Security" && ev.EventID == 4726:
			a.emitEvtAccountChange(ev)
		case channel == "Security" && ev.EventID == 4728, channel == "Security" && ev.EventID == 4732:
			a.emitEvtGroupChange(ev)
		case channel == "Security" && ev.EventID == 4719:
			a.emitEvtAuditPolicy(ev)
		case channel == "Microsoft-Windows-PowerShell/Operational" && ev.EventID == 4104:
			a.emitEvtScriptBlock(ev)
		case channel == "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" && ev.EventID == 1149:
			a.emitEvtRDPIn(ev)
		}
	}
}

// ---------------------------------------------------------------- 7045

// evtData 是宽松取值：同一事件的 EventData 在不同 Windows 版本/通道上
// 可能是 Name 属性型或无名 Data——真实 7045（Server 2022 实测）就是
// Name 属性（ServiceName/ImagePath/...），合成样例的无名假设不成立。
// 两种口径都试，先命名后位序。
func evtData(d map[string]string, names []string, idx int) string {
	for _, n := range names {
		if v := d[n]; v != "" {
			return v
		}
	}
	return d[fmt.Sprintf("data[%d]", idx)]
}

// emitEvtServiceInstall：新服务安装。persist 轮询（5min/定向）已有同类
// 覆盖，事件日志的价值是"OS 权威 + 全量"（含服务名/二进制/账户四元组），
// 且与 persist 告警的指纹不同源（EVT-SVCINST vs P-001），互为佐证。
func (a *Agent) emitEvtServiceInstall(ev winapi.EvtEvent) {
	svcName := evtData(ev.Data, []string{"servicename"}, 0)
	binPath := evtData(ev.Data, []string{"imagepath", "binarypathname"}, 1)
	acct := evtData(ev.Data, []string{"accountname"}, 4)
	if svcName == "" && binPath == "" {
		return // 渲染异常的事件不硬编故事
	}
	// 白名单优先：运维明确信任的安装路径不告警（filewatch/persist 同口径）
	if hit, _ := a.alw.Match("", winapi.PersistCommandPath(binPath), "", "", svcName, binPath); hit {
		a.log.Debug("evtlog_whitelisted", "event", 7045, "service", svcName)
		return
	}
	meta := a.enr.Describe(winapi.PersistCommandPath(binPath))
	score := 55
	summary := fmt.Sprintf("服务 %q（%s）由 %s 安装。服务安装是最高价值的持久化位置（T1543.003），OS 权威证据与自启动项扫描互为佐证。",
		svcName, binPath, acct)
	if meta.Exists && !meta.Signed {
		score = 65
		summary += "；服务二进制无数字签名"
	}

	a.emitAlert(model.AlertEnvelope{
		Fingerprint: fmt.Sprintf("evt:7045:%s:%s:%d", strings.ToLower(svcName), meta.Hash, ev.TimeCreated.Unix()/60),
		Title:       "事件日志：新服务安装 " + svcName,
		Summary:     summary,
		Verdict:     model.VerdictSuspicious,
		Severity:    model.SeverityHigh,
		Score:       score,
		ProcessName: svcName,
		ImagePath:   winapi.PersistCommandPath(binPath),
		ProcUser:    "SYSTEM/EVTLOG",
		RuleIDs:     []string{"EVT-SVCINST"},
		MITRE:       []string{"T1543.003"},
		Evidence: model.Evidence{
			Signals: []model.Signal{{
				Layer: "evtlog", ID: "EVT-SVCINST", Name: "服务安装事件",
				Score: score, Note: summary, MITRE: "T1543.003",
			}},
			Notes: []string{
				"service=" + svcName,
				"binpath=" + binPath,
				"account=" + acct,
				fmt.Sprintf("record_id=%d channel=System", ev.RecordID),
			},
		},
		OccurredAt: ev.TimeCreated,
	})
}

// ---------------------------------------------------------------- 104

// emitEvtLogCleared：事件日志被清（反取证 T1070.001）。微软 Appendix L
// 列为必查项；正常软件极少清 System 通道。104=System 通道、1102=Security
// 通道（1102 需"审核策略变更"审计开启，未开启则事件缺失）。
func (a *Agent) emitEvtLogCleared(ev winapi.EvtEvent, channel string) {
	a.emitAlert(model.AlertEnvelope{
		Fingerprint: fmt.Sprintf("evt:%d:%s:%d", ev.EventID, channel, ev.TimeCreated.Unix()),
		Title:       "事件日志：日志被清空（反取证信号）",
		Summary: fmt.Sprintf("%s 通道事件日志被清除。日志清空是攻击者抹除痕迹的经典动作（T1070.001），微软官方监控清单必查项；结合此前告警的时间线排查清空前的活动。",
			channel),
		Verdict:  model.VerdictSuspicious,
		Severity: model.SeverityHigh,
		Score:    60,
		ProcUser: "SYSTEM/EVTLOG",
		RuleIDs:  []string{"EVT-LOGCLR"},
		MITRE:    []string{"T1070.001"},
		Evidence: model.Evidence{
			Signals: []model.Signal{{
				Layer: "evtlog", ID: "EVT-LOGCLR", Name: "日志清空事件",
				Score: 60, Note: channel + " 通道日志被清除", MITRE: "T1070.001",
			}},
			Notes: []string{fmt.Sprintf("record_id=%d channel=%s", ev.RecordID, channel)},
		},
		OccurredAt: ev.TimeCreated,
	})
}

// emitEvtSchTask：计划任务创建（T1053.005）。inventory 的 tasks 节 30s
// 差量已有覆盖，事件日志的价值是 OS 权威 + 账户/即时光（与 persist/EVT-
// SVCINST 同款互补口径）。
func (a *Agent) emitEvtSchTask(ev winapi.EvtEvent) {
	taskName := evtData(ev.Data, []string{"taskname"}, 0)
	acct := evtData(ev.Data, []string{"subjectusername"}, 0)
	if taskName == "" {
		return
	}
	summary := fmt.Sprintf("计划任务 %q 由 %s 创建（事件日志权威证据，T1053.005）。与资产清单的计划任务变更互为佐证。",
		taskName, acct)
	a.emitAlert(model.AlertEnvelope{
		Fingerprint: fmt.Sprintf("evt:4698:%s:%d", strings.ToLower(taskName), ev.TimeCreated.Unix()/60),
		Title:       "事件日志：计划任务创建 " + taskName,
		Summary:     summary,
		Verdict:     model.VerdictSuspicious,
		Severity:    model.SeverityMedium,
		Score:       45,
		ProcessName: taskName,
		ProcUser:    "SYSTEM/EVTLOG",
		RuleIDs:     []string{"EVT-SCHTASK"},
		MITRE:       []string{"T1053.005"},
		Evidence: model.Evidence{
			Signals: []model.Signal{{
				Layer: "evtlog", ID: "EVT-SCHTASK", Name: "计划任务创建",
				Score: 45, Note: summary, MITRE: "T1053.005",
			}},
			Notes: []string{
				"task=" + taskName,
				"account=" + acct,
				fmt.Sprintf("record_id=%d", ev.RecordID),
			},
		},
		OccurredAt: ev.TimeCreated,
	})
}

// ---------------------------------------------------------------- 4625

// recentFailCount 返回聚合窗口内指定账户的登录失败次数（暴破成功
// 序列判定的数据源；调用方持锁约束与 evtBrutePush 相同——单 goroutine）。
func (a *Agent) recentFailCount(user string) int {
	a.brute.mu.Lock()
	defer a.brute.mu.Unlock()
	n := 0
	for _, r := range a.brute.window {
		if r.user == user {
			n++
		}
	}
	return n
}

// evtBrutePush 聚合登录失败：单条是常态噪声（输错密码），窗口内密集
// 失败才是暴破（T1110）。超阈值发聚合告警（计数+样本 Top），冷却
// 15min 防持续暴破刷屏。
func (a *Agent) evtBrutePush(ev winapi.EvtEvent) {
	a.brute.mu.Lock()
	defer a.brute.mu.Unlock()

	// 用事件时间盖章而不是消费时刻：游标追赶（探针重启/轮询滞后）会
	// 一次读到几十分钟前的失败——按消费时刻盖章会把陈旧失败误算成
	// "当前正在暴破"。事件时间才是行为发生的时刻。
	at := ev.TimeCreated
	if at.IsZero() {
		at = time.Now()
	}
	rec := evtBruteRec{at: at, ip: ev.Data["ipaddress"], user: ev.Data["targetusername"]}
	a.brute.window = append(a.brute.window, rec)
	cut := at.Add(-evtBruteWindow)
	k := 0
	for i, r := range a.brute.window {
		if r.at.After(cut) {
			a.brute.window[k] = a.brute.window[i]
			k++
		}
	}
	a.brute.window = a.brute.window[:k]
	if len(a.brute.window) > evtBruteCap {
		a.brute.window = append([]evtBruteRec(nil), a.brute.window[len(a.brute.window)-evtBruteCap:]...)
	}
	if len(a.brute.window) < evtBruteThreshold {
		return
	}
	// 陈旧批（游标追赶读到的历史失败）：不告警也不占冷却——
	// 窗口按事件时间自然过期，等真有新鲜暴破时再触发
	newest := a.brute.window[len(a.brute.window)-1].at
	if time.Since(newest) > evtBruteWindow {
		return
	}
	if time.Since(a.brute.lastHit) < 15*time.Minute {
		return
	}
	a.brute.lastHit = time.Now()

	// 样本聚合：按来源 IP 计数取 Top3 + 失败账户样例
	ipCount := map[string]int{}
	users := map[string]bool{}
	for _, r := range a.brute.window {
		if r.ip != "" {
			ipCount[r.ip]++
		}
		if len(users) < 5 && r.user != "" {
			users[r.user] = true
		}
	}
	ips := make([]string, 0, len(ipCount))
	for ip := range ipCount {
		ips = append(ips, ip)
	}
	sort.Slice(ips, func(i, j int) bool { return ipCount[ips[i]] > ipCount[ips[j]] })
	if len(ips) > 3 {
		ips = ips[:3]
	}
	var userList []string
	for u := range users {
		userList = append(userList, u)
	}

	summary := fmt.Sprintf("%s 内 %d 次登录失败（阈值 %d）。目标账户样例：%s；来源 Top：%s。密集失败是密码暴破（T1110）的直接形态，互联网暴露机器尤其注意。",
		evtBruteWindow, len(a.brute.window), evtBruteThreshold,
		strings.Join(userList, ", "), strings.Join(ips, ", "))
	a.emitAlert(model.AlertEnvelope{
		Fingerprint: fmt.Sprintf("evt:4625:%d", time.Now().Truncate(15*time.Minute).Unix()),
		Title:       fmt.Sprintf("事件日志：登录失败暴发（%d 次/分钟）", len(a.brute.window)),
		Summary:     summary,
		Verdict:     model.VerdictSuspicious,
		Severity:    model.SeverityHigh,
		Score:       60,
		ProcUser:    "SYSTEM/EVTLOG",
		RuleIDs:     []string{"EVT-BRUTE"},
		MITRE:       []string{"T1110"},
		Evidence: model.Evidence{
			Signals: []model.Signal{{
				Layer: "evtlog", ID: "EVT-BRUTE", Name: "登录失败聚合",
				Score: 60, Note: summary, MITRE: "T1110",
			}},
			Notes: []string{fmt.Sprintf("failed=%d window=60s", len(a.brute.window))},
		},
		OccurredAt: time.Now(),
	})
}

// ---------------------------------------------------------------- 1149

// emitEvtRDPIn：RDP 入站会话（横向移动 T1021.001 的到达信号）。
// 1149 记录的是"谁从哪台机器连进来"——内网里出现非运维来源的 RDP
// 就是横向移动的到达证据。Data 为 Name 属性型（User/Domain/SourceIp）。
func (a *Agent) emitEvtRDPIn(ev winapi.EvtEvent) {
	user := evtData(ev.Data, []string{"user"}, 0)
	src := evtData(ev.Data, []string{"sourceip"}, 2)
	if user == "" && src == "" {
		return
	}
	summary := fmt.Sprintf("RDP 会话建立：账户 %q 自 %s 连入。RDP 入站是横向移动（T1021.001）的到达信号，请核对该来源与账户是否预期。",
		user, src)
	a.emitAlert(model.AlertEnvelope{
		Fingerprint: fmt.Sprintf("evt:1149:%s:%s:%d", strings.ToLower(user), src, ev.TimeCreated.Unix()/300),
		Title:       "事件日志：RDP 入站会话",
		Summary:     summary,
		Verdict:     model.VerdictSuspicious,
		Severity:    model.SeverityMedium,
		Score:       45,
		ProcUser:    "SYSTEM/EVTLOG",
		RuleIDs:     []string{"EVT-RDPIN"},
		MITRE:       []string{"T1021.001"},
		Evidence: model.Evidence{
			Signals: []model.Signal{{
				Layer: "evtlog", ID: "EVT-RDPIN", Name: "RDP 入站",
				Score: 45, Note: summary, MITRE: "T1021.001",
			}},
			Notes: []string{
				"user=" + user,
				"source=" + src,
				fmt.Sprintf("record_id=%d", ev.RecordID),
			},
		},
		OccurredAt: ev.TimeCreated,
	})
}

// ---------------------------------------------------------------- 游标

func (a *Agent) loadEvtCursor() evtCursor {
	var cp evtCursor
	raw, err := os.ReadFile(a.cfg.Path(evtCursorFile))
	if err != nil {
		return cp
	}
	if err := json.Unmarshal(raw, &cp); err != nil {
		a.log.Warn("evt_cursor_parse_failed", "err", err)
	}
	return cp
}

func (a *Agent) saveEvtCursor(cp evtCursor) {
	raw, err := json.MarshalIndent(cp, "", "  ")
	if err != nil {
		a.log.Warn("evt_cursor_marshal_failed", "err", err)
		return
	}
	path := a.cfg.Path(evtCursorFile)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		a.log.Warn("evt_cursor_write_failed", "err", err)
		return
	}
	if err := os.Rename(tmp, path); err != nil {
		a.log.Warn("evt_cursor_rename_failed", "err", err)
	}
}
