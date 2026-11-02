package agentapp

// USN Journal 断点补采（应用层编排）。
//
// 与 winapi/usn.go 的分工：winapi 只负责"怎么读"，这里负责
// 检查点持久化、卷去重、时间窗过滤与日志。拆开的原因是
// 读日志涉及 Win32 结构，编排涉及数据目录/策略，混在一起两头难测。
//
// 语义：
//   - 首次运行（无检查点）：把基线推到当前 NextUSN，不把历史 journal
//     当成"刚刚落地"（否则第一次上线会凭空多出一批落地信号）；
//   - 之后每次启动：从检查点读到当前，补上停机窗口内的创建/改名/写入；
//   - journal 被重建或检查点早于保留窗口：reset 如实记录，从最旧可用
//     位置重放（仍受记录数上限约束），不假装无损；
//   - 只把 30 分钟内的记录写入 FileWatcher——更早的落地对"落地即执行"
//     判定没有意义，反而会污染 byBase 索引。

//   - 运行期轮询（usnPollLoop）持续消费增量：落地类喂 FileWatcher，
//     删除/改名类喂勒索防御（ransom.Defense）——诱饵被删必须准实时
//     发现，只靠启动补采会漏掉"改完就重启探针"的攻击窗口；
//   - reset 批次不投勒索防御：重放的是位置不确定的历史，会变成误报源，
//     缺失的诱饵由 Defense 的 30s 自检静默重建兜底。

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"time"

	"zedr/internal/agent/ransom"
	"zedr/internal/agent/winapi"
)

const (
	usnCheckpointFile = "usn.json"
	// usnMaxRecords 是单次读取的事件预算。v1 取 5000，端到端实测暴露：
	// 开发机 C: 卷 USN 产量 200+ 条/秒（浏览器缓存/构建工具/包管理器），
	// 5000/30s 永远追不平，事件滞后分钟级——落地类全被 30min 新鲜度
	// 过滤、删除类告警迟到。提至 20000 并配合 usnPollOnce 的 tick 内
	// 追赶循环（4 轮），典型机器每轮读不满即追平。
	usnMaxRecords    = 20000
	usnMaxAge        = 30 * time.Minute
	usnMaxFutureSkew = 5 * time.Minute
	// usnPollMaxBackoff 轮询连续失败的最大退避。全卷失败通常意味着
	// 权限/卷结构问题，超时就保持 10 分钟节奏不再增长——不放弃
	// （卷可能恢复），也不让指数失控。
	usnPollMaxBackoff = 10 * time.Minute
)

type usnVolumeState struct {
	JournalID uint64 `json:"journal_id"`
	NextUSN   uint64 `json:"next_usn"`
}

type usnCheckpoint struct {
	Volumes map[string]usnVolumeState `json:"volumes"`
}

// usnCatchup 对所有被监控目录所在卷做一次断点补采。
// 失败只记 warn：USN 需要管理员/NTFS，缺任何条件都不应影响主链路。
func (a *Agent) usnCatchup() {
	if a.fw == nil && a.fileDefense == nil {
		return
	}
	cp := a.loadUSNCheckpoint()
	if cp.Volumes == nil {
		cp.Volumes = map[string]usnVolumeState{}
	}

	volumes := map[string]struct{}{}
	if a.fw != nil {
		for _, dir := range a.fw.WatchedDirs() {
			if vol, ok := winapi.USNVolumeOf(dir); ok {
				volumes[vol] = struct{}{}
			}
		}
	}
	// 诱饵目录所在卷也要补：停机窗口内诱饵被删/被改名，必须补投防御
	if a.fileDefense != nil {
		for _, dir := range a.fileDefense.CanaryDirs() {
			if vol, ok := winapi.USNVolumeOf(dir); ok {
				volumes[vol] = struct{}{}
			}
		}
	}
	if len(volumes) == 0 {
		return
	}

	changed := false
	for vol := range volumes {
		st := cp.Volumes[vol]
		events, next, journalID, reset, err := winapi.ReadUSNJournal(
			vol, st.NextUSN, st.JournalID, usnMaxRecords)
		if err != nil {
			a.log.Warn("usn_catchup_failed", "volume", vol, "err", err)
			continue
		}
		recorded, defense := a.dispatchUSNEvents(events, reset, time.Now())
		cp.Volumes[vol] = usnVolumeState{JournalID: journalID, NextUSN: next}
		changed = true
		a.log.Info("usn_catchup", "volume", vol, "events", len(events),
			"recorded", recorded, "defense", defense, "reset", reset, "next_usn", next)
	}
	if changed {
		a.saveUSNCheckpoint(cp)
	}
}

// usnPollLoop 是 USN 的运行期轮询：启动补采只覆盖停机窗口，诱饵篡改
// 需要准实时事件。周期取 cfg.USNPollInterval；由主线在 Run 里 go 启动。
//
// 退避策略：连续 ≥3 轮"全部卷读取失败"才指数退避（上限 10 分钟），成功
// 一轮立即恢复原间隔。部分卷失败不退避——健康卷的检查点已推进，退避反而
// 会让健康卷停摆。
func (a *Agent) usnPollLoop(ctx context.Context) {
	if !a.cfg.USNPoll || a.fileDefense == nil {
		return
	}
	interval := a.cfg.USNPollInterval
	if interval <= 0 {
		// time.NewTicker/NewTimer 对 <=0 直接 panic：配置兜底而不是信任
		interval = 30 * time.Second
	}

	delay := interval
	failStreak := 0
	for {
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		if a.usnPollOnce() {
			failStreak = 0
			delay = interval
			continue
		}
		failStreak++
		if failStreak < 3 {
			a.log.Warn("usn_poll_failed", "fail_streak", failStreak)
			continue
		}
		backoff := interval
		for i := 3; i <= failStreak && backoff < usnPollMaxBackoff; i++ {
			backoff *= 2
		}
		if backoff > usnPollMaxBackoff {
			backoff = usnPollMaxBackoff
		}
		delay = backoff
		a.log.Warn("usn_poll_backoff", "fail_streak", failStreak, "delay", delay.String())
	}
}

// usnPollOnce 跑一轮全卷增量读取。返回本轮是否"有卷成功"（全部失败
// 才算轮次失败，驱动退避）。
func (a *Agent) usnPollOnce() bool {
	volumes := a.usnPollVolumes()
	if len(volumes) == 0 {
		return true // 没有可读卷不是失败：静默跳过，等卷出现
	}
	cp := a.loadUSNCheckpoint()
	if cp.Volumes == nil {
		cp.Volumes = map[string]usnVolumeState{}
	}

	successes := 0
	changed := false
	now := time.Now()
	for _, vol := range volumes {
		st := cp.Volumes[vol]
		// 追赶循环：开发机上卷的 USN 产量可达数百条/秒（浏览器缓存、
		// 构建工具、包管理器），单轮 maxRecords 顶格说明还没追平——
		// 不追平的话事件滞后会无限增长（实测 5000/30s 预算下滞后
		// 超过分钟级，落地类全被 30min 新鲜度过滤掉）。同一 tick 内
		// 最多再读 3 轮（4×20000=8 万条/卷/tick 硬上限），读不满即追平。
		var sumEvents, sumRecorded, sumDefense, rounds int
		for attempt := 0; attempt < 4; attempt++ {
			events, next, journalID, reset, err := winapi.ReadUSNJournal(
				vol, st.NextUSN, st.JournalID, usnMaxRecords)
			if err != nil {
				a.log.Warn("usn_poll_read_failed", "volume", vol, "err", err)
				break
			}
			successes++
			rounds++
			recorded, defense := a.dispatchUSNEvents(events, reset, now)
			sumEvents += len(events)
			sumRecorded += recorded
			sumDefense += defense
			st = usnVolumeState{JournalID: journalID, NextUSN: next}
			if reset {
				a.log.Warn("usn_journal_reset", "volume", vol, "next_usn", next)
			}
			if len(events) < usnMaxRecords {
				break // 本轮没读满 = 已追平
			}
		}
		if st != cp.Volumes[vol] {
			// 空轮次 NextUSN 不动：不落检查点，避免每 30s 一次无意义磁盘写
			cp.Volumes[vol] = st
			changed = true
		}
		// 空轮次不刷 Info：轮询间隔内多数轮次没有事件
		if sumEvents > 0 || sumDefense > 0 {
			a.log.Info("usn_poll", "volume", vol, "events", sumEvents,
				"recorded", sumRecorded, "defense", sumDefense,
				"rounds", rounds, "next_usn", st.NextUSN)
		}
	}
	if changed {
		a.saveUSNCheckpoint(cp)
	}
	return successes > 0
}

// usnPollVolumes 圈定本轮要轮询的卷：全部固定 NTFS 卷（覆盖"文件被
// 改到别处"）+ 诱饵目录所在卷（保证诱饵放在非系统盘时也被盯住）。
// 去重且顺序稳定（A→Z + 诱饵卷追加），日志可读。
func (a *Agent) usnPollVolumes() []string {
	seen := map[string]struct{}{}
	var out []string
	add := func(v string) {
		if v == "" {
			return
		}
		if _, dup := seen[v]; dup {
			return
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	for _, v := range winapi.FixedNTFSVolumes() {
		add(v)
	}
	if a.fileDefense != nil {
		for _, dir := range a.fileDefense.CanaryDirs() {
			if v, ok := winapi.USNVolumeOf(dir); ok {
				add(v)
			}
		}
	}
	return out
}

// dispatchUSNEvents 按事件类别分流，返回 (落地入库数, 防御投递数)：
//   - 落地类（create/rename_new/write）沿用 30min 新鲜度过滤后喂
//     FileWatcher 的 byBase 兜底索引（口径不变）；
//   - 删除/配对成功的跨扩展名改名投给勒索防御——USN 只有 leaf name，
//     Defense 摘要里会如实标注路径未知；
//   - rename_old 不单独投递：配对信息已随 rename_new（OldName）走，
//     再投会双重计数；配对失败（跨批次）意味着旧名未知，无法判定
//     扩展名变化，宁可漏报也不猜；
//   - reset 批次不投防御（历史重放会变成误报源），落地仍收（有 30min
//     新鲜度过滤兜着）。
func (a *Agent) dispatchUSNEvents(events []winapi.USNEvent, reset bool, now time.Time) (recorded, defense int) {
	for _, ev := range events {
		switch ev.Kind {
		case winapi.USNKindCreate, winapi.USNKindRenameNew, winapi.USNKindWrite:
			age := now.Sub(ev.When)
			if age > usnMaxAge || age < -usnMaxFutureSkew {
				continue
			}
			if a.fw != nil && a.fw.RecordDropByBase(ev.Name, ev.When) {
				recorded++
			}
		}
		if reset || a.fileDefense == nil {
			continue
		}
		switch ev.Kind {
		case winapi.USNKindDelete:
			a.fileDefense.Consume(ransom.Event{
				Kind: "removed", Path: ev.Name, When: ev.When, Source: "usn",
			})
			defense++
		case winapi.USNKindRenameNew:
			if ev.OldName == "" ||
				strings.EqualFold(filepath.Ext(ev.OldName), filepath.Ext(ev.Name)) {
				continue
			}
			a.fileDefense.Consume(ransom.Event{
				Kind: "renamed", Path: ev.Name, OldPath: ev.OldName,
				When: ev.When, Source: "usn",
			})
			defense++
		}
	}
	return recorded, defense
}

func (a *Agent) loadUSNCheckpoint() usnCheckpoint {
	var cp usnCheckpoint
	raw, err := os.ReadFile(a.cfg.Path(usnCheckpointFile))
	if err != nil {
		return cp
	}
	if err := json.Unmarshal(raw, &cp); err != nil {
		a.log.Warn("usn_checkpoint_parse_failed", "err", err)
	}
	return cp
}

func (a *Agent) saveUSNCheckpoint(cp usnCheckpoint) {
	raw, err := json.MarshalIndent(cp, "", "  ")
	if err != nil {
		a.log.Warn("usn_checkpoint_marshal_failed", "err", err)
		return
	}
	path := a.cfg.Path(usnCheckpointFile)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		a.log.Warn("usn_checkpoint_write_failed", "err", err)
		return
	}
	// temp+rename：进程在写检查点途中被杀不会留下半个 JSON，
	// 下次启动最坏只是少补一段（并会被 reset 逻辑如实报告）。
	if err := os.Rename(tmp, path); err != nil {
		a.log.Warn("usn_checkpoint_rename_failed", "err", err)
	}
}
