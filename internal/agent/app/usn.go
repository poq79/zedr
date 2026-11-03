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
	// usnMaxCatchRounds/usnCatchupRounds 是 tick 内/启动时的追赶轮数上限：
	// 4×20000=8 万条/卷/tick（poll）、3×20000=6 万条/卷（catchup，阻塞
	// 启动路径刻意少一轮）。读满即再读，读不满 = 已追平；跑满上限仍未
	// 追平则置 lagging（自监控告警）。
	usnMaxCatchRounds = 4
	usnCatchupRounds  = 3
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
		now := time.Now()
		var sumEvents, sumRecorded, sumDefense int
		reset := false
		for attempt := 0; attempt < usnCatchupRounds; attempt++ {
			events, next, journalID, r, err := winapi.ReadUSNJournal(
				vol, st.NextUSN, st.JournalID, usnMaxRecords)
			if err != nil {
				a.log.Warn("usn_catchup_failed", "volume", vol, "err", err)
				break
			}
			if r {
				reset = true
			}
			recorded, defense := a.dispatchUSNEvents(events, reset, now)
			sumEvents += len(events)
			sumRecorded += recorded
			sumDefense += defense
			st = usnVolumeState{JournalID: journalID, NextUSN: next}
			if len(events) < usnMaxRecords {
				break // 追平
			}
		}
		// 超长停机（>3×20000 条/卷）按设计截断推进：reset 语义已如实
		// 报告，不假装全量——追平的长尾由 usnPollLoop 的 tick 内追赶继续
		cp.Volumes[vol] = st
		changed = true
		a.log.Info("usn_catchup", "volume", vol, "events", sumEvents,
			"recorded", sumRecorded, "defense", sumDefense,
			"reset", reset, "next_usn", st.NextUSN)
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
	lagStreak := 0
	for {
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		ok, lagging := a.usnPollOnce()
		a.usnLagging.Store(lagging)
		if ok {
			failStreak = 0
			delay = interval
		} else {
			failStreak++
		}
		// 滞后自监控：跑满追赶预算仍未追平 = 卷产量超过检测预算，
		// 事件将滞后（缺失是可接受的降级，但必须让运维看得见）
		if lagging {
			lagStreak++
			if lagStreak == 3 {
				a.log.Warn("usn_poll_lagging",
					"hint", "卷的 USN 产量超过 tick 内追赶预算（4x20000/卷），删除/改名事件将滞后到达；持续如此可调大 HG_AGENT_USN_POLL_INTERVAL 并关注该卷的写入活动")
			}
		} else {
			lagStreak = 0
		}
		if ok {
			continue
		}
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

// usnPollOnce 跑一轮全卷增量读取。返回（是否有卷成功, 是否仍有滞后）：
// 前者驱动退避（全部失败才算轮次失败），后者驱动滞后自监控——
// 跑满追赶预算还没追平说明卷产量超过检测预算。
func (a *Agent) usnPollOnce() (ok bool, lagging bool) {
	volumes := a.usnPollVolumes()
	if len(volumes) == 0 {
		return true, false // 没有可读卷不是失败：静默跳过，等卷出现
	}
	cp := a.loadUSNCheckpoint()
	if cp.Volumes == nil {
		cp.Volumes = map[string]usnVolumeState{}
	}

	successes := 0
	laggingAny := false
	changed := false
	now := time.Now()
	for _, vol := range volumes {
		st := cp.Volumes[vol]
		// 追赶循环：开发机上卷的 USN 产量可达数百条/秒（浏览器缓存、
		// 构建工具、包管理器），单轮 maxRecords 顶格说明还没追平——
		// 不追平的话事件滞后会无限增长（实测 5000/30s 预算下滞后
		// 超过分钟级，落地类全被 30min 新鲜度过滤掉）。同一 tick 内
		// 最多 usnMaxCatchRounds 轮，读不满即追平。
		var sumEvents, sumRecorded, sumDefense, rounds int
		for attempt := 0; attempt < usnMaxCatchRounds; attempt++ {
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
		if rounds == usnMaxCatchRounds {
			laggingAny = true // 最后一轮仍读满 = 未追平
		}
	}
	if changed {
		a.saveUSNCheckpoint(cp)
	}
	return successes > 0, laggingAny
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
		case winapi.USNKindRenameOld:
			// 未配对的 rename_old（改出本卷/跨批次改名）：旧名在语义上
			// 已消失，按 renamed_old 投递——canary 按名匹配能抓到"诱饵
			// 被改名走"（否则 USN 路径对此漏报），而速率窗口对
			// renamed_old 权重为 0，正常改名的海量 rename_old 不会变成
			// 勒索速率噪声。冷却键按诱饵去重，双事件同达只告警一次。
			a.fileDefense.Consume(ransom.Event{
				Kind: "renamed_old", Path: ev.Name, When: ev.When, Source: "usn",
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
		// 主文件损坏：回退上一份备份。检查点倒退的最坏后果是"重放一小段
		// 已处理记录"（落地有 byBase 去重、删除有冷却去重），好过整份
		// 基线作废——作废会让所有卷当首次运行，停机窗口全部漏掉。
		if bak, err2 := os.ReadFile(a.cfg.Path(usnCheckpointFile + ".bak")); err2 == nil {
			if err3 := json.Unmarshal(bak, &cp); err3 == nil && cp.Volumes != nil {
				a.log.Warn("usn_checkpoint_fallback_bak", "err", err)
				return cp
			}
		}
		return usnCheckpoint{}
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
	// 写前轮换：当前主文件挪成 .bak（存在才挪），再做 temp+rename 原子写。
	// .bak 是 load 侧损坏回退的来源——两次写入都损坏（掉电/杀进程）才
	// 会真的丢基线，概率远低于单文件。
	if old, err := os.ReadFile(path); err == nil {
		_ = os.WriteFile(path+".bak", old, 0o600)
	}
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
