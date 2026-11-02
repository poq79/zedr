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

import (
	"encoding/json"
	"os"
	"time"

	"zedr/internal/agent/winapi"
)

const (
	usnCheckpointFile = "usn.json"
	usnMaxRecords     = 5000
	usnMaxAge         = 30 * time.Minute
	usnMaxFutureSkew  = 5 * time.Minute
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
	if a.fw == nil {
		return
	}
	cp := a.loadUSNCheckpoint()
	if cp.Volumes == nil {
		cp.Volumes = map[string]usnVolumeState{}
	}

	volumes := map[string]struct{}{}
	for _, dir := range a.fw.WatchedDirs() {
		if vol, ok := winapi.USNVolumeOf(dir); ok {
			volumes[vol] = struct{}{}
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
		now := time.Now()
		recorded := 0
		for _, ev := range events {
			age := now.Sub(ev.When)
			if age > usnMaxAge || age < -usnMaxFutureSkew {
				continue
			}
			if a.fw.RecordDropByBase(ev.Name, ev.When) {
				recorded++
			}
		}
		cp.Volumes[vol] = usnVolumeState{JournalID: journalID, NextUSN: next}
		changed = true
		a.log.Info("usn_catchup", "volume", vol, "events", len(events),
			"recorded", recorded, "reset", reset, "next_usn", next)
	}
	if changed {
		a.saveUSNCheckpoint(cp)
	}
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
