// Package collect 实现 Windows 侧的进程采集。
//
// 采集策略（对应报告第 5 章"性能工程"）：
//   - 用"进程表来源"(Source) 做增量比对，只对"新出现的 PID"做昂贵富化；
//   - 网络连接用单次 GetExtendedTcpTable 全量拉取，避免每进程一次系统调用；
//   - 已退出进程保留在历史表中，用于还原"父进程已退出"的孤儿链路；
//   - 定期做一次全量深度扫描（补模块信息），频率远低于增量轮询。
//
// 来源可插拔：默认 auto（NtQuerySystemInformation 优先、失败回退 Toolhelp32），
// 也可以通过配置强制指定，便于在新老 Windows 版本上快速切换验证。
package collect

import (
	"strings"
	"sync"
	"time"

	"zedr/internal/agent/winapi"
	"zedr/internal/model"
)

// Collector 维护跨轮次的进程状态。
type Collector struct {
	mu sync.Mutex

	src     Source
	srcNote string

	prev    map[uint32]rawProc      // 上一轮的进程
	history map[uint32]historyEntry // 已退出进程，用于血缘回溯
	order   []uint32                // history 的 FIFO 顺序
	// known 保存上一轮为每个 PID 富化出的完整身份（路径/命令行/账号/
	// 启动时间）。进程退出时随 rawProc 一起进 history——只留一个进程名
	// 的话，攻击链里"父进程是谁、执行了什么"会在父进程退出后永久丢失。
	known map[uint32]ProcessInfo

	lastFullScan  time.Time
	deepScanEvery time.Duration
	maxHistory    int
}

type historyEntry struct {
	rawProc
	// Info 是退出前最后一次成功富化的身份快照（零值表示当时未采集到）。
	Info     ProcessInfo
	ExitedAt time.Time
}

// Snapshot 是一轮采集的快照（供 Ancestry / ConnectionsOf 使用）。
type Snapshot = Table

// New 创建采集器。
func New(sourceName string, deepScanEvery time.Duration) (*Collector, error) {
	src, note, err := NewSource(sourceName)
	if err != nil {
		return nil, err
	}
	if deepScanEvery <= 0 {
		deepScanEvery = 15 * time.Minute
	}
	return &Collector{
		src:           src,
		srcNote:       note,
		prev:          make(map[uint32]rawProc, 512),
		history:       make(map[uint32]historyEntry, 2048),
		known:         make(map[uint32]ProcessInfo, 512),
		deepScanEvery: deepScanEvery,
		maxHistory:    2048,
	}, nil
}

// SourceName 返回实际使用的采集源名称。
func (c *Collector) SourceName() string { return c.src.Name() }

// SourceNote 返回选择该采集源的原因（写日志用）。
func (c *Collector) SourceNote() string { return c.srcNote }

// Poll 执行一轮采集，返回需要检测的新进程（已含路径/命令行/账号等字段）。
//
// forceDeep=true 时对所有进程都做完整富化（用于全量扫描与手动重扫）。
func (c *Collector) Poll(forceDeep bool) ([]ProcessInfo, *Snapshot, error) {
	start := time.Now()

	table, err := c.src.Table()
	if err != nil {
		return nil, nil, err
	}

	c.mu.Lock()
	deep := forceDeep || start.Sub(c.lastFullScan) >= c.deepScanEvery
	if deep {
		c.lastFullScan = start
	}

	// 找出新增 / PID 复用 的进程
	var fresh []rawProc
	for pid, cur := range table.Procs {
		if pid == 0 || pid == 4 {
			continue // System Idle / System 伪进程
		}
		old, existed := c.prev[pid]
		if existed && !isNewProcess(old, cur) {
			continue
		}
		if existed {
			// PID 复用：旧进程没等到"消失"那一轮就被新进程顶替了。
			// 先把它按旧身份归档，否则父链里会凭空少一代。
			c.pushHistoryLocked(pid, old, c.known[pid])
		}
		fresh = append(fresh, cur)
	}

	// 记录本轮消失的进程，用于血缘回溯
	for pid, old := range c.prev {
		if _, still := table.Procs[pid]; !still {
			c.pushHistoryLocked(pid, old, c.known[pid])
			delete(c.known, pid)
		}
	}
	c.prev = table.Procs
	c.mu.Unlock()

	out := make([]ProcessInfo, 0, len(fresh))
	for _, rp := range fresh {
		pi := c.describe(rp)
		out = append(out, pi)
		c.mu.Lock()
		c.known[pi.PID] = pi
		c.mu.Unlock()
	}
	return out, table, nil
}

// isNewProcess 判断同一 PID 是否已被新进程复用。
//
// 优先用 CreateTime 比对（NtQuery 来源提供）；Toolhelp32 不提供创建时间，
// 退化为进程名比对——这正是引入创建时间字段的意义。
func isNewProcess(old, cur rawProc) bool {
	if old.Name != cur.Name {
		return true
	}
	if old.CreateTime != 0 && cur.CreateTime != 0 && old.CreateTime != cur.CreateTime {
		return true
	}
	return false
}

// describe 对单个进程做完整富化。
func (c *Collector) describe(rp rawProc) ProcessInfo {
	pi := ProcessInfo{
		PID:  rp.PID,
		PPID: rp.PPID,
		Name: rp.Name,
	}
	if pi.Name == "" {
		if n, err := winapi.ImageNameOf(rp.PID); err == nil {
			pi.Name = n
		}
	}

	if path, err := winapi.ImagePath(rp.PID); err == nil {
		pi.Path = path
	}
	if cmd, err := winapi.CommandLine(rp.PID); err == nil {
		pi.CmdLine = cmd
	}
	if user, err := winapi.ProcessUser(rp.PID); err == nil {
		pi.User = user
	}
	if sid, err := winapi.SessionID(rp.PID); err == nil {
		pi.SessionID = sid
	}
	pi.Elevated = winapi.IsElevated(rp.PID)
	pi.IsWow64 = winapi.IsWow64(rp.PID)

	// 优先用内核给出的创建时间，避免再发起一次系统调用
	if rp.CreateTime > 0 {
		pi.StartTime = filetimeToTime(rp.CreateTime)
	} else if ts, err := winapi.ProcessStartTime(rp.PID); err == nil && ts > 0 {
		pi.StartTime = time.Unix(ts, 0).UTC()
	}
	return pi
}

// filetimeToTime 把 FILETIME 计数（1601 起 100ns）转换为 UTC 时间。
func filetimeToTime(ft int64) time.Time {
	const epochDiff = 116444736000000000
	ns := (ft - epochDiff) * 100
	if ns <= 0 {
		return time.Time{}
	}
	return time.Unix(0, ns).UTC()
}

// ProcessInfo 是采集层输出（与检测引擎入参保持一致）。
type ProcessInfo struct {
	PID       uint32
	PPID      uint32
	Name      string
	Path      string
	CmdLine   string
	User      string
	SessionID uint32
	Elevated  bool
	IsWow64   bool
	StartTime time.Time
}

func (c *Collector) pushHistoryLocked(pid uint32, rp rawProc, info ProcessInfo) {
	if _, exists := c.history[pid]; !exists {
		c.order = append(c.order, pid)
	}
	c.history[pid] = historyEntry{rawProc: rp, Info: info, ExitedAt: time.Now()}

	if len(c.order) > c.maxHistory {
		drop := len(c.order) - c.maxHistory
		for i := 0; i < drop; i++ {
			delete(c.history, c.order[i])
		}
		c.order = append([]uint32(nil), c.order[drop:]...)
	}
}

// Ancestry 从 pid 向上回溯父进程链，返回由近到远的祖先列表。
//
// 同时返回父进程是否仍存活：父进程已退出是"规避型启动"的常见特征。
//
// 历史条目现在带完整身份：父进程退出后仍能给出路径与命令行，告警证据
// 不会退化成"只有进程名"。同时用启动时间做 PID 复用防护——父进程必须
// 比子进程先存在，否则这个 PID 属于另一个进程实例。
func (c *Collector) Ancestry(snap *Snapshot, pid uint32) ([]model.AncestorLink, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	var chain []model.AncestorLink
	cur := pid
	parentAlive := false
	childStart := c.startTimeOfLocked(snap, pid)

	for i := 0; i < 12; i++ {
		raw, ok := snap.Procs[cur]
		if !ok {
			if h, ok := c.history[cur]; ok {
				raw = h.rawProc
			} else {
				break
			}
		}
		ppid := raw.PPID
		if ppid == 0 || ppid == cur {
			break
		}

		parentRaw, parentInSnap := snap.Procs[ppid]
		name, path, cmd := "", "", ""
		parentStart := time.Time{}

		// 优先用富化快照（含路径/命令行），比现场再查一次 API 更可靠：
		// 父进程可能在这一瞬间刚退出，现场查询会失败。
		if info, ok := c.known[ppid]; ok && info.PID != 0 {
			name, path, cmd, parentStart = info.Name, info.Path, info.CmdLine, info.StartTime
		}
		if parentInSnap {
			if name == "" {
				name = parentRaw.Name
			}
			if parentStart.IsZero() && parentRaw.CreateTime > 0 {
				parentStart = filetimeToTime(parentRaw.CreateTime)
			}
		} else {
			h, ok := c.history[ppid]
			if !ok {
				break
			}
			if name == "" {
				name = h.Name
			}
			if path == "" {
				path = h.Info.Path
			}
			if cmd == "" {
				cmd = h.Info.CmdLine
			}
			if parentStart.IsZero() {
				parentStart = h.Info.StartTime
			}
			// 退出时间兜底：历史条目的 ExitedAt 是"观测到消失"的时刻，
			// 只能挡住明显早于子进程启动的复用，不能当作精确退出时间。
			if !childStart.IsZero() && !h.ExitedAt.IsZero() && h.ExitedAt.Before(childStart) {
				break
			}
		}
		if name == "" {
			break
		}
		// 强不变量：父进程必须先于子进程存在。启动时间反了 = 同一 PID
		// 的另一个实例，继续连会把两代无关进程拼成一条假血缘。
		if !parentStart.IsZero() && !childStart.IsZero() && parentStart.After(childStart) {
			break
		}
		// 只对第一层父进程做现场路径兜底（其余层开销大且价值低）。
		if i == 0 && path == "" {
			if p, err := winapi.ImagePath(ppid); err == nil {
				path = p
			}
		}

		chain = append(chain, model.AncestorLink{
			PID: ppid, PPID: raw.PPID, Name: name, Path: path, Cmd: cmd,
		})
		if i == 0 {
			parentAlive = parentInSnap
			if !parentStart.IsZero() {
				childStart = parentStart // 下一层按父进程的启动时间继续校验
			}
		}
		cur = ppid
	}

	return chain, parentAlive
}

// startTimeOfLocked 返回某进程已掌握的启动时间（已知富化 > 快照 > 历史）。
func (c *Collector) startTimeOfLocked(snap *Snapshot, pid uint32) time.Time {
	if info, ok := c.known[pid]; ok && !info.StartTime.IsZero() {
		return info.StartTime
	}
	if raw, ok := snap.Procs[pid]; ok && raw.CreateTime > 0 {
		return filetimeToTime(raw.CreateTime)
	}
	if h, ok := c.history[pid]; ok {
		return h.Info.StartTime
	}
	return time.Time{}
}

// NameOf 返回快照中某 PID 的进程名。
func (c *Collector) NameOf(snap *Snapshot, pid uint32) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if p, ok := snap.Procs[pid]; ok {
		return p.Name
	}
	if h, ok := c.history[pid]; ok {
		return h.Name
	}
	return ""
}

// IdentOf 返回某 PID 的进程名与启动时间（"已知最完整"口径与血缘一致：
// 富化缓存 > 快照 CreateTime > 退出历史）。网络行为检测需要启动时间做
// PID 复用判定——复用不清零行为窗口，旧进程的扫描扇出会算到新进程头上。
func (c *Collector) IdentOf(snap *Snapshot, pid uint32) (string, time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	var name string
	if p, ok := snap.Procs[pid]; ok {
		name = p.Name
	}
	return name, c.startTimeOfLocked(snap, pid)
}

// Modules 采集指定进程的模块列表（仅对可疑进程调用，成本较高）。
func (c *Collector) Modules(pid uint32) []model.ModuleInfo {
	mods, err := winapi.ProcessModules(pid)
	if err != nil {
		return nil
	}
	out := make([]model.ModuleInfo, 0, len(mods))
	for _, m := range mods {
		out = append(out, model.ModuleInfo{
			Name: m.Name, Path: m.Path, BaseAddr: m.BaseAddr, Size: m.Size,
		})
	}
	return out
}

// ConnectionsOf 把系统级连接表投影成某进程的连接列表。
func (c *Collector) ConnectionsOf(snap *Snapshot, pid uint32) []model.NetConn {
	raw := snap.Conns[pid]
	if len(raw) == 0 {
		return nil
	}
	out := make([]model.NetConn, 0, len(raw))
	for _, c := range raw {
		// 只保留已建立 / 监听 / 半开 状态，过滤 TIME_WAIT 等噪声
		if c.State != "ESTABLISHED" && c.State != "LISTEN" && c.State != "SYN_SENT" {
			continue
		}
		out = append(out, model.NetConn{
			Proto: c.Proto, LocalIP: c.LocalIP, LocalPort: uint32(c.LocalPort),
			RemoteIP: c.RemoteIP, RemotePort: uint32(c.RemotePort), State: c.State,
		})
	}
	return out
}

// KnownMachineProcesses 是一批"几乎总在运行"的系统进程名。
var KnownMachineProcesses = map[string]struct{}{
	"system": {}, "smss.exe": {}, "csrss.exe": {}, "wininit.exe": {}, "winlogon.exe": {},
	"services.exe": {}, "lsass.exe": {}, "svchost.exe": {}, "explorer.exe": {},
	"spoolsv.exe": {}, "dwm.exe": {}, "fontdrvhost.exe": {}, "ctfmon.exe": {},
	"taskhostw.exe": {}, "sihost.exe": {}, "runtimebroker.exe": {}, "searchindexer.exe": {},
}

// IsKnownMachineProcess 判断是否为常见系统进程。
func IsKnownMachineProcess(name string) bool {
	_, ok := KnownMachineProcesses[strings.ToLower(name)]
	return ok
}
