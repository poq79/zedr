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

	lastFullScan  time.Time
	deepScanEvery time.Duration
	maxHistory    int
}

type historyEntry struct {
	rawProc
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
		fresh = append(fresh, cur)
	}

	// 记录本轮消失的进程，用于血缘回溯
	for pid, old := range c.prev {
		if _, still := table.Procs[pid]; !still {
			c.pushHistoryLocked(pid, old)
		}
	}
	c.prev = table.Procs
	c.mu.Unlock()

	out := make([]ProcessInfo, 0, len(fresh))
	for _, rp := range fresh {
		out = append(out, c.describe(rp))
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

func (c *Collector) pushHistoryLocked(pid uint32, rp rawProc) {
	if _, exists := c.history[pid]; !exists {
		c.order = append(c.order, pid)
	}
	c.history[pid] = historyEntry{rawProc: rp, ExitedAt: time.Now()}

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
func (c *Collector) Ancestry(snap *Snapshot, pid uint32) ([]model.AncestorLink, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	var chain []model.AncestorLink
	cur := pid
	parentAlive := false

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
		name := ""
		path := ""
		if parentInSnap {
			name = parentRaw.Name
		} else if h, ok := c.history[ppid]; ok {
			name = h.Name
		}
		if name == "" {
			break
		}
		// 只对第一层父进程查完整路径（其余层开销大且价值低）
		if i == 0 {
			if p, err := winapi.ImagePath(ppid); err == nil {
				path = p
			}
		}

		chain = append(chain, model.AncestorLink{
			PID: ppid, PPID: raw.PPID, Name: name, Path: path,
		})
		if i == 0 {
			parentAlive = parentInSnap
		}
		cur = ppid
	}

	return chain, parentAlive
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
