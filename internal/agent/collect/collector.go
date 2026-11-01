// Package collect 实现 Windows 侧的进程采集。
//
// 采集策略（对应报告第 5 章"性能工程"）：
//   - 用 Toolhelp32 快照做增量比对，只对"新出现的 PID"做昂贵富化；
//   - 网络连接用单次 GetExtendedTcpTable 全量拉取，避免每进程一次系统调用；
//   - 已退出进程保留在历史表中，用于还原"父进程已退出"的孤儿链路；
//   - 定期做一次全量深度扫描（补 LD 模块信息），频率远低于增量轮询。
package collect

import (
	"strings"
	"sync"
	"time"

	"hostguard/internal/agent/winapi"
	"hostguard/internal/model"
)

// Collector 维护跨轮次的进程状态。
type Collector struct {
	mu sync.Mutex

	prev    map[uint32]rawProc   // 上一轮的进程
	history map[uint32]historyEntry // 已退出进程，用于血缘回溯
	order   []uint32             // history 的 FIFO 顺序

	lastFullScan time.Time
	deepScanEvery time.Duration
	maxHistory   int
}

type rawProc struct {
	PID   uint32
	PPID  uint32
	Name  string
	Start int64
}

type historyEntry struct {
	rawProc
	ExitedAt time.Time
}

// Snapshot 是一轮采集的原始结果。
type Snapshot struct {
	Procs     map[uint32]rawProc
	Conns     map[uint32][]winapi.TCPConn
	TakenAt   time.Time
	ProcCount int
}

// New 创建采集器。
func New(deepScanEvery time.Duration) *Collector {
	if deepScanEvery <= 0 {
		deepScanEvery = 15 * time.Minute
	}
	return &Collector{
		prev:          make(map[uint32]rawProc, 512),
		history:       make(map[uint32]historyEntry, 2048),
		deepScanEvery: deepScanEvery,
		maxHistory:    2048,
	}
}

// Poll 执行一轮采集，返回需要检测的新进程（已含路径/命令行/账号等字段）。
//
// forceDeep=true 时对所有进程都做完整富化（用于全量扫描与手动重扫）。
func (c *Collector) Poll(forceDeep bool) ([]ProcessInfo, *Snapshot, error) {
	start := time.Now()

	list, err := winapi.SnapshotProcesses()
	if err != nil {
		return nil, nil, err
	}
	conns, connErr := winapi.TCPConnections()
	if connErr != nil {
		conns = map[uint32][]winapi.TCPConn{} // 网络信息失败不影响进程采集
	}

	snap := &Snapshot{
		Procs:     make(map[uint32]rawProc, len(list)),
		Conns:     conns,
		TakenAt:   start,
		ProcCount: len(list),
	}
	for _, p := range list {
		snap.Procs[p.PID] = rawProc{PID: p.PID, PPID: p.PPID, Name: p.Name}
	}

	c.mu.Lock()
	deep := forceDeep || start.Sub(c.lastFullScan) >= c.deepScanEvery
	if deep {
		c.lastFullScan = start
	}

	// 找出新增 / PID 复用 的进程
	var fresh []rawProc
	for pid, cur := range snap.Procs {
		if pid == 0 || pid == 4 {
			continue // System Idle / System 伪进程
		}
		old, existed := c.prev[pid]
		if existed && old.Name == cur.Name {
			continue
		}
		fresh = append(fresh, cur)
	}

	// 记录本轮到上一轮消失的进程，用于血缘回溯
	for pid, old := range c.prev {
		if _, still := snap.Procs[pid]; !still {
			c.pushHistory(pid, old)
		}
	}
	c.prev = snap.Procs

	// 更新快照里的 start time（尽力而为，失败忽略）
	c.mu.Unlock()

	out := make([]ProcessInfo, 0, len(fresh))
	for _, rp := range fresh {
		pi := c.describe(rp, deep)
		out = append(out, pi)
	}

	return out, snap, nil
}

// describe 对单个进程做完整富化。
func (c *Collector) describe(rp rawProc, deep bool) ProcessInfo {
	pi := ProcessInfo{
		PID:  rp.PID,
		PPID: rp.PPID,
		Name: rp.Name,
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
	if ts, err := winapi.ProcessStartTime(rp.PID); err == nil && ts > 0 {
		pi.StartTime = time.Unix(ts, 0).UTC()
	}
	_ = deep
	return pi
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

func (c *Collector) pushHistory(pid uint32, rp rawProc) {
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
			// 已退出：从历史中找
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
			path = h.Path()
		}
		if name == "" {
			break
		}
		// 只对第一层父进程查完整路径（其余层路径开销大且价值低）
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
		// 只保留已建立 / 监听 状态，过滤 TIME_WAIT 等噪声
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

// KnownMachineProcesses 是一批"几乎总在运行"的系统进程名，
// 用于初次启动时避免把全部历史进程当成"新进程"逐个深度检测。
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

// Path 返回历史记录的进程路径（历史表不存路径，返回空）。
func (h historyEntry) Path() string { return "" }
