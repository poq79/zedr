package liveapi

// peers.go：外联对端聚合（契约 §16.2，"谁在跟这台机器说话"）。
//
// 纯聚合端点：数据源就是 /netstat 已经在用的 Deps.Netstat（连接表）+ 进程
// 快照（给 PID 补名字），不新增任何系统调用或采集面。只统计 ESTABLISHED：
// LISTEN/TIME_WAIT 不代表当前有对端在通信，混进来会让"外联对端"失去意义。
//
// 截断语义（顶层 truncated）：
//   - peers 数组按连接数降序取前 200；
//   - by_process 数组按对端数降序取前 50；
//   - counts 与两个数组的长度无关，始终描述完整快照（established=ESTABLISHED
//     连接总数，public/private=按对端 IP 去重后的公网/内网对端数），这样即使
//     peers 被截断，分析师仍能看到机器真实的对外连接规模。
//
// 预算 5s 是契约上界：本端点只有一次 GetExtendedTcpTable 调用 + O(行数)
// 的内存聚合，实测远低于预算；枚举器不接受 context，因此没有中途取消路径，
// 这里不引入无意义的超时分支。

import (
	"fmt"
	"net/http"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"zedr/internal/agent/state"
	"zedr/internal/agent/winapi"
	"zedr/internal/platform/httpx"
)

const (
	peersMax          = 200
	peersByProcessMax = 50
)

// peerPort 是对端 IP 下的端口聚合行。
type peerPort struct {
	Port  uint16 `json:"port"`
	Conns int    `json:"conns"`
}

// peerEntry 是按远端 IP 聚合后的对端（契约 §16.2 peers[]）。
type peerEntry struct {
	IP    string     `json:"ip"`
	Class string     `json:"class"`
	Ports []peerPort `json:"ports"`
	Conns int        `json:"conns"`
	Procs []string   `json:"procs"`
}

// peerProcess 是按进程聚合的视图（契约 §16.2 by_process[]）。
type peerProcess struct {
	PID       uint32 `json:"pid"`
	Name      string `json:"name"`
	Conns     int    `json:"conns"`
	PeerCount int    `json:"peer_count"`
}

// peersCounts 描述完整快照，不受数组截断影响。
type peersCounts struct {
	Established int `json:"established"`
	Public      int `json:"public"`
	Private     int `json:"private"`
}

// peersResult 是 /peers 的完整响应（httpx.WriteJSON 包进 data）。
type peersResult struct {
	GeneratedAt string        `json:"generated_at"`
	Truncated   bool          `json:"truncated"`
	Counts      peersCounts   `json:"counts"`
	Peers       []peerEntry   `json:"peers"`
	ByProcess   []peerProcess `json:"by_process"`
}

// handlePeers 返回 GET /peers（需要 Deps.Netstat；Procs/Snapshot 未接线时
// 进程名退化为"(已退出)"，端点本身仍可用）。
func (s *server) handlePeers(w http.ResponseWriter, r *http.Request) {
	if s.d.Netstat == nil {
		httpx.WriteError(w, r, errNotImplemented("网络连接表"))
		return
	}
	httpx.WriteJSON(w, r, http.StatusOK, buildPeersResult(
		s.d.Netstat(), s.snapshotRows(), time.Now().UTC()))
}

// peerAgg 是聚合中间态：同一远端 IP 的端口/进程计数。
type peerAgg struct {
	ip    string
	class string
	conns int
	ports map[uint16]int
	procs map[uint32]int // pid → 该对端上的连接数
}

// procAgg 是按进程聚合的中间态。
type procAgg struct {
	pid   uint32
	conns int
	peers map[string]struct{}
}

// buildPeersResult 是纯聚合逻辑（单测直接注入桩连接表/进程快照）。
func buildPeersResult(rows []winapi.NetRow, snap []state.ProcRow, generatedAt time.Time) peersResult {
	pidName := make(map[uint32]string, len(snap))
	for _, p := range snap {
		pidName[p.PID] = procDisplayName(p)
	}

	peers := make(map[string]*peerAgg)
	procs := make(map[uint32]*procAgg)
	var counts peersCounts

	for _, row := range rows {
		if !strings.EqualFold(row.State, "ESTABLISHED") || row.RemoteIP == "" {
			continue
		}
		counts.Established++

		p := peers[row.RemoteIP]
		if p == nil {
			p = &peerAgg{
				ip:    row.RemoteIP,
				class: classifyRemote(row.RemoteIP),
				ports: make(map[uint16]int),
				procs: make(map[uint32]int),
			}
			peers[row.RemoteIP] = p
		}
		p.conns++
		p.ports[row.RemotePort]++
		p.procs[row.PID]++

		pr := procs[row.PID]
		if pr == nil {
			pr = &procAgg{pid: row.PID, peers: make(map[string]struct{})}
			procs[row.PID] = pr
		}
		pr.conns++
		pr.peers[row.RemoteIP] = struct{}{}
	}

	// 对端分类计数按 IP 去重：同一个公网 IP 上开 100 条连接仍只算 1 个
	// 对端，否则 counts.public 会退化成"连接数"，与 established 口径重复。
	for _, p := range peers {
		switch p.class {
		case "public":
			counts.Public++
		case "private":
			counts.Private++
		}
	}

	outPeers := make([]peerEntry, 0, len(peers))
	for _, p := range peers {
		outPeers = append(outPeers, p.entry(pidName))
	}
	// 连接数降序；同数按 IP 升序保证多次调用输出稳定（前端可做 diff）。
	sort.Slice(outPeers, func(i, j int) bool {
		if outPeers[i].Conns != outPeers[j].Conns {
			return outPeers[i].Conns > outPeers[j].Conns
		}
		return outPeers[i].IP < outPeers[j].IP
	})

	outProcs := make([]peerProcess, 0, len(procs))
	for _, p := range procs {
		name := pidName[p.pid]
		if name == "" {
			name = "(已退出)"
		}
		outProcs = append(outProcs, peerProcess{
			PID:       p.pid,
			Name:      name,
			Conns:     p.conns,
			PeerCount: len(p.peers),
		})
	}
	// 对端数降序（"谁在跟最多对端说话"）；同数按连接数降序、PID 升序。
	sort.Slice(outProcs, func(i, j int) bool {
		if outProcs[i].PeerCount != outProcs[j].PeerCount {
			return outProcs[i].PeerCount > outProcs[j].PeerCount
		}
		if outProcs[i].Conns != outProcs[j].Conns {
			return outProcs[i].Conns > outProcs[j].Conns
		}
		return outProcs[i].PID < outProcs[j].PID
	})

	res := peersResult{
		GeneratedAt: generatedAt.Format(time.RFC3339),
		Counts:      counts,
		Peers:       []peerEntry{},
		ByProcess:   []peerProcess{},
	}
	if len(outPeers) > peersMax {
		res.Truncated = true
		outPeers = outPeers[:peersMax]
	}
	if len(outProcs) > peersByProcessMax {
		res.Truncated = true
		outProcs = outProcs[:peersByProcessMax]
	}
	res.Peers = outPeers
	res.ByProcess = outProcs
	return res
}

// entry 把一个远端 IP 的聚合中间态转成线协议行。
func (p *peerAgg) entry(pidName map[uint32]string) peerEntry {
	ports := make([]peerPort, 0, len(p.ports))
	for port, conns := range p.ports {
		ports = append(ports, peerPort{Port: port, Conns: conns})
	}
	sort.Slice(ports, func(i, j int) bool {
		if ports[i].Conns != ports[j].Conns {
			return ports[i].Conns > ports[j].Conns
		}
		return ports[i].Port < ports[j].Port
	})

	type procRef struct {
		pid   uint32
		name  string
		conns int
	}
	refs := make([]procRef, 0, len(p.procs))
	for pid, conns := range p.procs {
		name := pidName[pid]
		if name == "" {
			name = "(已退出)"
		}
		refs = append(refs, procRef{pid: pid, name: name, conns: conns})
	}
	// 同一进程的多条连接只出现一次；按连接数降序，同数按名字/PID 升序。
	sort.Slice(refs, func(i, j int) bool {
		if refs[i].conns != refs[j].conns {
			return refs[i].conns > refs[j].conns
		}
		if refs[i].name != refs[j].name {
			return refs[i].name < refs[j].name
		}
		return refs[i].pid < refs[j].pid
	})
	procStrs := make([]string, 0, len(refs))
	for _, ref := range refs {
		procStrs = append(procStrs, fmt.Sprintf("%s(%d)", ref.name, ref.pid))
	}

	return peerEntry{
		IP:    p.ip,
		Class: p.class,
		Ports: ports,
		Conns: p.conns,
		Procs: procStrs,
	}
}

// procDisplayName 取进程可读名：优先 Name，缺失时退回路径的文件名，
// 两者都没有才用"(未知)"。快照里 Name 为空属于异常采集，不能当成
// "已退出"（那会让分析师误判进程生命周期）。
func procDisplayName(p state.ProcRow) string {
	if p.Name != "" {
		return p.Name
	}
	if p.Path != "" {
		return filepath.Base(p.Path)
	}
	return "(未知)"
}
