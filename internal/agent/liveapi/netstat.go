// 本文件 NEUTRAL：/netstat 双平台编译。唯一的平台差异点——对快照内存活
// PID 的实时富化（启动时刻/提权态）——收敛为 netRealtime 平台钩子
// （Windows：OpenProcess/GetProcessTimes；Linux：/proc/[pid] 只读解析，
// 见 platform_linux.go）。
package liveapi

// netstat.go：/netstat（契约 §5.2 v1 + §11.2 v2 富化）。
//
// v2 富化口径（向后兼容：只增字段不改 v1 字段名）：
//   - 快照 join 提供 proc_user/proc_cmdline/proc_name/proc_path；
//   - proc_started_at/proc_elevated 对快照内存活进程做实时查询（唯一 PID
//     有上限护栏）；ProcRow 不含这两项，只能按 PID 实时取；
//   - exited = PID 不在快照。探针快照不保留历史行（Reap 即删），单快照
//     窗口内无法回溯"上次叫什么"，按契约降级输出 "(已退出)"——局限如实
//     注释：要还原历史名需要持久化进程史，属后续批次。

import (
	"net"
	"net/http"

	"zedr/internal/agent/nettypes"
	"zedr/internal/agent/state"
	"zedr/internal/platform/httpx"
	"zedr/internal/platform/redact"
)

// netRealtimeEnrichMax 逐 PID 实时富化的上限：超过说明连接表被非常规
// 占用，OpenProcess/GetProcessTimes 逐个查的成本失控，宁可少给字段。
const netRealtimeEnrichMax = 256

// netItem 是 /netstat 输出行：连接五元组 + 富化的归属进程信息。
// 内嵌 nettypes.NetRow（winapi.NetRow 的单一事实源）让 JSON 字段原地展开，
// 线协议与契约逐字对齐；v2 追加字段全部 omitempty，老消费者解析不受影响。
type netItem struct {
	nettypes.NetRow
	ProcName      string `json:"proc_name"`
	ProcPath      string `json:"proc_path"`
	ProcUser      string `json:"proc_user,omitempty"`
	ProcStartedAt int64  `json:"proc_started_at,omitempty"` // unix 秒（进程真实启动时刻）
	ProcCmdline   string `json:"proc_cmdline,omitempty"`    // 已过 redact
	ProcElevated  bool   `json:"proc_elevated,omitempty"`
	Exited        bool   `json:"exited,omitempty"`
	RemoteClass   string `json:"remote_class,omitempty"` // loopback|private|public|multicast|reserved
}

func (s *server) handleNetstat(w http.ResponseWriter, r *http.Request) {
	if s.d.Netstat == nil {
		httpx.WriteError(w, r, errNotImplemented("网络连接表"))
		return
	}
	rows := s.d.Netstat()
	if len(rows) > procMax {
		rows = rows[:procMax]
	}
	httpx.WriteJSON(w, r, http.StatusOK, map[string]any{
		"items": s.enrichNetRows(rows, s.snapshotRows()),
	})
}

// enrichNetRows 把连接表与进程快照 join 成富化行（/netstat 全表与
// /procinfo 单进程过滤后共用）。
func (s *server) enrichNetRows(rows []nettypes.NetRow, snap []state.ProcRow) []netItem {
	byPID := make(map[uint32]state.ProcRow, len(snap))
	for _, p := range snap {
		byPID[p.PID] = p
	}

	// 实时富化集合：快照内唯一 PID（连接表里同一进程几十条连接是常态，
	// 按 PID 去重后才谈得上成本可控）；逐 PID 的实时查询在平台钩子里，
	// 成本护栏（netRealtimeEnrichMax）在钩子两侧共同遵守
	startedAt := make(map[uint32]int64, len(byPID))
	elevated := make(map[uint32]bool, len(byPID))
	if len(byPID) > 0 && len(byPID) <= netRealtimeEnrichMax {
		pids := make([]uint32, 0, len(byPID))
		for pid := range byPID {
			pids = append(pids, pid)
		}
		startedAt, elevated = netRealtime(pids)
	}

	items := make([]netItem, 0, len(rows))
	for _, row := range rows {
		item := netItem{NetRow: row, RemoteClass: classifyRemote(row.RemoteIP)}
		if p, ok := byPID[row.PID]; ok {
			item.ProcName = p.Name
			item.ProcPath = p.Path
			item.ProcUser = p.User
			item.ProcCmdline = redact.CmdLine(p.CmdLine)
			item.ProcStartedAt = startedAt[row.PID]
			item.ProcElevated = elevated[row.PID]
		} else {
			// 连接还在、进程没了（典型：短命植入跑完即退）——排查高价值
			// 信号，显式标注而不是留空让前端猜
			item.Exited = true
			item.ProcName = "(已退出)"
		}
		items = append(items, item)
	}
	return items
}

// classifyRemote 远端地址分类（契约 §11.2 五类）。
// 判定顺序：loopback → multicast → private(RFC1918+链路本地) →
// reserved(0.0.0.0/:: 与 240/4) → 其余 public。UDP 行远端恒为
// 0.0.0.0:0，归 reserved 是刻意的：它不是一次真实外联。
func classifyRemote(ipStr string) string {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return "" // 地址非法时宁可缺省也不瞎分类
	}
	switch {
	case ip.IsLoopback():
		return "loopback"
	case ip.IsMulticast() || ip.IsLinkLocalMulticast():
		return "multicast"
	case ip.IsPrivate(), ip.IsLinkLocalUnicast():
		return "private"
	case ip.IsUnspecified():
		return "reserved"
	}
	if ip4 := ip.To4(); ip4 != nil && ip4[0] >= 240 {
		return "reserved" // 240.0.0.0/4（含广播 255.255.255.255）
	}
	return "public"
}
