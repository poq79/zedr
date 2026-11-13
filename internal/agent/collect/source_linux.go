//go:build linux

package collect

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"zedr/internal/agent/nettypes"
)

// NewSource 按名字构造采集源（Linux）。procfs 是当前唯一实现；
// 保留 auto 名称与 Windows 侧配置对齐（同一份 HG_AGENT_COLLECTOR 语义）。
// 未在 Linux 实机验证：解析口径按 procfs 稳定 ABI（kernel 5.x/6.x 文档），
// 解析逻辑在 parse_procdata.go（neutral，Windows 上有单测锁定）。
func NewSource(name string) (Source, string, error) {
	switch name {
	case SourceProcfs, "", SourceAuto:
		return procfsSource{}, "procfs 采集（/proc/[pid]）", nil
	default:
		return nil, "", fmt.Errorf("未知的采集源 %q（Linux 仅支持 procfs）", name)
	}
}

// procfsSource 是 Linux 的进程表来源：直接读 /proc。
//
// 设计口径：
//   - 单次快照一次目录扫描，不做每进程一次额外系统调用（与 Windows 侧
//     "单次全量拉取"策略对齐）；
//   - CreateTime 由 /proc/[pid]/stat 的 starttime（boot 起的秒+厘秒）经
//     /proc/uptime 锚到墙钟（PID 复用判定依赖它）；
//   - 连接表来自 /proc/net/tcp + tcp6，归属 PID 经 inode→fd 扫描还原
//     （单次遍历全部进程的 fd 目录，避免每连接一次系统调用）；
//   - 竞态是固有属性：读 stat 时进程刚退出 → 跳过该 PID（Windows 侧
//     同口径），不视为错误。
type procfsSource struct{}

func (procfsSource) Name() string { return SourceProcfs }

func (procfsSource) Table() (*Table, error) {
	start := time.Now()

	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}
	up, uerr := readUptimeSeconds()

	t := &Table{Procs: make(map[uint32]rawProc, len(entries))}
	for _, e := range entries {
		pid, err := strconv.ParseUint(e.Name(), 10, 32)
		if err != nil {
			continue // 非 PID 目录（net/ sys/ bus/ ...）
		}
		stat, serr := readProcStat(uint32(pid))
		if serr != nil {
			continue // 进程已退出（竞态固有，跳过）
		}
		raw := rawProc{
			PID:  uint32(pid),
			Name: stat.Comm,
			PPID: stat.PPID,
		}
		if uerr == nil {
			raw.CreateTime = bootTicksToUnixNanos(stat.StartTimeTicks, up)
		}
		if raw.Name == "" {
			raw.Name = strconv.FormatUint(pid, 10)
		}
		t.Procs[uint32(pid)] = raw
	}
	t.TakenAt = start
	t.Count = len(t.Procs)

	// 连接表失败不影响进程采集（与 Windows 侧同一降级口径）
	if conns, cerr := procfsTCPConns(); cerr == nil {
		t.Conns = conns
	}
	return t, nil
}

// readProcStat 读 /proc/[pid]/stat 并交给纯解析函数（切分规则见
// parseProcStat：comm 含空格/括号，必须按最后一个 ')' 切）。
func readProcStat(pid uint32) (procStat, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return procStat{}, err
	}
	st, err := parseProcStat(data)
	if err != nil {
		// 带上 pid 上下文：调用方按 PID 粒度跳过，日志要能定位是哪个
		return st, fmt.Errorf("pid %d: %w", pid, err)
	}
	return st, nil
}

// readUptimeSeconds 读 /proc/uptime（解析规则见 parseUptime）。
func readUptimeSeconds() (float64, error) {
	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0, err
	}
	return parseUptime(data)
}

// procfsTCPConns 把 /proc/net/tcp + tcp6 解析为 pid → 连接表。
// 归属还原：一次遍历所有进程的 fd 目录，把 socket:[inode] 映射到 PID，
// 再按 inode 挂到连接上——n 个连接 m 个进程的成本是 O(总 fd 数)，
// 与 Windows 侧 GetExtendedTcpTable 的"单次全量"策略对齐。
func procfsTCPConns() (map[uint32][]nettypes.TCPConn, error) {
	inodePID, err := scanSocketInodes()
	if err != nil {
		return nil, err
	}
	out := make(map[uint32][]nettypes.TCPConn, 256)
	for _, file := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		data, err := os.ReadFile(file)
		if err != nil {
			continue // tcp6 不存在（纯 IPv4 内核）是常态
		}
		for _, e := range parseNetTCPEntries(data, protoOf(file)) {
			if e.Inode == 0 {
				continue // TIME_WAIT / 无 inode 的 socket，本就无法归属
			}
			pid, ok := inodePID[e.Inode]
			if !ok {
				// 归属不明的连接不进表：连接表按 PID 组织，netwatch/
				// chain 全按进程视角消费，一条"无主"连接挂不进任何
				// 进程的序列。诚实边界：非 root 时别的用户的 fd 目录
				// 读不到，这部分连接（含其inode）会被整体丢掉。
				continue
			}
			conn := e.Conn
			conn.PID = pid
			out[pid] = append(out[pid], conn)
		}
	}
	return out, nil
}

func protoOf(file string) string {
	if strings.HasSuffix(file, "6") {
		return "tcp6"
	}
	return "tcp"
}

// scanSocketInodes 遍历 /proc/[pid]/fd，建立 socket inode → PID 映射。
// 无权限的 fd 目录（非 root 扫别的用户进程）整目录跳过，与采集层
// "能采多少采多少"的口径一致。
func scanSocketInodes() (map[uint64]uint32, error) {
	out := make(map[uint64]uint32, 1024)
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		pid, err := strconv.ParseUint(e.Name(), 10, 32)
		if err != nil {
			continue
		}
		fds, err := os.ReadDir(filepath.Join("/proc", e.Name(), "fd"))
		if err != nil {
			continue
		}
		for _, fd := range fds {
			link, err := os.Readlink(filepath.Join("/proc", e.Name(), "fd", fd.Name()))
			if err != nil {
				continue
			}
			if inode, ok := strings.CutPrefix(link, "socket:["); ok {
				if ino, err := strconv.ParseUint(strings.TrimSuffix(inode, "]"), 10, 64); err == nil {
					out[ino] = uint32(pid)
				}
			}
		}
	}
	return out, nil
}
