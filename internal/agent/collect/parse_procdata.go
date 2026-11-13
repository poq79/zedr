package collect

// 本文件是 procfs 采集的**纯解析层**：只做字符串→结构的转换，不碰
// 真实文件系统。刻意不打 //go:build linux 标签——本仓库没有 Linux
// 测试环境，Phase A1 的验证口径 = 交叉编译 + 纯逻辑单测；解析函数
// 放 neutral 文件，单测才能在 Windows 上直接跑。IO 壳（读文件 →
// 调这里的函数）留在 source_linux.go / collector_linux.go 的
// //go:build linux 之后。
//
// 未在 Linux 实机验证：解析口径按 procfs 稳定 ABI（kernel 5.x/6.x 的
// fs/proc/array.c 与 net/ipv4/tcp_seq.c 打印格式），如有出入以实机
// 实测为准。

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"zedr/internal/agent/nettypes"
)

// procStat 是 /proc/[pid]/stat 的字段子集（采集层够用即可，不追求全量）。
type procStat struct {
	Comm           string
	State          string
	PPID           uint32
	StartTimeTicks uint64 // 全文件 field 22：boot 起的时钟滴答（USER_HZ=100，秒+厘秒精度）
}

// parseProcStat 从 /proc/[pid]/stat 的文件内容解析字段子集。
//
// 格式为 "%d (%s) %c ..."（fs/proc/array.c）：comm 夹在第一个 '(' 与
// 最后一个 ')' 之间，且 comm 本身可含空格与括号（内核线程名带空格、
// systemd 的助手进程名就叫 "(sd-pam)"）——所以不能按空格取第一个
// 字段，也不能按第一个 ')' 切。')' 之后的字段区只有数字与单个状态
// 字母，不会再出现 ')'，按**最后一个** ')' 切是唯一可靠切分点；
// comm 开头同理必须锚定**第一个** '('（PID 是纯数字，长度不定）。
// PPID/StartTime 的数字解析失败静默为零：内核恒打印合法整数，出现
// 垃圾值说明文件本身已残缺，给零值好过丢弃整条进程记录。
func parseProcStat(data []byte) (procStat, error) {
	var st procStat
	s := string(data)
	l := strings.LastIndexByte(s, ')')
	open := strings.IndexByte(s, '(')
	if open < 0 || l < 0 || open >= l {
		return st, fmt.Errorf("stat 缺少 comm 括号对")
	}
	st.Comm = s[open+1 : l]
	// Fields 自动吞掉 ") " 的空格与可能的连续空白
	rest := strings.Fields(s[l+1:])
	if len(rest) < 20 {
		return st, fmt.Errorf("stat 字段不足: got %d, want >= 20", len(rest))
	}
	st.State = rest[0]
	ppid, _ := strconv.ParseUint(rest[1], 10, 32)
	st.PPID = uint32(ppid)
	st.StartTimeTicks, _ = strconv.ParseUint(rest[19], 10, 64) // rest[0]=field 3 → rest[19]=field 22
	return st, nil
}

// parseUptime 解析 /proc/uptime 第一列（boot 起的秒，恒带两位小数；
// 第二列是全核 idle 累计，这里不需要）。失败必须报错而不是给零值：
// uptime 是 CreateTime 锚定的基准，静默给 0 会把所有进程的启动时间
// 推到 1970 年，PID 复用判定会被彻底带歪。
func parseUptime(data []byte) (float64, error) {
	f := strings.Fields(string(data))
	if len(f) == 0 {
		return 0, fmt.Errorf("uptime 为空")
	}
	return strconv.ParseFloat(f[0], 64)
}

// parseHexAddr 解析 /proc/net/tcp(6) 地址列 "AABBCCDD:1F90"。
//
// kernel 打印口径（tcp_seq.c 对 __be32 用 %08X，机器小端）：
//   - IPv4：8 个 hex 字符 = 4 字节整体小端（127.0.0.1 → 0100007F）；
//   - IPv6：32 字符 = 4 组 × 8 字符，**组内**小端、组间正序
//     （::1 → 00000000000000000000000001000000）。
//
// 还原：每组 4 字节倒序放回、组间顺序不变。IPv4-mapped IPv6
// （::ffff:a.b.c.d）net.IP 会退回点分十进制展示，Proto 字段仍标注
// tcp6 不会与 v4 混淆。未在 Linux 实机验证，口径由单测固定样例锁定。
func parseHexAddr(s string) (string, uint16, bool) {
	host, port, ok := strings.Cut(s, ":")
	if !ok {
		return "", 0, false
	}
	p, err := strconv.ParseUint(port, 16, 16)
	if err != nil {
		return "", 0, false
	}
	if len(host) != 8 && len(host) != 32 {
		return "", 0, false
	}
	groups := len(host) / 8
	var b [16]byte
	for g := 0; g < groups; g++ {
		word := host[g*8 : g*8+8]
		for i := 0; i < 4; i++ {
			n, perr := strconv.ParseUint(word[i*2:i*2+2], 16, 8)
			if perr != nil {
				return "", 0, false
			}
			// 打印序第 i 字节是网络序第 3-i 字节（组内小端还原）
			b[g*4+(3-i)] = byte(n)
		}
	}
	return net.IP(b[:groups*4]).String(), uint16(p), true
}

// procTCPStateNames 把 /proc/net/tcp 的十六进制状态码映射成与 Windows
// GetExtendedTcpTable 相同的状态字符串——netwatch/检测层不感知平台差。
// 口径出自 net/ipv4/tcp_states.h。
var procTCPStateNames = map[string]string{
	"01": "ESTABLISHED", "02": "SYN_SENT", "03": "SYN_RECV",
	"04": "FIN_WAIT1", "05": "FIN_WAIT2", "06": "TIME_WAIT",
	"07": "CLOSE", "08": "CLOSE_WAIT", "09": "LAST_ACK",
	"0A": "LISTEN", "0B": "CLOSING",
}

// procTCPStateName 查状态名，未知码保留原文（检测层可观测到新状态码
// 的存在，而不是静默归入某个已知桶）。内核按 %02X 恒打印大写，这里
// ToUpper 是对魔改内核/容器的容错。
func procTCPStateName(code string) string {
	if name, ok := procTCPStateNames[strings.ToUpper(code)]; ok {
		return name
	}
	return "UNKNOWN(" + code + ")"
}

// tcpSockEntry 是 /proc/net/tcp(6) 单行解析产物：连接本体 + 归属线索。
// inode 是 socket 在内核里的唯一标识，PID 归属由 IO 壳经
// /proc/[pid]/fd 的 "socket:[inode]" 链接反查——纯解析层不碰文件系统。
// Inode=0 表示该行没有可用的 inode（字段缺失/非数字；TIME_WAIT 套接字
// 内核也报 0），两种情况都无法归属 PID。
type tcpSockEntry struct {
	Conn  nettypes.TCPConn
	Inode uint64
}

// parseNetTCPEntries 解析 /proc/net/tcp(6) 全文为连接条目（无 PID）。
//
// 行形状（net/ipv4/tcp_seq.c）："sl: local rem st tx:rx tr:when
// retrnsmt uid timeout inode ..."，下标 9 是 inode 列。表头/空行/
// 字段数不足 10 的残行整行跳过：表头判定用"首列不以 ':' 结尾"
// （数据行 sl 列恒为 "N:"），调用方传整文件或掐了表头的文件都能解析；
// 残行不做截断解析——缺 inode 列意味着无法归属 PID，半条记录只会
// 给检测层制造噪声。地址列异常的行同样宁缺毋滥。
func parseNetTCPEntries(data []byte, proto string) []tcpSockEntry {
	var out []tcpSockEntry
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) == 0 || !strings.HasSuffix(f[0], ":") {
			continue // 空行 / 表头行
		}
		if len(f) < 10 {
			continue // 不足 inode 列，残行
		}
		lIP, lPort, ok := parseHexAddr(f[1])
		if !ok {
			continue
		}
		rIP, rPort, _ := parseHexAddr(f[2])
		e := tcpSockEntry{Conn: nettypes.TCPConn{
			Proto: proto, LocalIP: lIP, LocalPort: lPort,
			RemoteIP: rIP, RemotePort: rPort,
			State: procTCPStateName(f[3]),
		}}
		if ino, err := strconv.ParseUint(f[9], 10, 64); err == nil {
			e.Inode = ino
		}
		out = append(out, e)
	}
	return out
}

// parseNetTCP 是无 PID 版便捷入口：只要连接本体、丢弃归属线索。
// 生产路径（procfsTCPConns）需要 inode 归属 PID，走 parseNetTCPEntries；
// 本函数留给纯连接表消费方与测试。
func parseNetTCP(data []byte, proto string) []nettypes.TCPConn {
	entries := parseNetTCPEntries(data, proto)
	out := make([]nettypes.TCPConn, 0, len(entries))
	for _, e := range entries {
		out = append(out, e.Conn)
	}
	return out
}

// bootTicksToUnixNanosAt 把 stat.starttime（boot 起的 USER_HZ 厘秒）锚到
// Unix 纳秒。now 由调用方注入：锚定用"当前墙钟 - 当前 uptime"反推
// boot 时刻，不读 /proc/stat 的 btime（多读一个文件多一次读取间隙
// 漂移，uptime 与 starttime 同文件族口径更一致）；时间参数化后纯
// 函数可在任意平台单测。USER_HZ 恒为 100（userspace ABI 冻结值）。
func bootTicksToUnixNanosAt(ticks uint64, uptimeSec float64, now time.Time) int64 {
	if ticks == 0 {
		// starttime=0 = boot 时刻已存在的进程（idle/systemd）。0 同时是
		// rawProc.CreateTime 的"未知"哨兵——boot 期进程的启动时间按未知
		// 处理是已知损失（PID 复用判定对这几个 PID 退化成只看名字），
		// 好过伪造一个墙钟时刻。
		return 0
	}
	bootAt := now.Add(-time.Duration(uptimeSec * float64(time.Second)))
	startAt := bootAt.Add(time.Duration(ticks) * (time.Second / 100))
	return startAt.UnixNano()
}

// bootTicksToUnixNanos 是采集路径的薄包装（now 注入真实墙钟）。
func bootTicksToUnixNanos(ticks uint64, uptimeSec float64) int64 {
	return bootTicksToUnixNanosAt(ticks, uptimeSec, time.Now())
}

// parseCmdline 把 /proc/[pid]/cmdline（NUL 分隔的 argv）归一成空格
// 连接的命令行展示。参数本身含空格时边界会糊掉——cmdline 没有引号
// 信息，无法无损还原，这是与 Windows GetCommandLine 展示口径对齐的
// 已知损失；检测层的关键词/规则匹配按子串命中，不受影响。内核线程
// 的 cmdline 为空 → 返回空串，由调用方决定回退。
func parseCmdline(data []byte) string {
	return strings.Join(strings.Fields(strings.ReplaceAll(string(data), "\x00", " ")), " ")
}

// parseStatusUIDs 从 /proc/[pid]/status 的 "Uid:\treal\teffective\t..."
// 行取 real/effective uid。euid==0 是 Elevated 判定口径（与 Windows
// 管理员语义对齐）。ok=false 表示没读到合法 Uid 行——status 对同
// 用户/root 恒可读，读不到多半是权限或竞态，调用方按"用户未知"处理。
func parseStatusUIDs(data []byte) (uid, euid int, ok bool) {
	for _, line := range strings.Split(string(data), "\n") {
		if rest, found := strings.CutPrefix(line, "Uid:"); found {
			f := strings.Fields(rest)
			if len(f) >= 2 {
				uid, _ = strconv.Atoi(f[0])
				euid, _ = strconv.Atoi(f[1])
				return uid, euid, true
			}
		}
	}
	return 0, 0, false
}
