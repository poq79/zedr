// 本文件 NEUTRAL：Linux /proc 只读解析（无构建标签）。
//
// 为什么放中性文件而不是 linux 标签：① 解析函数是纯逻辑，验证口径要求
// 在 Windows 上跑单测锁定口径（内核文档样例）；② IO 入口读 /proc 固定
// 路径，Windows 上这些文件不存在、函数返回零值，天然不会被执行——
// 中性编译不引入任何 Windows 行为变化。
//
// 与 internal/agent/collect 的 parse_procdata.go 各持一份解析的原因：
// collect 的解析符号（parseHexAddr/parseNetTCPEntries）是私有的，且
// collect 包不在本次移植的所有权范围内、正被检测管线持续演进；调查面
// （liveapi）与检测管线（collect）的消费节奏不同，耦合对方的私有符号
// 会让两个方向互相牵制。两份实现口径一致（同一内核文档 tcp_seq.c/
// tcp_states.h），各自的样例单测互为参照——一边改口径另一边的测试会
// 暴露分歧。
//
// 未在 Linux 实机验证（本机无 Linux 测试环境）；验证口径 = GOOS=linux
// 交叉编译 + 本文件单测在 Windows 上运行。
package liveapi

// linuxproc.go：/proc/net/tcp(6) → nettypes.NetRow 投影（/netstat 数据源，
// 含 LISTEN）+ 单 PID 实时字段（启动时刻/euid）+ /etc/os-release 解析。

import (
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"zedr/internal/agent/nettypes"
)

// procNetStateNames 把 /proc/net/tcp 的十六进制状态码映射成与 Windows
// GetExtendedTcpTable 相同的状态字符串——服务端/前端按状态过滤时不感知
// 平台差。口径出自 net/ipv4/tcp_states.h（与 collect 的映射表同源）。
var procNetStateNames = map[string]string{
	"01": "ESTABLISHED", "02": "SYN_SENT", "03": "SYN_RECV",
	"04": "FIN_WAIT1", "05": "FIN_WAIT2", "06": "TIME_WAIT",
	"07": "CLOSE", "08": "CLOSE_WAIT", "09": "LAST_ACK",
	"0A": "LISTEN", "0B": "CLOSING",
}

// procNetStateName 查状态名；未知码保留原文（新状态码可观测，不静默归桶）。
func procNetStateName(code string) string {
	if name, ok := procNetStateNames[strings.ToUpper(code)]; ok {
		return name
	}
	return "UNKNOWN(" + code + ")"
}

// parseProcNetAddr 解析 /proc/net/tcp(6) 地址列 "AABBCCDD:1F90"。
//
// kernel 打印口径（tcp_seq.c 对 __be32 用 %08X，机器小端）：
//   - IPv4：8 个 hex 字符 = 4 字节整体小端（127.0.0.1 → 0100007F）；
//   - IPv6：32 字符 = 4 组 × 8 字符，组内小端、组间正序
//     （::1 → 00000000000000000000000001000000）。
func parseProcNetAddr(s string) (string, uint16, bool) {
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
	ip := make([]byte, groups*4)
	copy(ip, b[:groups*4])
	return formatProcNetIP(ip), uint16(p), true
}

// formatProcNetIP 把还原出的字节展示成点分/冒号形态。IPv4 用点分十进制；
// IPv6 用 net.IP.String()（IPv4-mapped 会退回点分展示，proto 字段仍标注
// tcp6 不会混淆）。
func formatProcNetIP(b []byte) string {
	if len(b) == 4 {
		return strconv.Itoa(int(b[0])) + "." + strconv.Itoa(int(b[1])) + "." +
			strconv.Itoa(int(b[2])) + "." + strconv.Itoa(int(b[3]))
	}
	return net.IP(b).String()
}

// procSockRow 是一行解析产物：连接本体 + inode 归属线索。
// Inode=0 表示没有可用归属（字段缺失/TIME_WAIT 套接字内核也报 0）。
type procSockRow struct {
	Row   nettypes.NetRow
	Inode uint64
}

// parseProcNetRows 解析 /proc/net/tcp(6) 全文为连接行（无 PID）。
//
// 行形状："sl local rem st tx:rx tr:when retrnsmt uid timeout inode ..."，
// 下标 9 是 inode 列。表头/空行/字段数不足 10 的残行整行跳过（缺 inode
// 列意味着无法归属 PID，半条记录只会给调查面制造噪声）；地址列异常的行
// 同样宁缺毋滥。LISTEN 行照常保留——"谁在监听"是调查的高价值结论。
func parseProcNetRows(data []byte, proto string) []procSockRow {
	var out []procSockRow
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) == 0 || !strings.HasSuffix(f[0], ":") {
			continue // 空行 / 表头行（数据行 sl 列恒为 "N:"）
		}
		if len(f) < 10 {
			continue // 不足 inode 列，残行
		}
		lIP, lPort, ok := parseProcNetAddr(f[1])
		if !ok {
			continue
		}
		rIP, rPort, _ := parseProcNetAddr(f[2])
		row := procSockRow{Row: nettypes.NetRow{
			Proto: proto, LocalIP: lIP, LocalPort: lPort,
			RemoteIP: rIP, RemotePort: rPort,
			State: procNetStateName(f[3]),
		}}
		if ino, err := strconv.ParseUint(f[9], 10, 64); err == nil {
			row.Inode = ino
		}
		out = append(out, row)
	}
	return out
}

// ProcfsNetstat 是 Linux /netstat 的数据源入口（导出给组合根接线：
// liveapi.Deps.Netstat = liveapi.ProcfsNetstat）。
//
// 诚实边界：只投影 TCP（/proc/net/tcp + tcp6）；UDP 行没有 TCP 式状态
// 语义，混进 NetRow 会让 State 字段失真，v1 不收。读不到的表按缺省
// 跳过（容器/权限裁剪下的最小可用），不返回错误——调查面"能拿到多少
// 拿多少"。
func ProcfsNetstat() []nettypes.NetRow {
	var rows []procSockRow
	for _, spec := range [2]struct {
		path  string
		proto string
	}{
		{"/proc/net/tcp", "tcp"},
		{"/proc/net/tcp6", "tcp6"},
	} {
		data, err := os.ReadFile(spec.path)
		if err != nil {
			continue // 表不存在（无 IPv6 支持/权限裁剪）不是错误
		}
		rows = append(rows, parseProcNetRows(data, spec.proto)...)
	}
	if len(rows) == 0 {
		return []nettypes.NetRow{}
	}

	// inode → PID：扫描 /proc/[pid]/fd 的 "socket:[inode]" 链接反查。
	// 与 collect 的同口径做法各持一份（见文件头）；扫描面 = 全部存活
	// 进程的 fd 表，端点是按需触发的调查动作，成本可接受。
	need := make(map[uint64]struct{}, len(rows))
	for _, r := range rows {
		if r.Inode != 0 {
			need[r.Inode] = struct{}{}
		}
	}
	owners := procInodeOwners(need)

	out := make([]nettypes.NetRow, 0, len(rows))
	for _, r := range rows {
		r.Row.PID = owners[r.Inode]
		out = append(out, r.Row)
	}
	return out
}

// procInodeOwners 扫描 /proc/[0-9]*/fd 的 readlink，返回 need 里命中的
// inode → PID 映射。单进程枚举失败（竞态退出/权限）跳过，不让一个进程
// 失败放大成整表失败。
func procInodeOwners(need map[uint64]struct{}) map[uint64]uint32 {
	owners := make(map[uint64]uint32, len(need))
	if len(need) == 0 {
		return owners
	}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return owners
	}
	for _, e := range entries {
		pid, err := strconv.ParseUint(e.Name(), 10, 32)
		if err != nil || pid == 0 {
			continue // 非 PID 目录（acpi/fdinfo 等）与 0 号无效
		}
		fds, err := os.ReadDir("/proc/" + e.Name() + "/fd")
		if err != nil {
			continue // 竞态退出/无权限：跳过
		}
		for _, fd := range fds {
			link, err := os.Readlink("/proc/" + e.Name() + "/fd/" + fd.Name())
			if err != nil {
				continue
			}
			ino, ok := socketInodeOf(link)
			if !ok {
				continue
			}
			if _, hit := need[ino]; hit {
				owners[ino] = uint32(pid)
			}
		}
	}
	return owners
}

// socketInodeOf 从 readlink 结果 "socket:[12345]" 提取 inode。
func socketInodeOf(link string) (uint64, bool) {
	rest, ok := strings.CutPrefix(link, "socket:[")
	if !ok || !strings.HasSuffix(rest, "]") {
		return 0, false
	}
	ino, err := strconv.ParseUint(rest[:len(rest)-1], 10, 64)
	return ino, err == nil
}

// ---------------------------------------------------------------- 单 PID 实时字段

// parseProcStatStarttime 解析 /proc/[pid]/stat 的 starttime 字段（第 22 列，
// boot 起的 USER_HZ 厘秒）。comm 字段可含空格与括号，按"最后一个 ')' 之后"
// 切分再数列：剩余部分首列是 state（第 3 列），starttime 位于剩余下标
// 22-3=19。解析失败 ok=false（调用方省略字段，不给零值冒充 1970 年）。
func parseProcStatStarttime(data []byte) (uint64, bool) {
	s := string(data)
	i := strings.LastIndexByte(s, ')')
	if i < 0 {
		return 0, false
	}
	f := strings.Fields(s[i+1:])
	// 剩余首列 = state（第 3 列）；starttime 是第 22 列 → 下标 19
	if len(f) <= 19 {
		return 0, false
	}
	v, err := strconv.ParseUint(f[19], 10, 64)
	if err != nil {
		return 0, false
	}
	return v, true
}

// parseProcUptime 解析 /proc/uptime 第一列（boot 起的秒，恒带两位小数）。
func parseProcUptime(data []byte) (float64, bool) {
	f := strings.Fields(string(data))
	if len(f) == 0 {
		return 0, false
	}
	v, err := strconv.ParseFloat(f[0], 64)
	if err != nil || v < 0 {
		return 0, false
	}
	return v, true
}

// procStarttimeUnix 把某 PID 的 stat.starttime 锚定为 unix 秒。
// 锚定用"当前墙钟 - 当前 uptime"反推 boot 时刻（与 collect 同口径，避免
// 多读 /proc/stat btime 引入读取间隙漂移）。USER_HZ 恒为 100（userspace
// ABI 冻结值）。任一环节失败返回 0（调用方省略字段，诚实未知）。
func procStarttimeUnix(pid uint32, now time.Time) int64 {
	stat, err := os.ReadFile("/proc/" + strconv.FormatUint(uint64(pid), 10) + "/stat")
	if err != nil {
		return 0
	}
	ticks, ok := parseProcStatStarttime(stat)
	if !ok {
		return 0
	}
	up, ok := procUptimeSeconds()
	if !ok {
		return 0
	}
	boot := now.Add(-time.Duration(up * float64(time.Second)))
	return boot.Add(time.Duration(ticks*10) * (time.Second / 100)).Unix()
}

// procUptimeSeconds 读 /proc/uptime（独立小函数便于失败即跳过）。
func procUptimeSeconds() (float64, bool) {
	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0, false
	}
	return parseProcUptime(data)
}

// parseProcUidReal 解析 /proc/[pid]/status 的 Uid 行第一个值（real uid）。
func parseProcUidReal(data []byte) (uint32, bool) {
	for _, line := range strings.Split(string(data), "\n") {
		rest, ok := strings.CutPrefix(line, "Uid:")
		if !ok {
			continue
		}
		f := strings.Fields(rest)
		if len(f) == 0 {
			return 0, false
		}
		v, err := strconv.ParseUint(f[0], 10, 32)
		if err != nil {
			return 0, false
		}
		return uint32(v), true
	}
	return 0, false
}

// procIsRootEuid 判定某进程是否以 uid 0 运行（proc_elevated 的 Linux 口径：
// root = 提权；读不到 = false，"非 root"与"未知"不可区分是已知口径局限，
// 与 Windows 侧 IsElevated 的注释一致）。
func procIsRootEuid(pid uint32) bool {
	data, err := os.ReadFile("/proc/" + strconv.FormatUint(uint64(pid), 10) + "/status")
	if err != nil {
		return false
	}
	uid, ok := parseProcUidReal(data)
	return ok && uid == 0
}

// ---------------------------------------------------------------- /etc/os-release

// parseOSReleasePretty 取 /etc/os-release 的 PRETTY_NAME（去引号）；缺失
// 返回空串（调用方回退 "linux"）。
func parseOSReleasePretty(data []byte) string {
	for _, line := range strings.Split(string(data), "\n") {
		if v, ok := strings.CutPrefix(line, "PRETTY_NAME="); ok {
			return strings.Trim(strings.TrimSpace(v), `"`)
		}
	}
	return ""
}

// linuxOSName 拼可读系统描述（PRETTY_NAME + 内核版本）；两个来源都读不到
// 时退回 "linux"（诚实降级，与 lapp 的 linuxOSVersion 同思路）。
func linuxOSName() string {
	name := ""
	if data, err := os.ReadFile("/etc/os-release"); err == nil {
		name = parseOSReleasePretty(data)
	}
	if name == "" {
		name = "linux"
	}
	if rel, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
		name += " " + strings.TrimSpace(string(rel))
	}
	return name
}
