package linuxinv

// procnet.go — listeners 节：/proc/net/tcp{,6}+udp{,6} 解析 + inode→PID。
//
// 解析口径与 internal/agent/hygiene/linuxparse.go 同源（暴露面视图）。
// 两包各自持有一份小解析器是刻意取舍：hygiene 与 linuxinv 是两个独立
// 的视图包，互相 import 会让"体检按需采集"与"清单周期采集"的调用面
// 耦合在一起；~60 行解析逻辑的双份维护成本低于跨包耦合（同一取舍也
// 见 recon 的 nettypes 行类型）。两边解析语义若分叉，测试 fixture 是
// 同一份内核文档口径，diff 会立刻暴露。

import (
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
)

// invListener / invUDPListener 字段名对齐 Windows invListenersSection
// 的线协议（port/pid/process）。
type invListener struct {
	Port    uint16 `json:"port"`
	PID     uint32 `json:"pid"`
	Process string `json:"process,omitempty"`
}

type invUDPListener struct {
	Port uint16 `json:"port"`
	PID  uint32 `json:"pid"`
}

// listenersSection 监听端口节，payload 形状与 Windows 完全一致：
// {"tcp":[{port,pid,process}],"udp":[{port,pid}]}——服务端 Diff 的
// keyFn（proto|port）与服务端契约零分叉。
//
// 进程名解析：/proc/net 只有 socket inode，先扫 /proc/[pid]/fd 反查
// inode→PID，再逐 PID 读 /proc/[pid]/comm（比 /proc/[pid]/status 轻）。
// 这是本节最贵的一步（O(进程×fd)），Windows 版逐 PID 查询的成本同级；
// 30s 周期 + 差量协议（稳定态不上报）下可接受。pid 读不到（竞态退出）
// 留 0/空名——诚实缺席。
func listenersSection() (any, error) {
	out := map[string]any{
		"tcp": []invListener{},
		"udp": []invUDPListener{},
	}

	var rows []linuxNetRow
	for _, src := range []struct{ file, proto string }{
		{"/proc/net/tcp", "tcp"}, {"/proc/net/tcp6", "tcp"},
		{"/proc/net/udp", "udp"}, {"/proc/net/udp6", "udp"},
	} {
		if data, err := os.ReadFile(src.file); err == nil {
			rows = append(rows, parseProcNet(src.proto, string(data))...)
		}
	}
	if len(rows) == 0 {
		// 四个表全读不到（非 Linux / 严重异常）：报错让 Manager 跳过
		// 本节，不输出"零监听"的假象。
		return nil, fmt.Errorf("/proc/net 四表均不可读")
	}

	inodePID := scanSocketInodes()
	procName := func(pid uint32) string {
		if pid == 0 {
			return ""
		}
		return readFirstLine("/proc/" + strconv.FormatUint(uint64(pid), 10) + "/comm")
	}

	tcp := make([]invListener, 0, 16)
	udp := make([]invUDPListener, 0, 8)
	// 去重键 (proto,port,pid,inode)：同一监听 socket 在 tcp 表里可能有
	// v4/v6 两行（0.0.0.0 与 ::），端口+进程相同就保留一条——与 Windows
	// TCPConnections 的 pid→conns 投影语义一致，也避免 Diff 主键碰撞。
	seen := make(map[string]bool, 32)
	for _, r := range rows {
		if r.Proto == "tcp" && r.State != procTCPListenHex {
			continue
		}
		key := fmt.Sprintf("%s|%d|%d|%d", r.Proto, r.LocalPort, inodePID[r.Inode], r.Inode)
		if seen[key] {
			continue
		}
		seen[key] = true
		pid := inodePID[r.Inode]
		if r.Proto == "tcp" {
			tcp = append(tcp, invListener{Port: r.LocalPort, PID: pid, Process: procName(pid)})
		} else {
			udp = append(udp, invUDPListener{Port: r.LocalPort, PID: pid})
		}
	}

	sort.Slice(tcp, func(i, j int) bool {
		if tcp[i].Port != tcp[j].Port {
			return tcp[i].Port < tcp[j].Port
		}
		return tcp[i].PID < tcp[j].PID
	})
	sort.Slice(udp, func(i, j int) bool {
		if udp[i].Port != udp[j].Port {
			return udp[i].Port < udp[j].Port
		}
		return udp[i].PID < udp[j].PID
	})
	out["tcp"] = tcp
	out["udp"] = udp
	return out, nil
}

// linuxNetRow 是 /proc/net/{tcp,tcp6,udp,udp6} 的一行。
type linuxNetRow struct {
	Proto     string // 调用方按来源文件注入（tcp/tcp6/udp/udp6 归一）
	LocalIP   string
	LocalPort uint16
	State     string // st 列十六进制原串（TCP: 0A=LISTEN 01=ESTABLISHED…）
	Inode     uint64
}

// procTCPListenHex 是 TCP 状态机里的 LISTEN 编码（st 列）。
const procTCPListenHex = "0A"

// parseProcNet 解析 /proc/net/tcp|tcp6|udp|udp6 文本（四文件列布局一致）。
// 端口列是 4 位 hex；解析失败的行跳过（覆盖面优先，不让单行脏数据拖垮整节）。
func parseProcNet(proto, data string) []linuxNetRow {
	var out []linuxNetRow
	lines := strings.Split(data, "\n")
	for i, raw := range lines {
		if i == 0 {
			continue // 表头
		}
		fields := strings.Fields(strings.TrimSpace(raw))
		// sl local rem st tx:rx tr:tm->when retrnsmt uid timeout inode
		if len(fields) < 10 {
			continue
		}
		ip, port, ok := parseHexSockaddr(fields[1])
		if !ok {
			continue
		}
		row := linuxNetRow{Proto: proto, LocalIP: ip, LocalPort: port, State: fields[3]}
		if n, err := strconv.ParseUint(fields[9], 10, 64); err == nil {
			row.Inode = n
		}
		out = append(out, row)
	}
	return out
}

// parseHexSockaddr 解析 "AABBCCDD:1F90" 形态的 hex 地址:端口。
func parseHexSockaddr(s string) (string, uint16, bool) {
	i := strings.LastIndexByte(s, ':')
	if i <= 0 {
		return "", 0, false
	}
	port, err := strconv.ParseUint(s[i+1:], 16, 16)
	if err != nil {
		return "", 0, false
	}
	switch len(s[:i]) {
	case 8:
		ip, ok := parseHexIPv4(s[:i])
		if !ok {
			return "", 0, false
		}
		return ip, uint16(port), true
	case 32:
		ip, ok := parseHexIPv6(s[:i])
		if !ok {
			return "", 0, false
		}
		return ip, uint16(port), true
	default:
		return "", 0, false
	}
}

// parseHexIPv4 解析 8 位 hex IPv4。字节序（docs.kernel.org/networking/
// proc_net_tcp.html）：内核按 32 位主机序整数打印，x86 小端机上字节序
// 反——127.0.0.1 打印为 0100007F，最低字节是 IP 第一段。
// **未在 Linux 实机验证**，首日校准项。
func parseHexIPv4(hex8 string) (string, bool) {
	if len(hex8) != 8 {
		return "", false
	}
	v, err := strconv.ParseUint(hex8, 16, 32)
	if err != nil {
		return "", false
	}
	return fmt.Sprintf("%d.%d.%d.%d",
		v&0xFF, (v>>8)&0xFF, (v>>16)&0xFF, (v>>24)&0xFF), true
}

// parseHexIPv6 解析 32 位 hex IPv6。字节序：内核按 IP6_HEX_FMT
// （"%08X%08X%08X%08X"）打印 in6_addr 的 4 个 u6_addr32 原生序字——
// 小端机上每个 8 hex 组内部字节反（::1 打印为 …01000000）。还原：
// 每组按小端展开 4 字节拼成 16 字节网络序地址。**未在 Linux 实机验证**。
func parseHexIPv6(hex32 string) (string, bool) {
	if len(hex32) != 32 {
		return "", false
	}
	var b [16]byte
	for g := 0; g < 4; g++ {
		v, err := strconv.ParseUint(hex32[g*8:(g+1)*8], 16, 32)
		if err != nil {
			return "", false
		}
		b[g*4+0] = byte(v & 0xFF)
		b[g*4+1] = byte((v >> 8) & 0xFF)
		b[g*4+2] = byte((v >> 16) & 0xFF)
		b[g*4+3] = byte((v >> 24) & 0xFF)
	}
	return net.IP(b[:]).String(), true
}

// scanSocketInodes 反查 socket inode → PID（/proc/[pid]/fd 的
// "socket:[inode]" 符号链接）。同一 socket 被多进程共享（fork）时
// 先到先得——不做"唯一持有者"的虚假判定。
func scanSocketInodes() map[uint64]uint32 {
	out := make(map[uint64]uint32, 64)
	ents, err := os.ReadDir("/proc")
	if err != nil {
		return out
	}
	for _, e := range ents {
		if !e.IsDir() {
			continue
		}
		pid, err := strconv.ParseUint(e.Name(), 10, 32)
		if err != nil {
			continue
		}
		fds, err := os.ReadDir("/proc/" + e.Name() + "/fd")
		if err != nil {
			continue // 权限不足或进程已退出
		}
		dir := "/proc/" + e.Name() + "/fd/"
		for _, fd := range fds {
			link, err := os.Readlink(dir + fd.Name())
			if err != nil {
				continue
			}
			// 形态："socket:[12345]"
			if !strings.HasPrefix(link, "socket:[") || !strings.HasSuffix(link, "]") {
				continue
			}
			inode, err := strconv.ParseUint(link[8:len(link)-1], 10, 64)
			if err != nil {
				continue
			}
			if _, ok := out[inode]; !ok {
				out[inode] = uint32(pid)
			}
		}
	}
	return out
}
