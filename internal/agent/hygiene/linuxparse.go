package hygiene

// linuxparse.go — Linux 配置/procfs 文本格式的纯解析函数（无构建标签）。
//
// 为什么放中性文件：这些函数零系统 I/O，只做"文本 → 结构"；本机没有
// Linux 测试环境，纯逻辑单测必须在 Windows 上就能跑全（验证口径见
// 内部验收记录）。
// 采集入口（读文件 + 调用这些函数）在 hygiene_linux.go（linux 标签）。
//
// 未在 Linux 实机验证：解析口径按各发行版惯例与内核文档
// （docs.kernel.org/networking/proc_net_tcp.html）实现。

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// ---------------------------------------------------------------- dpkg

// dpkgTopLimit 是目录清单类条目的单来源上限。dpkg 全量是真实软件面
// （Windows 版同样全量返回），但 /usr/local/bin 一类目录里可能混入
// 大量一次性脚本，截断防止本地面板 payload 失控。
const dirAppsLimit = 100

// parseDpkgStatus 解析 /var/lib/dpkg/status（RFC822 段落格式）为已安装
// 软件清单。只取 "install ok installed" 状态的段落——dpkg 把卸载残留
// 留在文件里（Status: deinstall ok config-files），那不是已安装软件，
// 混进来会是噪声。dpkg status 本身没有安装日期列，InstallDate 恒空。
func parseDpkgStatus(data []byte) []InstalledApp {
	type para struct {
		app       InstalledApp
		installed bool
	}
	var out []InstalledApp
	var cur *para
	flush := func() {
		if cur != nil && cur.installed && cur.app.Name != "" {
			out = append(out, cur.app)
		}
		cur = nil
	}
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimRight(raw, "\r")
		if line == "" {
			flush()
			continue
		}
		// 续行（以空格开头的 Description 正文）：不参与字段提取
		if line[0] == ' ' || line[0] == '\t' {
			continue
		}
		i := strings.IndexByte(line, ':')
		if i < 0 {
			continue
		}
		key, val := line[:i], strings.TrimSpace(line[i+1:])
		switch key {
		case "Package":
			flush()
			cur = &para{app: InstalledApp{Name: val, Source: "dpkg"}}
		case "Version":
			if cur != nil {
				cur.app.Version = val
			}
		case "Installed-Size":
			if cur != nil {
				if n, err := strconv.ParseUint(val, 10, 64); err == nil {
					cur.app.SizeKB = n
				}
			}
		case "Status":
			if cur != nil {
				// 三个状态词（want/install 各类残留）；want=install 且
				// 第三词=installed 才是"装着"
				f := strings.Fields(val)
				cur.installed = len(f) == 3 && f[0] == "install" && f[2] == "installed"
			}
		case "Maintainer":
			if cur != nil {
				cur.app.Publisher = val
			}
		}
	}
	flush()
	return out
}

// ---------------------------------------------------------------- sshd

// parseSshdEffective 提取 sshd_config 的生效键值。
//
// 语义要点（sshd_config(5)）：同一关键字出现多次时"第一次出现"生效，
// 所以这里先到先得；Include 指令不跟随（v1 口径：主文件明面值，注释
// 里如实标注这个边界，不做虚假的"完整生效配置"承诺）。Match 块是
// 条件覆盖（按用户/来源生效），不是全局值——全局口径止步于第一个
// Match 指令。
func parseSshdEffective(data []byte) map[string]string {
	out := map[string]string{}
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(strings.TrimRight(raw, "\r"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		i := strings.IndexAny(line, " \t=")
		if i < 0 {
			continue
		}
		key := strings.ToLower(line[:i])
		if key == "match" {
			break
		}
		val := strings.TrimSpace(line[i+1:])
		val = strings.Trim(val, `"`)
		// sshd 的选项名大小写不敏感；值保留原样（yes/no/不等）
		if _, ok := out[key]; !ok {
			out[key] = val
		}
	}
	return out
}

// ---------------------------------------------------------------- sudo

// countSudoNopasswd 统计 sudoers 文本中含 NOPASSWD 的授权行数。
// 传行切片而不是整文件：/etc/sudoers 与 /etc/sudoers.d/* 都走同一函数。
// 只数不含内联注释的行；Alias 定义（Cmnd_Alias 等）里出现 NOPASSWD
// 的行同样计入——误报方向是"多报"，对体检是安全的。
func countSudoNopasswd(lines []string) int {
	n := 0
	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if i := strings.Index(line, "#"); i > 0 {
			// 行内注释截断（#include 指令以 # 开头已被前缀分支处理）
			line = strings.TrimSpace(line[:i])
		}
		if strings.Contains(line, "NOPASSWD") {
			n++
		}
	}
	return n
}

// ---------------------------------------------------------------- login.defs

// parseLoginDefs 解析 /etc/login.defs 的 KEY value 行。同名键后值覆盖
// 前值（shadow 套件逐条赋值语义）；注释与空行跳过。
func parseLoginDefs(data []byte) map[string]string {
	out := map[string]string{}
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(strings.TrimRight(raw, "\r"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		out[strings.ToUpper(fields[0])] = fields[1]
	}
	return out
}

// ---------------------------------------------------------------- procfs 网络

// linuxNetRow 是 /proc/net/{tcp,tcp6,udp,udp6} 的一行（只取体检需要的列）。
type linuxNetRow struct {
	Proto     string // 调用方按来源文件注入（tcp/tcp6/udp/udp6 归一为 tcp/udp）
	LocalIP   string
	LocalPort uint16
	State     string // st 列十六进制原串（TCP: 0A=LISTEN 01=ESTABLISHED…）
	Inode     uint64 // socket inode，调用方据此反查 /proc/[pid]/fd 得 PID
}

// procTCPListenHex 是 TCP 状态机里的 LISTEN 编码（st 列）。
const procTCPListenHex = "0A"

// parseProcNet 解析 /proc/net/tcp|tcp6|udp|udp6 的文本。四个文件列布局
// 一致，共用一个解析器；proto 由调用方按来源文件传入并写进行里——
// UDP 行也有 st 列（恒 07 一类），靠 st 无法区分 tcp/udp，必须按来源。
// 解析失败的行跳过——网络表的价值在覆盖面，单行脏数据不该让整个
// 暴露面视图空白。
func parseProcNet(proto, data string) []linuxNetRow {
	var out []linuxNetRow
	lines := strings.Split(data, "\n")
	for i, raw := range lines {
		if i == 0 {
			continue // 表头
		}
		fields := strings.Fields(strings.TrimSpace(raw))
		// 最少列数：sl local rem st tx:rx tr:tm->when retrnsmt uid timeout inode
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

// parseRpmQA 解析 rpm -qa --qf 输出（name\tversion\tsize 行）。
func parseRpmQA(data []byte) []InstalledApp {
	var out []InstalledApp
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimRight(raw, "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		f := strings.Split(line, "\t")
		if len(f) < 2 || f[0] == "" {
			continue
		}
		app := InstalledApp{Name: f[0], Version: f[1], Source: "rpm"}
		if len(f) >= 3 {
			if n, err := strconv.ParseUint(strings.TrimSpace(f[2]), 10, 64); err == nil {
				app.SizeKB = n / 1024 // rpm 的 SIZE 是字节
			}
		}
		out = append(out, app)
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
	hexAddr := s[:i]
	switch len(hexAddr) {
	case 8:
		ip, ok := parseHexIPv4(hexAddr)
		if !ok {
			return "", 0, false
		}
		return ip, uint16(port), true
	case 32:
		ip, ok := parseHexIPv6(hexAddr)
		if !ok {
			return "", 0, false
		}
		return ip, uint16(port), true
	default:
		return "", 0, false
	}
}

// parseHexIPv4 解析 8 位 hex 的 IPv4（/proc/net/tcp 的 local_address）。
//
// 字节序（docs.kernel.org/networking/proc_net_tcp.html）：内核把地址
// 按 32 位主机序整数打印，x86 小端机上字节序是反的——127.0.0.1 打印为
// 0100007F。按小端还原：value 的最低字节是 IP 第一段。
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

// parseHexIPv6 解析 32 位 hex 的 IPv6（/proc/net/tcp6）。
//
// 字节序：内核按 IP6_HEX_FMT("%08X%08X%08X%08X") 打印 in6_addr 的 4 个
// u6_addr32 原生序字——小端机上每个 8 hex 组内部字节是反的（::1 打印为
// 00000000000000000000000001000000，见 kernel 文档与 tcp6_seq_show 实现）。
// 还原：每组按小端展开 4 字节，拼接成 16 字节网络序地址。
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
	// 直接手拼：避免 net.IP 引入（包保持轻依赖，且这里语义就是格式化）
	return formatIPv6(&b), true
}

// formatIPv6 按 RFC 5952 风格格式化：:: 压缩最长一段零，前导零省略。
// 简化实现（v1）：只做零段压缩与 :: 替换，不做 IPv4 映射地址的
// 特殊书写——net.IP.String 的行为足够接近，这里独立实现是为包内
// 零新依赖与可测性。
func formatIPv6(b *[16]byte) string {
	groups := make([]uint16, 8)
	for i := range groups {
		groups[i] = uint16(b[i*2])<<8 | uint16(b[i*2+1])
	}
	// 找最长零段（长度≥2 才值得压缩）
	bestStart, bestLen := -1, 0
	for i := 0; i < 8; {
		if groups[i] != 0 {
			i++
			continue
		}
		j := i
		for j < 8 && groups[j] == 0 {
			j++
		}
		if j-i > bestLen {
			bestStart, bestLen = i, j-i
		}
		i = j
	}
	var sb strings.Builder
	for i := 0; i < 8; i++ {
		if bestLen >= 2 && i == bestStart {
			sb.WriteString("::")
			i += bestLen - 1 // 循环尾 i++ 会跳过整段
			continue
		}
		// ::后不再追加冒号（上面已写两个），其余组间补冒号
		if sb.Len() > 0 && !strings.HasSuffix(sb.String(), "::") {
			sb.WriteByte(':')
		}
		sb.WriteString(strings.ToLower(strconv.FormatUint(uint64(groups[i]), 16)))
	}
	out := sb.String()
	if out == "::" {
		return out // 全零地址
	}
	return out
}

// ---------------------------------------------------------------- 文件权限

// modeWorldWritable 判断一个文件模式是否"其他用户可写"（o+w）。
// 只看 Perm 位：setuid/setgid/sticky 与可写判定无关。目录同样计入——
// 世界可写目录若无 sticky 位（如 /tmp 那样的 1773 例外）是提权跳板。
func modeWorldWritable(mode os.FileMode) bool {
	return mode.Perm()&0o002 != 0
}
