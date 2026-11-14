// 本文件 NEUTRAL：/proc/net/arp、/proc/net/route、/etc/resolv.conf 的
// 纯解析逻辑（无 IO、无构建标签），供 /netinfo 的 Linux 版使用。放中性
// 文件的原因同 linuxproc.go：解析口径要能在 Windows 上跑单测锁定。
//
// 未在 Linux 实机验证（待 Kali 复验）；验证口径 = GOOS=linux 交叉编译 +
// 本文件单测在 Windows 上运行（内核文档与 proc(5) 手册样例）。
package liveapi

// netinfo_linuxparse.go：Linux 网络面文本表的解析。

import (
	"strconv"
	"strings"
)

// linuxArpRow 是 /proc/net/arp 一行。
// 表格式（proc(5)/内核 arp.c seq 输出）：
//
//	IP address  HW type  Flags  MAC address  Mask  Device
//
// 注意表头把第 4 列误标成 "IP address"，实际是硬件地址（内核打印格式串
// 的既有事实）；Flags 0x2=complete、0x0=incomplete（未解析完成）。
type linuxArpRow struct {
	IP     string
	MAC    string
	Flags  uint32
	Device string
}

// parseProcNetArp 解析 /proc/net/arp 全文。表头/空行/字段数不足/地址
// 非法的行整行跳过（残行宁缺毋滥，与 parseProcNetRows 同纪律）。
func parseProcNetArp(data []byte) []linuxArpRow {
	var out []linuxArpRow
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) < 6 {
			continue // 表头（6 列）会被下面的地址校验拦下
		}
		if !validDottedIP(f[0]) {
			continue // 表头行 "IP address ..." / 残行
		}
		flags, err := strconv.ParseUint(strings.TrimPrefix(f[2], "0x"), 16, 32)
		if err != nil {
			continue
		}
		out = append(out, linuxArpRow{
			IP:     f[0],
			MAC:    f[3],
			Flags:  uint32(flags),
			Device: f[5],
		})
	}
	return out
}

// validDottedIP 粗校验点分十进制（a.b.c.d 且每段 0-255）。/proc 表的
// 行首列不合法 = 表头或异常行，直接跳过。
func validDottedIP(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		if p == "" || len(p) > 3 {
			return false
		}
		v, err := strconv.Atoi(p)
		if err != nil || v < 0 || v > 255 {
			return false
		}
	}
	return true
}

// linuxRouteRow 是 /proc/net/route 一行（数值列保持原始小端序整数，
// 由投影层用 hexLEIP 转点分十进制）。
// 表格式（proc(5)）：Iface Destination Gateway Flags RefCnt Use Metric Mask
// MTU Window IRTT；Destination/Gateway/Mask 是 __be32 以 %08X 打印——
// 小端机器上整数值的字节序与网络序相反，还原规则见 hexLEIP。
type linuxRouteRow struct {
	Iface   string
	Dest    uint32
	Gateway uint32
	Mask    uint32
	Metric  int32
	Flags   uint32
}

// parseProcNetRoute 解析 /proc/net/route 全文。表头/残行跳过；
// 数值列解析失败的行整行跳过（路由条目残缺比缺行更误导）。
func parseProcNetRoute(data []byte) []linuxRouteRow {
	var out []linuxRouteRow
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) < 8 {
			continue
		}
		if f[0] == "Iface" {
			continue // 表头
		}
		dest, err1 := strconv.ParseUint(f[1], 16, 32)
		gw, err2 := strconv.ParseUint(f[2], 16, 32)
		metric, err3 := strconv.ParseUint(f[6], 10, 32)
		mask, err4 := strconv.ParseUint(f[7], 16, 32)
		flags, err5 := strconv.ParseUint(f[3], 10, 32)
		if err1 != nil || err2 != nil || err3 != nil || err4 != nil || err5 != nil {
			continue
		}
		out = append(out, linuxRouteRow{
			Iface:   f[0],
			Dest:    uint32(dest),
			Gateway: uint32(gw),
			Mask:    uint32(mask),
			Metric:  int32(metric),
			Flags:   uint32(flags),
		})
	}
	return out
}

// hexLEIP 把 /proc/net/route 的十六进制小端整数值还原成点分十进制。
//
// 内核以 %08X 打印 __be32：目标 192.168.1.0 的网络序字节 C0 A8 01 00 在
// 小端机器上作为 u32 读出 = 0x0001A8C0，打印为 "0001A8C0"。还原 = 按
// 小端字节序（低位字节在前）逐字节展开：
//
//	0x0001A8C0 → 0xC0,0xA8,0x01,0x00 → "192.168.1.0" ✓
//
// 这与 linuxproc.go 的 parseProcNetAddr（/proc/net/tcp 的 %08X 打印）是
// 同一底层规则：打印序第 i 字节 = 网络序第 3-i 字节。
func hexLEIP(v uint32) string {
	return strconv.Itoa(int(v&0xFF)) + "." +
		strconv.Itoa(int((v>>8)&0xFF)) + "." +
		strconv.Itoa(int((v>>16)&0xFF)) + "." +
		strconv.Itoa(int((v>>24)&0xFF))
}

// linuxDnsRow 是 resolv.conf 一条解析配置。
type linuxDnsRow struct {
	Name string
	Type string // nameserver / search / domain
}

// parseResolvConf 解析 /etc/resolv.conf 为配置行（保持文件顺序——
// resolver 的查找顺序本身有语义）。注释/空行/其他指令（options 等）
// 跳过。诚实口径：这是"解析配置"快照，不是 Windows DnsCache 那样的
// 运行期缓存（Linux 无用户态缓存枚举对等），note 由 handler 说明。
func parseResolvConf(data []byte) []linuxDnsRow {
	var out []linuxDnsRow
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		switch f[0] {
		case "nameserver":
			if validDottedIP(f[1]) || strings.Contains(f[1], ":") {
				out = append(out, linuxDnsRow{Name: f[1], Type: "nameserver"})
			}
		case "search":
			// search 行可带多个域名（proc(5)），逐个展开
			for _, d := range f[1:] {
				out = append(out, linuxDnsRow{Name: d, Type: "search"})
			}
		case "domain":
			out = append(out, linuxDnsRow{Name: f[1], Type: "domain"})
		}
	}
	return out
}
