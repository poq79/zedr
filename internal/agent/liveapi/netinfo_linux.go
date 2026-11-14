//go:build linux

// netinfo_linux.go：/netinfo 的 Linux 实现（IO 壳）。
//
// 五段的数据源与诚实映射（形状与 Windows netinfo_shapes.go 共享同一
// 定义，前端零改动可渲染）：
//   - arp：/proc/net/arp。State 映射进 Windows 的 MIB_IPNET_TYPE 词汇：
//     ATF_PERM(0x4)→static、ATF_COM(0x2)→dynamic、0→invalid（未完成条目）、
//     其余→other——横向移动判定依赖"这台机器最近接触过谁"，词汇对齐让
//     服务端/AI 的既有规则不感知平台差。if_index 用内核真实 ifindex
//     （/proc/net/arp 只给接口名，经 net.Interfaces 的 name→index 映射还原；
//     Windows 同字段是 GetIpNetTable 的 ifIndex，语义同源）。
//   - routes：/proc/net/route（IPv4；IPv6 路由表 ipv6_route 的前缀语义
//     与 Windows 路由形状差异大，v1 不做——诚实边界）。地址列按
//     hexLEIP 还原（见 netinfo_linuxparse.go 的小端规则说明）。
//   - dns：/etc/resolv.conf——这是"解析配置"快照，不是 Windows DnsCache
//     那样的运行期缓存（Linux 无用户态缓存枚举对等；systemd-resolved 的
//     缓存在其 D-Bus 后面，只读纪律不引）。note 随段说明。
//   - adapters：net.Interfaces/iface.Addrs（标准库 netlink，纯 Go 系统调
//     用，无命令执行）+ /sys/class/net/*/operstate + 默认网关（从
//     /proc/net/route 的 default 路由反推）。DNS 字段恒空：resolv.conf
//     是全局配置，Windows 的每网卡 DNS 无对等，note 说明。
//   - shares：恒空——Linux 无 Windows LM 共享枚举语义；检测到 samba
//     配置文件时在 note 里提示（不解析共享定义）。
//
// 降级口径与 Windows 版一致：一段失败只让该段 null + errors 短说明，
// 绝不整页 500。
//
// 未在 Linux 实机验证（待 Kali 复验）；验证口径 = GOOS=linux 交叉编译 +
// netinfo_linuxparse.go 纯逻辑单测（testdata 夹具）。
package liveapi

// netinfo_linux.go：网络面实时快照（Linux 口径）。

import (
	"net"
	"net/http"
	"os"
	"strings"

	"zedr/internal/platform/httpx"
)

// atfPerm/atfCom 是 linux at_arp.h 的邻居表标志位（State 映射依据）。
const (
	atfPerm = 0x4 // 永久条目（管理员手工配置）→ Windows "static"
	atfCom  = 0x2 // 已解析完成 → Windows "dynamic"
)

func (s *server) handleNetinfo(w http.ResponseWriter, r *http.Request) {
	wanted, invalid := parseNetinfoSections(r.URL.Query().Get("sections"))

	out := map[string]any{"sections": wanted}
	errs := map[string]string{}
	trunc := map[string]bool{}
	notes := map[string]string{}
	if len(invalid) > 0 {
		errs["sections"] = "忽略了无法识别的段: " + strings.Join(invalid, ",")
	}

	for _, sec := range wanted {
		switch sec {
		case "arp":
			items, truncated, err := buildNetinfoArpLinux()
			netinfoPutSection(out, errs, trunc, "arp", items, truncated, err)
		case "routes":
			items, truncated, err := buildNetinfoRoutesLinux()
			netinfoPutSection(out, errs, trunc, "routes", items, truncated, err)
		case "dns":
			items, err := buildNetinfoDNSLinux()
			netinfoPutSection(out, errs, trunc, "dns", items, false, err)
			if err == nil {
				notes["dns"] = "本段为 /etc/resolv.conf 解析配置快照，不是运行期解析缓存" +
					"（Linux 无用户态缓存枚举对等；systemd-resolved 缓存不走用户态文件）"
			}
		case "adapters":
			items, err := buildNetinfoAdaptersLinux()
			netinfoPutSection(out, errs, trunc, "adapters", items, false, err)
			if err == nil {
				notes["adapters"] = "dns 字段恒空：/etc/resolv.conf 是全局配置，" +
					"无每网卡 DNS 对等（全局解析配置见 dns 段）"
			}
		case "shares":
			items, note, err := buildNetinfoSharesLinux()
			netinfoPutSection(out, errs, trunc, "shares", items, false, err)
			if err == nil {
				notes["shares"] = note
			}
		}
	}
	if len(trunc) > 0 {
		out["truncated"] = trunc
	}
	if len(errs) > 0 {
		out["errors"] = errs
	}
	if len(notes) > 0 {
		out["notes"] = notes
	}
	httpx.WriteJSON(w, r, http.StatusOK, out)
}

// linuxIfIndexMap 返回接口名 → 内核 ifindex（arp/routes 的 if_index 还原；
// Windows 侧同字段语义 = 内核接口索引）。读不到返回空表（if_index 落 0，
// "未知索引"而不是编造）。
func linuxIfIndexMap() map[string]uint32 {
	out := map[string]uint32{}
	ifaces, err := net.Interfaces()
	if err != nil {
		return out
	}
	for _, ifc := range ifaces {
		out[ifc.Name] = uint32(ifc.Index)
	}
	return out
}

func buildNetinfoArpLinux() ([]netinfoArpItem, bool, error) {
	data, err := os.ReadFile("/proc/net/arp")
	if err != nil {
		return nil, false, err
	}
	rows := parseProcNetArp(data)
	truncated := len(rows) > netinfoListCap
	if truncated {
		rows = rows[:netinfoListCap]
	}
	ifIndexes := linuxIfIndexMap()
	items := make([]netinfoArpItem, 0, len(rows))
	for _, row := range rows {
		state := "other"
		switch {
		case row.Flags&atfPerm != 0:
			state = "static"
		case row.Flags&atfCom != 0:
			state = "dynamic"
		case row.Flags == 0:
			state = "invalid" // 未完成条目（对端无响应，MAC 列为 ?）
		}
		items = append(items, netinfoArpItem{
			IP:      row.IP,
			MAC:     row.MAC,
			IfIndex: ifIndexes[row.Device],
			State:   state,
		})
	}
	return items, truncated, nil
}

func buildNetinfoRoutesLinux() ([]netinfoRouteItem, bool, error) {
	data, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return nil, false, err
	}
	rows := parseProcNetRoute(data)
	truncated := len(rows) > netinfoListCap
	if truncated {
		rows = rows[:netinfoListCap]
	}
	ifIndexes := linuxIfIndexMap()
	items := make([]netinfoRouteItem, 0, len(rows))
	for _, row := range rows {
		items = append(items, netinfoRouteItem{
			Dest:    hexLEIP(row.Dest),
			Mask:    hexLEIP(row.Mask),
			Gateway: hexLEIP(row.Gateway),
			IfIndex: ifIndexes[row.Iface],
			Metric:  row.Metric,
		})
	}
	return items, truncated, nil
}

func buildNetinfoDNSLinux() ([]netinfoDnsItem, error) {
	data, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		return nil, err
	}
	rows := parseResolvConf(data)
	items := make([]netinfoDnsItem, 0, len(rows))
	for _, row := range rows {
		items = append(items, netinfoDnsItem{
			Name: row.Name,
			Type: row.Type,
			Data: "",
			TTL:  0, // 配置没有 TTL 语义，0 与 Windows 的"未知不编造"口径一致
		})
	}
	return items, nil
}

// buildNetinfoAdaptersLinux 组装网卡段：标准库 net.Interfaces（netlink，
// 纯系统调用）+ /sys/class/net/*/operstate + /proc/net/route 默认路由
// 反推网关。单网卡 Addrs 读失败跳过该网卡 IP 字段（不整段失败）。
func buildNetinfoAdaptersLinux() ([]netinfoAdapterItem, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	// 默认网关：Dest=0 的路由（每接口取第一条；多默认路由是策略路由
	// 的复杂场景，v1 只报最先出现的）。
	gateways := map[string]string{}
	if data, rerr := os.ReadFile("/proc/net/route"); rerr == nil {
		for _, row := range parseProcNetRoute(data) {
			if row.Dest == 0 && gateways[row.Iface] == "" {
				gateways[row.Iface] = hexLEIP(row.Gateway)
			}
		}
	}

	items := make([]netinfoAdapterItem, 0, len(ifaces))
	for _, ifc := range ifaces {
		item := netinfoAdapterItem{
			Name:      ifc.Name,
			MAC:       ifc.HardwareAddr.String(),
			IPs:       []string{},
			DNS:       []string{}, // 全局 resolv.conf，无每网卡对等（notes 说明）
			Gateway:   gateways[ifc.Name],
			OperState: operstateOf(ifc),
		}
		if addrs, aerr := ifc.Addrs(); aerr == nil {
			for _, a := range addrs {
				// CIDR 前缀剥掉（Windows 侧 IPs 是裸地址形态）
				item.IPs = append(item.IPs, strings.Split(a.String(), "/")[0])
			}
		}
		items = append(items, item)
	}
	return items, nil
}

// operstateOf 读 /sys/class/net/<name>/operstate；读不到按 Flags 兜底
// （up/down 二值；loopback 等内核报 unknown 的接口在文件里如实带出）。
func operstateOf(ifc net.Interface) string {
	if data, err := os.ReadFile("/sys/class/net/" + ifc.Name + "/operstate"); err == nil {
		if s := strings.TrimSpace(string(data)); s != "" {
			return s
		}
	}
	if ifc.Flags&net.FlagUp != 0 {
		return "up"
	}
	return "down"
}

// buildNetinfoSharesLinux：Linux 无 SMB 共享枚举语义，恒空表。检测到
// samba 配置文件时在 note 里提示（不解析共享定义，也不上报 null——
// "确定没有共享枚举面"是事实而非失败）。
func buildNetinfoSharesLinux() ([]netinfoShareItem, string, error) {
	note := "Linux 无 SMB 共享枚举语义（Windows LM 共享面），恒为空表"
	if _, err := os.Stat("/etc/samba/smb.conf"); err == nil {
		note += "；检测到 /etc/samba/smb.conf（samba 共享定义未解析）"
	}
	return []netinfoShareItem{}, note, nil
}
