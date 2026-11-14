//go:build windows
// +build windows

package liveapi

// netinfo.go：/netinfo 网络面实时快照（ARP/路由/DNS 缓存/网卡/SMB 共享）。
//
// 调查价值（各段为什么值得看）：
//   - arp：内网横向痕迹——端口扫描与 SMB/WMI 横移都会在邻居表留下最近
//     接触过的内网 IP，dynamic 条目在老化前（几分钟到小时级）是"刚接触
//     过"的时间证据；
//   - routes：网段拓扑——直连网段之外出现静态路由（跨网段打洞/跳板）、
//     异常网关都是可达面变化；
//   - dns：C2 域名解析残留——任何域名回连前必过本机解析缓存，比流量侧
//     取证更早、且不依赖网络位置；注意 Data 字段在部分 Windows 版本上
//     恒为空（winapi.DnsCacheEntry 的诚实声明），Name+Type 已足够识别
//     C2 域名线索；
//   - shares：横向移动跳板面——ADMIN$/C$/自定义共享是挂载与投递入口，
//     新增共享本身就是可疑事件；
//   - adapters：多宿主与网段归属，配合 routes/dns 判断"这台机器能到哪"。
//
// 降级口径：五段来自五个互相独立的 API（iphlpapi×2/dnsapi/getaddrinfo/
// netapi32），一段失败只让该段为 null + errors 短说明，其余照常返回，
// 绝不整页 500——调查员要的是"能拿到多少拿多少"，一段故障放大成整页
// 失败只会让证据全丢。
//
// 段选择：sections 参数逗号分隔，非法值忽略（不报 400——多给一个错段名
// 不该让整次调查失败），在 errors.sections 里说明忽略了什么。

import (
	"net/http"
	"strings"

	"zedr/internal/agent/winapi"
	"zedr/internal/platform/httpx"
)

// 段清单/条目形状/公共收敛逻辑（parseNetinfoSections、netinfoXxxItem、
// netinfoPutSection、errBrief）在 netinfo_shapes.go（NEUTRAL，双平台共享
// 同一形状定义）；本文件只保留 Windows 专属的 winapi 采集壳。

// handleNetinfo 返回 GET /netinfo。
// 响应契约：
//
//	{
//	  "sections": ["arp", ...],          // 实际返回的段（规范序，去重后）
//	  "arp": [...] | null,               // 仅请求的段出现；null = 该段采集失败
//	  "routes": [...], "dns": [...], "adapters": [...], "shares": [...],
//	  "truncated": {"arp": true},        // 仅有段被条数顶截断时出现
//	  "errors": {                        // 仅有可说明的错误时出现
//	    "sections": "忽略了无法识别的段: xxx",
//	    "arp": "GetIpNetTable 失败: errno=..."
//	  }
//	}
func (s *server) handleNetinfo(w http.ResponseWriter, r *http.Request) {
	wanted, invalid := parseNetinfoSections(r.URL.Query().Get("sections"))

	out := map[string]any{"sections": wanted}
	errs := map[string]string{}
	trunc := map[string]bool{}
	if len(invalid) > 0 {
		errs["sections"] = "忽略了无法识别的段: " + strings.Join(invalid, ",")
	}

	for _, sec := range wanted {
		switch sec {
		case "arp":
			items, truncated, err := buildNetinfoArp()
			netinfoPutSection(out, errs, trunc, "arp", items, truncated, err)
		case "routes":
			items, truncated, err := buildNetinfoRoutes()
			netinfoPutSection(out, errs, trunc, "routes", items, truncated, err)
		case "dns":
			items, truncated, err := buildNetinfoDNS()
			netinfoPutSection(out, errs, trunc, "dns", items, truncated, err)
		case "adapters":
			items, err := buildNetinfoAdapters()
			netinfoPutSection(out, errs, trunc, "adapters", items, false, err)
		case "shares":
			items, err := buildNetinfoShares()
			netinfoPutSection(out, errs, trunc, "shares", items, false, err)
		}
	}
	if len(trunc) > 0 {
		out["truncated"] = trunc
	}
	if len(errs) > 0 {
		out["errors"] = errs
	}
	httpx.WriteJSON(w, r, http.StatusOK, out)
}

func buildNetinfoArp() ([]netinfoArpItem, bool, error) {
	rows, err := winapi.ArpTable()
	if err != nil {
		return nil, false, err
	}
	truncated := len(rows) > netinfoListCap
	if truncated {
		rows = rows[:netinfoListCap]
	}
	items := make([]netinfoArpItem, 0, len(rows))
	for _, row := range rows {
		items = append(items, netinfoArpItem{
			IP:      row.IP,
			MAC:     row.MAC,
			IfIndex: row.IfIndex,
			State:   row.State,
		})
	}
	return items, truncated, nil
}

func buildNetinfoRoutes() ([]netinfoRouteItem, bool, error) {
	rows, err := winapi.RouteTable()
	if err != nil {
		return nil, false, err
	}
	truncated := len(rows) > netinfoListCap
	if truncated {
		rows = rows[:netinfoListCap]
	}
	items := make([]netinfoRouteItem, 0, len(rows))
	for _, row := range rows {
		items = append(items, netinfoRouteItem{
			Dest:    row.Dest,
			Mask:    row.Mask,
			Gateway: row.Gateway,
			IfIndex: row.IfIndex,
			Metric:  row.Metric,
		})
	}
	return items, truncated, nil
}

func buildNetinfoDNS() ([]netinfoDnsItem, bool, error) {
	rows, err := winapi.DnsCache()
	if err != nil {
		return nil, false, err
	}
	// DnsCache 自带 dnsMaxEntries=512 防环上限，语义与本端点 cap 一致；
	// 到达上限也不会超出 netinfoListCap，无需再截。
	items := make([]netinfoDnsItem, 0, len(rows))
	for _, row := range rows {
		items = append(items, netinfoDnsItem{
			Name: row.Name,
			Type: row.Type,
			Data: row.Data,
			TTL:  row.TTL,
		})
	}
	return items, false, nil
}

func buildNetinfoAdapters() ([]netinfoAdapterItem, error) {
	rows, err := winapi.Adapters()
	if err != nil {
		return nil, err
	}
	items := make([]netinfoAdapterItem, 0, len(rows))
	for _, row := range rows {
		// IPs/DNS 在 winapi 侧已初始化为空切片，这里防御性再收一遍：
		// nil 序列化成 null 会让前端每个字段都要判空
		ips := row.IPs
		if ips == nil {
			ips = []string{}
		}
		dns := row.DNS
		if dns == nil {
			dns = []string{}
		}
		items = append(items, netinfoAdapterItem{
			Name:      row.Name,
			MAC:       row.MAC,
			IPs:       ips,
			Gateway:   row.Gateway,
			DNS:       dns,
			OperState: row.OperState,
		})
	}
	return items, nil
}

func buildNetinfoShares() ([]winapi.ShareInfo, error) {
	rows, err := winapi.NetShares()
	if err != nil {
		return nil, err
	}
	if rows == nil {
		rows = []winapi.ShareInfo{}
	}
	return rows, nil
}
