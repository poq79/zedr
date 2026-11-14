// 本文件 NEUTRAL（无构建标签）：/netinfo 的线协议形状与段选择逻辑。
//
// 2026-11-14 从 netinfo.go（windows 标签）平移而来：Linux 版 /netinfo
// （netinfo_linux.go）需要与 Windows 逐字段一致的形状与同语义的 sections
// 参数处理——形状定义放中性文件由双平台共享，是"前端零改动可渲染"的
// 唯一可靠保证（两份定义必然漂移）。netinfo.go 只保留 Windows 专属的
// winapi 采集壳。
package liveapi

// netinfo_shapes.go：/netinfo 的段清单、条目形状与公共收敛逻辑。

import "strings"

// netinfoListCap 是 arp/routes/dns 三段的条数硬顶：表被异常撑大时保护
// 隧道响应体；adapters/shares 是"通常 <50 条"的小集合，全量返回不设顶。
const netinfoListCap = 512

// netinfoSectionOrder 是段的规范顺序：输出按此序，不随请求参数顺序漂移
// （两次请求同参数输出逐字段可比，前端可以做 diff）。
var netinfoSectionOrder = []string{"arp", "routes", "dns", "adapters", "shares"}

// netinfoArpItem 等 struct：winapi 侧四个结构体都没有 json tag（历史
// 消费方按 Go 字段名取值），直接序列化会输出大写混排，这里统一收敛成
// snake_case 线协议（学 tasks.go 的做法）。shares 例外——winapi.ShareInfo
// 自带 json tag，直接复用避免两处定义漂移。
type netinfoArpItem struct {
	IP      string `json:"ip"`
	MAC     string `json:"mac"`
	IfIndex uint32 `json:"if_index"`
	State   string `json:"state"`
}

type netinfoRouteItem struct {
	Dest    string `json:"dest"`
	Mask    string `json:"mask"`
	Gateway string `json:"gateway"`
	IfIndex uint32 `json:"if_index"`
	Metric  int32  `json:"metric"`
}

type netinfoDnsItem struct {
	Name string `json:"name"`
	Type string `json:"type"`
	Data string `json:"data"`
	TTL  uint32 `json:"ttl"`
}

type netinfoAdapterItem struct {
	Name      string   `json:"name"`
	MAC       string   `json:"mac"`
	IPs       []string `json:"ips"`
	Gateway   string   `json:"gateway"`
	DNS       []string `json:"dns"`
	OperState string   `json:"oper_state"`
}

// netinfoShareItem 是 shares 段的形状（与 winapi.ShareInfo 的 json tag
// 一致；Windows 侧直接用 winapi.ShareInfo，Linux 侧无 SMB 语义恒空表，
// 定义于此只为形状单一事实源）。
type netinfoShareItem struct {
	Name   string `json:"name"`
	Path   string `json:"path"`
	Remark string `json:"remark"`
}

// parseNetinfoSections 解析 sections 参数：空 = 全部五段；非法段名进
// invalid（原样保留 token，便于请求方对照自己传了什么）；合法段去重后
// 按规范顺序返回。
func parseNetinfoSections(raw string) (wanted []string, invalid []string) {
	if strings.TrimSpace(raw) == "" {
		return append([]string{}, netinfoSectionOrder...), nil
	}
	set := map[string]bool{}
	for _, part := range strings.Split(raw, ",") {
		p := strings.ToLower(strings.TrimSpace(part))
		if p == "" {
			continue
		}
		known := false
		for _, s := range netinfoSectionOrder {
			if p == s {
				known = true
				break
			}
		}
		if !known {
			invalid = append(invalid, p)
			continue
		}
		set[p] = true
	}
	for _, s := range netinfoSectionOrder {
		if set[s] {
			wanted = append(wanted, s)
		}
	}
	return wanted, invalid
}

// netinfoPutSection 收敛"段 → 响应"的公共形态：成功放数组（nil 收敛为
// 空数组），失败放 null + 短错误说明。
func netinfoPutSection(out map[string]any, errs map[string]string, trunc map[string]bool,
	sec string, items any, truncated bool, err error) {
	if err != nil {
		out[sec] = nil
		errs[sec] = errBrief(err)
		return
	}
	if items == nil {
		items = []any{}
	}
	out[sec] = items
	if truncated {
		trunc[sec] = true
	}
}

// errBrief 错误说明截短（/netinfo 与 /usn 共用）：错误文案进响应体，
// 不设上限会被 fmt.Errorf 链里的路径/缓冲长度撑到失控。
func errBrief(err error) string {
	msg := err.Error()
	if len(msg) > 160 {
		msg = msg[:160] + "…"
	}
	return msg
}
