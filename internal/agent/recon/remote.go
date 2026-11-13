//go:build windows
// +build windows

package recon

// remote.go：远程管理面识别（契约 §12.3 remote 类）。
//
// 这一类的价值不是"发现端口"，而是回答两个问题：
//   1. RDP 有没有开 NLA（注册表 RDP-Tcp\UserAuthentication）；
//   2. SMB 有哪些共享（NetShareEnum，含默认管理共享）。
// 第三方远控（TeamViewer/向日葵/ToDesk/AnyDesk/RustDesk/Radmin）按进程
// 指纹识别——它们通常不监听固定端口，端口表看不到。

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"zedr/internal/agent/state"
	"zedr/internal/agent/winapi"
)

// thirdPartyRemote 是商业远控产品的进程指纹。
type thirdPartyRemote struct {
	Kind      string
	Title     string
	ProcNames []string
	CmdRe     *regexp.Regexp
	Note      string
}

var thirdPartyRemotes = []thirdPartyRemote{
	{
		Kind: "teamviewer", Title: "TeamViewer",
		ProcNames: []string{"teamviewer", "teamviewer_service", "teamviewer_desktop"},
		CmdRe:     regexp.MustCompile(`(?i)teamviewer`),
	},
	{
		Kind: "sunlogin", Title: "向日葵 SunloginClient",
		ProcNames: []string{"sunloginclient", "sunloginclient_service", "sunloginremote"},
		CmdRe:     regexp.MustCompile(`(?i)sunlogin`),
	},
	{
		Kind: "todesk", Title: "ToDesk",
		ProcNames: []string{"todesk", "todesk_service"},
		CmdRe:     regexp.MustCompile(`(?i)todesk`),
	},
	{
		Kind: "anydesk", Title: "AnyDesk",
		ProcNames: []string{"anydesk", "anydesk_service"},
		CmdRe:     regexp.MustCompile(`(?i)anydesk`),
	},
	{
		Kind: "rustdesk", Title: "RustDesk",
		ProcNames: []string{"rustdesk"},
		CmdRe:     regexp.MustCompile(`(?i)rustdesk`),
	},
	{
		Kind: "radmin", Title: "Radmin",
		ProcNames: []string{"rserver3", "radmin", "rvcontrolsvc", "r_server"},
		CmdRe:     regexp.MustCompile(`(?i)radmin|rserver3`),
	},
}

// detectRemote 是 remote 类入口。
func detectRemote(ctx context.Context, b *base) (Category, error) {
	cat := newCategory("remote", CategoryTitle("remote"))
	if err := ctx.Err(); err != nil {
		return cat, nil
	}

	// RDP：端口 + 注册表 NLA/SecurityLayer。
	if len(b.byPort[3389]) > 0 {
		pid := b.portListenerPID(3389)
		rdp := b.readRDP()
		details := map[string]any{
			"product":             "rdp",
			"nla_enabled":         rdp.NLAEnabled,
			"security_layer":      rdp.SecurityLayer,
			"security_layer_name": securityLayerName(rdp.SecurityLayer),
		}
		if !rdp.FoundNLA {
			details["nla_source"] = "default"
		} else {
			details["nla_source"] = "registry"
		}
		if rdp.Err != "" {
			details["registry_error"] = rdp.Err
		}
		item := b.newAsset("remote", "rdp", "远程桌面 (RDP)", pid, []uint16{3389}, details)
		item.Exposure = passiveExposure(item.Listens, true)
		switch {
		case !rdp.NLAEnabled:
			item.Exposure = Exposure{
				Level:    LevelHigh,
				Evidence: []string{"RDP-Tcp\\UserAuthentication=0（NLA 未启用）", rdpEvidence(rdp)},
			}
			addFinding(&cat, &item, LevelHigh, "RDP 未启用 NLA",
				"网络级认证关闭后，凭据暴力/中间人/RDP 漏洞面显著扩大；建议开启 NLA 并限制来源")
		case rdp.SecurityLayer == 0:
			item.Exposure = Exposure{
				Level:    LevelMedium,
				Evidence: []string{"RDP-Tcp\\SecurityLayer=0（RDP Security Layer）", rdpEvidence(rdp)},
			}
			addFinding(&cat, &item, LevelMedium, "RDP 使用弱安全层",
				"SecurityLayer=0 使用传统 RDP 加密；建议改为 Negotiate 或 SSL/TLS")
		}
		cat.Items = append(cat.Items, item)
	}

	// SMB：445 + 共享列表。默认管理共享是系统正常面，只对"非默认共享"报风险。
	if len(b.byPort[445]) > 0 {
		pid := b.portListenerPID(445)
		shares := []winapi.ShareInfo{}
		details := map[string]any{"product": "smb", "shares": shares}
		shares, err := winapi.NetShares()
		if err != nil {
			details["shares_error"] = err.Error()
		} else {
			details["shares"] = shares
		}
		item := b.newAsset("remote", "smb", "SMB 文件共享", pid, []uint16{445}, details)
		item.Exposure = passiveExposure(item.Listens, true)
		var custom []string
		for _, sh := range shares {
			if isDefaultShare(sh.Name) {
				continue
			}
			custom = append(custom, sh.Name)
		}
		if len(custom) > 0 {
			item.Exposure = Exposure{
				Level:    LevelMedium,
				Evidence: []string{"存在非默认共享: " + strings.Join(custom, ", ")},
			}
			addFinding(&cat, &item, LevelMedium, "存在非默认 SMB 共享",
				"非默认共享可能暴露业务目录/凭据文件；确认共享权限与访问来源（默认 C$/ADMIN$/IPC$ 不计入）")
		}
		cat.Items = append(cat.Items, item)
	}

	// WinRM：5985 明文 / 5986 TLS。
	for _, port := range []uint16{5985, 5986} {
		if len(b.byPort[port]) == 0 {
			continue
		}
		pid := b.portListenerPID(port)
		kind := "winrm"
		details := map[string]any{"product": "winrm", "port": port, "tls": port == 5986}
		item := b.newAsset("remote", kind, fmt.Sprintf("WinRM (%d)", port), pid, []uint16{port}, details)
		item.Exposure = passiveExposure(item.Listens, true)
		if port == 5985 && anyNonLoopback(item.Listens) {
			item.Exposure = Exposure{Level: LevelMedium, Evidence: []string{"WinRM 明文 HTTP 监听非回环地址"}}
			addFinding(&cat, &item, LevelMedium, "WinRM 明文 HTTP 监听非回环地址",
				"5985 不加密凭据/命令内容；建议改用 5986 或限制来源")
		}
		cat.Items = append(cat.Items, item)
	}

	// SSH：端口 + 进程；不做协议握手（v1 只做资产盘点）。
	if len(b.byPort[22]) > 0 {
		pid := b.portListenerPID(22)
		item := b.newAsset("remote", "ssh", "SSH 服务", pid, []uint16{22}, map[string]any{"product": "ssh"})
		item.Exposure = passiveExposure(item.Listens, true)
		if anyNonLoopback(item.Listens) {
			addFinding(&cat, &item, LevelLow, "SSH 端口监听非回环地址",
				"确认是否允许远程登录及是否禁用口令认证")
		}
		cat.Items = append(cat.Items, item)
	}

	// VNC：5900/5800。只识别监听；认证强度不主动试。
	for _, port := range []uint16{5900, 5800} {
		if len(b.byPort[port]) == 0 {
			continue
		}
		pid := b.portListenerPID(port)
		item := b.newAsset("remote", "vnc", fmt.Sprintf("VNC (%d)", port), pid, []uint16{port}, map[string]any{"product": "vnc", "port": port})
		item.Exposure = passiveExposure(item.Listens, true)
		if anyNonLoopback(item.Listens) {
			item.Exposure = Exposure{Level: LevelMedium, Evidence: []string{"VNC 端口监听非回环地址"}}
			addFinding(&cat, &item, LevelMedium, "VNC 端口监听非回环地址",
				"VNC 常见弱口令/无认证配置；建议仅回环或经隧道访问")
		}
		cat.Items = append(cat.Items, item)
	}

	// 第三方远控：一个产品一条资产，代表进程取最小 PID，附全部 PID 数。
	for _, prod := range thirdPartyRemotes {
		var pids []uint32
		for _, row := range b.procs {
			if remoteMatches(prod, row) {
				pids = append(pids, row.PID)
			}
		}
		if len(pids) == 0 {
			continue
		}
		pid := pids[0]
		for _, p := range pids {
			if p < pid {
				pid = p
			}
		}
		ports := b.portsForPID(pid)
		details := map[string]any{
			"product":       prod.Kind,
			"process_count": len(pids),
			"pids":          pids,
		}
		item := b.newAsset("remote", prod.Kind, prod.Title, pid, ports, details)
		item.Exposure = Exposure{Level: LevelLow, Evidence: []string{fmt.Sprintf("进程 %s（PID %d）在运行", item.Title, pid)}}
		addFinding(&cat, &item, LevelLow, "第三方远控软件在运行",
			prod.Title+" 可能为授权运维工具；建议核对安装来源、账号归属与访问策略，非授权应卸载")
		cat.Items = append(cat.Items, item)
	}

	sortItems(cat.Items)
	return cat, nil
}

// remoteMatches 进程名精确匹配或命令行正则。
func remoteMatches(prod thirdPartyRemote, row state.ProcRow) bool {
	name := procBaseName(row.Name)
	for _, n := range prod.ProcNames {
		if name == strings.ToLower(n) {
			return true
		}
	}
	return prod.CmdRe != nil && prod.CmdRe.MatchString(row.CmdLine)
}

// isDefaultShare 判断 Windows 默认管理共享：IPC$、ADMIN$、print$ 与
// 盘符共享（C$/D$…）。只按 "$" 后缀一刀切会把业务隐藏共享（backup$）
// 误判成默认面，恰恰漏掉最该报的暴露。
func isDefaultShare(name string) bool {
	u := strings.ToUpper(strings.TrimSpace(name))
	if u == "" {
		return true
	}
	switch u {
	case "IPC$", "ADMIN$", "PRINT$":
		return true
	}
	if len(u) == 2 && u[0] >= 'A' && u[0] <= 'Z' && u[1] == '$' {
		return true // 盘符根共享 C$ / D$
	}
	return false
}

// securityLayerName 把 RDP SecurityLayer 数值转可读名。
func securityLayerName(v uint32) string {
	switch v {
	case 0:
		return "RDP Security Layer"
	case 1:
		return "Negotiate"
	case 2:
		return "SSL/TLS"
	default:
		return fmt.Sprintf("unknown_%d", v)
	}
}

// rdpEvidence 生成 RDP 注册表证据（NLA/SecurityLayer 的实际取值）。
func rdpEvidence(r rdpSettings) string {
	return fmt.Sprintf("UserAuthentication=%t, SecurityLayer=%d(%s)",
		r.NLAEnabled, r.SecurityLayer, securityLayerName(r.SecurityLayer))
}
