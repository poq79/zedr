//go:build linux

package recon

// remote_linux.go — 远程管理面识别，remote 类的 Linux 实现。
//
// 与 remote.go（Windows 版）的对照关系：
//   - RDP：Windows 读注册表 NLA/SecurityLayer；Linux 的等价物是 xrdp
//     （3389），其认证配置在 /etc/xrdp/ 文本配置里，v1 只盘点 + 标注
//     "认证细节未采集"（不冒充有 NLA 结论）；
//   - SMB：Windows 用 NetShareEnum 枚举共享；Linux 的 samba 共享清单
//     要解析 smb.conf include 链，v1 不做——端口盘点 + 诚实标注；
//   - WinRM：Windows 专属协议，Linux 侧不识别（5985/5986 监听在 Linux
//     上几乎不存在，真出现会由 web 类的 generic HTTP 覆盖）；
//   - SSH：端口 + 进程同 Windows；Linux 额外读 /etc/ssh/sshd_config 的
//     明面配置（Windows 版没有等价物，这是 Linux 的加分项）；
//   - VNC / 第三方远控：进程指纹口径完全一致。
//
// 输出结构体（Category/AssetItem/Exposure/Finding）与 Windows 版逐字段
// 一致（types.go 共享）——服务端消费零分叉。
//
// 未在 Linux 实机验证（本机无 Linux 测试环境）。

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"strings"

	"zedr/internal/agent/state"
)

// linuxRemoteProduct 是远控/远程桌面的进程指纹（与 Windows 版
// thirdPartyRemote 同构）。跨平台产品保留原表；注释标注平台差异。
type linuxRemoteProduct struct {
	Kind      string
	Title     string
	ProcNames []string
	CmdRe     *regexp.Regexp
	Note      string
}

// linuxRemoteRemotes 的产品集合与 Windows 版 thirdPartyRemotes 一致：
// TeamViewer/AnyDesk/RustDesk/Sunlogin/ToDesk 都有 Linux 版本
// （Radmin 是 Windows-only，Linux 侧剔除）。
var linuxRemoteRemotes = []linuxRemoteProduct{
	{
		Kind: "teamviewer", Title: "TeamViewer",
		ProcNames: []string{"teamviewer", "teamviewer_service", "teamviewer_desktop"},
		CmdRe:     regexp.MustCompile(`(?i)teamviewer`),
	},
	{
		Kind: "sunlogin", Title: "向日葵 SunloginClient",
		ProcNames: []string{"sunloginclient", "sunloginclient_service", "sunloginremote", "runsunloginclient"},
		CmdRe:     regexp.MustCompile(`(?i)sunlogin`),
	},
	{
		Kind: "todesk", Title: "ToDesk",
		ProcNames: []string{"todesk", "todesk_service", "todeskclient"},
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
}

// detectRemote 是 remote 类的 Linux 入口（签名与 Windows 版一致）。
func detectRemote(ctx context.Context, b *base) (Category, error) {
	cat := newCategory("remote", CategoryTitle("remote"))
	if err := ctx.Err(); err != nil {
		return cat, nil
	}

	// SSH：端口 + 进程 + sshd 配置明面值。
	if len(b.byPort[22]) > 0 {
		pid := b.portListenerPID(22)
		details := map[string]any{"product": "ssh"}
		if cfg := sshdDetails(); cfg != nil {
			for k, v := range cfg {
				details[k] = v
			}
		} else {
			details["sshd_config"] = "未读取到 /etc/ssh/sshd_config（容器/精简镜像常见）"
		}
		item := b.newAsset("remote", "ssh", "SSH 服务", pid, []uint16{22}, details)
		item.Exposure = passiveExposure(item.Listens, true)
		if anyNonLoopback(item.Listens) {
			addFinding(&cat, &item, LevelLow, "SSH 端口监听非回环地址",
				"确认是否允许远程登录；details 里有 PermitRootLogin/PasswordAuthentication 明面值，口令+root 可登录的组合建议收紧")
		}
		cat.Items = append(cat.Items, item)
	}

	// RDP：Linux 上 3389 的服务端是 xrdp。注册表 NLA 是 Windows 专属
	// 采集面，不伪造等价结论，details 如实标注。
	if len(b.byPort[3389]) > 0 {
		pid := b.portListenerPID(3389)
		item := b.newAsset("remote", "rdp", "远程桌面 (xrdp)", pid, []uint16{3389},
			map[string]any{
				"product": "xrdp",
				"note":    "RDP NLA/SecurityLayer 为 Windows 专属采集面，Linux 版未采集认证细节",
			})
		item.Exposure = passiveExposure(item.Listens, true)
		if anyNonLoopback(item.Listens) {
			addFinding(&cat, &item, LevelMedium, "xrdp 监听非回环地址",
				"xrdp 历史漏洞较多（认证绕过/缓冲区溢出）；建议仅经隧道访问或限制来源")
		}
		cat.Items = append(cat.Items, item)
	}

	// SMB：Linux 上 445 通常是 samba。共享枚举（NetShareEnum）是 Windows
	// 专属能力，smb.conf 的 include 链离线解析不完整，v1 只盘点端口。
	if len(b.byPort[445]) > 0 {
		pid := b.portListenerPID(445)
		item := b.newAsset("remote", "smb", "SMB 文件共享 (samba)", pid, []uint16{445},
			map[string]any{
				"product": "samba",
				"note":    "共享清单枚举为 Windows 专属能力（NetShareEnum），Linux 版未枚举 smb.conf 共享",
			})
		item.Exposure = passiveExposure(item.Listens, true)
		if anyNonLoopback(item.Listens) {
			addFinding(&cat, &item, LevelLow, "SMB 端口监听非回环地址",
				"确认 /etc/samba/smb.conf 的共享目录与访客访问（map to guest）配置")
		}
		cat.Items = append(cat.Items, item)
	}

	// VNC：5900/5800。只识别监听；认证强度不主动试（与 Windows 同口径）。
	for _, port := range []uint16{5900, 5800} {
		if len(b.byPort[port]) == 0 {
			continue
		}
		pid := b.portListenerPID(port)
		item := b.newAsset("remote", "vnc", fmt.Sprintf("VNC (%d)", port), pid, []uint16{port},
			map[string]any{"product": "vnc", "port": port})
		item.Exposure = passiveExposure(item.Listens, true)
		if anyNonLoopback(item.Listens) {
			item.Exposure = Exposure{Level: LevelMedium, Evidence: []string{"VNC 端口监听非回环地址"}}
			addFinding(&cat, &item, LevelMedium, "VNC 端口监听非回环地址",
				"VNC 常见弱口令/无认证配置（x11vnc/vino 均如此）；建议仅回环或经隧道访问")
		}
		cat.Items = append(cat.Items, item)
	}

	// 第三方远控：一个产品一条资产，代表进程取最小 PID，附全部 PID 数
	//（与 Windows 版同口径）。
	for _, prod := range linuxRemoteRemotes {
		var pids []uint32
		for _, row := range b.procs {
			if remoteMatchesLinux(prod, row) {
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

// remoteMatchesLinux 进程名精确匹配或命令行正则（与 Windows 版
// remoteMatches 同逻辑）。
func remoteMatchesLinux(prod linuxRemoteProduct, row state.ProcRow) bool {
	name := procBaseName(row.Name)
	for _, n := range prod.ProcNames {
		if name == strings.ToLower(n) {
			return true
		}
	}
	return prod.CmdRe != nil && prod.CmdRe.MatchString(row.CmdLine)
}

// sshdDetails 读 sshd_config 的明面安全值（PermitRootLogin/
// PasswordAuthentication）。"第一次出现的值生效"是 sshd_config(5) 的
// 语义；Match 块是按用户/来源的条件覆盖，不是全局值——全局口径止步
// 于第一个 Match 指令；Include 子配置不跟随（离线还原合并顺序不可靠，
// 不做虚假的"完整生效配置"承诺）。读取失败/键缺席时返回 nil，由
// 调用方诚实标注。
func sshdDetails() map[string]any {
	data, err := os.ReadFile("/etc/ssh/sshd_config")
	if err != nil {
		return nil
	}
	cfg := map[string]string{}
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(strings.TrimRight(raw, "\r"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		i := strings.IndexAny(line, " \t")
		if i < 0 {
			continue
		}
		key := strings.ToLower(line[:i])
		if key == "match" {
			break
		}
		val := strings.TrimSpace(line[i+1:])
		if _, ok := cfg[key]; !ok {
			cfg[key] = val
		}
	}
	out := map[string]any{}
	if v, ok := cfg["permitrootlogin"]; ok {
		out["permit_root_login"] = v
	}
	if v, ok := cfg["passwordauthentication"]; ok {
		out["password_authentication"] = v
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
