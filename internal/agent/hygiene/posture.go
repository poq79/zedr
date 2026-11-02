package hygiene

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/sys/windows/registry"

	"zedr/internal/agent/winapi"
)

// Check 是一条体检项。State 用三色语义（对齐 Windows 安全中心的绿/黄/红
// 惯例）：ok=正常，warn=需关注，err=高风险；info=无法判断/仅陈述事实。
// 刻意不做数字总分——"92 分"式的评分无法解释每一分的来源，只会制造
// 虚假安全感；这里每一项都必须自带"为什么"和"怎么办"。
type Check struct {
	ID     string `json:"id"`
	Group  string `json:"group"` // config | update | privacy
	Title  string `json:"title"`
	State  string `json:"state"` // ok | warn | err | info
	Value  string `json:"value"`
	Why    string `json:"why"`
	Advice string `json:"advice,omitempty"`
}

// Posture 汇总本机安全配置体检。单个检查项失败降级为 info（写明"无法
// 判断"），绝不让整个体检视图空白，也绝不用默认值冒充测量结果。
func Posture() []Check {
	checks := make([]Check, 0, 16)
	checks = append(checks,
		checkUAC(),
		checkRDP(),
		checkSMBv1(),
		checkDefender(),
		checkFirewall(),
		checkLSA(),
		checkShares(),
		checkPatch(),
		checkRebootPending(),
		checkAdvertID(),
		checkTelemetry(),
		checkSilentApps(),
		checkTailored(),
	)
	return checks
}

func checkUAC() Check {
	c := Check{ID: "uac", Group: "config", Title: "用户账户控制 (UAC)",
		Why: "UAC 是恶意程序静默提权的第一道闸。被降成\"从不通知\"后，提权动作不再有用户可见的确认。"}
	enable, ok1, _ := winapi.RegDWORD(registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`, "EnableLUA")
	prompt, ok2, _ := winapi.RegDWORD(registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`, "ConsentPromptBehaviorAdmin")
	switch {
	case ok1 && enable == 0:
		c.State, c.Value, c.Advice = "err", "UAC 已完全关闭",
			"设置 → 搜索\"用户账户控制\"，把滑块调回默认档。"
	case ok2 && prompt == 0:
		c.State, c.Value, c.Advice = "warn", "提权时静默放行（不通知）",
			"设置 → 搜索\"用户账户控制\"，恢复\"仅在应用尝试更改我的电脑时通知\"。"
	case !ok1 && !ok2:
		c.State, c.Value = "info", "未显式配置（按系统默认，通知开启）"
	default:
		c.State, c.Value = "ok", "开启（更改需确认）"
	}
	return c
}

func checkRDP() Check {
	deny, ok, _ := winapi.RegDWORD(registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Control\Terminal Server`, "fDenyTSConnections")
	c := Check{ID: "rdp", Group: "config", Title: "远程桌面 (RDP)",
		Why: "RDP 是勒索软件与爆破工具最爱的入口之一；不需要远程办公时开着它等于多留一扇门。"}
	switch {
	case ok && deny == 0:
		c.State, c.Value, c.Advice = "warn", "开启（任意账号可尝试登录）",
			"设置 → 系统 → 远程桌面 关闭；或确有需要时限定可登录账号并开 NLA。"
	case ok:
		c.State, c.Value = "ok", "关闭"
	default:
		c.State, c.Value = "info", "无法判断（注册表读取失败）"
	}
	return c
}

func checkSMBv1() Check {
	v, ok, _ := winapi.RegDWORD(registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters`, "SMB1")
	c := Check{ID: "smbv1", Group: "config", Title: "SMB v1 文件共享协议",
		Why: "SMBv1 是 WannaCry 一类蠕虫的入侵通道，微软已默认禁用多年；开着它属于高危遗留配置。"}
	switch {
	case ok && v != 0:
		c.State, c.Value, c.Advice = "err", "启用",
			"控制面板 → 程序 → 启用或关闭 Windows 功能 → 取消\"SMB 1.0\"。"
	case ok:
		c.State, c.Value = "ok", "已禁用"
	default:
		// Win10/11 新系统该值缺席 = 未安装 SMBv1，按默认禁用处理
		c.State, c.Value = "ok", "未安装（默认禁用）"
	}
	return c
}

func checkDefender() Check {
	info, err := winapi.DefenderStatus()
	c := Check{ID: "defender", Group: "config", Title: "杀毒实时防护",
		Why: "实时防护关掉后，恶意文件落地时不再有任何报警；排除项是最常见的留后门手法。"}
	switch {
	case err != nil:
		c.State, c.Value = "info", "无法判断（读取失败）"
	case info.RealtimeState == "off":
		c.State, c.Value, c.Advice = "err", "实时保护已关闭", "Windows 安全中心 → 病毒和威胁防护 → 重新开启实时保护。"
	case info.RealtimeState == "unknown":
		c.State, c.Value = "info", "状态未知（本机无 Defender 或被第三方接管）"
	default:
		c.State, c.Value = "ok", "开启"
	}
	n := len(info.ExclusionPaths) + len(info.ExclusionProcesses) + len(info.ExclusionExtensions)
	if n > 0 && c.State != "err" {
		c.Value += fmt.Sprintf("；排除项 %d 条（路径 %d / 进程 %d / 扩展名 %d）", n,
			len(info.ExclusionPaths), len(info.ExclusionProcesses), len(info.ExclusionExtensions))
	}
	return c
}

func checkFirewall() Check {
	profs, err := winapi.FirewallProfiles()
	c := Check{ID: "firewall", Group: "config", Title: "防火墙（三张网络配置档）",
		Why: "防火墙关闭后，本机监听的服务会直接暴露给所在网络里的所有设备。"}
	if err != nil || len(profs) == 0 {
		c.State, c.Value = "info", "无法判断（读取失败）"
		return c
	}
	var off []string
	for _, p := range profs {
		if !p.Enabled {
			off = append(off, p.Name)
		}
	}
	if len(off) > 0 {
		c.State, c.Value, c.Advice = "warn", "已关闭："+strings.Join(off, "、"),
			"Windows 安全中心 → 防火墙和网络保护 → 逐个配置档重新开启。"
		return c
	}
	c.State, c.Value = "ok", "全部开启"
	return c
}

func checkLSA() Check {
	v, ok, _ := winapi.RegDWORD(registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Control\LSA`, "RunAsPPL")
	c := Check{ID: "lsa", Group: "config", Title: "LSA 凭据保护",
		Why: "LSA 保护开启后，mimikatz 一类抓取 Windows 凭据的工具会直接失效。新版 Windows 默认开启。"}
	switch {
	case ok && v != 0:
		c.State, c.Value = "ok", "开启"
	case ok:
		c.State, c.Value, c.Advice = "warn", "被显式关闭",
			"注册表 HKLM\\SYSTEM\\CurrentControlSet\\Control\\LSA 的 RunAsPPL 恢复为 1（需重启生效）。"
	default:
		c.State, c.Value = "info", "未显式配置（新版 Windows 默认开启）"
	}
	return c
}

// standardShareNames 是 Windows 默认管理共享；除它们之外的共享才是
// 用户/软件有意开放的。
var standardShareNames = map[string]bool{
	"ADMIN$": true, "IPC$": true, "C$": true, "D$": true, "E$": true, "F$": true,
}

func checkShares() Check {
	shares, err := winapi.NetShares()
	c := Check{ID: "shares", Group: "config", Title: "文件共享（SMB 共享点）",
		Why: "共享文件夹会暴露给局域网内所有设备；被勒索软件利用时就是横向移动的通道。"}
	if err != nil {
		c.State, c.Value = "info", "无法判断（读取失败）"
		return c
	}
	var open []string
	for _, s := range shares {
		if !standardShareNames[strings.ToUpper(s.Name)] {
			open = append(open, s.Name)
		}
	}
	if len(open) == 0 {
		c.State, c.Value = "ok", "无自定义共享"
		return c
	}
	sort.Strings(open)
	c.State, c.Value, c.Advice = "info",
		fmt.Sprintf("开放共享 %d 个：%s", len(open), strings.Join(open, "、")),
		"如果是你有意共享的就没问题；不认识的共享请在\"计算机管理 → 共享文件夹\"里核查。"
	return c
}

func checkPatch() Check {
	build, disp, ubr := "", "", ""
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Windows NT\CurrentVersion`, registry.QUERY_VALUE); err == nil {
		build, _, _ = k.GetStringValue("CurrentBuildNumber")
		disp, _, _ = k.GetStringValue("DisplayVersion")
		if v, _, err := k.GetIntegerValue("UBR"); err == nil {
			ubr = strconv.FormatUint(v, 10)
		}
		k.Close()
	}
	c := Check{ID: "patch", Group: "update", Title: "系统补丁基线",
		Why: "大量真实攻击打的不是漏洞本身，而是几个月都不打补丁的机器。"}
	if build == "" {
		c.State, c.Value = "info", "无法判断（注册表读取失败）"
		return c
	}
	ver := build + "." + firstNonEmpty(ubr, "?")
	if disp != "" {
		ver += "（" + disp + "）"
	}
	c.State, c.Value = "info", "Windows 补丁级别 "+ver+
		"；本机体检不联网比对最新补丁号，最新状态请看 Windows 更新页"
	return c
}

func checkRebootPending() Check {
	pending := false
	var reasons []string
	for _, p := range []string{
		`SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending`,
		`SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired`,
	} {
		if k, err := registry.OpenKey(registry.LOCAL_MACHINE, p, registry.QUERY_VALUE); err == nil {
			k.Close()
			pending = true
			reasons = append(reasons, "系统更新")
			break
		}
	}
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Control\Session Manager`, registry.QUERY_VALUE); err == nil {
		if v, _, err := k.GetStringsValue("PendingFileRenameOperations"); err == nil && len(v) > 0 {
			pending = true
			reasons = append(reasons, "待替换的系统文件")
		}
		k.Close()
	}
	c := Check{ID: "reboot", Group: "update", Title: "待重启的更新",
		Why: "补丁下载完但没重启 = 保护没生效，很多机器\"打了补丁还是中招\"就卡在这一步。"}
	if pending {
		c.State, c.Value, c.Advice = "warn",
			"有未完成的更新在等重启（"+strings.Join(dedupe(reasons), "、")+"）",
			"方便时重启一次，让已下载的安全补丁真正生效。"
		return c
	}
	c.State, c.Value = "ok", "没有待重启的更新"
	return c
}

func checkAdvertID() Check {
	v, ok, _ := winapi.RegDWORD(registry.CURRENT_USER,
		`SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo`, "Enabled")
	c := Check{ID: "adid", Group: "privacy", Title: "Windows 广告 ID",
		Why: "开启后应用可以拿到一个跨应用关联你的广告标识，行为画像会被拼接起来。"}
	switch {
	case ok && v != 0:
		c.State, c.Value, c.Advice = "warn", "开启",
			"设置 → 隐私和安全性 → 常规 → 关闭\"允许应用使用广告 ID\"。"
	case ok:
		c.State, c.Value = "ok", "已关闭"
	default:
		c.State, c.Value = "info", "未配置（按系统默认，开启）"
	}
	return c
}

func checkTelemetry() Check {
	v, ok, _ := winapi.RegDWORD(registry.LOCAL_MACHINE,
		`SOFTWARE\Policies\Microsoft\Windows\DataCollection`, "AllowTelemetry")
	c := Check{ID: "telemetry", Group: "privacy", Title: "Windows 诊断数据级别",
		Why: "诊断数据是发给微软的遥测；策略键只在专业版/企业版可管理，家庭版按系统默认。"}
	if !ok {
		c.State, c.Value = "info", "未配置（按系统默认级别）"
		return c
	}
	levels := map[uint32]string{0: "安全", 1: "基本", 2: "增强", 3: "完全"}
	c.State, c.Value = "info", "策略级别："+levels[v]
	return c
}

func checkSilentApps() Check {
	v, ok, _ := winapi.RegDWORD(registry.CURRENT_USER,
		`SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager`, "SilentInstalledAppsEnabled")
	c := Check{ID: "silent_apps", Group: "privacy", Title: "系统静默安装推广应用",
		Why: "开启后 Windows 会静默往开始菜单里装推广的应用——和捆装软件是同一种行为，只是来源换成了系统。"}
	switch {
	case ok && v != 0:
		c.State, c.Value, c.Advice = "warn", "允许静默安装",
			"设置 → 隐私和安全性 → 常规，或组策略关闭\"静默安装推荐的运用\"。"
	case ok:
		c.State, c.Value = "ok", "已关闭"
	default:
		c.State, c.Value = "info", "未配置（按系统默认，开启）"
	}
	return c
}

func checkTailored() Check {
	v, ok, _ := winapi.RegDWORD(registry.CURRENT_USER,
		`SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy`, "TailoredExperiencesWithDiagnosticDataEnabled")
	c := Check{ID: "tailored", Group: "privacy", Title: "个性化体验（用诊断数据定制提示）",
		Why: "开启即表示同意把诊断数据用于个性化推荐，属于隐私面而非安全面，供知情选择。"}
	switch {
	case ok && v != 0:
		c.State, c.Value, c.Advice = "info", "开启",
			"设置 → 隐私和安全性 → 常规 → 关闭\"定制体验\"。"
	case ok:
		c.State, c.Value = "ok", "已关闭"
	default:
		c.State, c.Value = "info", "未配置（按系统默认，开启）"
	}
	return c
}

func dedupe(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := in[:0]
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
