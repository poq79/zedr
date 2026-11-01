package liveapi

// baseline.go：安全基线 Tab 的只读检查端点（契约 §13.2）。
//
// 十个检查项全部是"读事实"而非"下结论"：注册表用 winapi.RegDWORD，
// Defender/防火墙复用 winapi 已有的采集函数，Guest 用 LocalUsers。
// 状态口径统一为四档：
//   - pass：读到明确的安全值；
//   - warn：值缺失/未显式配置，或处于可接受但不完整的中间态；
//   - fail：读到明确的危险值；
//   - info：读不到（权限/类型异常/枚举失败），按"无法判断"呈现。
//
// 铁律：读取失败绝不拿默认值冒充测量结果；只有在 Windows 文档明确
// 规定默认值的场景（UAC EnableLUA、WDigest 缺失）才按默认值判断，
// 并在 evidence 里写明"按默认值"。这样排障时能区分"机器确实没配"
// 与"探针没读到"。
//
// 端点不接收参数、不执行命令、不写任何状态；单次调用目标 <200ms
// （Defender 查询含一次 SCM 简查）。

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"golang.org/x/sys/windows/registry"

	"zedr/internal/agent/winapi"
	"zedr/internal/platform/httpx"
)

// 基线项状态（契约 §13.2 的 status 枚举）。
const (
	baselinePass = "pass"
	baselineWarn = "warn"
	baselineFail = "fail"
	baselineInfo = "info"
)

// 注册表路径集中在一处：单测可传入同一路径的变体验证降级行为，
// 也避免十个检查项各自拼字符串拼错。
const (
	regPathUAC       = `SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`
	regPathLanmanSrv = `SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters`
	regPathRDPTcp    = `SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp`
	regPathLsa       = `SYSTEM\CurrentControlSet\Control\Lsa`
	regPathWDigest   = `SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest`
)

// baselineItem 是单个检查项（契约 §13.2 items[]）。
type baselineItem struct {
	Key         string `json:"key"`
	Title       string `json:"title"`
	Status      string `json:"status"`
	Current     string `json:"current"`
	Recommended string `json:"recommended"`
	Evidence    string `json:"evidence"`
}

// baselineScore 是四档状态的计数汇总。info 不进 pass/warn/fail，
// 但 total 恒等于 items 长度，前端可据此发现"有项目未能判断"。
type baselineScore struct {
	Pass  int `json:"pass"`
	Warn  int `json:"warn"`
	Fail  int `json:"fail"`
	Total int `json:"total"`
}

// baselineResult 是 /baseline 的完整响应（由 httpx.WriteJSON 包进 data）。
type baselineResult struct {
	GeneratedAt string         `json:"generated_at"`
	Score       baselineScore  `json:"score"`
	Items       []baselineItem `json:"items"`
}

// HandleBaseline 返回 GET /baseline 的 handler。
//
// 独立构造函数而非 *server 方法：本端点不需要 Deps 里的任何注入项，
// 也就不会与 liveapi.go 的 Deps 演进耦合；路由由主会话在 New 里接线
// （本文件按所有权约定不修改 liveapi.go）。
func HandleBaseline() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		items := []baselineItem{
			checkDefender(),
			checkFirewall(),
			checkUACAt(regPathUAC),
			checkSMBv1At(regPathLanmanSrv),
			checkSMBSigningAt(regPathLanmanSrv),
			checkRDPNLAAt(regPathRDPTcp),
			checkLSAPPLAt(regPathLsa),
			checkWDigestAt(regPathWDigest),
			checkRestrictAnonAt(regPathLsa),
			checkGuest(),
		}
		httpx.WriteJSON(w, r, http.StatusOK, baselineResult{
			GeneratedAt: time.Now().UTC().Format(time.RFC3339),
			Score:       scoreBaseline(items),
			Items:       items,
		})
	}
}

// scoreBaseline 汇总计数；未知状态（不应出现）不计入任何一档，
// 但 total 仍按条目数统计，保证总分能暴露差距。
func scoreBaseline(items []baselineItem) baselineScore {
	s := baselineScore{Total: len(items)}
	for _, it := range items {
		switch it.Status {
		case baselinePass:
			s.Pass++
		case baselineWarn:
			s.Warn++
		case baselineFail:
			s.Fail++
		}
	}
	return s
}

// dwordCheck 描述一个"读 DWORD 后按值判定"的检查项。
// judge 只在值确实读到后调用；缺失与读取失败走各自的固定分支，
// 保证十个检查项的错误处理不会各写一套、各漏一处。
type dwordCheck struct {
	key, title      string
	path, valueName string
	recommended     string
	missingStatus   string
	missingEvidence string
	judge           func(v uint32) (status, current, evidence string)
}

// evalDWORDCheck 执行一次注册表读取并组装基线项。
func evalDWORDCheck(c dwordCheck) baselineItem {
	item := baselineItem{
		Key:         c.key,
		Title:       c.title,
		Recommended: c.recommended,
	}
	v, ok, err := winapi.RegDWORD(registry.LOCAL_MACHINE, c.path, c.valueName)
	switch {
	case err != nil:
		// 权限/类型异常：不猜测，明确告诉操作者"没读到"
		item.Status = baselineInfo
		item.Current = "无法读取"
		item.Evidence = fmt.Sprintf("读取 %s\\%s 失败：%v", c.path, c.valueName, err)
	case !ok:
		item.Status = c.missingStatus
		item.Current = "未配置"
		item.Evidence = c.missingEvidence
	default:
		item.Status, item.Current, item.Evidence = c.judge(v)
	}
	return item
}

// ---------------------------------------------------------------- 1. Defender

func checkDefender() baselineItem {
	item := baselineItem{
		Key:         "defender",
		Title:       "Defender 实时保护",
		Recommended: "保持实时保护开启；若由第三方 AV 接管，应确认其提供等效的实时防护",
	}
	d, err := winapi.DefenderStatus()
	if err != nil {
		item.Status = baselineInfo
		item.Current = "查询失败"
		item.Evidence = fmt.Sprintf("Defender 状态查询失败：%v", err)
		return item
	}
	switch d.RealtimeState {
	case "on":
		item.Status = baselinePass
		item.Current = "实时保护开启"
		item.Evidence = "策略未禁用实时保护且 WinDefend 服务正在运行"
	case "off":
		item.Status = baselineFail
		item.Current = "实时保护关闭"
		item.Evidence = "策略显式关闭实时保护，或 WinDefend 服务未运行；第三方防护软件接管时也会呈现为关闭，需人工确认实际防护来源"
	default:
		item.Status = baselineInfo
		item.Current = "状态未知"
		item.Evidence = "无法读取实时保护策略，也无法确认 WinDefend 服务状态"
	}
	return item
}

// ---------------------------------------------------------------- 2. 防火墙

func checkFirewall() baselineItem {
	item := baselineItem{
		Key:         "firewall",
		Title:       "防火墙三档启用",
		Recommended: "域/专用/公用三个配置档全部启用防火墙",
	}
	profiles, err := winapi.FirewallProfiles()
	if err != nil {
		item.Status = baselineInfo
		item.Current = "查询失败"
		item.Evidence = fmt.Sprintf("防火墙配置查询失败：%v", err)
		return item
	}
	if len(profiles) == 0 {
		item.Status = baselineInfo
		item.Current = "没有可用的配置档"
		item.Evidence = "FirewallProfiles 返回空列表，无法判断防火墙状态"
		return item
	}

	enabled := 0
	var disabled []string
	var detail []string
	for _, p := range profiles {
		state := "关闭"
		if p.Enabled {
			enabled++
			state = "开启"
		} else {
			disabled = append(disabled, p.Name)
		}
		detail = append(detail, p.Name+"="+state)
	}
	item.Current = fmt.Sprintf("%d/%d 个配置档启用（%s）", enabled, len(profiles), strings.Join(detail, "，"))
	switch {
	case enabled == len(profiles):
		item.Status = baselinePass
		item.Evidence = "domain/standard/public 三个配置档均启用防火墙"
	case enabled == 0:
		item.Status = baselineFail
		item.Evidence = "三个配置档全部关闭，主机网络面完全不受防火墙约束"
	default:
		item.Status = baselineWarn
		item.Evidence = "以下配置档关闭：" + strings.Join(disabled, "、") + "；对应网络位置不受防火墙保护"
	}
	return item
}

// ---------------------------------------------------------------- 3. UAC

// checkUACAt 读 UAC 两个开关。path 参数化只为单测注入错误路径；
// 生产调用固定 regPathUAC。
//
// 默认值口径（Windows 文档规定）：
//   - EnableLUA 缺失 = 1（UAC 开启）；
//   - ConsentPromptBehaviorAdmin 缺失 = 5（对非 Windows 二进制提示同意）。
//
// 两者都必须在 evidence 里注明"按默认值"，避免把"未配置"读成"已实测"。
func checkUACAt(path string) baselineItem {
	item := baselineItem{
		Key:         "uac",
		Title:       "UAC 用户账户控制",
		Recommended: "EnableLUA=1，且 ConsentPromptBehaviorAdmin≠0（管理员提权必须提示）",
	}
	lua, luaOK, luaErr := winapi.RegDWORD(registry.LOCAL_MACHINE, path, "EnableLUA")
	consent, consentOK, consentErr := winapi.RegDWORD(registry.LOCAL_MACHINE, path, "ConsentPromptBehaviorAdmin")
	if luaErr != nil || consentErr != nil {
		item.Status = baselineInfo
		item.Current = "无法读取"
		var reasons []string
		if luaErr != nil {
			reasons = append(reasons, "EnableLUA: "+luaErr.Error())
		}
		if consentErr != nil {
			reasons = append(reasons, "ConsentPromptBehaviorAdmin: "+consentErr.Error())
		}
		item.Evidence = "读取 UAC 注册表值失败：" + strings.Join(reasons, "；")
		return item
	}

	var notes []string
	if !luaOK {
		lua = 1
		notes = append(notes, "EnableLUA 缺失，按 Windows 默认值 1 处理")
	}
	if !consentOK {
		consent = 5
		notes = append(notes, "ConsentPromptBehaviorAdmin 缺失，按 Windows 默认值 5 处理")
	}
	item.Current = fmt.Sprintf("EnableLUA=%d，ConsentPromptBehaviorAdmin=%d", lua, consent)
	if len(notes) > 0 {
		item.Current += "（" + strings.Join(notes, "；") + "）"
	}

	switch {
	case lua == 0:
		item.Status = baselineFail
		item.Evidence = "EnableLUA=0，UAC 已被整体关闭，管理员操作不再经过同意/凭据提示"
	case consent == 0:
		item.Status = baselineFail
		item.Evidence = "ConsentPromptBehaviorAdmin=0（Elevate without prompting），管理员提权无任何提示"
	default:
		item.Status = baselinePass
		item.Evidence = "UAC 已启用且管理员提权需要提示"
		if len(notes) > 0 {
			item.Evidence += "；" + strings.Join(notes, "；")
		}
	}
	return item
}

// ---------------------------------------------------------------- 4. SMBv1

func checkSMBv1At(path string) baselineItem {
	return evalDWORDCheck(dwordCheck{
		key:             "smbv1",
		title:           "SMBv1 已关闭",
		path:            path,
		valueName:       "SMB1",
		recommended:     "显式设置 SMB1=0，并在系统功能中移除 SMBv1 协议",
		missingStatus:   baselineWarn,
		missingEvidence: "LanmanServer\\Parameters 下没有 SMB1 值：新版 Windows 默认已移除 SMBv1，但未显式禁用，仍需人工确认（缺失也可能是系统不再提供该键）",
		judge: func(v uint32) (string, string, string) {
			if v == 0 {
				return baselinePass, "SMB1=0（已禁用）", "注册表显式关闭 SMBv1 服务端协议"
			}
			return baselineFail, fmt.Sprintf("SMB1=%d（未关闭）", v), "SMBv1 服务端协议未关闭；该协议存在已公开的远程利用面"
		},
	})
}

// ---------------------------------------------------------------- 5. SMB 签名

func checkSMBSigningAt(path string) baselineItem {
	return evalDWORDCheck(dwordCheck{
		key:             "smb_signing",
		title:           "SMB 签名强制",
		path:            path,
		valueName:       "RequireSecuritySignature",
		recommended:     "RequireSecuritySignature=1，要求服务端 SMB 签名",
		missingStatus:   baselineWarn,
		missingEvidence: "未显式配置 RequireSecuritySignature：系统默认值可能允许协商降级，建议显式设为 1",
		judge: func(v uint32) (string, string, string) {
			switch v {
			case 1:
				return baselinePass, "RequireSecuritySignature=1", "服务端要求 SMB 签名，可缓解中间人篡改"
			case 0:
				return baselineFail, "RequireSecuritySignature=0", "未强制 SMB 签名，连接可被降级或中间人篡改"
			default:
				return baselineWarn, fmt.Sprintf("RequireSecuritySignature=%d（非常规值）", v), "值不是 0/1，配置来源可疑，需人工核对"
			}
		},
	})
}

// ---------------------------------------------------------------- 6. RDP NLA

func checkRDPNLAAt(path string) baselineItem {
	return evalDWORDCheck(dwordCheck{
		key:             "rdp_nla",
		title:           "RDP 网络级认证（NLA）",
		path:            path,
		valueName:       "UserAuthentication",
		recommended:     "RDP-Tcp\\UserAuthentication=1，要求 NLA",
		missingStatus:   baselineWarn,
		missingEvidence: "RDP-Tcp 下没有 UserAuthentication 值：未显式启用 NLA，远程桌面暴露面更大",
		judge: func(v uint32) (string, string, string) {
			if v == 1 {
				return baselinePass, "UserAuthentication=1（NLA 已启用）", "远程桌面在建立会话前要求网络级身份验证"
			}
			return baselineFail, fmt.Sprintf("UserAuthentication=%d（NLA 未启用）", v), "未要求 NLA，未认证连接可直接到达登录界面，增加暴力破解与预认证漏洞暴露面"
		},
	})
}

// ---------------------------------------------------------------- 7. LSA 保护

func checkLSAPPLAt(path string) baselineItem {
	return evalDWORDCheck(dwordCheck{
		key:             "lsa_ppl",
		title:           "LSA 保护（RunAsPPL）",
		path:            path,
		valueName:       "RunAsPPL",
		recommended:     "RunAsPPL=1 或 2，以保护 LSA 进程免受内存读取",
		missingStatus:   baselineWarn,
		missingEvidence: "Lsa 下没有 RunAsPPL 值：未启用 LSA 保护，凭据窃取工具可读取 lsass 内存",
		judge: func(v uint32) (string, string, string) {
			switch v {
			case 1, 2:
				return baselinePass, fmt.Sprintf("RunAsPPL=%d（LSA 保护已启用）", v), "lsass 以受保护进程运行，普通管理员权限无法直接读取其内存"
			case 0:
				return baselineFail, "RunAsPPL=0（LSA 保护关闭）", "LSA 保护被显式关闭，lsass 内存可被高权限进程读取"
			default:
				return baselineWarn, fmt.Sprintf("RunAsPPL=%d（非常规值）", v), "值不是 0/1/2，需人工核对策略来源"
			}
		},
	})
}

// ---------------------------------------------------------------- 8. WDigest

func checkWDigestAt(path string) baselineItem {
	return evalDWORDCheck(dwordCheck{
		key:             "wdigest",
		title:           "WDigest 不缓存明文凭据",
		path:            path,
		valueName:       "UseLogonCredential",
		recommended:     "UseLogonCredential=0（或不存在），禁止 WDigest 在内存中保存明文口令",
		missingStatus:   baselinePass,
		missingEvidence: "UseLogonCredential 不存在：Windows 8.1+ 默认不缓存 WDigest 明文凭据，按安全默认处理",
		judge: func(v uint32) (string, string, string) {
			switch v {
			case 0:
				return baselinePass, "UseLogonCredential=0", "WDigest 不会在内存中保存明文口令"
			case 1:
				return baselineFail, "UseLogonCredential=1", "WDigest 被显式开启明文凭据缓存，lsass 内存中可提取明文口令"
			default:
				return baselineWarn, fmt.Sprintf("UseLogonCredential=%d（非常规值）", v), "值不是 0/1，需人工核对配置来源"
			}
		},
	})
}

// ---------------------------------------------------------------- 9. 匿名枚举

func checkRestrictAnonAt(path string) baselineItem {
	return evalDWORDCheck(dwordCheck{
		key:             "restrict_anon",
		title:           "限制匿名枚举",
		path:            path,
		valueName:       "RestrictAnonymous",
		recommended:     "RestrictAnonymous=1，限制匿名用户枚举账户与共享",
		missingStatus:   baselineWarn,
		missingEvidence: "Lsa 下没有 RestrictAnonymous 值：系统默认 0=允许匿名枚举，未显式收紧",
		judge: func(v uint32) (string, string, string) {
			if v == 1 {
				return baselinePass, "RestrictAnonymous=1", "匿名连接无法枚举本地账户与共享名"
			}
			return baselineFail, fmt.Sprintf("RestrictAnonymous=%d（允许匿名枚举）", v), "未限制匿名枚举，攻击者可先摸清账户与共享面"
		},
	})
}

// ---------------------------------------------------------------- 10. Guest

func checkGuest() baselineItem {
	item := baselineItem{
		Key:         "guest",
		Title:       "内置 Guest 账户禁用",
		Recommended: "内置 Guest（SID 以 -501 结尾）保持禁用状态",
	}
	users, err := winapi.LocalUsers()
	if err != nil {
		item.Status = baselineInfo
		item.Current = "账户枚举失败"
		item.Evidence = fmt.Sprintf("无法枚举本地账户：%v", err)
		return item
	}
	if len(users) == 0 {
		item.Status = baselineInfo
		item.Current = "账户表为空"
		item.Evidence = "账户枚举成功但返回空表，无法确认 Guest 状态"
		return item
	}

	var guest *winapi.UserAccount
	sidMissing := 0
	for i := range users {
		u := &users[i]
		if strings.EqualFold(u.Name, "Guest") || strings.HasSuffix(u.SID, "-501") {
			guest = u
			break
		}
		if u.SID == "" {
			sidMissing++
		}
	}
	if guest == nil {
		// 账户已删除，或已重命名且 SID 反查失败：没有可禁用的内置 Guest。
		item.Status = baselinePass
		item.Current = "未发现内置 Guest 账户"
		item.Evidence = "账户名与 SID 均未匹配内置 Guest（SID 以 -501 结尾）"
		if sidMissing > 0 {
			item.Evidence += fmt.Sprintf("；另有 %d 个账户 SID 反查失败，若 Guest 已被重命名则可能漏判", sidMissing)
		}
		return item
	}

	who := guest.Name
	if guest.SID != "" {
		who += "（" + guest.SID + "）"
	}
	if guest.Disabled {
		item.Status = baselinePass
		item.Current = "Guest 已禁用"
		item.Evidence = "内置账户 " + who + " 的标志位为 ACCOUNTDISABLE"
		return item
	}
	item.Status = baselineFail
	item.Current = "Guest 处于启用状态"
	item.Evidence = "内置账户 " + who + " 未禁用，可被匿名/弱口令登录利用"
	return item
}
