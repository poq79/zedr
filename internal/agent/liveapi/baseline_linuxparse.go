// 本文件 NEUTRAL：/baseline 的 Linux 检查项纯逻辑（事实 → 判定，无 IO）。
// IO 壳在 baseline_linux.go。放中性文件的原因同其他 linuxparse 文件：
// 判定口径要能在 Windows 上跑单测锁定（testdata 夹具注入事实）。
//
// 与 Windows baseline.go 的契约对齐：items[]/score 形状逐字段一致，状态
// 四档（pass/warn/fail/info）同一口径；铁律一致——读取失败绝不拿默认值
// 冒充测量结果，只有在上游文档明确规定默认值的场景（sshd 的
// PermitRootLogin=prohibit-password / PasswordAuthentication=yes）才按
// 默认值判断并在 evidence 写明"按默认值"。
//
// 未在 Linux 实机验证（待 Kali 复验）；验证口径 = GOOS=linux 交叉编译 +
// 本文件单测在 Windows 上运行。
package liveapi

// baseline_linuxparse.go：Linux 十项安全基线检查（纯判定）。

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// 状态四档（与 Windows baseline.go 的枚举值一致；常量名带 linux 前缀
// 是因为 Windows 侧同名常量在其构建文件里，中性文件不能撞名）。
const (
	linuxBaselinePass = "pass"
	linuxBaselineWarn = "warn"
	linuxBaselineFail = "fail"
	linuxBaselineInfo = "info"
)

// linuxBaselineItem 与 Windows baseline.go 的 baselineItem 逐字段对齐
// （前端 BaselineItem 类型零改动可渲染）。
type linuxBaselineItem struct {
	Key         string `json:"key"`
	Title       string `json:"title"`
	Status      string `json:"status"`
	Current     string `json:"current"`
	Recommended string `json:"recommended"`
	Evidence    string `json:"evidence"`
}

// linuxBaselineScore 与 Windows baselineScore 逐字段对齐：info 不进
// pass/warn/fail，total 恒等于 items 长度（前端据此发现"有项目未能判断"）。
type linuxBaselineScore struct {
	Pass  int `json:"pass"`
	Warn  int `json:"warn"`
	Fail  int `json:"fail"`
	Total int `json:"total"`
}

// linuxBaselineResult 是 /baseline 的完整响应（Windows baselineResult
// 同形状）。
type linuxBaselineResult struct {
	GeneratedAt string              `json:"generated_at"`
	Score       linuxBaselineScore  `json:"score"`
	Items       []linuxBaselineItem `json:"items"`
}

// linuxHostKey 是一个 SSH 主机私钥文件的权限快照。
type linuxHostKey struct {
	Name string
	Perm uint32
}

// linuxBaselineFacts 是 IO 壳交给判定层的全部事实。nil 切片/空串 = 对应
// 事实不可得（文件不存在/不可读），判定层按 info/降级处理，绝不猜。
type linuxBaselineFacts struct {
	// SSH：SshdConfigs 已按 sshd 解析顺序排好（sshd_config.d/*.conf 按
	// 文件名字典序在前，主配置在后——Debian/RHEL 的 Include 都在文件顶部，
	// sshd 指令 first-match-wins，故 drop-in 生效）。sshd 的 Match 块
	// 不做块级作用域解析（首值口径可能落在 Match 条件内），v1 诚实边界。
	SshdPresent bool
	SshdConfigs []string

	// sudo：SudoersReadable=false 表示主 sudoers 不可读（判定走 info）；
	// SudoersLines 是主文件 + sudoers.d/* 已读到的全部行。
	SudoersReadable bool
	SudoersLines    []string

	// umask：login.defs（首选）/etc/profile（兜底）。nil = 不可读。
	LoginDefs []byte
	Profile   []byte

	// coredump：limits.conf + limits.d/* 行。
	LimitsLines []string

	// MAC：AppArmor 内核参数原文（"Y"/"N"/""=不可读）；SELinux 配置
	//（nil = 不存在）。
	AppArmorEnabled string
	SELinuxConfig   []byte

	// 防火墙：ufw 配置（nil=未安装）；firewalld 开机自启链接存在；
	// iptables 持久化规则文件路径（""=无）。
	UfwConf           []byte
	FirewalldEnabled  bool
	IptablesRulesFile string

	// SSH 主机私钥权限快照。
	HostKeys []linuxHostKey

	// 账户：Passwd nil = 不可读；Shadow nil = 不可读（判定走 info）。
	Passwd []byte
	Shadow []byte

	// 自动更新：包管理系统存在性 + 自动更新机制痕迹。
	AptSystem      bool
	AptAutoUpdates bool
	DnfSystem      bool
	DnfAutoTimer   bool
}

// buildLinuxBaselineResult 组装完整响应（纯逻辑，单测注入事实）。
// 十项检查与任务清单一一对应；不做凑数项，读取失败的信息缺口由 info
// 项如实呈现（score.total 能暴露它们）。
func buildLinuxBaselineResult(f *linuxBaselineFacts, now time.Time) linuxBaselineResult {
	items := []linuxBaselineItem{
		linuxCheckSSHAccess(f),
		linuxCheckSudoNoPasswd(f),
		linuxCheckDefaultUmask(f),
		linuxCheckCoredump(f),
		linuxCheckMAC(f),
		linuxCheckFirewall(f),
		linuxCheckHostKeyPerm(f),
		linuxCheckUID0(f),
		linuxCheckEmptyPassword(f),
		linuxCheckAutoUpdates(f),
	}
	return linuxBaselineResult{
		GeneratedAt: now.UTC().Format(time.RFC3339),
		Score:       linuxScoreBaseline(items),
		Items:       items,
	}
}

// linuxScoreBaseline 与 Windows baseline.go 的 scoreBaseline 同口径：
// 未知状态不计入任何一档，total 仍按条目数统计。
func linuxScoreBaseline(items []linuxBaselineItem) linuxBaselineScore {
	s := linuxBaselineScore{Total: len(items)}
	for _, it := range items {
		switch it.Status {
		case linuxBaselinePass:
			s.Pass++
		case linuxBaselineWarn:
			s.Warn++
		case linuxBaselineFail:
			s.Fail++
		}
	}
	return s
}

// linuxWorstStatus 状态合并取最差（fail > warn > pass > info）。
func linuxWorstStatus(a, b string) string {
	rank := map[string]int{linuxBaselineFail: 3, linuxBaselineWarn: 2, linuxBaselinePass: 1, linuxBaselineInfo: 0}
	if rank[a] >= rank[b] {
		return a
	}
	return b
}

// ---------------------------------------------------------------- 1. SSH

// sshdFirstValue 按 sshd first-match-wins 语义取指令首个显式值。
// 键/值大小写不敏感（sshd_config 语法规定）；返回 found=false 表示全部
// 配置源都没写这条指令。
func sshdFirstValue(configs []string, key string) (val string, found bool) {
	for _, cfg := range configs {
		for _, raw := range strings.Split(cfg, "\n") {
			line := strings.TrimSpace(raw)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			f := strings.Fields(line)
			if len(f) < 2 || !strings.EqualFold(f[0], key) {
				continue
			}
			return strings.ToLower(f[1]), true
		}
	}
	return "", false
}

// linuxCheckSSHAccess 检查 PermitRootLogin / PasswordAuthentication。
// 默认值口径（sshd 文档规定）：PermitRootLogin 默认 prohibit-password、
// PasswordAuthentication 默认 yes——缺失按默认值判断并在 evidence 写明。
func linuxCheckSSHAccess(f *linuxBaselineFacts) linuxBaselineItem {
	item := linuxBaselineItem{
		Key:   "ssh_access",
		Title: "SSH 远程访问加固",
		Recommended: "PermitRootLogin=no（或 prohibit-password 仅密钥），" +
			"PasswordAuthentication=no（配合密钥认证）",
	}
	if !f.SshdPresent {
		item.Status = linuxBaselineInfo
		item.Current = "未发现 sshd 配置"
		item.Evidence = "/etc/ssh/sshd_config 不存在（可能未安装 OpenSSH 服务端）"
		return item
	}

	rootVal, rootFound := sshdFirstValue(f.SshdConfigs, "PermitRootLogin")
	pwVal, pwFound := sshdFirstValue(f.SshdConfigs, "PasswordAuthentication")

	rootStatus, rootNote := linuxBaselineWarn, "PermitRootLogin 未显式配置，按 sshd 默认值 prohibit-password（仅密钥可登 root）处理"
	rootCurrent := "未配置"
	if rootFound {
		rootCurrent = rootVal
		switch rootVal {
		case "no", "prohibit-password":
			rootStatus, rootNote = linuxBaselinePass, "PermitRootLogin="+rootVal+"：root 不能经密码直接登录"
		case "yes":
			rootStatus, rootNote = linuxBaselineFail, "PermitRootLogin=yes：root 可被密码暴力破解直接命中"
		default:
			rootStatus, rootNote = linuxBaselineWarn, "PermitRootLogin="+rootVal+"（非常规值），需人工核对"
		}
	}

	pwStatus, pwNote := linuxBaselineFail, "PasswordAuthentication 未显式配置，按 sshd 默认值 yes（允许密码认证）处理"
	pwCurrent := "未配置"
	if pwFound {
		pwCurrent = pwVal
		switch pwVal {
		case "no":
			pwStatus, pwNote = linuxBaselinePass, "PasswordAuthentication=no：密码暴力破解面已关闭"
		case "yes":
			pwStatus, pwNote = linuxBaselineFail, "PasswordAuthentication=yes：SSH 密码认证开放，暴露暴力破解与口令喷洒面"
		default:
			pwStatus, pwNote = linuxBaselineWarn, "PasswordAuthentication="+pwVal+"（非常规值），需人工核对"
		}
	}

	item.Status = linuxWorstStatus(rootStatus, pwStatus)
	item.Current = "PermitRootLogin=" + rootCurrent + "，PasswordAuthentication=" + pwCurrent
	item.Evidence = rootNote + "；" + pwNote +
		"；解析顺序：sshd_config.d/*.conf（字典序）→ sshd_config，first-match-wins；Match 块未做块级作用域解析"
	return item
}

// ---------------------------------------------------------------- 2. sudo

// linuxCheckSudoNoPasswd 检查 sudoers 的 NOPASSWD 条目。root 自身的
// NOPASSWD 不升级为 fail（root 已是最高权限，免密不构成提权路径），
// 但 evidence 如实列出。
func linuxCheckSudoNoPasswd(f *linuxBaselineFacts) linuxBaselineItem {
	item := linuxBaselineItem{
		Key:         "sudo_nopasswd",
		Title:       "sudo 免密条目",
		Recommended: "避免 NOPASSWD（尤其 ALL）；确需免密应限定命令范围且不覆盖提权组",
	}
	if !f.SudoersReadable {
		item.Status = linuxBaselineInfo
		item.Current = "sudoers 不可读"
		item.Evidence = "/etc/sudoers 不可读（探针权限不足或被裁剪），无法判定免密条目"
		return item
	}

	var hits []string
	rootAll := false
	for _, raw := range f.SudoersLines {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		i := strings.Index(line, "NOPASSWD:")
		if i < 0 {
			continue
		}
		hits = append(hits, line)
		if u := strings.Fields(line); len(u) > 0 && u[0] == "root" {
			continue // root 免密不构成提权
		}
		if strings.HasPrefix(strings.TrimSpace(line[i+len("NOPASSWD:"):]), "ALL") {
			rootAll = true
		}
	}

	if len(hits) == 0 {
		item.Status = linuxBaselinePass
		item.Current = "无 NOPASSWD 条目"
		item.Evidence = fmt.Sprintf("解析 sudoers 及 sudoers.d 共 %d 行，未发现免密条目", len(f.SudoersLines))
		return item
	}

	quoted := hits
	if len(quoted) > 5 {
		quoted = quoted[:5]
	}
	item.Evidence = fmt.Sprintf("发现 %d 条 NOPASSWD 条目（前 %d 条）：", len(hits), len(quoted)) +
		strings.Join(quoted, " ／ ")
	if rootAll {
		item.Status = linuxBaselineFail
		item.Current = fmt.Sprintf("存在免密 sudo ALL（%d 条）", len(hits))
		item.Evidence += "；包含非 root 账户的 NOPASSWD ALL——持有该条目的账户等价免密 root"
	} else {
		item.Status = linuxBaselineWarn
		item.Current = fmt.Sprintf("存在限定范围的免密 sudo（%d 条）", len(hits))
		item.Evidence += "；未发现 NOPASSWD ALL，命令范围需人工确认是否过宽"
	}
	return item
}

// ---------------------------------------------------------------- 3. umask

// parseUmaskFromShellText 从 login.defs/profile 文本中取 umask 配置。
// login.defs 语法 "UMASK\t022"（键大写），profile 语法 "umask 022"
// （shell 语法，键小写）。返回 (值, 原文文本, 是否找到)；来源文件名由
// 调用方标注（它知道自己读的是哪份文件）。
func parseUmaskFromShellText(data []byte, key string) (uint32, string, bool) {
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Fields(line)
		if len(f) < 2 || f[0] != key {
			continue
		}
		v, err := strconv.ParseUint(f[1], 8, 32)
		if err != nil {
			continue
		}
		return uint32(v), f[1], true
	}
	return 0, "", false
}

// linuxCheckDefaultUmask 检查默认 umask。umask 位语义 = 被禁止的权限位：
// 判定要反着读——022 禁了组/其他写（文件全局可读，标准但偏松），077
// 全禁（严），000 什么都没禁（其他可写，危险）。
func linuxCheckDefaultUmask(f *linuxBaselineFacts) linuxBaselineItem {
	item := linuxBaselineItem{
		Key:         "default_umask",
		Title:       "默认 umask",
		Recommended: "UMASK 027 或更严（禁止组/其他可写；建议一并收紧其他可读）",
	}
	val, src, found := uint32(0), "", false
	if f.LoginDefs != nil {
		if v, _, ok := parseUmaskFromShellText(f.LoginDefs, "UMASK"); ok {
			val, src, found = v, "/etc/login.defs", true
		}
	}
	if !found && f.Profile != nil {
		if v, _, ok := parseUmaskFromShellText(f.Profile, "umask"); ok {
			val, src, found = v, "/etc/profile", true
		}
	}
	if !found {
		item.Status = linuxBaselineWarn
		item.Current = "未显式配置"
		item.Evidence = "/etc/login.defs 与 /etc/profile 均未找到 umask 配置；实际生效值取决于 PAM/桌面会话默认，未冒充实测"
		return item
	}

	item.Current = fmt.Sprintf("UMASK=%03o（%s）", val, src)
	switch {
	case val&0o002 == 0 || val&0o020 == 0:
		item.Status = linuxBaselineFail
		item.Evidence = "umask 未禁止组写或/和其他写位，新建文件对其他用户可写，任意本地账户可篡改彼此文件"
	case val&0o004 == 0:
		item.Status = linuxBaselineWarn
		item.Evidence = "umask 禁止了写位但未禁止其他读位（如 022），新建文件全局可读——含敏感内容的文件也会被读"
	default:
		item.Status = linuxBaselinePass
		item.Evidence = "umask 禁止组/其他的读写位，新建文件仅属主可访问"
	}
	return item
}

// ---------------------------------------------------------------- 4. coredump

// linuxCheckCoredump 检查 limits.conf 的 core 条目。value 是"上限"：
// 0=禁用（安全），unlimited=不设限（危险）。
func linuxCheckCoredump(f *linuxBaselineFacts) linuxBaselineItem {
	item := linuxBaselineItem{
		Key:         "coredump_limits",
		Title:       "core dump 限制",
		Recommended: "* soft/hard core 0（禁用核心转储，防止内存中的凭据落盘）",
	}
	var entries []string
	unlimited := false
	hasZero := false
	for _, raw := range f.LimitsLines {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		flds := strings.Fields(line)
		// limits.conf 行：domain type item value（item 在第 3 列）
		if len(flds) < 4 || flds[2] != "core" {
			continue
		}
		entries = append(entries, line)
		if strings.EqualFold(flds[3], "unlimited") || strings.EqualFold(flds[3], "all") {
			unlimited = true
		}
		if flds[3] == "0" {
			hasZero = true
		}
	}

	if len(entries) == 0 {
		item.Status = linuxBaselineWarn
		item.Current = "未显式配置"
		item.Evidence = "limits.conf 与 limits.d 均无 core 条目；是否产生 coredump 取决于内核/systemd 默认，未冒充实测"
		return item
	}
	item.Evidence = "core 条目：" + strings.Join(entries, " ／ ")
	switch {
	case unlimited:
		item.Status = linuxBaselineFail
		item.Current = "core=unlimited"
		item.Evidence += "；核心转储不设上限，进程内存（含凭据）可整体落盘"
	case hasZero:
		item.Status = linuxBaselinePass
		item.Current = "core=0（已禁用）"
	default:
		item.Status = linuxBaselineWarn
		item.Current = "core 限制为非零值"
		item.Evidence += "；未禁用核心转储，仅限制了大小"
	}
	return item
}

// ---------------------------------------------------------------- 5. MAC

// linuxCheckMAC 检查 AppArmor/SELinux 启用态。AppArmor 参数 Y 判 pass
// （profile 加载态属运行态，evidence 注明未核验）；SELinux 按配置值
// enforcing/pass、permissive/warn、disabled/fail；两者都拿不到 → warn。
func linuxCheckMAC(f *linuxBaselineFacts) linuxBaselineItem {
	item := linuxBaselineItem{
		Key:         "mac_enforced",
		Title:       "强制访问控制（AppArmor/SELinux）",
		Recommended: "启用 AppArmor 或 SELinux（enforcing），至少不显式禁用",
	}
	if f.AppArmorEnabled == "Y" {
		item.Status = linuxBaselinePass
		item.Current = "AppArmor 已启用"
		item.Evidence = "/sys/module/apparmor/parameters/enabled = Y（各 profile 的加载/投诉态属运行态，未逐个核验）"
		return item
	}
	if f.SELinuxConfig != nil {
		selinux := ""
		for _, raw := range strings.Split(string(f.SELinuxConfig), "\n") {
			line := strings.TrimSpace(raw)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			if v, ok := strings.CutPrefix(line, "SELINUX="); ok {
				selinux = strings.TrimSpace(v)
			}
		}
		switch selinux {
		case "enforcing":
			item.Status = linuxBaselinePass
			item.Current = "SELinux enforcing"
			item.Evidence = "/etc/selinux/config SELINUX=enforcing"
		case "permissive":
			item.Status = linuxBaselineWarn
			item.Current = "SELinux permissive"
			item.Evidence = "SELinux 已加载策略但只告警不拦截（/etc/selinux/config SELINUX=permissive）"
		case "disabled":
			item.Status = linuxBaselineFail
			item.Current = "SELinux disabled"
			item.Evidence = "SELinux 被显式关闭（/etc/selinux/config SELINUX=disabled），主体仅受普通 DAC 权限约束"
		default:
			item.Status = linuxBaselineWarn
			item.Current = "SELinux 配置异常"
			item.Evidence = "/etc/selinux/config 存在但 SELINUX= 值不可识别（" + selinux + "）"
		}
		return item
	}
	item.Status = linuxBaselineWarn
	item.Current = "未检测到启用的 MAC"
	aaNote := "参数不可读"
	if f.AppArmorEnabled == "N" {
		aaNote = "内核参数为 N（AppArmor 未启用）"
	}
	item.Evidence = "AppArmor " + aaNote + "；/etc/selinux/config 不存在——主机仅依赖普通 DAC 权限模型"
	return item
}

// ---------------------------------------------------------------- 6. 防火墙

// linuxCheckFirewall 检查防火墙机制的存在与启用态（只判状态，不解析
// 全部规则——规则语义各异，误读比不读更误导）。
func linuxCheckFirewall(f *linuxBaselineFacts) linuxBaselineItem {
	item := linuxBaselineItem{
		Key:         "firewall",
		Title:       "本地防火墙",
		Recommended: "启用 ufw/firewalld，或至少持久化 iptables 基线规则",
	}
	var active []string
	ufwInstalledButOff := false
	if f.UfwConf != nil {
		enabled := false
		for _, raw := range strings.Split(string(f.UfwConf), "\n") {
			if v, ok := strings.CutPrefix(strings.TrimSpace(raw), "ENABLED="); ok {
				enabled = strings.EqualFold(strings.TrimSpace(v), "yes")
			}
		}
		if enabled {
			active = append(active, "ufw(ENABLED=yes)")
		} else {
			ufwInstalledButOff = true
		}
	}
	if f.FirewalldEnabled {
		active = append(active, "firewalld(开机自启)")
	}
	if f.IptablesRulesFile != "" {
		active = append(active, "iptables 规则文件("+f.IptablesRulesFile+")")
	}

	switch {
	case len(active) > 0:
		item.Status = linuxBaselinePass
		item.Current = strings.Join(active, "，")
		item.Evidence = "检测到防火墙机制处于启用/持久化状态（规则内容未逐条解析）"
	case ufwInstalledButOff:
		item.Status = linuxBaselineFail
		item.Current = "ufw 已安装但未启用"
		item.Evidence = "/etc/ufw/ufw.conf ENABLED=no 且未发现其他防火墙机制，主机网络面无本地过滤"
	default:
		item.Status = linuxBaselineWarn
		item.Current = "未发现防火墙配置"
		item.Evidence = "未检测到 ufw/firewalld/iptables 持久化配置（主机可能依赖网络层防护，需人工确认）"
	}
	return item
}

// ---------------------------------------------------------------- 7. 主机私钥

// linuxCheckHostKeyPerm 检查 /etc/ssh/ssh_host_*_key 权限。判"其他用户
// 可读"（0o004）：Debian 12 起私钥 0640 root:_ssh（专用组隔离）是合规
// 形态，组可读不判 fail——只看"其他"位。
func linuxCheckHostKeyPerm(f *linuxBaselineFacts) linuxBaselineItem {
	item := linuxBaselineItem{
		Key:         "ssh_hostkey_perm",
		Title:       "SSH 主机私钥权限",
		Recommended: "私钥 0600/0640，其他用户不可读",
	}
	if len(f.HostKeys) == 0 {
		item.Status = linuxBaselineInfo
		item.Current = "未发现主机私钥"
		item.Evidence = "/etc/ssh 下无 ssh_host_*_key（可能未安装 OpenSSH server）"
		return item
	}
	var bad []string
	for _, k := range f.HostKeys {
		if k.Perm&0o004 != 0 {
			bad = append(bad, fmt.Sprintf("%s(%03o)", k.Name, k.Perm))
		}
	}
	if len(bad) > 0 {
		item.Status = linuxBaselineFail
		item.Current = "存在其他用户可读的私钥"
		item.Evidence = "以下私钥对其他用户可读：" + strings.Join(bad, "，") +
			"；主机私钥泄露可被用于服务器冒充与中间人"
		return item
	}
	item.Status = linuxBaselinePass
	item.Current = fmt.Sprintf("%d 个私钥权限合规", len(f.HostKeys))
	item.Evidence = "全部主机私钥对其他用户不可读（组可读仅出现在专用组隔离形态，如 Debian _ssh 组）"
	return item
}

// ---------------------------------------------------------------- 8. UID 0

// linuxCheckUID0 检查 passwd 中 UID 0 的账户集合。root 之外还有 UID 0
// = 隐蔽 root 后门（不依赖 sudoers 的等价 root 身份）。
func linuxCheckUID0(f *linuxBaselineFacts) linuxBaselineItem {
	item := linuxBaselineItem{
		Key:         "uid0_accounts",
		Title:       "UID 0 账户",
		Recommended: "仅 root 拥有 UID 0；其他账户提权应走 sudo 并留痕",
	}
	if f.Passwd == nil {
		item.Status = linuxBaselineInfo
		item.Current = "passwd 不可读"
		item.Evidence = "/etc/passwd 不可读，无法识别 UID 0 账户"
		return item
	}
	var uid0 []string
	for _, p := range parsePasswdLines(f.Passwd) {
		if p.UID == 0 {
			uid0 = append(uid0, p.Name)
		}
	}
	if len(uid0) == 0 {
		item.Status = linuxBaselineInfo
		item.Current = "未识别到 UID 0 账户"
		item.Evidence = "passwd 解析成功但无 UID 0 条目（无 root 的异常状态，需人工核对）"
		return item
	}
	extra := []string{}
	for _, n := range uid0 {
		if n != "root" {
			extra = append(extra, n)
		}
	}
	if len(extra) == 0 {
		item.Status = linuxBaselinePass
		item.Current = "仅 root"
		item.Evidence = "UID 0 账户只有 root"
		return item
	}
	item.Status = linuxBaselineFail
	item.Current = "UID 0 账户: " + strings.Join(uid0, ", ")
	item.Evidence = "以下非 root 账户拥有 UID 0：" + strings.Join(extra, "，") +
		"——不依赖 sudoers 的等价 root 身份，典型后门手法"
	return item
}

// ---------------------------------------------------------------- 9. 空密码

// linuxCheckEmptyPassword 检查 shadow 中的空密码账户。"!"/"*" 开头是
// 锁定占位（不算空密码）；空串 = 该账户可以无密码通过登录认证。
func linuxCheckEmptyPassword(f *linuxBaselineFacts) linuxBaselineItem {
	item := linuxBaselineItem{
		Key:         "empty_password",
		Title:       "空密码账户",
		Recommended: "所有账户密码字段非空；可登录性用 nologin/锁定控制而非空口令",
	}
	if f.Shadow == nil {
		item.Status = linuxBaselineInfo
		item.Current = "shadow 不可读"
		item.Evidence = "/etc/shadow 不可读（探针权限不足或被裁剪），无法判断空密码账户"
		return item
	}
	var empty []string
	for _, s := range parseShadowLines(f.Shadow) {
		if s.Hash == "" {
			empty = append(empty, s.Name)
		}
	}
	if len(empty) == 0 {
		item.Status = linuxBaselinePass
		item.Current = "无空密码账户"
		item.Evidence = "全部 shadow 条目的密码字段非空（含 ! / * 锁定占位符）"
		return item
	}
	item.Status = linuxBaselineFail
	item.Current = fmt.Sprintf("%d 个空密码账户: %s", len(empty), strings.Join(empty, ", "))
	item.Evidence = "以下账户密码字段为空，可不提供口令通过登录认证：" + strings.Join(empty, "，")
	return item
}

// ---------------------------------------------------------------- 10. 自动更新

// linuxCheckAutoUpdates 检查无人值守安全更新机制的痕迹。按"存在性"
// 判定（apt periodic 目录 / 自动更新 timer 链接 / dnf-automatic），
// 不验证机制真的在跑（运行态属 journalctl 职责，只读纪律不执行命令）。
func linuxCheckAutoUpdates(f *linuxBaselineFacts) linuxBaselineItem {
	item := linuxBaselineItem{
		Key:         "auto_updates",
		Title:       "系统自动更新",
		Recommended: "启用无人值守安全更新（unattended-upgrades / dnf-automatic）",
	}
	switch {
	case f.AptAutoUpdates || f.DnfAutoTimer:
		item.Status = linuxBaselinePass
		item.Current = "自动更新机制已启用"
		item.Evidence = "检测到 apt periodic / apt-daily-upgrade.timer 或 dnf-automatic.timer 痕迹（是否成功执行未核验）"
	case f.AptSystem || f.DnfSystem:
		item.Status = linuxBaselineWarn
		item.Current = "未发现自动更新痕迹"
		item.Evidence = "检测到 apt/dnf 包管理系统，但未发现 unattended-upgrades / dnf-automatic 机制——安全补丁依赖人工"
	default:
		item.Status = linuxBaselineInfo
		item.Current = "未识别包管理系统"
		item.Evidence = "未检测到 apt/dnf（其他包管理器/容器镜像形态不在本检查覆盖面，诚实边界）"
	}
	return item
}
