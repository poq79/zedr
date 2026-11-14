// 本文件 NEUTRAL：/accounts 的 Linux 侧纯解析逻辑（无 IO、无构建标签）。
// 放中性文件的原因同 persist_linuxparse.go：解析口径要能在 Windows 上跑
// 单测锁定（testdata 夹具）；Linux 专属的文件读取壳在 accounts_linux.go。
//
// 未在 Linux 实机验证（待 Kali 复验）；验证口径 = GOOS=linux 交叉编译 +
// 本文件单测在 Windows 上运行。
package liveapi

// accounts_linuxparse.go：/etc/passwd、/etc/group、/etc/shadow、
// /etc/login.defs 的行解析 + /accounts Linux 投影（纯逻辑）。

import (
	"sort"
	"strconv"
	"strings"
	"time"
)

// linuxAccountsUser 与 Windows accounts.go 的 accountsUser 逐字段对齐
// （前端 AccountUser 类型零改动可渲染）。字段语义映射（无对等结构的字段
// 取"诚实近似"还是"留空"，逐字段注释）：
//   - sid：Linux 无 SID，填 "uid=<n>"（比留空有用：前端把它当唯一标识
//     展示，uid 是内核真实身份号）；
//   - disabled：登录 shell 为 nologin/false（与 linuxinv users 节同口径；
//     Linux 没有 Windows 式账户禁用标志，shell 是唯一的"能否登录"事实）；
//   - password_never_expires：shadow 的 max 老化字段为空或 >=99999（惯例
//     "永不过期"值）；shadow 不可读/无条目时恒 false（false 是"有过期
//     策略"的中性默认，前端无线协议区分"未知"）；
//   - password_age_days：shadow 的 lstchg（自 epoch 天数）到现在的天数；
//     无数据时 0（前端约定 0=无记录）；
//   - last_logon_unix：恒 0。/accounts 只读账户目录，登录历史在 utmp
//     （属 /sessions 职责）与 lastlog（v1 不做，避免多读一个历史文件）——
//     前端约定 0=从未登录/无记录，不伪造；
//   - comment：GECOS 原文。
type linuxAccountsUser struct {
	Name                 string `json:"name"`
	SID                  string `json:"sid"`
	Disabled             bool   `json:"disabled"`
	PasswordNeverExpires bool   `json:"password_never_expires"`
	PasswordAgeDays      int    `json:"password_age_days"`
	LastLogonUnix        int64  `json:"last_logon_unix"`
	Comment              string `json:"comment"`
	IsAdmin              bool   `json:"is_admin"`
}

// linuxAccountsPolicy 与 Windows accountsPolicy 逐字段对齐；0=未配置
// （前端按 — 显示）。
type linuxAccountsPolicy struct {
	MinPasswordLength uint32 `json:"min_password_length"`
	MaxAgeDays        uint32 `json:"max_age_days"`
	LockoutThreshold  uint32 `json:"lockout_threshold"`
}

// linuxPasswdEntry 是 /etc/passwd 一行（name:passwd:uid:gid:gecos:home:shell）。
type linuxPasswdEntry struct {
	Name  string
	UID   int
	GID   int
	Gecos string
	Home  string
	Shell string
}

// linuxShadowEntry 是 /etc/shadow 一行的关键字段。LastChange/MaxDays 取
// days 语义；-1 = 字段为空（无数据），与"0 天"区分。
type linuxShadowEntry struct {
	Name       string
	Hash       string
	LastChange int // 第 3 列 lstchg（自 1970-01-01 的天数）；空 = -1
	MaxDays    int // 第 5 列 max（口令最长使用天数）；空 = -1
}

// linuxAdminGroups 是管理员组判定口径：root 主组（gid 0）+ 提权组惯例名。
// 与 linuxinv users.go 的 sudoGroupMembers（sudo/wheel）+ loginGroupMembers
// （admin）同集合，再加 root 组本身——两个视图对同一台主机的 is_admin
// 结论必须一致，否则调查者会在两个 Tab 看到互相矛盾的答案。
var linuxAdminGroups = map[string]bool{
	"root":  true,
	"sudo":  true,
	"wheel": true,
	"admin": true,
}

// parsePasswdLines 解析 /etc/passwd 文本为条目列表（保文件顺序，输出稳定）。
// 残行（列数不足/uid 非数字）整行跳过——半条账户记录只会制造噪声。
func parsePasswdLines(data []byte) []linuxPasswdEntry {
	var out []linuxPasswdEntry
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(strings.TrimRight(raw, "\r"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// passwd 行：name:passwd:uid:gid:gecos:home:shell
		f := strings.Split(line, ":")
		if len(f) < 7 {
			continue
		}
		uid, err := strconv.Atoi(f[2])
		if err != nil {
			continue
		}
		gid, _ := strconv.Atoi(f[3])
		out = append(out, linuxPasswdEntry{
			Name:  f[0],
			UID:   uid,
			GID:   gid,
			Gecos: f[4],
			Home:  f[5],
			Shell: f[6],
		})
	}
	return out
}

// parseGroupLines 解析 /etc/group 为条目列表（成员含逗号分隔补齐）。
func parseGroupLines(data []byte) []linuxGroupEntry {
	var out []linuxGroupEntry
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(strings.TrimRight(raw, "\r"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// group 行：name:passwd:gid:members
		f := strings.Split(line, ":")
		if len(f) < 4 {
			continue
		}
		gid, _ := strconv.Atoi(f[2])
		out = append(out, linuxGroupEntry{
			Name:    f[0],
			GID:     gid,
			Members: strings.Split(f[3], ","),
		})
	}
	return out
}

// linuxGroupEntry 是 /etc/group 一行。
type linuxGroupEntry struct {
	Name    string
	GID     int
	Members []string
}

// parseShadowLines 解析 /etc/shadow（root 可读；探针以 root systemd 运行
// 通常可读）。哈希列以 "!" / "*" 开头 = 密码锁定（不是空密码，见
// buildLinuxAccounts 的 empty-password 口径）；列数 <2 的残行跳过
// （shadow 惯例是 9 列，但某些条目只写到 min 列——有 name+hash 就可用）。
func parseShadowLines(data []byte) []linuxShadowEntry {
	var out []linuxShadowEntry
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(strings.TrimRight(raw, "\r"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Split(line, ":")
		if len(f) < 2 {
			continue
		}
		out = append(out, linuxShadowEntry{
			Name:       f[0],
			Hash:       f[1],
			LastChange: shadowDaysField(f, 2),
			MaxDays:    shadowDaysField(f, 4),
		})
	}
	return out
}

// shadowDaysField 取第 idx 列的天数值；空/非法 = -1（无数据）。
func shadowDaysField(f []string, idx int) int {
	if idx >= len(f) || f[idx] == "" {
		return -1
	}
	v, err := strconv.Atoi(f[idx])
	if err != nil {
		return -1
	}
	return v
}

// linuxLoginDefs 是 /etc/login.defs 的策略键（PASS_MAX_DAYS / PASS_MIN_LEN）。
// Found 标志区分"未配置"（0 值语义 = 前端显示 —）与"配了 0"。
type linuxLoginDefs struct {
	MaxDays    uint32
	MaxDaysSet bool
	MinLen     uint32
	MinLenSet  bool
}

// parseLoginDefs 提取 login.defs 的 PASS_* 策略键。取首次出现（shadow
// utils 对同名键的处理口径未核实，两处同键的极端配置本就罕见——证据列
// 保真比键序猜测更重要）。
func parseLoginDefs(data []byte) linuxLoginDefs {
	var out linuxLoginDefs
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(strings.TrimRight(raw, "\r"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		v, err := strconv.ParseUint(f[1], 10, 32)
		if err != nil {
			continue
		}
		switch f[0] {
		case "PASS_MAX_DAYS":
			if !out.MaxDaysSet {
				out.MaxDays, out.MaxDaysSet = uint32(v), true
			}
		case "PASS_MIN_LEN":
			if !out.MinLenSet {
				out.MinLen, out.MinLenSet = uint32(v), true
			}
		}
	}
	return out
}

// linuxAccountsRaw 是 IO 壳交给投影层的全部原料（字节可能为 nil =
// 文件不存在/不可读，投影层逐段降级）。
type linuxAccountsRaw struct {
	Passwd    []byte // /etc/passwd（nil = 不可读，整页退化为空表 + note）
	Group     []byte // /etc/group（nil = 管理员判定降级为仅 uid==0）
	Shadow    []byte // /etc/shadow（nil = 过期/老化字段走保守默认）
	LoginDefs []byte // /etc/login.defs（nil = 策略卡全 0）
	Now       time.Time
}

// buildLinuxAccountsResult 是 /accounts 的纯投影：从原料字节算出与
// Windows accountsResult 同形状的响应体（map 形态，多一个 Linux 特有
// 的 note 键——逐段降级时说明哪些段缺数据，Windows 版无此键，消费方
// 按 future-field 兼容）。
//
// 单文件缺数据只降级对应字段，绝不整页失败：调查者要的是"能拿到多少
// 拿多少"，与 Windows 版"管理员/策略失败保留用户表"同一取舍。
func buildLinuxAccountsResult(raw linuxAccountsRaw) map[string]any {
	var notes []string

	out := map[string]any{
		"generated_at": raw.Now.UTC().Format(time.RFC3339),
	}

	// ---- 账户表（主数据）：不可读则整表为空 + note（不 500——
	// /etc/passwd 0644 世界可读，读不到通常是极端裁剪环境）----
	users := []linuxAccountsUser{}
	adminNames := map[string]bool{}
	if raw.Passwd != nil {
		entries := parsePasswdLines(raw.Passwd)

		// 管理员判定：uid==0 ∪ gid 属管理员组（主组）∪ 管理员组成员。
		// /etc/group 不可读时降级为仅 uid==0（root），note 说明口径收窄。
		adminGID := map[int]bool{}
		groupMembers := map[string]bool{}
		if raw.Group != nil {
			for _, g := range parseGroupLines(raw.Group) {
				if !linuxAdminGroups[g.Name] {
					continue
				}
				adminGID[g.GID] = true
				for _, m := range g.Members {
					if m = strings.TrimSpace(m); m != "" {
						groupMembers[m] = true
					}
				}
			}
		} else {
			notes = append(notes, "/etc/group 不可读：管理员判定降级为仅 uid==0 账户")
		}

		shadowByName := map[string]linuxShadowEntry{}
		if raw.Shadow != nil {
			for _, s := range parseShadowLines(raw.Shadow) {
				shadowByName[s.Name] = s
			}
		} else {
			notes = append(notes, "/etc/shadow 不可读：口令老化/过期字段为保守默认（不冒充实测）")
		}

		today := int(raw.Now.Unix() / 86400) // shadow 的天计数是 UTC 天（口径一致）

		for _, p := range entries {
			isAdmin := p.UID == 0 || adminGID[p.GID] || groupMembers[p.Name]
			if isAdmin {
				adminNames[p.Name] = true
			}
			// 组员可能不在 passwd（残留组条目）——Windows 版 Administrators()
			// 名单同样不依赖用户表，如实多列；is_admin 标记只在用户表生效。
			for m := range groupMembers {
				adminNames[m] = true
			}
			u := linuxAccountsUser{
				Name:          p.Name,
				SID:           "uid=" + strconv.Itoa(p.UID),
				Disabled:      shellDisablesLogin(p.Shell),
				LastLogonUnix: 0,
				Comment:       p.Gecos,
				IsAdmin:       isAdmin,
			}
			if s, ok := shadowByName[p.Name]; ok {
				// max 为空(-1)、0 或 >=99999 都表达"未启用口令老化"
				//（shadow(5)：0 = 口令永不需要更改；99999 = 惯例永不值）
				u.PasswordNeverExpires = s.MaxDays <= 0 || s.MaxDays >= 99999
				if s.LastChange > 0 && today >= s.LastChange {
					u.PasswordAgeDays = today - s.LastChange
				}
			}
			users = append(users, u)
		}
	} else {
		notes = append(notes, "/etc/passwd 不可读：账户表为空")
	}

	// 管理员名单与用户表共享同一判定集合（Windows 版契约：is_admin 的
	// 用户必须出现在 administrators 名单里）。组员可能不在 passwd
	//（残留组条目）——名单如实多列，is_admin 标记只在用户表生效。
	admins := make([]string, 0, len(adminNames))
	for n := range adminNames {
		admins = append(admins, n)
	}
	sort.Strings(admins)
	if admins == nil {
		admins = []string{}
	}

	// ---- 策略卡：login.defs 的 PASS_* 键；lockout 无 login.defs 对等
	//（pam_faillock 的 deny= 在 /etc/security/faillock.conf，v1 不解析
	// 以免和 PAM 栈的多层覆盖语义打架）——0=未配置，前端显示 — ----
	var policy linuxAccountsPolicy
	if raw.LoginDefs != nil {
		ld := parseLoginDefs(raw.LoginDefs)
		if ld.MaxDaysSet {
			policy.MaxAgeDays = ld.MaxDays
		}
		if ld.MinLenSet {
			policy.MinPasswordLength = ld.MinLen
		}
	} else {
		notes = append(notes, "/etc/login.defs 不可读：密码策略卡为空")
	}
	policy.LockoutThreshold = 0

	out["users"] = users
	out["administrators"] = admins
	out["policy"] = policy
	if len(notes) > 0 {
		out["note"] = strings.Join(notes, "；")
	}
	return out
}

// shellDisablesLogin 判定登录 shell 是否为禁登录值。与 linuxinv users.go
// 同口径（基名精确匹配 nologin/false，覆盖 /usr/sbin、/sbin、/usr/bin 等
// 变体路径），方向取舍一致：宁可少判 disabled，不可错判可登录账户。
// 空 shell 字段按 libc 惯例回退 /bin/sh（可登录），不判 disabled。
func shellDisablesLogin(shell string) bool {
	base := shell
	if i := strings.LastIndexByte(shell, '/'); i >= 0 {
		base = shell[i+1:]
	}
	return base == "nologin" || base == "false"
}
