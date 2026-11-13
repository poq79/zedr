package linuxinv

// users.go — users 节：可登录账户 + 提权组成员。
//
// 语义对齐 Windows accounts 节（{"items":[{name,...}]}，本地管理员组
// 成员清单）：Windows 的攻击语义是"管理员组变化 = 权限提升"，Linux
// 的等价物是"可登录 shell 账户 + sudo/wheel 组成员变化"——前者是
// 攻击者能直接登入的面，后者是能提权到 root 的面。payload 用 items
// 包装与 accounts 节同构，服务端 keyFn（name）可复用。

import (
	"os"
	"sort"
	"strconv"
	"strings"
)

// invUser 是 users 节单条条目。uid/gid/shell 是 Linux 特有字段
// （Windows accounts 没有，服务端按 future-field 兼容）；sudo 标记
// 对齐 Windows 的"管理员"语义。
type invUser struct {
	Name  string `json:"name"`
	UID   int    `json:"uid"`
	GID   int    `json:"gid,omitempty"`
	Home  string `json:"home,omitempty"`
	Shell string `json:"shell,omitempty"`
	Sudo  bool   `json:"sudo"`
}

// nologinShells 是"不可登录"的 shell 集合。覆盖两发行版惯例路径
// （/usr/sbin/nologin Debian 系、/sbin/nologin RHEL 系）+ /bin/false
// （systemd 套件用户常用）。按基名而不是全路径匹配：/usr/bin/false
// 这类变体也能兜住。判定方向的取舍：宁可少列（漏掉一个禁登录账户
// 是无害噪声），不可错判（把可登录账户排除会漏掉真实攻击面）——
// 基名匹配只命中 true/false/nologin 三个明确的禁登录值，不会误伤。
var nologinShells = map[string]bool{
	"nologin": true,
	"false":   true,
}

// usersSection 组装 users 节。
func usersSection() (any, error) {
	data, err := os.ReadFile("/etc/passwd")
	if err != nil {
		return nil, err
	}
	sudoNames := sudoGroupMembers()
	groupNames := loginGroupMembers()
	out := parsePasswd(data, sudoNames, groupNames)

	// 按 name 排序保证 hash 稳定（其余节同一条纪律）。
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return map[string]any{"items": out}, nil
}

// parsePasswd 把 /etc/passwd 文本解析为可登录账户列表（纯函数，单测
// 在 Windows 上跑）。sudoNames/groupNames 是调用方给出的提权组归属
// （离线无法从 passwd 自身判定）。
func parsePasswd(data []byte, sudoNames, groupNames map[string]bool) []invUser {
	out := make([]invUser, 0, 16)
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
		shellBase := shellBaseName(f[6])
		if nologinShells[shellBase] || f[6] == "" {
			continue // 系统账户/禁登录账户不是攻击面，不列
		}
		uid, _ := strconv.Atoi(f[2])
		gid, _ := strconv.Atoi(f[3])
		out = append(out, invUser{
			Name:  f[0],
			UID:   uid,
			GID:   gid,
			Home:  f[5],
			Shell: f[6],
			Sudo:  sudoNames[f[0]] || groupNames[f[0]],
		})
	}
	return out
}

// sudoGroupMembers 从 /etc/group 提取 sudo/wheel 组（提权语义的两个
// 惯例名）成员。以 "%wheel ALL=(ALL) ALL" 这类 sudoers 行为准的
// 完整判定要解析 sudoers——v1 用组归属近似，注释如实标注口径。
func sudoGroupMembers() map[string]bool {
	return groupMembers("sudo", "wheel")
}

// loginGroupMembers 是次级提权面（admin 组，Debian 部分变体使用）。
func loginGroupMembers() map[string]bool {
	return groupMembers("admin")
}

// groupMembers 读 /etc/group 里指定组的成员列表（逗号分隔）。
// 组外用户经 sudoers 的 +group/ldap 语义无法离线判定——诚实边界，
// 靠 persist 的 authorized_keys / sudoers 检测面补。
func groupMembers(groups ...string) map[string]bool {
	data, err := os.ReadFile("/etc/group")
	if err != nil {
		return map[string]bool{}
	}
	return parseGroup(data, groups)
}

// parseGroup 把 /etc/group 文本解析为指定组的成员集合（纯函数，单测
// 在 Windows 上跑）。
func parseGroup(data []byte, groups []string) map[string]bool {
	want := make(map[string]bool, len(groups))
	for _, g := range groups {
		want[g] = true
	}
	out := map[string]bool{}
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(strings.TrimRight(raw, "\r"))
		if line == "" {
			continue
		}
		// group 行：name:passwd:gid:members
		f := strings.Split(line, ":")
		if len(f) < 4 || !want[f[0]] {
			continue
		}
		for _, m := range strings.Split(f[3], ",") {
			if m = strings.TrimSpace(m); m != "" {
				out[m] = true
			}
		}
	}
	return out
}

// shellBaseName 取 shell 路径基名；空 shell 按 sh 兜底口径（极少见）。
func shellBaseName(shell string) string {
	if shell == "" {
		return ""
	}
	if i := strings.LastIndexByte(shell, '/'); i >= 0 {
		return shell[i+1:]
	}
	return shell
}
