// 本测试文件 NEUTRAL：/baseline Linux 判定纯逻辑在 Windows 上跑。
// 夹具：testdata/sshd_config（主配置）、testdata/sshd_config.d-dropin.conf
// （drop-in）、testdata/sudoers、testdata/limits.conf、testdata/login.defs、
// testdata/profile、testdata/selinux-config、testdata/ufw.conf、
// testdata/passwd、testdata/shadow。
package liveapi

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// baselineItemByKey 按断言键取检查项。
func baselineItemByKey(t *testing.T, items []linuxBaselineItem, key string) linuxBaselineItem {
	t.Helper()
	for _, it := range items {
		if it.Key == key {
			return it
		}
	}
	t.Fatalf("缺少检查项 %q", key)
	return linuxBaselineItem{}
}

func TestBuildLinuxBaselineResultFixture(t *testing.T) {
	f := &linuxBaselineFacts{
		SshdPresent:     true,
		SshdConfigs:     []string{string(mustFixture(t, "sshd_config.d-dropin.conf")), string(mustFixture(t, "sshd_config"))},
		SudoersReadable: true,
		SudoersLines:    strings.Split(string(mustFixture(t, "sudoers")), "\n"),
		LoginDefs:       mustFixture(t, "login.defs"),
		LimitsLines:     strings.Split(string(mustFixture(t, "limits.conf")), "\n"),
		AppArmorEnabled: "Y",
		UfwConf:         mustFixture(t, "ufw.conf"),
		HostKeys:        []linuxHostKey{{Name: "ssh_host_rsa_key", Perm: 0o600}},
		Passwd:          mustFixture(t, "passwd"),
		Shadow:          mustFixture(t, "shadow"),
		AptSystem:       true,
		AptAutoUpdates:  true,
	}

	res := buildLinuxBaselineResult(f, time.Unix(2000000000, 0))
	if len(res.Items) != 10 {
		t.Fatalf("期望 10 项实得 %d", len(res.Items))
	}
	// 夹具口径：fail = sudo NOPASSWD ALL / coredump unlimited / uid0 后门 /
	// 空密码；pass = ssh / umask / MAC / firewall / hostkey / auto_updates
	if res.Score.Total != 10 || res.Score.Pass != 6 || res.Score.Warn != 0 || res.Score.Fail != 4 {
		t.Errorf("score 口径不符: %+v", res.Score)
	}
	if _, err := time.Parse(time.RFC3339, res.GeneratedAt); err != nil {
		t.Errorf("generated_at 不是 RFC3339: %q", res.GeneratedAt)
	}

	// ssh：drop-in（prohibit-password + no）生效，Match 块不串味
	ssh := baselineItemByKey(t, res.Items, "ssh_access")
	if ssh.Status != linuxBaselinePass || !strings.Contains(ssh.Current, "prohibit-password") ||
		!strings.Contains(ssh.Current, "PasswordAuthentication=no") {
		t.Errorf("ssh_access 口径不符: %+v", ssh)
	}

	// sudo：ci-runner 的 NOPASSWD ALL → fail（deploy 的限定范围不升级）
	sudo := baselineItemByKey(t, res.Items, "sudo_nopasswd")
	if sudo.Status != linuxBaselineFail || !strings.Contains(sudo.Evidence, "ci-runner") {
		t.Errorf("sudo_nopasswd 口径不符: %+v", sudo)
	}

	// umask：login.defs UMASK 027 → pass
	if um := baselineItemByKey(t, res.Items, "default_umask"); um.Status != linuxBaselinePass ||
		!strings.Contains(um.Current, "027") || !strings.Contains(um.Current, "login.defs") {
		t.Errorf("default_umask 口径不符: %+v", um)
	}

	// coredump：root 的 unlimited → fail（尽管 * 是 0）
	if cd := baselineItemByKey(t, res.Items, "coredump_limits"); cd.Status != linuxBaselineFail ||
		!strings.Contains(cd.Current, "unlimited") {
		t.Errorf("coredump_limits 口径不符: %+v", cd)
	}

	if mac := baselineItemByKey(t, res.Items, "mac_enforced"); mac.Status != linuxBaselinePass {
		t.Errorf("mac_enforced(AppArmor Y) 口径不符: %+v", mac)
	}
	if fw := baselineItemByKey(t, res.Items, "firewall"); fw.Status != linuxBaselinePass ||
		!strings.Contains(fw.Current, "ufw") {
		t.Errorf("firewall 口径不符: %+v", fw)
	}
	if hk := baselineItemByKey(t, res.Items, "ssh_hostkey_perm"); hk.Status != linuxBaselinePass {
		t.Errorf("ssh_hostkey_perm(0600) 口径不符: %+v", hk)
	}
	// uid0：夹具 passwd 有 intruder(uid 0) → fail
	if u0 := baselineItemByKey(t, res.Items, "uid0_accounts"); u0.Status != linuxBaselineFail ||
		!strings.Contains(u0.Evidence, "intruder") {
		t.Errorf("uid0_accounts 口径不符: %+v", u0)
	}
	// 空密码：夹具 shadow 有 emptypass（hash 空）→ fail
	if ep := baselineItemByKey(t, res.Items, "empty_password"); ep.Status != linuxBaselineFail ||
		!strings.Contains(ep.Evidence, "emptypass") {
		t.Errorf("empty_password 口径不符: %+v", ep)
	}
	if up := baselineItemByKey(t, res.Items, "auto_updates"); up.Status != linuxBaselinePass {
		t.Errorf("auto_updates 口径不符: %+v", up)
	}

	// JSON 形状锁：与前端 BaselineItem/LiveBaseline 逐字一致
	b, _ := json.Marshal(res)
	var probe struct {
		GeneratedAt string           `json:"generated_at"`
		Score       map[string]any   `json:"score"`
		Items       []map[string]any `json:"items"`
	}
	if err := json.Unmarshal(b, &probe); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"pass", "warn", "fail", "total"} {
		if _, ok := probe.Score[k]; !ok {
			t.Errorf("score 缺少字段 %q", k)
		}
	}
	if len(probe.Items) != 10 {
		t.Fatal("items 反序列化失败")
	}
	for _, it := range probe.Items {
		for _, k := range []string{"key", "title", "status", "current", "recommended", "evidence"} {
			if _, ok := it[k]; !ok {
				t.Errorf("items[] 缺少字段 %q: %v", k, it)
			}
		}
	}
}

func TestLinuxCheckSSHAccessCases(t *testing.T) {
	mk := func(cfgs ...string) *linuxBaselineFacts {
		return &linuxBaselineFacts{SshdPresent: true, SshdConfigs: cfgs}
	}
	// 全缺失：root→warn(默认 prohibit-password)、pw→fail(默认 yes) → fail
	if it := linuxCheckSSHAccess(mk()); it.Status != linuxBaselineFail ||
		!strings.Contains(it.Evidence, "默认值") {
		t.Errorf("全缺失应 fail 且注明默认值: %+v", it)
	}
	// 未装 sshd → info
	if it := linuxCheckSSHAccess(&linuxBaselineFacts{}); it.Status != linuxBaselineInfo {
		t.Errorf("无 sshd 配置应 info: %+v", it)
	}
	// PermitRootLogin=yes → fail
	if it := linuxCheckSSHAccess(mk("PermitRootLogin yes\nPasswordAuthentication no")); it.Status != linuxBaselineFail ||
		!strings.Contains(it.Evidence, "PermitRootLogin=yes") {
		t.Errorf("root 密码登录应 fail: %+v", it)
	}
	// 双 pass → pass（键大小写不敏感）
	if it := linuxCheckSSHAccess(mk("permitrootlogin prohibit-password\npasswordauthentication  no")); it.Status != linuxBaselinePass {
		t.Errorf("加固配置应 pass（键小写不敏感）: %+v", it)
	}
}

func TestLinuxCheckSudoNoPasswdCases(t *testing.T) {
	// root 免密 ALL 不升级 fail（root 已是最高权限）
	lines := []string{"root ALL=(ALL:ALL) NOPASSWD: ALL", "%sudo ALL=(ALL:ALL) ALL"}
	if it := linuxCheckSudoNoPasswd(&linuxBaselineFacts{SudoersReadable: true, SudoersLines: lines}); it.Status != linuxBaselineWarn {
		t.Errorf("仅 root 免密应为 warn: %+v", it)
	}
	// 不可读 → info
	if it := linuxCheckSudoNoPasswd(&linuxBaselineFacts{}); it.Status != linuxBaselineInfo {
		t.Errorf("sudoers 不可读应 info: %+v", it)
	}
	// 无条目 → pass
	if it := linuxCheckSudoNoPasswd(&linuxBaselineFacts{SudoersReadable: true, SudoersLines: []string{"Defaults env_reset"}}); it.Status != linuxBaselinePass {
		t.Errorf("无 NOPASSWD 应 pass: %+v", it)
	}
}

func TestLinuxCheckDefaultUmaskCases(t *testing.T) {
	// profile 兜底：077 → pass
	f := &linuxBaselineFacts{Profile: mustFixture(t, "profile")}
	if it := linuxCheckDefaultUmask(f); it.Status != linuxBaselinePass ||
		!strings.Contains(it.Current, "profile") {
		t.Errorf("profile umask 077 应 pass: %+v", it)
	}
	// 000 → fail（其他/组写未禁止）
	if it := linuxCheckDefaultUmask(&linuxBaselineFacts{LoginDefs: []byte("UMASK 000\n")}); it.Status != linuxBaselineFail {
		t.Errorf("umask 000 应 fail: %+v", it)
	}
	// 022 → warn（全局可读）
	if it := linuxCheckDefaultUmask(&linuxBaselineFacts{LoginDefs: []byte("UMASK 022\n")}); it.Status != linuxBaselineWarn {
		t.Errorf("umask 022 应 warn: %+v", it)
	}
	// 两处都缺 → warn 未显式配置
	if it := linuxCheckDefaultUmask(&linuxBaselineFacts{}); it.Status != linuxBaselineWarn {
		t.Errorf("未配置应 warn: %+v", it)
	}
}

func TestLinuxCheckCoredumpCases(t *testing.T) {
	pass := &linuxBaselineFacts{LimitsLines: []string{"*\tsoft\tcore\t0", "*\thard\tcore\t0"}}
	if it := linuxCheckCoredump(pass); it.Status != linuxBaselinePass {
		t.Errorf("core=0 应 pass: %+v", it)
	}
	// 未配置 → warn
	if it := linuxCheckCoredump(&linuxBaselineFacts{}); it.Status != linuxBaselineWarn {
		t.Errorf("未配置应 warn: %+v", it)
	}
}

func TestLinuxCheckMACCases(t *testing.T) {
	// SELinux enforcing → pass；permissive → warn；disabled → fail
	enf := &linuxBaselineFacts{SELinuxConfig: mustFixture(t, "selinux-config")}
	if it := linuxCheckMAC(enf); it.Status != linuxBaselinePass {
		t.Errorf("SELinux enforcing 应 pass: %+v", it)
	}
	perm := &linuxBaselineFacts{SELinuxConfig: []byte("SELINUX=permissive\n")}
	if it := linuxCheckMAC(perm); it.Status != linuxBaselineWarn {
		t.Errorf("permissive 应 warn: %+v", it)
	}
	dis := &linuxBaselineFacts{SELinuxConfig: []byte("SELINUX=disabled\n")}
	if it := linuxCheckMAC(dis); it.Status != linuxBaselineFail {
		t.Errorf("disabled 应 fail: %+v", it)
	}
	// 两者皆缺 → warn
	if it := linuxCheckMAC(&linuxBaselineFacts{}); it.Status != linuxBaselineWarn {
		t.Errorf("无 MAC 应 warn: %+v", it)
	}
}

func TestLinuxCheckFirewallCases(t *testing.T) {
	// ufw 安装但未启用且无其他机制 → fail
	off := &linuxBaselineFacts{UfwConf: []byte("ENABLED=no\n")}
	if it := linuxCheckFirewall(off); it.Status != linuxBaselineFail {
		t.Errorf("ufw off 应 fail: %+v", it)
	}
	// iptables 持久化文件 → pass
	ipt := &linuxBaselineFacts{IptablesRulesFile: "/etc/iptables/rules.v4"}
	if it := linuxCheckFirewall(ipt); it.Status != linuxBaselinePass {
		t.Errorf("iptables 规则文件应 pass: %+v", it)
	}
	// 什么都没有 → warn
	if it := linuxCheckFirewall(&linuxBaselineFacts{}); it.Status != linuxBaselineWarn {
		t.Errorf("无防火墙痕迹应 warn: %+v", it)
	}
}

func TestLinuxCheckHostKeyPermCases(t *testing.T) {
	// 无私钥 → info
	if it := linuxCheckHostKeyPerm(&linuxBaselineFacts{}); it.Status != linuxBaselineInfo {
		t.Errorf("无私钥应 info: %+v", it)
	}
	// 0644 → fail（其他可读）；0640（Debian _ssh 组形态）→ pass
	f := &linuxBaselineFacts{HostKeys: []linuxHostKey{
		{Name: "ssh_host_rsa_key", Perm: 0o600},
		{Name: "ssh_host_ed25519_key", Perm: 0o640},
	}}
	if it := linuxCheckHostKeyPerm(f); it.Status != linuxBaselinePass {
		t.Errorf("0600/0640 应 pass: %+v", it)
	}
	f.HostKeys = append(f.HostKeys, linuxHostKey{Name: "ssh_host_bad_key", Perm: 0o644})
	if it := linuxCheckHostKeyPerm(f); it.Status != linuxBaselineFail ||
		!strings.Contains(it.Evidence, "ssh_host_bad_key") {
		t.Errorf("0644 应 fail: %+v", it)
	}
}

func TestLinuxCheckUID0AndEmptyPassword(t *testing.T) {
	// passwd 不可读 → info
	if it := linuxCheckUID0(&linuxBaselineFacts{}); it.Status != linuxBaselineInfo {
		t.Errorf("passwd 缺失应 info: %+v", it)
	}
	// 仅 root → pass
	onlyRoot := &linuxBaselineFacts{Passwd: []byte("root:x:0:0:root:/root:/bin/bash\n")}
	if it := linuxCheckUID0(onlyRoot); it.Status != linuxBaselinePass {
		t.Errorf("仅 root 应 pass: %+v", it)
	}
	// passwd 可读但无 uid0 → info（异常状态）
	noRoot := &linuxBaselineFacts{Passwd: []byte("kali:x:1000:1000::/home/kali:/bin/bash\n")}
	if it := linuxCheckUID0(noRoot); it.Status != linuxBaselineInfo {
		t.Errorf("无 uid0 应 info: %+v", it)
	}

	// shadow 不可读 → info
	if it := linuxCheckEmptyPassword(&linuxBaselineFacts{}); it.Status != linuxBaselineInfo {
		t.Errorf("shadow 缺失应 info: %+v", it)
	}
	// 无空密码 → pass（! / * 占位不算空）
	shadowNoEmpty := []byte("root:!:19901:0:99999:7:::\nkali:$6$x$y:19500:0:99999:7:::\n")
	if it := linuxCheckEmptyPassword(&linuxBaselineFacts{Shadow: shadowNoEmpty}); it.Status != linuxBaselinePass {
		t.Errorf("无空密码应 pass: %+v", it)
	}
}

func TestLinuxCheckAutoUpdatesCases(t *testing.T) {
	if it := linuxCheckAutoUpdates(&linuxBaselineFacts{AptSystem: true, AptAutoUpdates: true}); it.Status != linuxBaselinePass {
		t.Errorf("apt 自动更新应 pass: %+v", it)
	}
	if it := linuxCheckAutoUpdates(&linuxBaselineFacts{AptSystem: true}); it.Status != linuxBaselineWarn {
		t.Errorf("apt 无自动更新应 warn: %+v", it)
	}
	if it := linuxCheckAutoUpdates(&linuxBaselineFacts{DnfSystem: true, DnfAutoTimer: true}); it.Status != linuxBaselinePass {
		t.Errorf("dnf 自动更新应 pass: %+v", it)
	}
	if it := linuxCheckAutoUpdates(&linuxBaselineFacts{}); it.Status != linuxBaselineInfo {
		t.Errorf("非 apt/dnf 应 info: %+v", it)
	}
}

func TestLinuxScoreBaselineCountsInfo(t *testing.T) {
	items := []linuxBaselineItem{
		{Status: linuxBaselinePass},
		{Status: linuxBaselineWarn},
		{Status: linuxBaselineFail},
		{Status: linuxBaselineInfo},
	}
	score := linuxScoreBaseline(items)
	if score.Pass != 1 || score.Warn != 1 || score.Fail != 1 || score.Total != 4 {
		t.Errorf("score 口径不符: %+v", score)
	}
	if got := linuxWorstStatus(linuxBaselineWarn, linuxBaselineFail); got != linuxBaselineFail {
		t.Errorf("worst 合并口径不符: %q", got)
	}
	if got := linuxWorstStatus(linuxBaselinePass, linuxBaselineWarn); got != linuxBaselineWarn {
		t.Errorf("worst 合并口径不符: %q", got)
	}
}

// 保底：所有检查项的 evidence/current 非空（诚实呈现，不给空白字段）。
func TestLinuxBaselineItemsHaveEvidence(t *testing.T) {
	f := &linuxBaselineFacts{}
	res := buildLinuxBaselineResult(f, time.Unix(2000000000, 0))
	for _, it := range res.Items {
		if it.Status == "" || it.Evidence == "" || it.Current == "" || it.Title == "" || it.Recommended == "" {
			t.Errorf("%s 字段不完整: %+v", it.Key, it)
		}
	}
	if res.Score.Total != len(res.Items) || res.Score.Pass+res.Score.Warn+res.Score.Fail > res.Score.Total {
		t.Errorf("score 与 items 不一致: %+v", res.Score)
	}
}
