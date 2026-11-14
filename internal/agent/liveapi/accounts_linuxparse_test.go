// 本测试文件 NEUTRAL（无构建标签）：/accounts Linux 解析纯逻辑在 Windows
// 上跑（验证口径）。夹具在 testdata/passwd、testdata/group、testdata/shadow、
// testdata/login.defs。
package liveapi

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

// mustFixture 读 testdata 夹具（测试运行目录 = 包目录）。
func mustFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatalf("读夹具 %s 失败: %v", name, err)
	}
	return data
}

func TestBuildLinuxAccountsResult(t *testing.T) {
	// 固定时刻：today = 2000000000/86400 = 23148 天（shadow 天数口径）
	now := time.Unix(2000000000, 0)
	out := buildLinuxAccountsResult(linuxAccountsRaw{
		Passwd:    mustFixture(t, "passwd"),
		Group:     mustFixture(t, "group"),
		Shadow:    mustFixture(t, "shadow"),
		LoginDefs: mustFixture(t, "login.defs"),
		Now:       now,
	})

	if _, ok := out["note"]; ok {
		t.Errorf("夹具齐全时不应有 note: %v", out["note"])
	}

	rawUsers, ok := out["users"].([]linuxAccountsUser)
	if !ok {
		t.Fatalf("users 类型不符: %T", out["users"])
	}
	if len(rawUsers) != 11 {
		t.Fatalf("期望 11 个用户实得 %d", len(rawUsers))
	}
	byName := map[string]linuxAccountsUser{}
	for _, u := range rawUsers {
		byName[u.Name] = u
	}

	// root：uid0 → admin；shadow 老 20 年 → never=true；age=23148-19901
	root := byName["root"]
	if !root.IsAdmin || root.Disabled || root.SID != "uid=0" ||
		!root.PasswordNeverExpires || root.PasswordAgeDays != 23148-19901 ||
		root.LastLogonUnix != 0 || root.Comment != "root" {
		t.Errorf("root 字段口径不符: %+v", root)
	}

	// daemon：nologin → disabled；无管理员身份
	if d := byName["daemon"]; !d.Disabled || d.IsAdmin || d.SID != "uid=1" {
		t.Errorf("daemon 字段口径不符: %+v", d)
	}

	// kali：可登录、非管理员、GECOS 原文、shadow 老化字段
	kali := byName["kali"]
	if kali.Disabled || kali.IsAdmin ||
		kali.Comment != "Kali Linux, room 42, 555-0100," ||
		!kali.PasswordNeverExpires || kali.PasswordAgeDays != 23148-19500 {
		t.Errorf("kali 字段口径不符: %+v", kali)
	}

	// svc-deploy：/bin/false → disabled
	if s := byName["svc-deploy"]; !s.Disabled {
		t.Errorf("svc-deploy 应判 disabled: %+v", s)
	}

	// intruder：uid 0 但非 root —— is_admin 必须为 true（等价 root 后门）
	if i := byName["intruder"]; !i.IsAdmin {
		t.Errorf("uid0 非 root 账户应判 is_admin: %+v", i)
	}

	// wheelmember：wheel 组成员 → admin；shadow 有条目
	if w := byName["wheelmember"]; !w.IsAdmin {
		t.Errorf("wheel 组成员应判 is_admin: %+v", w)
	}

	// administrators 与 is_admin 同集合 + 组员可不在用户表（legacyadmin）
	admins, ok := out["administrators"].([]string)
	if !ok {
		t.Fatalf("administrators 类型不符: %T", out["administrators"])
	}
	want := "intruder,legacyadmin,root,wheelmember"
	if got := strings.Join(admins, ","); got != want {
		t.Errorf("administrators 期望 %q 实得 %q", want, got)
	}

	policy, ok := out["policy"].(linuxAccountsPolicy)
	if !ok {
		t.Fatalf("policy 类型不符: %T", out["policy"])
	}
	if policy.MinPasswordLength != 12 || policy.MaxAgeDays != 90 || policy.LockoutThreshold != 0 {
		t.Errorf("policy 口径不符: %+v", policy)
	}

	// JSON 形状锁：字段名与前端 AccountUser 类型逐字一致（Windows
	// accounts.go 同名契约）。
	b, _ := json.Marshal(root)
	var probe map[string]any
	if err := json.Unmarshal(b, &probe); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"name", "sid", "disabled", "password_never_expires",
		"password_age_days", "last_logon_unix", "comment", "is_admin"} {
		if _, ok := probe[k]; !ok {
			t.Errorf("users[] 缺少字段 %q: %s", k, b)
		}
	}
	bp, _ := json.Marshal(policy)
	var pprobe map[string]any
	_ = json.Unmarshal(bp, &pprobe)
	for _, k := range []string{"min_password_length", "max_age_days", "lockout_threshold"} {
		if _, ok := pprobe[k]; !ok {
			t.Errorf("policy 缺少字段 %q: %s", k, bp)
		}
	}
}

func TestBuildLinuxAccountsDegrade(t *testing.T) {
	now := time.Unix(2000000000, 0)

	// /etc/passwd 不可读：users 空表 + note，不报错不 500
	out := buildLinuxAccountsResult(linuxAccountsRaw{Now: now})
	if u, ok := out["users"].([]linuxAccountsUser); !ok || len(u) != 0 {
		t.Errorf("passwd 缺失应给空表: %T", out["users"])
	}
	if note, ok := out["note"].(string); !ok || !strings.Contains(note, "passwd") {
		t.Errorf("passwd 缺失应有 note: %v", out["note"])
	}

	// shadow 不可读：用户表照常，过期字段走保守默认（false），note 说明
	out = buildLinuxAccountsResult(linuxAccountsRaw{
		Passwd: mustFixture(t, "passwd"),
		Now:    now,
	})
	users := out["users"].([]linuxAccountsUser)
	for _, u := range users {
		if u.PasswordNeverExpires || u.PasswordAgeDays != 0 {
			t.Errorf("shadow 缺失时 %s 过期字段应为保守默认: %+v", u.Name, u)
		}
	}
	if note, ok := out["note"].(string); !ok || !strings.Contains(note, "shadow") {
		t.Errorf("shadow 缺失应有 note: %v", out["note"])
	}

	// group 不可读：管理员判定降级为仅 uid==0
	out = buildLinuxAccountsResult(linuxAccountsRaw{
		Passwd: mustFixture(t, "passwd"),
		Shadow: mustFixture(t, "shadow"),
		Now:    now,
	})
	admins := out["administrators"].([]string)
	if strings.Join(admins, ",") != "intruder,root" {
		t.Errorf("group 缺失时管理员应仅 uid0: %v", admins)
	}
}
