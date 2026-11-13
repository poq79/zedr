//go:build windows
// +build windows

package liveapi

// accounts_test.go：/accounts 的 JSON 结构与 is_admin 一致性。
// 真机 NetAPI 枚举；环境不允许枚举时 skip（与 winapi 侧测试口径一致）。

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestHandleAccountsShape(t *testing.T) {
	code, body := doGet(t, HandleAccounts(), "/accounts")
	if code == http.StatusForbidden || code == http.StatusInternalServerError {
		t.Skipf("当前环境无法枚举账户（status=%d body=%v）", code, body)
	}
	if code != http.StatusOK {
		t.Fatalf("期望 200 实得 %d body=%v", code, body)
	}
	d := dataOf(t, body)

	gen, _ := d["generated_at"].(string)
	if _, err := time.Parse(time.RFC3339, gen); err != nil {
		t.Errorf("generated_at 不是 RFC3339: %q (%v)", gen, err)
	}

	rawUsers, ok := d["users"].([]any)
	if !ok {
		t.Fatalf("users 不是数组: %T", d["users"])
	}
	if len(rawUsers) == 0 {
		t.Fatal("枚举成功但 users 为空")
	}

	rawAdmins, ok := d["administrators"].([]any)
	if !ok {
		t.Fatalf("administrators 不是数组: %T", d["administrators"])
	}
	adminSet := map[string]bool{}
	for _, a := range rawAdmins {
		name, _ := a.(string)
		if strings.TrimSpace(name) == "" {
			t.Error("administrators 含空名字")
			continue
		}
		adminSet[accountNameKey(name)] = true
	}

	userNames := map[string]bool{}
	adminFlagged := 0
	for i, raw := range rawUsers {
		u, ok := raw.(map[string]any)
		if !ok {
			t.Fatalf("users[%d] 不是对象", i)
		}
		name, _ := u["name"].(string)
		if name == "" {
			t.Errorf("users[%d].name 为空", i)
		}
		userNames[accountNameKey(name)] = true

		if _, ok := u["sid"].(string); !ok {
			t.Errorf("%s.sid 不是字符串", name)
		}
		if _, ok := u["comment"].(string); !ok {
			t.Errorf("%s.comment 不是字符串", name)
		}
		for _, f := range []string{"disabled", "password_never_expires", "is_admin"} {
			if _, ok := u[f].(bool); !ok {
				t.Errorf("%s.%s 不是 bool: %T", name, f, u[f])
			}
		}
		if age, ok := u["password_age_days"].(float64); !ok || age < 0 {
			t.Errorf("%s.password_age_days 非法: %v", name, u["password_age_days"])
		}
		if last, ok := u["last_logon_unix"].(float64); !ok || last < 0 {
			t.Errorf("%s.last_logon_unix 非法: %v", name, u["last_logon_unix"])
		}

		isAdmin, _ := u["is_admin"].(bool)
		if isAdmin {
			adminFlagged++
			if !adminSet[accountNameKey(name)] {
				t.Errorf("%s 被标记 is_admin，但不在 administrators 名单中", name)
			}
		}
	}

	// 反向校验：名单里能在用户表找到的账户必须被标记。
	for a := range adminSet {
		if userNames[a] {
			found := false
			for _, raw := range rawUsers {
				u := raw.(map[string]any)
				n, _ := u["name"].(string)
				if accountNameKey(n) == a {
					if v, _ := u["is_admin"].(bool); v {
						found = true
					}
				}
			}
			if !found {
				t.Errorf("管理员 %q 出现在用户表但 is_admin=false", a)
			}
		}
	}
	t.Logf("users=%d administrators=%d is_admin=%d", len(rawUsers), len(rawAdmins), adminFlagged)

	policy, ok := d["policy"].(map[string]any)
	if !ok {
		t.Fatalf("policy 不是对象: %T", d["policy"])
	}
	for _, f := range []string{"min_password_length", "max_age_days", "lockout_threshold"} {
		if _, ok := policy[f].(float64); !ok {
			t.Errorf("policy.%s 不是数字: %T", f, policy[f])
		}
	}
}

func TestAccountNameKey(t *testing.T) {
	cases := map[string]string{
		"Administrator":         "administrator",
		`MACHINE\Administrator`: "administrator",
		`DOMAIN\Alice`:          "alice",
		"  Bob  ":               "bob",
		`MACHINE\`:              "",
	}
	for in, want := range cases {
		if got := accountNameKey(in); got != want {
			t.Errorf("accountNameKey(%q)=%q，期望 %q", in, got, want)
		}
	}
}
