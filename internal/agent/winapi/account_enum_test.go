//go:build windows
// +build windows

package winapi

// account_enum_test.go：本地账户/管理员组/密码策略真机冒烟。
// NetAPI 在受限环境（非管理员、精简容器）可能直接拒绝，按契约只 skip
// 不 fail；能枚举时再断言量级与关键字段。

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestLocalUsers(t *testing.T) {
	start := time.Now()
	users, err := LocalUsers()
	if err != nil {
		t.Skipf("NetUserEnum 不可用（环境受限）: %v", err)
	}
	if el := time.Since(start); el > 2*time.Second {
		t.Errorf("LocalUsers 耗时 %s，超出预算", el)
	} else {
		t.Logf("LocalUsers 耗时 %s，%d 个账户", el, len(users))
	}
	if len(users) == 0 {
		t.Fatal("枚举成功但账户表为空")
	}

	foundAdmin := false
	for _, u := range users {
		if u.Name == "" {
			t.Error("存在空名称账户")
		}
		if u.PasswordAgeDays < 0 {
			t.Errorf("%s 的 PasswordAgeDays 为负: %d", u.Name, u.PasswordAgeDays)
		}
		if strings.EqualFold(u.Name, "Administrator") {
			foundAdmin = true
			if u.SID == "" {
				t.Errorf("Administrator 的 SID 反查失败")
			} else if !strings.HasPrefix(u.SID, "S-1-5-21-") {
				t.Errorf("Administrator 的 SID 形态异常: %s", u.SID)
			}
		}
	}
	if !foundAdmin {
		t.Error("本地账户中未找到 Administrator（重命名系统可忽略此条）")
	}
	raw, _ := json.Marshal(users)
	t.Logf("users=%s", raw)
}

func TestAdministrators(t *testing.T) {
	names, err := Administrators()
	if err != nil {
		t.Skipf("NetLocalGroupGetMembers 不可用（环境受限）: %v", err)
	}
	if len(names) == 0 {
		t.Fatal("本地 Administrators 组至少应有 1 个直接成员")
	}
	for _, n := range names {
		if strings.TrimSpace(n) == "" {
			t.Error("管理员名单含空名字")
		}
	}
	t.Logf("administrators=%v", names)
}

func TestLocalPolicyInfo(t *testing.T) {
	p, err := LocalPolicyInfo()
	if err != nil {
		t.Skipf("NetUserModalsGet 不可用（环境受限）: %v", err)
	}
	// 合理区间刻意放宽：0 表示"不限制/不可得"，企业策略常见 8~14；
	// 这里只拦明显异常的解析错误（例如结构体错位读出的天文数字）。
	if p.MinPasswordLength > 128 {
		t.Errorf("MinPasswordLength=%d 不合理", p.MinPasswordLength)
	}
	if p.MaxPasswordAgeDays > 36500 {
		t.Errorf("MaxPasswordAgeDays=%d 不合理（疑似秒/天换算错误）", p.MaxPasswordAgeDays)
	}
	if p.LockoutThreshold > 10000 {
		t.Errorf("LockoutThreshold=%d 不合理", p.LockoutThreshold)
	}
	t.Logf("policy=%+v", p)
}

func TestPasswordAgeDays(t *testing.T) {
	cases := []struct {
		seconds uint32
		want    uint32
	}{
		{0, 0},
		{86400, 1},
		{86400 * 90, 90},
		{86400*90 + 86399, 90}, // 向下取整
		{netPasswordNeverAges, 0},
	}
	for _, c := range cases {
		if got := passwordAgeDays(c.seconds); got != c.want {
			t.Errorf("passwordAgeDays(%d)=%d，期望 %d", c.seconds, got, c.want)
		}
	}
}
