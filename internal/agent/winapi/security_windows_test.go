//go:build windows
// +build windows

package winapi

import (
	"encoding/json"
	"testing"
	"time"
)

// 真机冒烟：三个采集函数可跑、量级正确、耗时在预算内。
// 断言刻意从宽（字段可空、只查存在性）——不同机器/版本上排除项与
// 防火墙状态差异很大，这里验证的是"能采、不崩、不超时"，不是具体值。
func TestDefenderStatus(t *testing.T) {
	start := time.Now()
	d, err := DefenderStatus()
	if err != nil {
		t.Fatalf("DefenderStatus 失败: %v", err)
	}
	if el := time.Since(start); el > 2*time.Second {
		t.Errorf("DefenderStatus 耗时 %s，超出预算（目标 <100ms）", el)
	} else {
		t.Logf("耗时 %s", el)
	}
	// 字段可空但不崩；RealtimeState 必须在三个合法取值内
	switch d.RealtimeState {
	case "on", "off", "unknown":
	default:
		t.Errorf("RealtimeState 非法取值: %q", d.RealtimeState)
	}
	raw, _ := json.Marshal(d)
	t.Logf("defender=%s", raw)
}

func TestFirewallProfiles(t *testing.T) {
	start := time.Now()
	p, err := FirewallProfiles()
	if err != nil {
		t.Fatalf("FirewallProfiles 失败: %v", err)
	}
	if el := time.Since(start); el > 2*time.Second {
		t.Errorf("FirewallProfiles 耗时 %s，超出预算", el)
	} else {
		t.Logf("耗时 %s", el)
	}
	if len(p) != 3 {
		t.Fatalf("应有 3 个 profile，实际 %d 个", len(p))
	}
	want := []string{"domain", "standard", "public"}
	for i, w := range want {
		if p[i].Name != w {
			t.Errorf("profile[%d] 名字 = %q, 期望 %q", i, p[i].Name, w)
		}
	}
	raw, _ := json.Marshal(p)
	t.Logf("firewall=%s", raw)
}

func TestLocalAdmins(t *testing.T) {
	start := time.Now()
	admins, err := LocalAdmins()
	if err != nil {
		t.Fatalf("LocalAdmins 失败: %v", err)
	}
	if el := time.Since(start); el > 2*time.Second {
		t.Errorf("LocalAdmins 耗时 %s，超出预算", el)
	} else {
		t.Logf("耗时 %s", el)
	}
	if len(admins) < 1 {
		t.Fatal("本地管理员组至少应有 1 个成员")
	}
	for _, a := range admins {
		if a.Name == "" {
			t.Error("存在无名成员条目")
		}
	}
	raw, _ := json.Marshal(admins)
	t.Logf("admins=%s", raw)
}
