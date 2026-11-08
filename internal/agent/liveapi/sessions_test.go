package liveapi

// sessions_test.go：/sessions 真机冒烟。
// LSA 枚举对普通用户可用（见 winapi/logonsession.go），任何运行中的机器
// 至少有 System/服务类会话；字段断言以契约键存在性为主。

import (
	"net/http"
	"testing"
	"time"
)

func TestSessionsEndpoint(t *testing.T) {
	h := newInvestigationMux(Deps{StartTime: time.Now()})
	code, body := doGet(t, h, "/sessions")
	if code != http.StatusOK {
		t.Fatalf("期望 200 实得 %d body=%v", code, body)
	}
	d := dataOf(t, body)
	items, ok := d["items"].([]any)
	if !ok {
		t.Fatalf("items 缺失: %v", body)
	}
	if total, _ := d["total"].(float64); int(total) != len(items) {
		t.Errorf("total 与 items 不符: %d vs %d", int(total), len(items))
	}
	if len(items) < 1 {
		t.Fatal("任何运行中的机器至少应有 1 个登录会话（System 会话）")
	}
	first, _ := items[0].(map[string]any)
	for _, key := range []string{"logon_id", "username", "domain", "logon_type",
		"logon_type_name", "session", "logon_time", "auth_package"} {
		if _, ok := first[key]; !ok {
			t.Errorf("items[0] 缺字段 %q: %v", key, first)
		}
	}
	t.Logf("sessions=%d 首条=%v", len(items), first)
}
