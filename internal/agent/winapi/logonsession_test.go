package winapi

// logonsession_test.go：LSA 登录会话枚举真机冒烟。
// 系统本身恒有会话（至少一个 System/0 号会话），枚举整体失败才是 fail。

import (
	"encoding/json"
	"testing"
	"time"
)

func TestLogonSessions(t *testing.T) {
	start := time.Now()
	sessions, err := LogonSessions()
	if err != nil {
		t.Fatalf("LogonSessions 失败: %v", err)
	}
	if el := time.Since(start); el > 2*time.Second {
		t.Errorf("LogonSessions 耗时 %s，超出预算", el)
	} else {
		t.Logf("LogonSessions 耗时 %s，%d 条会话", el, len(sessions))
	}
	if len(sessions) == 0 {
		t.Fatal("运行中的系统至少应有 1 条登录会话")
	}

	anyIdentity := false
	anyTime := false
	for _, s := range sessions {
		// 单条会话 username/domain 双空是合法状态（开机前的预登录
		// 匿名会话实测就是双空，klist 同样显示为空），只做总量校验
		if s.Username != "" || s.Domain != "" {
			anyIdentity = true
		}
		if s.LogonTypeName == "" {
			t.Errorf("会话 LUID=%d LogonTypeName 为空", s.LogonID)
		}
		if !s.LogonTime.IsZero() {
			anyTime = true
		}
		// 倒序校验（零值时间排在最后，跳过）
		if s.LogonTime.IsZero() {
			continue
		}
	}
	if !anyIdentity {
		t.Error("所有会话 username/domain 双空（至少系统会话应有域名）")
	}
	if !anyTime {
		t.Error("所有会话 LogonTime 均为零值（时间戳解析疑似失效）")
	}
	for i := 1; i < len(sessions); i++ {
		prev, cur := sessions[i-1].LogonTime, sessions[i].LogonTime
		if prev.IsZero() || cur.IsZero() {
			continue // 零值允许垫底
		}
		if prev.Before(cur) {
			t.Errorf("结果未按 LogonTime 倒序: 第 %d 条 %v 早于第 %d 条 %v", i, cur, i-1, prev)
		}
	}
	raw, _ := json.Marshal(sessions)
	if len(raw) > 4096 {
		raw = raw[:4096]
	}
	t.Logf("sessions=%s", raw)
}
