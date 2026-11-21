package service

import (
	"strings"
	"testing"
)

// 简报文本是 IM 推送的最终形态：值班在手机上看的就是这段字。
// 锁三件事——关键数字都出现、空窗口有诚实话术、无模型依赖（确定性渲染）。
func TestDailyBriefingText(t *testing.T) {
	b := &DailyBriefing{
		WindowHours:  24,
		AlertsNew:    42,
		CriticalNew:  3,
		EventsOpen:   2,
		ChainHits:    1,
		OpsPending:   5,
		HostsOffline: 1,
		TopRules:     []BriefRule{{RuleID: "HG-001", Count: 12}, {RuleID: "CHAIN-DROP-EXEC-C2", Count: 1}},
		RecentCrit: []BriefAlert{
			{ID: "a1", Title: "测试标题", Hostname: "host-a", Score: 95},
		},
	}
	text := b.Text()
	for _, want := range []string{
		"近 24h", "42", "critical 3", "值班队列待审 5", "失联主机 1",
		"HG-001×12", "CHAIN-DROP-EXEC-C2×1", "[95] 测试标题 @ host-a",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("简报文本缺 %q\n%s", want, text)
		}
	}
	if strings.Contains(text, "无新增告警") {
		t.Fatal("非空窗口不应出现空窗口话术")
	}
}

func TestDailyBriefingTextEmpty(t *testing.T) {
	b := &DailyBriefing{WindowHours: 24}
	text := b.Text()
	if !strings.Contains(text, "无新增告警") {
		t.Fatalf("空窗口应出现诚实话术\n%s", text)
	}
}
