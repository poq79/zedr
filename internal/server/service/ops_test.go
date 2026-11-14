package service

import (
	"testing"
	"time"

	"zedr/internal/model"
	"zedr/internal/server/domain"
)

// TestClusterByGap 验证事件聚类的时间间隔切分逻辑。
func TestClusterByGap(t *testing.T) {
	base := time.Date(2026, 1, 1, 10, 0, 0, 0, time.Local)
	mk := func(offset time.Duration, host string) domain.Alert {
		return domain.Alert{Hostname: host, CreatedAt: base.Add(offset)}
	}

	alerts := []domain.Alert{
		mk(0, "pc"), mk(10*time.Minute, "pc"), mk(20*time.Minute, "pc"),
		mk(2*time.Hour, "pc"), mk(2*time.Hour+5*time.Minute, "pc"),
	}
	groups := clusterByGap(alerts, incidentGap)

	if len(groups) != 2 {
		t.Fatalf("应聚成 2 个事件（20 分钟间隔连续，1 小时间隔断开），实际 %d", len(groups))
	}
	if groups[0][0].CreatedAt != base || len(groups[0]) != 3 {
		t.Fatalf("第一簇应为 3 条连续告警，实际 %d", len(groups[0]))
	}
}

// TestBuildIncident 验证事件聚合字段：峰值严重度、MITRE 去重、
// 未处置计数、时间跨度。
func TestBuildIncident(t *testing.T) {
	base := time.Date(2026, 1, 1, 10, 0, 0, 0, time.Local)
	group := []domain.Alert{
		{Hostname: "pc", CreatedAt: base, Severity: domain.SeverityMedium, Score: 44,
			Status: model.StatusOpen, ProcessName: "a.exe", MITRE: []string{"T1059"}, RuleIDs: []string{"HG-001"}},
		{Hostname: "pc", CreatedAt: base.Add(20 * time.Minute), Severity: domain.SeverityCritical, Score: 92,
			Status: model.StatusAcknowledged, ProcessName: "a.exe", MITRE: []string{"T1059", "T1547"}, RuleIDs: []string{"HG-001", "HG-016"}},
	}

	inc := buildIncident("pc", group)

	if inc.PeakSeverity != "critical" {
		t.Fatalf("峰值严重度应为 critical，实际 %q", inc.PeakSeverity)
	}
	if inc.MaxScore != 92 {
		t.Fatalf("峰值分应为 92，实际 %d", inc.MaxScore)
	}
	if inc.AlertCount != 2 || inc.OpenCount != 1 {
		t.Fatalf("计数错误: total=%d open=%d", inc.AlertCount, inc.OpenCount)
	}
	if len(inv(inc.MITRE)) != 2 || len(inc.RuleIDs) != 2 {
		t.Fatalf("MITRE/规则应去重: %v / %v", inc.MITRE, inc.RuleIDs)
	}
	if len(inc.Processes) != 1 {
		t.Fatalf("同名进程应去重: %v", inc.Processes)
	}
	if inc.DurationSec != 20*60 {
		t.Fatalf("时间跨度应为 1200s，实际 %d", inc.DurationSec)
	}
	if inc.ID == "" {
		t.Fatal("事件 ID 不应为空")
	}
}

func inv(s []string) []string { return s }

// TestValidatePasswordStrength 验证密码强度策略。
func TestValidatePasswordStrength(t *testing.T) {
	bad := []string{
		"short1A!",        // 太短
		"alllowercase123", // 缺大写与符号（两类）
		"ALLUPPERCASE123", // 缺小写与符号（两类）
		"abcdefghij",      // 只有一类
	}
	for _, pw := range bad {
		if err := ValidatePasswordStrength(pw); err == nil {
			t.Fatalf("应拒绝弱密码 %q", pw)
		}
	}
	good := []string{"Adm1n!strator2026", "Str0ng-Pass.Phra5e", "Correct-Horse-42!"}
	for _, pw := range good {
		if err := ValidatePasswordStrength(pw); err != nil {
			t.Fatalf("应接受 %q: %v", pw, err)
		}
	}
}
