package service

import "testing"

// TestInvestigateVerdict 锁定判定阈值。2026-11-06 复盘：旧版基线 40 分
// 起步且只有加分没有减分，值班队列 50 条清一色 suspicious——阈值语义
// 变更必须过这道门。
func TestInvestigateVerdict(t *testing.T) {
	cases := map[int]string{
		0:   "benign",
		29:  "benign",
		30:  "inconclusive",
		44:  "inconclusive",
		45:  "suspicious",
		69:  "suspicious",
		70:  "malicious",
		100: "malicious",
	}
	for score, want := range cases {
		if got := investigateVerdict(score); got != want {
			t.Errorf("investigateVerdict(%d) = %q, want %q", score, got, want)
		}
	}
}

// TestInvestigateVerdictScorePath 用分数推演四类真实场景，防止加减分
// 项再向"一律可疑"漂移：
//
//	孤立未签名文件告警 35-10=25 → benign；
//	已签名开发工具告警 35-12-10=13 → benign；
//	主机级观察事件 35+10-10=35 → inconclusive；
//	未签名+驻留 35+20=55 → suspicious。
func TestInvestigateVerdictScorePath(t *testing.T) {
	lone := investigateScoreBase - 10 // 三路加重证据均缺
	if got := investigateVerdict(lone); got != "benign" {
		t.Errorf("孤立未签名事件应 benign，score=%d got %q", lone, got)
	}
	signed := investigateScoreBase - 12 - 10
	if got := investigateVerdict(signed); got != "benign" {
		t.Errorf("签名样本孤立事件应 benign，score=%d got %q", signed, got)
	}
	hostLevel := investigateScoreBase + 10 - 10 // 一类异标题关联，无进程上下文
	if got := investigateVerdict(hostLevel); got != "inconclusive" {
		t.Errorf("主机级观察事件应 inconclusive，score=%d got %q", hostLevel, got)
	}
	persist := investigateScoreBase + 20
	if got := investigateVerdict(persist); got != "suspicious" {
		t.Errorf("未签名+驻留应 suspicious，score=%d got %q", persist, got)
	}
}

// TestVerdictLabel 覆盖现行枚举与队列里的历史字符串。
func TestVerdictLabel(t *testing.T) {
	cases := map[string]string{
		"malicious":    "恶意",
		"suspicious":   "可疑",
		"inconclusive": "证据不足",
		"benign":       "倾向误报",
		"benign-需人工确认": "证据不足", // 旧版队列存量的拼接字符串
		"未知枚举":         "未知枚举",
	}
	for v, want := range cases {
		if got := VerdictLabel(v); got != want {
			t.Errorf("VerdictLabel(%q) = %q, want %q", v, got, want)
		}
	}
}
