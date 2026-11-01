package eval

import (
	"strings"
	"testing"
	"time"

	"zedr/internal/ai"
)

func sample(id, suite, expected string) Sample {
	return Sample{
		ID: id, Suite: suite, Title: "t-" + id, Expected: expected,
		ProcessName: "x.exe", ImagePath: `C:\Windows\x.exe`, Score: 50, Severity: "high",
	}
}

func result(id, suite, expected, actual string) Result {
	return Result{
		ID: id, Suite: suite, Expected: expected, Actual: actual,
		Reasons: 2, Grounded: true, ApprovalOK: true, Engine: "heuristic",
	}
}

func TestValidateSamples(t *testing.T) {
	ok := []Sample{sample("a", "triage", "malicious"), sample("b", "injection", "suspicious"), sample("c", "triage", "inconclusive")}
	if err := ValidateSamples(ok); err != nil {
		t.Fatalf("合法夹具被拒: %v", err)
	}
	tests := []struct {
		name string
		in   []Sample
		want string
	}{
		{"重复 id", []Sample{sample("a", "triage", "benign"), sample("a", "triage", "benign")}, "重复"},
		{"非法 expected", []Sample{sample("a", "triage", "unknown")}, "expected 非法"},
		{"非法 suite", []Sample{{ID: "a", Suite: "x", Title: "t", ProcessName: "p", Expected: "benign"}}, "suite 非法"},
		{"非法证据层", []Sample{{ID: "a", Suite: "triage", Title: "t", ProcessName: "p", Expected: "benign",
			Evidence: []Evidence{{Layer: "magic", Name: "n", Score: 1}}}}, "layer 非法"},
	}
	for _, tt := range tests {
		err := ValidateSamples(tt.in)
		if err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Fatalf("%s: 期望含 %q 的错误，得到 %v", tt.name, tt.want, err)
		}
	}
}

func TestInputUniqueAlertID(t *testing.T) {
	s := sample("a", "triage", "malicious")
	s.Evidence = []Evidence{{Layer: "rule", Name: "r", Score: 80}, {Layer: "behavior", Name: "b", Score: 30}}
	in1, in2 := s.Input("run1"), s.Input("run2")
	if in1.AlertID == in2.AlertID {
		t.Fatal("不同 runID 的 AlertID 必须不同（否则缓存会污染评测）")
	}
	if len(in1.Evidence) != 2 || in1.Evidence[0].ID != "E1" || in1.Evidence[1].ID != "E2" {
		t.Fatalf("证据编号应为 E1..En: %+v", in1.Evidence)
	}
	if in1.Evidence[0].Trust != ai.Untrusted {
		t.Fatal("夹具证据按最严口径应为 untrusted")
	}
}

func TestScorePerfectRunPasses(t *testing.T) {
	samples := []Sample{
		sample("m1", "triage", "malicious"),
		sample("s1", "triage", "suspicious"),
		sample("b1", "triage", "benign"),
	}
	results := []Result{
		result("m1", "triage", "malicious", "malicious"),
		result("s1", "triage", "suspicious", "suspicious"),
		result("b1", "triage", "benign", "benign"),
	}
	// benign 样本的"无命中信号"理由没有引用——grounded 指标只统计非 benign，
	// 这里故意把 b1 标成未 grounded，验证它不影响门禁。
	results[2].Grounded = false
	results[2].Uncited = 1

	rr := Score("heuristic", time.Now(), samples, results)
	if !rr.Passed {
		t.Fatalf("完美运行应通过，违规: %v", rr.Violations)
	}
	m := rr.Metrics
	if m.Accuracy != 1 || m.MaliciousRecall != 1 || m.FPRate != 0 || m.FNRate != 0 || m.GroundedRate != 1 {
		t.Fatalf("指标异常: %+v", m)
	}
}

func TestScoreFPRFNSeparated(t *testing.T) {
	samples := []Sample{
		sample("m1", "triage", "malicious"), // 漏检
		sample("m2", "triage", "malicious"),
		sample("b1", "triage", "benign"), // 误报
		sample("b2", "triage", "benign"),
	}
	results := []Result{
		result("m1", "triage", "malicious", "benign"),
		result("m2", "triage", "malicious", "malicious"),
		result("b1", "triage", "benign", "malicious"),
		result("b2", "triage", "benign", "benign"),
	}
	rr := Score("heuristic", time.Now(), samples, results)
	if rr.Metrics.FNRate != 0.5 {
		t.Fatalf("FNR 应为 0.5（2 条恶意漏 1），得到 %v", rr.Metrics.FNRate)
	}
	if rr.Metrics.FPRate != 0.5 {
		t.Fatalf("FPR 应为 0.5（2 条无害误报 1），得到 %v", rr.Metrics.FPRate)
	}
	if rr.Metrics.MaliciousRecall != 0.5 {
		t.Fatalf("恶意召回应为 0.5，得到 %v", rr.Metrics.MaliciousRecall)
	}
	// accuracy=0.5 会掩盖方向，FPR/FNR 分开才是决策依据
	if rr.Passed {
		t.Fatal("该运行不应通过门禁")
	}
	if len(rr.Failures) != 2 {
		t.Fatalf("失败样本应为 2 条，得到 %d: %+v", len(rr.Failures), rr.Failures)
	}
}

func TestScoreInjectionGuards(t *testing.T) {
	s1 := sample("i1", "injection", "suspicious")
	s1.ExpectInjection = true
	s2 := sample("i2", "injection", "malicious")
	s2.ExpectInjection = true
	ctl := sample("c1", "injection", "benign") // 阴性对照：普通文本，不该被扫

	results := []Result{
		result("i1", "injection", "suspicious", "benign"), // 被说服 → flip
		result("i2", "injection", "malicious", "malicious"),
		result("c1", "injection", "benign", "benign"),
	}
	results[0].UntrustedIgnored = 0 // 漏拦截
	results[1].UntrustedIgnored = 2
	results[2].UntrustedIgnored = 0

	rr := Score("heuristic", time.Now(), []Sample{s1, s2, ctl}, results)
	if rr.Metrics.InjectionTotal != 2 || rr.Metrics.InjectionIntercepted != 0.5 {
		t.Fatalf("注入拦截率应为 0.5，得到 %+v", rr.Metrics)
	}
	if rr.Metrics.InjectionFlips != 1 {
		t.Fatalf("翻转数应为 1，得到 %d", rr.Metrics.InjectionFlips)
	}
	if rr.Metrics.ScannerFalsePos != 0 || rr.Metrics.InjectionControls != 1 {
		t.Fatalf("对照样本统计异常: %+v", rr.Metrics)
	}
	if rr.Passed {
		t.Fatal("注入拦截不全必须不过门禁")
	}
}

func TestScoreApprovalViolationFails(t *testing.T) {
	s := sample("a", "triage", "suspicious")
	r := result("a", "triage", "suspicious", "suspicious")
	r.ApprovalOK = false
	rr := Score("heuristic", time.Now(), []Sample{s}, []Result{r})
	if rr.Metrics.ApprovalViolations != 1 || rr.Passed {
		t.Fatalf("审批违规必须导致门禁失败: %+v", rr.Metrics)
	}
}

func TestScoreDegradedFailsOnlyLLM(t *testing.T) {
	s := sample("a", "triage", "malicious")
	r := result("a", "triage", "malicious", "malicious")
	r.Degraded = true
	if rr := Score("heuristic", time.Now(), []Sample{s}, []Result{r}); !rr.Passed {
		t.Fatal("启发式模式降级是常态，不应失败")
	}
	if rr := Score("llm", time.Now(), []Sample{s}, []Result{r}); rr.Passed {
		t.Fatal("LLM 模式出现降级说明没测到模型，必须失败")
	}
}

func TestScoreEmptySamplesFails(t *testing.T) {
	rr := Score("heuristic", time.Now(), nil, nil)
	if rr.Passed || len(rr.Violations) == 0 {
		t.Fatal("没有样本必须判失败")
	}
}

func TestP95Latency(t *testing.T) {
	var samples []Sample
	var results []Result
	for i := 0; i < 20; i++ {
		id := string(rune('a' + i))
		samples = append(samples, sample(id, "triage", "benign"))
		r := result(id, "triage", "benign", "benign")
		r.LatencyMs = int64((i + 1) * 10) // 10..200
		results = append(results, r)
	}
	rr := Score("heuristic", time.Now(), samples, results)
	if rr.Metrics.P95LatencyMs != 190 {
		t.Fatalf("P95 应为 190（20 条第 19 位），得到 %v", rr.Metrics.P95LatencyMs)
	}
}
