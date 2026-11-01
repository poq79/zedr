package liveapi

// baseline_test.go：/baseline 的结构契约与"读取失败必须降级 info"。
// 真机跑（会读注册表/Defender 状态），但不执行任何命令。

import (
	"net/http"
	"testing"
	"time"
)

// 契约 §13.2 的固定顺序与 key 集合。
var wantBaselineKeys = []string{
	"defender", "firewall", "uac", "smbv1", "smb_signing",
	"rdp_nla", "lsa_ppl", "wdigest", "restrict_anon", "guest",
}

func TestHandleBaselineShape(t *testing.T) {
	code, body := doGet(t, HandleBaseline(), "/baseline")
	if code != http.StatusOK {
		t.Fatalf("期望 200 实得 %d body=%v", code, body)
	}
	d := dataOf(t, body)

	gen, _ := d["generated_at"].(string)
	if gen == "" {
		t.Fatal("缺少 generated_at")
	}
	if _, err := time.Parse(time.RFC3339, gen); err != nil {
		t.Errorf("generated_at 不是 RFC3339: %q (%v)", gen, err)
	}

	rawItems, ok := d["items"].([]any)
	if !ok {
		t.Fatalf("items 不是数组: %T", d["items"])
	}
	if len(rawItems) != len(wantBaselineKeys) {
		t.Fatalf("items 数量=%d，期望 %d", len(rawItems), len(wantBaselineKeys))
	}

	counts := map[string]int{}
	seen := map[string]bool{}
	for i, raw := range rawItems {
		it, ok := raw.(map[string]any)
		if !ok {
			t.Fatalf("items[%d] 不是对象: %T", i, raw)
		}
		key, _ := it["key"].(string)
		if key != wantBaselineKeys[i] {
			t.Errorf("items[%d].key=%q，期望 %q（顺序是契约的一部分）", i, key, wantBaselineKeys[i])
		}
		if seen[key] {
			t.Errorf("检查项 key 重复: %q", key)
		}
		seen[key] = true

		for _, f := range []string{"title", "status", "current", "recommended", "evidence"} {
			v, _ := it[f].(string)
			if v == "" {
				t.Errorf("%s.%s 为空", key, f)
			}
		}
		status, _ := it["status"].(string)
		switch status {
		case baselinePass, baselineWarn, baselineFail, baselineInfo:
			counts[status]++
		default:
			t.Errorf("%s.status 非法: %q", key, status)
		}
		t.Logf("%-14s %-4s %s", key, status, it["current"])
	}

	score, ok := d["score"].(map[string]any)
	if !ok {
		t.Fatalf("score 不是对象: %T", d["score"])
	}
	num := func(k string) int {
		v, _ := score[k].(float64)
		return int(v)
	}
	if got := num("total"); got != len(rawItems) {
		t.Errorf("score.total=%d，items 数量=%d", got, len(rawItems))
	}
	if got, want := num("pass"), counts[baselinePass]; got != want {
		t.Errorf("score.pass=%d，items 中 pass=%d", got, want)
	}
	if got, want := num("warn"), counts[baselineWarn]; got != want {
		t.Errorf("score.warn=%d，items 中 warn=%d", got, want)
	}
	if got, want := num("fail"), counts[baselineFail]; got != want {
		t.Errorf("score.fail=%d，items 中 fail=%d", got, want)
	}
	if sum := counts[baselinePass] + counts[baselineWarn] + counts[baselineFail] + counts[baselineInfo]; sum != len(rawItems) {
		t.Errorf("四档计数之和=%d，items 数量=%d", sum, len(rawItems))
	}
	t.Logf("baseline score=%v items=%d", score, len(rawItems))
}

func TestBaselineUACReadErrorIsInfo(t *testing.T) {
	// 内嵌 NUL 的路径必然读取失败：必须降级 info 且带原因，不能 panic
	// 或悄悄按默认值判 pass。
	it := checkUACAt("SOFTWARE\x00HostGuard-H5")
	if it.Status != baselineInfo {
		t.Fatalf("读取失败应降级 info，实得 %q (%+v)", it.Status, it)
	}
	if it.Evidence == "" {
		t.Error("info 项必须说明读取失败原因")
	}
}

func TestBaselineMissingKeyDegrades(t *testing.T) {
	// 不存在的键：SMBv1 按契约判 warn（未显式禁用），且不 panic。
	it := checkSMBv1At(`SOFTWARE\HostGuard-H5-NoSuchKey-9f3a`)
	if it.Status != baselineWarn {
		t.Errorf("缺失 SMB1 值应判 warn，实得 %q (%+v)", it.Status, it)
	}
	if it.Current != "未配置" || it.Evidence == "" {
		t.Errorf("缺失分支文案不完整: %+v", it)
	}
}

func TestScoreBaseline(t *testing.T) {
	got := scoreBaseline([]baselineItem{
		{Status: baselinePass},
		{Status: baselineWarn},
		{Status: baselineFail},
		{Status: baselineInfo},
	})
	want := baselineScore{Pass: 1, Warn: 1, Fail: 1, Total: 4}
	if got != want {
		t.Errorf("scoreBaseline=%+v，期望 %+v", got, want)
	}
}
