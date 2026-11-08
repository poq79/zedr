package liveapi

// drivers_test.go：/drivers 真机冒烟。
// EnumDeviceDrivers 普通用户可用（见 winapi/drivers.go），任何运行中的
// Windows 至少加载 1 个内核驱动；verify=1 分支覆盖验签字段契约。

import (
	"net/http"
	"testing"
	"time"
)

func TestDriversEndpoint(t *testing.T) {
	h := newInvestigationMux(Deps{StartTime: time.Now()})
	code, body := doGet(t, h, "/drivers")
	if code != http.StatusOK {
		t.Fatalf("期望 200 实得 %d body=%v", code, body)
	}
	d := dataOf(t, body)
	items, ok := d["items"].([]any)
	if !ok {
		t.Fatalf("items 缺失: %v", body)
	}
	if len(items) < 1 {
		t.Fatal("任何运行中的 Windows 至少加载 1 个内核驱动")
	}
	if total, _ := d["total"].(float64); int(total) != len(items) {
		t.Errorf("total 与 items 不符: %d vs %d", int(total), len(items))
	}
	// verify 缺省（=0）：verified_count 恒 0，且不出现验签字段
	if vc, _ := d["verified_count"].(float64); int(vc) != 0 {
		t.Errorf("verify 缺省时 verified_count 期望 0 实得 %v", d["verified_count"])
	}
	first, _ := items[0].(map[string]any)
	for _, key := range []string{"name", "path", "size", "mtime_unix"} {
		if _, ok := first[key]; !ok {
			t.Errorf("items[0] 缺字段 %q: %v", key, first)
		}
	}
	if _, has := first["signed"]; has {
		t.Errorf("verify=0 时不应输出 signed（未验≠没签）: %v", first)
	}
	t.Logf("drivers=%d 首条=%v", len(items), first)
}

func TestDriversEndpointVerify(t *testing.T) {
	h := newInvestigationMux(Deps{StartTime: time.Now()})
	code, body := doGet(t, h, "/drivers?verify=1")
	if code != http.StatusOK {
		t.Fatalf("期望 200 实得 %d body=%v", code, body)
	}
	d := dataOf(t, body)
	items, ok := d["items"].([]any)
	if !ok || len(items) < 1 {
		t.Fatalf("items 缺失或为空: %v", body)
	}
	vc, _ := d["verified_count"].(float64)
	if int(vc) > 50 {
		t.Fatalf("verified_count 超 50 上限: %v", d["verified_count"])
	}
	if int(vc) > len(items) {
		t.Fatalf("verified_count %d 超过 items 数 %d", int(vc), len(items))
	}
	if int(vc) == 0 {
		t.Fatal("verify=1 且机器有驱动时 verified_count 不应为 0")
	}
	// 前 verified_count 个条目必须带 signed；其后不得带（边界语义锁定：
	// "验过才说"，分析师可据 verified_count 划分可信区间）
	for i := 0; i < int(vc); i++ {
		it, _ := items[i].(map[string]any)
		if _, ok := it["signed"]; !ok {
			t.Errorf("items[%d] 被 verify 却缺 signed: %v", i, it)
		}
	}
	if int(vc) < len(items) {
		it, _ := items[int(vc)].(map[string]any)
		if _, has := it["signed"]; has {
			t.Errorf("items[%d] 未被 verify 却带 signed: %v", int(vc), it)
		}
	}
	t.Logf("verified=%d/%d", int(vc), len(items))
}
