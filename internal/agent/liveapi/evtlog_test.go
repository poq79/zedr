package liveapi

// evtlog_test.go：/evtlog 端点契约测试。
//
// liveapi.go 归主线会话，本波次三个新端点（/evtlog /sessions /drivers）
// 尚未并入 New()——newInvestigationMux 以与 New() 完全相同的方式接线，
// 主线注册后可无缝切换回 New(Deps{...})。
// 真机冒烟走 System 通道（管理员权限下可读）；断言以结构/钳制/方向为主，
// 不写死事件数量——通道内容随机器状态变化。

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

// newInvestigationMux 镜像 New() 的接线（含 recoverWrap），注册本波次三个
// 新端点；主线把这三个 HandleFunc 行并入 New() 后，此 helper 即可退役。
func newInvestigationMux(d Deps) http.Handler {
	s := &server{d: d}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /evtlog", s.handleEvtLog)
	mux.HandleFunc("GET /sessions", s.handleSessions)
	mux.HandleFunc("GET /drivers", s.handleDrivers)
	return recoverWrap(mux)
}

func TestEvtLogEndpointSystem(t *testing.T) {
	h := newInvestigationMux(Deps{StartTime: time.Now()})
	code, body := doGet(t, h, "/evtlog?channel=System&max=5")
	if code != http.StatusOK {
		t.Fatalf("期望 200 实得 %d body=%v", code, body)
	}
	d := dataOf(t, body)
	if d["channel"] != "System" {
		t.Errorf("channel 回显不符: %v", d["channel"])
	}
	if xp, _ := d["xpath"].(string); xp == "" || !strings.Contains(xp, "timediff") {
		t.Errorf("xpath 应回显实际查询（含时间窗）: %v", d["xpath"])
	}
	items, ok := d["items"].([]any)
	if !ok {
		t.Fatalf("items 缺失: %v", body)
	}
	if len(items) > 5 {
		t.Fatalf("max=5 钳制失效: %d", len(items))
	}
	if cnt, _ := d["count"].(float64); int(cnt) != len(items) {
		t.Errorf("count 与 items 长度不符: %d vs %d", int(cnt), len(items))
	}
	if tr, ok := d["truncated"].(bool); !ok {
		t.Errorf("truncated 应为布尔: %v", d["truncated"])
	} else if tr && len(items) != 5 {
		t.Errorf("truncated=true 但 items 未满 max: %d", len(items))
	}
	// 字段契约 + 方向契约（新→旧，RecordID 递减）
	var lastRID float64 = -1
	for i, raw := range items {
		it, _ := raw.(map[string]any)
		for _, key := range []string{"record_id", "time_created", "event_id", "level", "data"} {
			if _, ok := it[key]; !ok {
				t.Errorf("items[%d] 缺字段 %q: %v", i, key, it)
			}
		}
		rid, _ := it["record_id"].(float64)
		if lastRID >= 0 && rid > lastRID {
			t.Errorf("items 应按 RecordID 递减（新→旧）: %v 之后出现 %v", lastRID, rid)
		}
		lastRID = rid
	}
	if len(items) > 0 {
		t.Logf("样例一条: %v", items[0])
	} else {
		t.Log("System 通道 60 分钟内零事件（异常环境，仅记录）")
	}
}

func TestEvtLogEndpointValidation(t *testing.T) {
	h := newInvestigationMux(Deps{StartTime: time.Now()})
	// channel 必填
	if code, _ := doGet(t, h, "/evtlog"); code != http.StatusBadRequest {
		t.Errorf("缺 channel 期望 400 实得 %d", code)
	}
	// channel 超长（>200）
	if code, _ := doGet(t, h, "/evtlog?channel="+url.QueryEscape(strings.Repeat("a", 201))); code != http.StatusBadRequest {
		t.Errorf("超长 channel 期望 400 实得 %d", code)
	}
	// 对拍：恰好 200 长度应放行（保证校验没有整体失灵）
	if code, body := doGet(t, h, "/evtlog?channel="+url.QueryEscape(strings.Repeat("a", 200))); code != http.StatusOK {
		t.Errorf("200 长度 channel 期望放行(通道不存在→200) 实得 %d body=%v", code, body)
	}
}

func TestEvtLogEndpointFakeChannel(t *testing.T) {
	h := newInvestigationMux(Deps{StartTime: time.Now()})
	// 通道不存在是调查结论：200 + count 0（绝不能 5xx）
	code, body := doGet(t, h, "/evtlog?channel=ZedrNoSuchChannel&max=5")
	if code != http.StatusOK {
		t.Fatalf("不存在通道期望 200 实得 %d body=%v", code, body)
	}
	d := dataOf(t, body)
	if cnt, _ := d["count"].(float64); int(cnt) != 0 {
		t.Errorf("count 期望 0 实得 %v", d["count"])
	}
	if items, _ := d["items"].([]any); len(items) != 0 {
		t.Errorf("items 期望空: %v", items)
	}
	if d["channel"] != "ZedrNoSuchChannel" || d["xpath"] == "" {
		t.Errorf("channel/xpath 应回显: %v", d)
	}
}

func TestEvtLogEndpointIDsFilter(t *testing.T) {
	h := newInvestigationMux(Deps{StartTime: time.Now()})
	// ids 过滤 + 非法 token（abc/空段）忽略；7036 在运行中的机器上持续产生，
	// 24h 窗口内几乎必命中，但断言仍保持"命中则必在过滤集"的软形态。
	code, body := doGet(t, h, "/evtlog?channel=System&ids=7036,abc,,7045&minutes=1440&max=10")
	if code != http.StatusOK {
		t.Fatalf("期望 200 实得 %d body=%v", code, body)
	}
	items, _ := dataOf(t, body)["items"].([]any)
	if len(items) > 10 {
		t.Fatalf("max=10 钳制失效: %d", len(items))
	}
	for i, raw := range items {
		it, _ := raw.(map[string]any)
		if id, _ := it["event_id"].(float64); id != 7036 && id != 7045 {
			t.Errorf("items[%d] EventID=%v 不在过滤集", i, it["event_id"])
		}
	}
	// ids 全非法 → 等价于无过滤（不 400，容错口径）
	if code, body := doGet(t, h, "/evtlog?channel=System&ids=abc,xyz&max=3"); code != http.StatusOK {
		t.Errorf("ids 全非法期望 200 实得 %d body=%v", code, body)
	}
	t.Logf("ids 过滤命中 %d 条", len(items))
}
