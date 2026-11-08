// evtquery_test.go：EvtReadLatest 反向查询测试。
//
// 真机通道冒烟（管理员权限下 System 通道可读），断言以方向/钳制/过滤
// 契约为主，不写死事件数量——通道内容随机器状态变化。

package winapi

import (
	"errors"
	"testing"

	"golang.org/x/sys/windows"
)

func TestEvtReadLatestSystemChannel(t *testing.T) {
	events, latest, err := EvtReadLatest("System", "", 5)
	if err != nil {
		t.Fatalf("EvtReadLatest(System) 报错: %v", err)
	}
	if len(events) > 5 {
		t.Fatalf("maxEvents=5 钳制失效: %d 条", len(events))
	}
	// 方向契约：RecordID 严格递减（新→旧）
	for i := 1; i < len(events); i++ {
		if events[i-1].RecordID <= events[i].RecordID {
			t.Errorf("递减契约被破坏: events[%d].RecordID=%d <= events[%d].RecordID=%d",
				i-1, events[i-1].RecordID, i, events[i].RecordID)
		}
	}
	for i, ev := range events {
		if ev.Data == nil {
			t.Errorf("events[%d].Data 必须非 nil", i)
		}
		if ev.Channel != "System" {
			t.Errorf("events[%d].Channel = %q, want System", i, ev.Channel)
		}
	}
	if len(events) > 0 {
		if latest != events[0].RecordID {
			t.Errorf("latest=%d 应等于首条（最新）RecordID=%d", latest, events[0].RecordID)
		}
		t.Logf("System 最近 %d 条：首条 RecordID=%d EventID=%d",
			len(events), events[0].RecordID, events[0].EventID)
	}
}

// TestEvtReadLatestCursorPlayoff 与正向 EvtReadBatch 对拍：latest 作为
// sinceID 时，正向增量读不得再包含反向批里已读过的记录（两种方向共享
// 同一 RecordID 空间，游标可互通是调用方组合使用的前提）。
func TestEvtReadLatestCursorPlayoff(t *testing.T) {
	events, latest, err := EvtReadLatest("System", "", 10)
	if err != nil {
		t.Fatalf("EvtReadLatest 报错: %v", err)
	}
	if len(events) < 2 {
		t.Skip("通道事件不足，无法对拍游标")
	}
	fwd, _, err := EvtReadBatch("System", "", latest, 10)
	if err != nil {
		t.Fatalf("EvtReadBatch(latest=%d) 报错: %v", latest, err)
	}
	for _, ev := range fwd {
		if ev.RecordID <= latest {
			t.Errorf("游标过滤失效: RecordID=%d <= latest=%d", ev.RecordID, latest)
		}
	}
}

func TestEvtReadLatestXPathFilter(t *testing.T) {
	// 7036（服务状态变化）在任何运行中的 Windows 上都持续产生，反向取 3 条
	// 应立即命中且全部匹配（验证 XPath 过滤在反向方向同样生效）。
	events, latest, err := EvtReadLatest("System", "*[System[(EventID=7036)]]", 3)
	if err != nil {
		t.Fatalf("EvtReadLatest(7036) 报错: %v", err)
	}
	if len(events) > 3 {
		t.Fatalf("钳制失效: %d 条", len(events))
	}
	for _, ev := range events {
		if ev.EventID != 7036 {
			t.Errorf("过滤失效: EventID=%d, want 7036", ev.EventID)
		}
	}
	if len(events) == 0 {
		t.Log("System 通道 7036 零命中（异常环境，仅记录不断言）")
	} else {
		t.Logf("7036 反向命中 %d 条，latest=%d", len(events), latest)
	}
}

func TestEvtReadLatestFakeChannel(t *testing.T) {
	events, latest, err := EvtReadLatest("ZedrFakeChannel", "*", 10)
	if err == nil {
		t.Fatal("不存在的通道必须报错")
	}
	if len(events) != 0 || latest != 0 {
		t.Errorf("失败返回应为零值: events=%d latest=%d", len(events), latest)
	}
	// 错误码必须可判（liveapi 层据此区分 403 与 200-count0）：
	// 伪通道应落在"通道不存在"族（15006/15007/15036），而非 ACCESS_DENIED。
	switch {
	case errors.Is(err, windows.ERROR_EVT_CHANNEL_NOT_FOUND),
		errors.Is(err, windows.ERROR_EVT_INVALID_CHANNEL_PATH),
		errors.Is(err, windows.ERROR_EVT_CANNOT_OPEN_CHANNEL_OF_QUERY):
		t.Logf("伪通道 errno 落在通道不可用族: %v", err)
	case errors.Is(err, windows.ERROR_ACCESS_DENIED):
		t.Fatalf("伪通道不应报 ACCESS_DENIED(5): %v", err)
	default:
		t.Fatalf("伪通道 errno 不在可判族内（liveapi 层无法分类）: %v", err)
	}
}
