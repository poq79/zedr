package notify

import (
	"testing"

	"zedr/internal/server/domain"
)

// fakeChannel 是可拨动计数的渠道替身，模拟"有失败无成功/静默/恢复"。
type fakeChannel struct {
	sent, failed, dropped int64
}

func (f *fakeChannel) Ingest(domain.Alert) {}
func (f *fakeChannel) Stats() (sent, failed, dropped int64) {
	return f.sent, f.failed, f.dropped
}
func (f *fakeChannel) Close() {}

func named(n string, f *fakeChannel) NamedChannel {
	return NamedChannel{Name: n, Channel: f}
}

// TestWatchdogDegradesAfterStreak 连续 N 窗"有失败无成功"→ degraded；
// 一次成功 → 复位 ok，并产生两次翻转事件。
func TestWatchdogDegradesAfterStreak(t *testing.T) {
	fc := &fakeChannel{}
	w := NewWatchdog([]NamedChannel{named("feishu", fc)}, 3)

	// 构造基线后的 3 个失败窗：前 2 窗不翻转，第 3 窗翻转 degraded
	var tr []Transition
	for i := 0; i < 3; i++ {
		fc.failed++
		tr = w.Observe()
		if i < 2 && len(tr) != 0 {
			t.Fatalf("第 %d 窗不应翻转: %v", i, tr)
		}
	}
	if len(tr) != 1 || tr[0].Channel != "feishu" || tr[0].To != "degraded" {
		t.Fatalf("第 3 窗应翻转 degraded: %v", tr)
	}
	if rep := w.Report(); rep.State != "degraded" || !rep.Channels[0].Degraded || rep.Channels[0].Streak != 3 {
		t.Fatalf("报告不符: %+v", rep)
	}

	// 恢复：一个成功窗 → ok
	fc.sent++
	fc.failed++
	tr = w.Observe()
	if len(tr) != 1 || tr[0].To != "ok" {
		t.Fatalf("成功窗应复位 ok: %v", tr)
	}
	if rep := w.Report(); rep.State != "ok" || rep.Channels[0].Degraded {
		t.Fatalf("复位后报告不符: %+v", rep)
	}
}

// TestWatchdogSilentAndDroppedWindows 静默窗与 dropped-only 窗都不推进
// streak——没告警可发、防风暴丢弃都不是渠道故障。
func TestWatchdogSilentAndDroppedWindows(t *testing.T) {
	fc := &fakeChannel{}
	w := NewWatchdog([]NamedChannel{named("dingtalk", fc)}, 2)

	fc.failed++
	w.Observe() // streak=1
	fc.dropped += 5
	if tr := w.Observe(); len(tr) != 0 {
		t.Fatalf("dropped-only 窗不应翻转: %v", tr)
	}
	if rep := w.Report(); rep.Channels[0].Streak != 1 {
		t.Fatalf("静默窗不应推进 streak: %+v", rep.Channels[0])
	}
	fc.failed++
	if tr := w.Observe(); len(tr) != 1 || tr[0].To != "degraded" {
		t.Fatalf("达阈值应翻转: %v", tr)
	}
}

// TestWatchdogMixedWindow 混合成败的窗（有成功也有失败）不推进——
// 渠道没全坏。
func TestWatchdogMixedWindow(t *testing.T) {
	fc := &fakeChannel{}
	w := NewWatchdog([]NamedChannel{named("webhook", fc)}, 2)
	for i := 0; i < 4; i++ {
		fc.sent++
		fc.failed++
		if tr := w.Observe(); len(tr) != 0 {
			t.Fatalf("混合窗不应翻转: %v", tr)
		}
	}
	if rep := w.Report(); rep.State != "ok" {
		t.Fatalf("混合窗后应为 ok: %+v", rep)
	}
}

// TestWatchdogUnconfigured 没配渠道报 unconfigured，不算故障但要可见。
func TestWatchdogUnconfigured(t *testing.T) {
	w := NewWatchdog(nil, 3)
	if rep := w.Report(); rep.State != "unconfigured" || rep.Configured != 0 {
		t.Fatalf("未配置应报 unconfigured: %+v", rep)
	}
}

// TestWatchdogThresholdFloor threshold 非法值兜底为 1（构造不 panic，
// 一个失败窗即 degraded）。
func TestWatchdogThresholdFloor(t *testing.T) {
	fc := &fakeChannel{}
	w := NewWatchdog([]NamedChannel{named("slack", fc)}, 0)
	fc.failed++
	if tr := w.Observe(); len(tr) != 1 || tr[0].To != "degraded" {
		t.Fatalf("threshold 兜底为 1 时应立即翻转: %v", tr)
	}
}

// TestWatchdogMultiChannelIndependent 多渠道相互独立：一个坏不影响另一个。
func TestWatchdogMultiChannelIndependent(t *testing.T) {
	bad, good := &fakeChannel{}, &fakeChannel{}
	w := NewWatchdog([]NamedChannel{named("feishu", bad), named("syslog", good)}, 2)

	bad.failed++
	w.Observe()
	bad.failed++
	w.Observe() // feishu degraded
	if rep := w.Report(); rep.State != "degraded" || !rep.Channels[0].Degraded || rep.Channels[1].Degraded {
		t.Fatalf("多渠道独立性不符: %+v", rep)
	}

	// syslog 混合成败：复位自己，不影响 feishu 的 degraded 状态
	good.sent++
	good.failed += 10
	w.Observe()
	rep := w.Report()
	if rep.Channels[1].Streak != 0 {
		t.Fatalf("syslog 混合窗应复位自身 streak: %+v", rep.Channels[1])
	}
	if !rep.Channels[0].Degraded {
		t.Fatalf("feishu 状态不应被 syslog 影响: %+v", rep.Channels[0])
	}
}
