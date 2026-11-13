//go:build windows
// +build windows

package liveapi

// info_test.go：/info 端点。

import (
	"net/http"
	"testing"
	"time"

	"zedr/internal/agent/state"
)

func TestInfoNotImplemented(t *testing.T) {
	h := New(Deps{StartTime: time.Now()})
	if code, _ := doGet(t, h, "/info"); code != http.StatusNotImplemented {
		t.Fatalf("Runtime==nil 期望 501 实得 %d", code)
	}
}

func TestInfoFields(t *testing.T) {
	h := New(Deps{
		Version:   "9.9.9-fallback",
		StartTime: time.Now().Add(-60 * time.Second),
		Runtime: func() state.RuntimeInfo {
			return state.RuntimeInfo{
				Hostname:     "box1",
				AgentVersion: "1.2.3",
				UptimeSec:    120,
				ProcCount:    55,
				CPUPercent:   3.5,
				MemMB:        220.5,
				ScanInterval: "2s",
				Collector:    "ntquery",
			}
		},
	})
	code, body := doGet(t, h, "/info")
	if code != http.StatusOK {
		t.Fatalf("期望 200 实得 %d body=%v", code, body)
	}
	d := dataOf(t, body)
	if d["version"] != "1.2.3" { // RuntimeInfo 优先于 Deps.Version
		t.Errorf("version 期望 1.2.3 实得 %v", d["version"])
	}
	if d["hostname"] != "box1" || d["scan_interval"] != "2s" || d["collector"] != "ntquery" {
		t.Errorf("字段不符: %v", d)
	}
	if v, _ := d["uptime_sec"].(float64); v != 120 {
		t.Errorf("uptime_sec 期望 120 实得 %v", d["uptime_sec"])
	}
	if v, _ := d["proc_count"].(float64); v != 55 {
		t.Errorf("proc_count 期望 55 实得 %v", d["proc_count"])
	}
	if v, _ := d["cpu_percent"].(float64); v != 3.5 {
		t.Errorf("cpu_percent 期望 3.5 实得 %v", d["cpu_percent"])
	}
	if v, _ := d["mem_mb"].(float64); v != 220.5 {
		t.Errorf("mem_mb 期望 220.5 实得 %v", d["mem_mb"])
	}
}

func TestInfoRuntimeFallbacks(t *testing.T) {
	// RuntimeInfo 未维护版本/uptime 时回退 Deps（scan 回调首轮前的瞬态）
	h := New(Deps{
		Version:   "9.9.9-fallback",
		StartTime: time.Now().Add(-30 * time.Second),
		Runtime:   func() state.RuntimeInfo { return state.RuntimeInfo{Hostname: "box2"} },
	})
	_, body := doGet(t, h, "/info")
	d := dataOf(t, body)
	if d["version"] != "9.9.9-fallback" {
		t.Errorf("version 应回退 Deps.Version: %v", d["version"])
	}
	if up, _ := d["uptime_sec"].(float64); up < 29 || up > 120 {
		t.Errorf("uptime_sec 应回退 StartTime 推算: %v", d["uptime_sec"])
	}
}
