package agentapp

// 抖动原语的边界回归（2026-11-19 数据库健康度轮 P0-3）。
// 不测具体值（随机），只测：结果永远落在声明区间内、零值透传。

import (
	"testing"
	"time"
)

func TestJitterIntervalBounds(t *testing.T) {
	base := 30 * time.Second
	span := time.Duration(float64(base) * HeartbeatJitterFrac)
	lo, hi := base-span, base+span
	for i := 0; i < 1000; i++ {
		got := JitterInterval(base, HeartbeatJitterFrac)
		if got < lo || got > hi {
			t.Fatalf("got %v, want in [%v, %v]", got, lo, hi)
		}
	}
	if JitterInterval(0, HeartbeatJitterFrac) != 0 {
		t.Fatal("zero base must pass through")
	}
	if JitterInterval(-time.Second, HeartbeatJitterFrac) != -time.Second {
		t.Fatal("negative base must pass through")
	}
	if JitterInterval(time.Second, 0) != time.Second {
		t.Fatal("zero frac must pass through")
	}
}

func TestJitterDurationBounds(t *testing.T) {
	limit := 5 * time.Second
	for i := 0; i < 1000; i++ {
		got := JitterDuration(limit)
		if got < 0 || got > limit {
			t.Fatalf("got %v, want in [0, %v]", got, limit)
		}
	}
	if JitterDuration(0) != 0 {
		t.Fatal("zero limit must return 0")
	}
	if JitterDuration(-time.Second) != 0 {
		t.Fatal("negative limit must return 0")
	}
}
