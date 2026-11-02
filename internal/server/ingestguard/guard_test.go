package ingestguard

import (
	"testing"

	"zedr/internal/platform/apperr"
)

func codeOf(err error) apperr.Code {
	if err == nil {
		return ""
	}
	return apperr.From(err).Code
}

func TestRateLimitIsPerAgentAndByAlertCount(t *testing.T) {
	g := New(0.001, 10, 8) // 几乎不补充令牌，便于稳定断言
	release, err := g.Admit("agent-a", 10)
	if err != nil {
		t.Fatalf("first Admit: %v", err)
	}
	release()

	if _, err := g.Admit("agent-a", 1); codeOf(err) != apperr.CodeTooManyRequests {
		t.Fatalf("second Admit err = %v, want too_many_requests", err)
	}
	// 另一个终端有自己的桶，不受影响
	release, err = g.Admit("agent-b", 1)
	if err != nil {
		t.Fatalf("other agent should pass: %v", err)
	}
	release()
}

func TestPerAgentInflightRejectsConcurrentBatch(t *testing.T) {
	g := New(1000, 1000, 8)
	releaseA, err := g.Admit("agent-a", 1)
	if err != nil {
		t.Fatalf("first Admit: %v", err)
	}
	defer releaseA()

	if _, err := g.Admit("agent-a", 1); codeOf(err) != apperr.CodeUnavailable {
		t.Fatalf("concurrent same-agent err = %v, want unavailable", err)
	}
	releaseB, err := g.Admit("agent-b", 1)
	if err != nil {
		t.Fatalf("other agent should pass: %v", err)
	}
	releaseB()
}

func TestGlobalInflightCap(t *testing.T) {
	g := New(1000, 1000, 2)
	r1, err := g.Admit("a", 1)
	if err != nil {
		t.Fatalf("Admit a: %v", err)
	}
	defer r1()
	r2, err := g.Admit("b", 1)
	if err != nil {
		t.Fatalf("Admit b: %v", err)
	}
	defer r2()

	if _, err := g.Admit("c", 1); codeOf(err) != apperr.CodeUnavailable {
		t.Fatalf("third agent err = %v, want unavailable", err)
	}
	if got := g.Stats().Inflight; got != 2 {
		t.Fatalf("Inflight = %d, want 2", got)
	}
}

func TestReleaseIsIdempotent(t *testing.T) {
	g := New(1000, 1000, 2)
	release, err := g.Admit("a", 1)
	if err != nil {
		t.Fatalf("Admit: %v", err)
	}
	release()
	release() // 重复调用不应把计数减成负数
	if got := g.Stats().Inflight; got != 0 {
		t.Fatalf("Inflight = %d, want 0", got)
	}
	r, err := g.Admit("a", 1)
	if err != nil {
		t.Fatalf("Admit after release: %v", err)
	}
	r()
}
