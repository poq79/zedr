package service

// zeroclick_test.go：zero-click 三道预算闸的契约测试。核心保证：
// 非 critical+malicious 一律不跑；同指纹 30 分钟去重；每主机每小时
// 上限精确生效；开关关闭全灭。

import (
	"testing"
	"time"

	"zedr/internal/server/domain"
)

func zcAlert(fp, host string, sev domain.Severity, v domain.Verdict) *domain.Alert {
	return &domain.Alert{ID: "a-" + fp, Fingerprint: fp, Hostname: host, Severity: sev, Verdict: v}
}

func TestZeroClickGateHappy(t *testing.T) {
	s := &AIService{}
	s.SetZeroClick(true, 3)
	a := zcAlert("fp-1", "HOST-A", domain.SeverityCritical, domain.VerdictMalicious)
	if ok, _ := s.zeroClickGate(a); !ok {
		t.Fatal("critical+malicious 首次应放行")
	}
}

func TestZeroClickGateNotCritical(t *testing.T) {
	s := &AIService{}
	s.SetZeroClick(true, 3)
	cases := []struct {
		sev domain.Severity
		v   domain.Verdict
	}{
		{domain.SeverityHigh, domain.VerdictMalicious},
		{domain.SeverityCritical, domain.VerdictSuspicious},
	}
	for i, c := range cases {
		if ok, _ := s.zeroClickGate(zcAlert("fp-nc-"+string(rune('a'+i)), "HOST-N", c.sev, c.v)); ok {
			t.Fatalf("case %d：非 critical+malicious 不应放行", i)
		}
	}
}

func TestZeroClickGateFingerprintDedup(t *testing.T) {
	s := &AIService{}
	s.SetZeroClick(true, 10)
	a := zcAlert("fp-dup", "HOST-D", domain.SeverityCritical, domain.VerdictMalicious)
	if ok, _ := s.zeroClickGate(a); !ok {
		t.Fatal("首次应放行")
	}
	if ok, _ := s.zeroClickGate(a); ok {
		t.Fatal("同指纹 30 分钟内应去重")
	}
	// 时间窗口推进：手工回拨 last 时间戳模拟窗口过期
	s.zc.mu.Lock()
	s.zc.fpLast[a.Fingerprint] = time.Now().Add(-zeroClickWindow - time.Minute)
	s.zc.mu.Unlock()
	if ok, _ := s.zeroClickGate(a); !ok {
		t.Fatal("窗口过期后应放行")
	}
}

func TestZeroClickGateHostCap(t *testing.T) {
	s := &AIService{}
	s.SetZeroClick(true, 2)
	mk := func(i int) *domain.Alert {
		return zcAlert("fp-cap-"+string(rune('a'+i)), "HOST-CAP", domain.SeverityCritical, domain.VerdictMalicious)
	}
	if ok, _ := s.zeroClickGate(mk(0)); !ok {
		t.Fatal("第 1 条应放行")
	}
	if ok, _ := s.zeroClickGate(mk(1)); !ok {
		t.Fatal("第 2 条应放行")
	}
	if ok, _ := s.zeroClickGate(mk(2)); ok {
		t.Fatal("第 3 条应触发每主机每小时上限")
	}
	// 不同主机不受影响
	if ok, _ := s.zeroClickGate(zcAlert("fp-other", "HOST-OTHER", domain.SeverityCritical, domain.VerdictMalicious)); !ok {
		t.Fatal("其他主机不应被殃及")
	}
}

func TestZeroClickDisabled(t *testing.T) {
	s := &AIService{}
	s.SetZeroClick(false, 3)
	if ok, _ := s.zeroClickGate(zcAlert("fp-x", "HOST-X", domain.SeverityCritical, domain.VerdictMalicious)); ok {
		t.Fatal("关闭后应一律不放行")
	}
}

// 上限非正数回退默认 3（防误配 0/负数把功能静默打死）。
func TestZeroClickMaxPerHostFallback(t *testing.T) {
	s := &AIService{}
	s.SetZeroClick(true, -1)
	if s.zc.maxPerHost != 3 {
		t.Fatalf("非正数应回退 3: %d", s.zc.maxPerHost)
	}
}
