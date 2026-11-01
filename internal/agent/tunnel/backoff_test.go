package tunnel

import (
	"context"
	"testing"
	"time"
)

func TestBackoffExponentialSequence(t *testing.T) {
	// 抖动归零：序列必须严格是 1s→2s→…→30s 封顶（契约 §3.3）
	bo := newTunnelBackoff(time.Second, 30*time.Second, 0)
	want := []time.Duration{
		1 * time.Second, 2 * time.Second, 4 * time.Second,
		8 * time.Second, 16 * time.Second,
		30 * time.Second, 30 * time.Second, 30 * time.Second,
	}
	for i, w := range want {
		bo.bump()
		if got := bo.delay(); got != w {
			t.Fatalf("第 %d 次失败后的退避 = %v，期望 %v", i+1, got, w)
		}
	}
}

func TestBackoffJitterBounds(t *testing.T) {
	bo := newTunnelBackoff(time.Second, time.Minute, 0.2)
	bo.bump()
	for i := 0; i < 200; i++ {
		d := bo.delay()
		if d < 800*time.Millisecond || d > 1200*time.Millisecond {
			t.Fatalf("抖动越界：got %v，期望 [0.8s, 1.2s]", d)
		}
	}
}

func TestBackoffUnsupportedFlip(t *testing.T) {
	bo := newTunnelBackoff(time.Second, 30*time.Second, 0)

	if !bo.setUnsupported(true) {
		t.Fatal("首次切入静默模式应报告翻转")
	}
	if bo.setUnsupported(true) {
		t.Fatal("重复切入静默模式不应报告翻转（只记一次日志的依据）")
	}
	if !bo.unsupported {
		t.Fatal("静默标志未生效")
	}

	// 翻回正常后退避必须清零：对端修复后的第一次重连走最快路径
	bo.bump()
	bo.bump()
	if !bo.setUnsupported(false) {
		t.Fatal("翻回正常应报告翻转")
	}
	if got := bo.delay(); got != time.Second {
		t.Fatalf("翻回正常后首个退避 = %v，期望 1s（退避应已清零）", got)
	}
	if bo.setUnsupported(false) {
		t.Fatal("重复翻回正常不应报告翻转")
	}
}

func TestBackoffResetAfterHealthySession(t *testing.T) {
	bo := newTunnelBackoff(time.Second, 30*time.Second, 0)
	for i := 0; i < 6; i++ { // 爬到 30s 封顶
		bo.bump()
	}
	if got := bo.delay(); got != 30*time.Second {
		t.Fatalf("前置条件不成立：got %v", got)
	}
	bo.reset()
	if got := bo.delay(); got != time.Second {
		t.Fatalf("reset 后退避 = %v，期望 1s", got)
	}
}

func TestSleepCtxCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(10 * time.Millisecond)
		cancel()
	}()
	start := time.Now()
	if sleepCtx(ctx, time.Hour) {
		t.Fatal("ctx 取消后 sleepCtx 应返回 false")
	}
	if time.Since(start) > time.Second {
		t.Fatalf("取消未及时解除阻塞，耗时 %v", time.Since(start))
	}
}
