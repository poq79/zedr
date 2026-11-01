package tunnel

import (
	"context"
	"math/rand/v2"
	"time"
)

// tunnelBackoff 管理 Manager 的重试节奏（契约 §3.3）。
//
// 两种模式：
//   - 正常：指数退避 1s→2s→…→30s 封顶，±20% 抖动（网络抖动/服务端重启）；
//   - 静默：对端不支持隧道（404/400，老版本服务端）时每小时一次——
//     这不是瞬时故障，按秒级重试只会刷出无穷日志。
//
// 模式翻转时的日志由 Manager 负责（它知道 agent 上下文，能记出有用的字段）。
// 非并发安全：仅 Manager 的循环 goroutine 使用，故意不加锁。
type tunnelBackoff struct {
	base        time.Duration
	max         time.Duration
	jitterFrac  float64
	attempt     int
	unsupported bool
}

func newTunnelBackoff(base, max time.Duration, jitterFrac float64) *tunnelBackoff {
	if base <= 0 {
		base = time.Second
	}
	if max < base {
		max = base
	}
	if jitterFrac < 0 {
		jitterFrac = 0
	}
	return &tunnelBackoff{base: base, max: max, jitterFrac: jitterFrac}
}

// bump 记一次失败，把退避推进一格。
func (b *tunnelBackoff) bump() {
	// attempt 有界：rawDelay 里的倍增循环在 d 达到 max 后提前退出，
	// 这里只防 attempt 无限增长占内存
	if b.attempt < 64 {
		b.attempt++
	}
}

// reset 清零退避（健康长会话结束后调用）。
func (b *tunnelBackoff) reset() { b.attempt = 0 }

// delay 返回当前档位的等待时长（读操作，不推进游标）。
// attempt 记录已失败次数，档位 = attempt-1：首次失败等 base，
// 之后逐次翻倍直到 max。
func (b *tunnelBackoff) delay() time.Duration {
	d := b.base
	for i := 1; i < b.attempt && d < b.max; i++ {
		d *= 2
	}
	if d > b.max {
		d = b.max
	}
	return jitterDur(d, b.jitterFrac)
}

// setUnsupported 切换静默模式；返回 true 表示本次调用造成了翻转
// （调用方据此记一次日志）。翻回正常时同时清零退避——对端升级完
// 服务端的第一次重连不该背上历史退避。
func (b *tunnelBackoff) setUnsupported(v bool) bool {
	if b.unsupported == v {
		return false
	}
	b.unsupported = v
	if !v {
		b.attempt = 0
	}
	return true
}

// jitterDur 对 d 施加 ±frac 的均匀抖动：把大量探针的重连尝试在时间轴上
// 摊开，避免服务端恢复瞬间被同步洪水打垮（thundering herd）。
func jitterDur(d time.Duration, frac float64) time.Duration {
	if frac <= 0 || d <= 0 {
		return d
	}
	f := 1 - frac + 2*frac*rand.Float64() // 均匀分布 [1-frac, 1+frac]
	return time.Duration(float64(d) * f)
}

// sleepCtx 可被 ctx 取消的睡眠；返回 false 表示 ctx 已取消（应立即退出）。
func sleepCtx(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		select {
		case <-ctx.Done():
			return false
		default:
			return true
		}
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}
