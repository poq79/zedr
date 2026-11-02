// Package ingestguard 是终端告警上报入口的背压闸。
//
// 为什么需要它：终端凭证是长期有效的，一台被入侵/失控的终端可以
//
//   - 用合法凭证在几秒内灌入几十万条告警，把 SQLite 单写者打满，
//     所有主机的告警时间线一起停摆；
//   - 或者并发开几十个上报请求，让每条告警都去抢数据库连接。
//
// 这里做三件事（对应 Wazuh fastqueue / Velociraptor comms 的思想）：
//   - 每终端按"告警条数"限速（token bucket，不是按请求数）；
//   - 每终端同时只允许一个批次在写（同主机的告警天然串行）；
//   - 全局在途批次上限，保护 SQLite 单写者。
//
// 被拒绝的批次由终端 spool 保留并重试，不会丢数据——限流不是丢弃。
package ingestguard

import (
	"sync"
	"sync/atomic"

	"zedr/internal/platform/apperr"
	"zedr/internal/platform/httpx"
)

// Guard 是线程安全的入口闸。nil 值等价于不限制（老部署/测试）。
type Guard struct {
	bucket      *httpx.TokenBucket
	maxInflight int

	mu       sync.Mutex
	inflight map[string]int // agentID -> 在途批次数
	total    int

	allowed     atomic.Int64
	rateLimited atomic.Int64
	busy        atomic.Int64
	alerts      atomic.Int64
}

// Stats 是累计计数，供 /metrics 或排障日志使用。
type Stats struct {
	Allowed     int64 `json:"allowed"`
	RateLimited int64 `json:"rate_limited"`
	Busy        int64 `json:"busy"`
	Alerts      int64 `json:"alerts"`
	Inflight    int   `json:"inflight"`
}

// New 创建闸门。rps<=0 关闭速率限制；maxInflight<=0 使用默认 8。
func New(rps, burst float64, maxInflight int) *Guard {
	if maxInflight <= 0 {
		maxInflight = 8
	}
	if maxInflight > 64 {
		maxInflight = 64
	}
	return &Guard{
		bucket:      httpx.NewTokenBucket(rps, burst),
		maxInflight: maxInflight,
		inflight:    make(map[string]int),
	}
}

// Admit 尝试接收一个批次；成功返回 release，调用方必须 defer 调用。
//
// 拒绝语义：
//   - 429：终端上报速率超限（终端会保留 spool 并退避重试）；
//   - 503：同一终端已有批次在写，或全局在途批次打满。
func (g *Guard) Admit(agentID string, alerts int) (func(), error) {
	if g == nil {
		return func() {}, nil
	}
	if alerts <= 0 {
		return func() {}, nil
	}

	g.mu.Lock()
	if g.inflight[agentID] > 0 {
		g.mu.Unlock()
		g.busy.Add(1)
		return nil, apperr.Unavailable("该终端已有告警批次在处理中，请稍后重试")
	}
	if g.total >= g.maxInflight {
		g.mu.Unlock()
		g.busy.Add(1)
		return nil, apperr.Unavailable("服务端告警写入繁忙，请稍后重试")
	}
	g.inflight[agentID]++
	g.total++
	g.mu.Unlock()

	var once sync.Once
	release := func() {
		once.Do(func() {
			g.mu.Lock()
			g.inflight[agentID]--
			if g.inflight[agentID] <= 0 {
				delete(g.inflight, agentID)
			}
			g.total--
			g.mu.Unlock()
		})
	}
	// 在途槽拿到后再扣令牌：反过来的话，被忙碌拒绝的请求会白白吃掉速率额度。
	if !g.bucket.AllowN(agentID, float64(alerts)) {
		release()
		g.rateLimited.Add(1)
		return nil, apperr.TooManyRequests("告警上报速率超限，请降低频率后重试")
	}

	g.allowed.Add(1)
	g.alerts.Add(int64(alerts))
	return release, nil
}

// Stats 返回累计计数快照。
func (g *Guard) Stats() Stats {
	if g == nil {
		return Stats{}
	}
	g.mu.Lock()
	inflight := g.total
	g.mu.Unlock()
	return Stats{
		Allowed:     g.allowed.Load(),
		RateLimited: g.rateLimited.Load(),
		Busy:        g.busy.Load(),
		Alerts:      g.alerts.Load(),
		Inflight:    inflight,
	}
}
