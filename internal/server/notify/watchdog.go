package notify

// 通知看门狗（对标 yaklang/OpenXDR 的通知看门狗，RESEARCH-OPENXDR §7 P0-2）：
// 渠道连续失败时把"通知没送出去"变成可发现的状态，而不是等值班的人
// 发现"怎么飞书三天没消息了"（OpenXDR 2026-11 真实事故的断点）。
//
// 判定口径刻意保守：
//   - 只认"有失败且无成功"的观测窗——渠道混合成败说明没全坏；
//   - 静默窗（无发送也无失败）不推进 streak——没告警可发不算故障；
//   - dropped 不参与——防风暴丢弃是设计行为，不是渠道故障；
//   - 连续 N 个窗（默认 3，≈3 分钟）才判 degraded——排除单次网络抖动。
//
// 实现走 Stats() 轮询增量而不是改各渠道的发送路径：Channel 契约已有
// per-channel 计数，渠道实现零改动；代价是窗口粒度（60s tick）而非实时，
// 对"通知没人收到"这类分钟级问题足够。
//
// 已知边界（诚实声明）：syslog 是 UDP 无回执，"成功"只代表本地 socket
// 没报错，看门狗对它天然少报；IM/webhook/邮件渠道有 HTTP 状态回执，判定可信。

import (
	"sync"
	"time"
)

// NamedChannel 给渠道带上身份——Channel 接口没有 Name()，
// 装配点（app.go）天然知道每个渠道是谁，在那里绑定最省事。
type NamedChannel struct {
	Name    string
	Channel Channel
}

// ChannelHealth 是单渠道的看门狗快照。
type ChannelHealth struct {
	Name    string `json:"name"`
	Sent    int64  `json:"sent"`
	Failed  int64  `json:"failed"`
	Dropped int64  `json:"dropped"`
	Streak  int    `json:"streak"`  // 连续"有失败无成功"的观测窗数
	Degraded bool `json:"degraded"`
}

// Report 是 /notify/health 端点与管理台总览的看门狗快照。
type Report struct {
	Configured int             `json:"configured"` // 渠道数；0 = 通知未配置（不算故障，但要可见）
	State      string          `json:"state"`      // ok | degraded | unconfigured
	Channels   []ChannelHealth `json:"channels"`
}

// Transition 是一次观测里的状态翻转，供调用方打日志。
type Transition struct {
	Channel string
	To      string // ok | degraded
}

// Watchdog 轮询各渠道 Stats 增量，维护连续失败窗计数。
type Watchdog struct {
	mu        sync.Mutex
	chs       []NamedChannel
	prev      map[string][3]int64 // 渠道名 → 上次 (sent, failed, dropped)
	streaks   map[string]int
	since     map[string]time.Time // 进入 degraded 的时刻；无记录 = ok
	threshold int
}

// NewWatchdog 构建看门狗。threshold 是判 degraded 的连续失败窗数，>=1。
func NewWatchdog(chs []NamedChannel, threshold int) *Watchdog {
	if threshold < 1 {
		threshold = 1
	}
	prev := make(map[string][3]int64, len(chs))
	for _, nc := range chs {
		s, f, d := nc.Channel.Stats()
		prev[nc.Name] = [3]int64{s, f, d}
	}
	return &Watchdog{
		chs:       chs,
		prev:      prev,
		streaks:   make(map[string]int, len(chs)),
		since:     make(map[string]time.Time),
		threshold: threshold,
	}
}

// Observe 采样一轮所有渠道计数，推进/复位 streak，返回本轮状态翻转。
// 与 janitor 的 60s tick 同节奏调用即可。
func (w *Watchdog) Observe() []Transition {
	w.mu.Lock()
	defer w.mu.Unlock()

	var trans []Transition
	for _, nc := range w.chs {
		sent, failed, _ := nc.Channel.Stats()
		prev := w.prev[nc.Name]
		w.prev[nc.Name] = [3]int64{sent, failed, 0}

		switch {
		case sent > prev[0]:
			// 有成功就复位：渠道没全坏
			w.streaks[nc.Name] = 0
		case failed > prev[1]:
			// 有失败且无成功
			w.streaks[nc.Name]++
		}
		// 两增量皆 0：静默窗，streak 原样保留

		nowDegraded := w.streaks[nc.Name] >= w.threshold
		wasDegraded := w.since[nc.Name].IsZero() == false
		switch {
		case nowDegraded && !wasDegraded:
			w.since[nc.Name] = time.Now()
			trans = append(trans, Transition{Channel: nc.Name, To: "degraded"})
		case !nowDegraded && wasDegraded:
			delete(w.since, nc.Name)
			trans = append(trans, Transition{Channel: nc.Name, To: "ok"})
		}
	}
	return trans
}

// Report 当前快照。State：unconfigured（没配渠道）/ degraded（任一渠道
// 连续失败）/ ok。未配置不算故障——很多部署不用通知——但要可见，
// 让"以为配了通知其实没配"的错觉暴露出来。
func (w *Watchdog) Report() Report {
	w.mu.Lock()
	defer w.mu.Unlock()

	rep := Report{Configured: len(w.chs)}
	if len(w.chs) == 0 {
		rep.State = "unconfigured"
		return rep
	}
	rep.State = "ok"
	for _, nc := range w.chs {
		s, f, d := nc.Channel.Stats()
		ch := ChannelHealth{
			Name:    nc.Name,
			Sent:    s,
			Failed:  f,
			Dropped: d,
			Streak:  w.streaks[nc.Name],
			Degraded: w.streaks[nc.Name] >= w.threshold,
		}
		if ch.Degraded {
			rep.State = "degraded"
		}
		rep.Channels = append(rep.Channels, ch)
	}
	return rep
}
