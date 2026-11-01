package service

import (
	"context"
	"runtime"
	"sort"
	"time"

	"hostguard/internal/model"
	"hostguard/internal/server/domain"
)

// ---------------------------------------------------------------- /metrics

// MetricsSnapshot 是 /metrics 端点需要的全部数值。
// 一次性取齐，handler 只负责渲染，避免在文本输出里散落数据库调用。
type MetricsSnapshot struct {
	TotalHosts  int
	OnlineHosts int
	Alerts24h   int
	OpenAlerts  int
	CriticalOpen int
	SeverityDist map[string]int
	AvgScore     float64

	WebhookSent    int64
	WebhookFailed  int64
	WebhookDropped int64

	Goroutines int
	HeapAlloc  uint64
	UptimeSec  float64
}

// Metrics 组装指标快照。
//
// 数据全部来自已有的 Dashboard 聚合（一次 SQL 组查询）与运行时状态，
// 不为新端点增加专门查询——监控指标的实时性要求是秒级，这个开销可忽略。
func (s *StatsService) Metrics(ctx context.Context, startedAt time.Time, wh SentFailedDropped) *MetricsSnapshot {
	m := &MetricsSnapshot{SeverityDist: map[string]int{}}

	if d, err := s.Dashboard(ctx, 24*time.Hour, time.Hour); err == nil && d != nil {
		m.TotalHosts = d.TotalHosts
		m.OnlineHosts = d.OnlineHosts
		m.Alerts24h = d.Alerts24h
		m.OpenAlerts = d.OpenAlerts
		m.CriticalOpen = d.CriticalOpen
		m.SeverityDist = d.SeverityDist
		m.AvgScore = d.AvgScore
	}

	m.WebhookSent, m.WebhookFailed, m.WebhookDropped = wh()

	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	m.Goroutines = runtime.NumGoroutine()
	m.HeapAlloc = ms.HeapAlloc
	m.UptimeSec = time.Since(startedAt).Seconds()

	return m
}

// SentFailedDropped 是 webhook 统计的取值函数（nil 安全由实现方保证）。
type SentFailedDropped func() (sent, failed, dropped int64)

// ---------------------------------------------------------------- 事件聚合

// Incident 是一次"疑似同一活动"的告警聚类。
//
// 聚类规则刻意简单：同主机、相邻告警间隔 ≤ 30 分钟即归入同一事件。
// 更复杂的关联（父子进程、同指纹、同 MITRE 战术链）需要持久化事件表
// 和状态机，属于规模化后的演进方向；在当前规模下，这个启发式
// 已经能把"扫一场 attack 的 8 条告警"合成 1 个事件，运维收益最大。
const incidentGap = 30 * time.Minute

// Incident 是聚合后的视图。
type Incident struct {
	ID            string   `json:"id"`
	Hostname      string   `json:"hostname"`
	AlertCount    int      `json:"alert_count"`
	PeakSeverity  string   `json:"peak_severity"`
	MaxScore      int      `json:"max_score"`
	OpenCount     int      `json:"open_count"`
	MITRE         []string `json:"mitre"`
	Processes     []string `json:"processes"`
	RuleIDs       []string `json:"rule_ids"`
	StartedAt     time.Time `json:"started_at"`
	LastAt        time.Time `json:"last_at"`
	DurationSec   int      `json:"duration_sec"`
	AlertIDs      []string `json:"alert_ids"`
}

// ListIncidents 把未处置告警聚合成事件视图。
//
// 排序口径：活跃度（最近告警时间倒序）——值班场景最先要看的是
// "正在发生什么"，而不是"最大的事件是什么"。
func (s *StatsService) ListIncidents(ctx context.Context, limit int) ([]Incident, error) {
	if limit <= 0 || limit > 100 {
		limit = 50
	}

	// 只聚合未处置的：已处置/误报不再构成"正在进行的事件"
	alerts, _, err := s.repos.Alerts.List(ctx, domain.AlertFilter{
		Status:   []domain.AlertStatus{model.StatusOpen, model.StatusAcknowledged},
		Page:     1,
		PageSize: 200,
		Sort:     "oldest",
	})
	if err != nil {
		return nil, err
	}

	// 按主机分组（List 按 created_at 升序返回，同主机内时间有序）
	byHost := map[string][]domain.Alert{}
	order := []string{}
	for _, a := range alerts {
		if _, ok := byHost[a.Hostname]; !ok {
			order = append(order, a.Hostname)
		}
		byHost[a.Hostname] = append(byHost[a.Hostname], a)
	}

	out := make([]Incident, 0, 8)
	for _, host := range order {
		groups := clusterByGap(byHost[host], incidentGap)
		for _, g := range groups {
			out = append(out, buildIncident(host, g))
		}
	}

	// 最近活跃的排前面
	sort.Slice(out, func(i, j int) bool { return out[i].LastAt.After(out[j].LastAt) })
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

// clusterByGap 把时间有序的告警切成簇：相邻间隔超过 gap 即断开。
func clusterByGap(alerts []domain.Alert, gap time.Duration) [][]domain.Alert {
	var groups [][]domain.Alert
	cur := []domain.Alert{alerts[0]}
	for i := 1; i < len(alerts); i++ {
		if alerts[i].CreatedAt.Sub(alerts[i-1].CreatedAt) > gap {
			groups = append(groups, cur)
			cur = []domain.Alert{alerts[i]}
		} else {
			cur = append(cur, alerts[i])
		}
	}
	return append(groups, cur)
}

func buildIncident(host string, group []domain.Alert) Incident {
	inc := Incident{
		Hostname:  host,
		AlertCount: len(group),
		AlertIDs:  make([]string, 0, len(group)),
		StartedAt: group[0].CreatedAt,
		LastAt:    group[len(group)-1].CreatedAt,
		MITRE:     []string{},
		Processes: []string{},
		RuleIDs:   []string{},
	}
	inc.DurationSec = int(inc.LastAt.Sub(inc.StartedAt).Seconds())

	severityRank := map[string]int{"low": 0, "medium": 1, "high": 2, "critical": 3}
	seenProc := map[string]bool{}
	seenRule := map[string]bool{}
	seenMITRE := map[string]bool{}

	for _, a := range group {
		if severityRank[string(a.Severity)] >= severityRank[inc.PeakSeverity] {
			inc.PeakSeverity = string(a.Severity)
		}
		if a.Score > inc.MaxScore {
			inc.MaxScore = a.Score
		}
		if a.Status == model.StatusOpen {
			inc.OpenCount++
		}
		if !seenProc[a.ProcessName] {
			seenProc[a.ProcessName] = true
			inc.Processes = append(inc.Processes, a.ProcessName)
		}
		for _, r := range a.RuleIDs {
			if !seenRule[r] {
				seenRule[r] = true
				inc.RuleIDs = append(inc.RuleIDs, r)
			}
		}
		for _, m := range a.MITRE {
			if !seenMITRE[m] {
				seenMITRE[m] = true
				inc.MITRE = append(inc.MITRE, m)
			}
		}
		inc.AlertIDs = append(inc.AlertIDs, a.ID)
	}

	inc.ID = host + "@" + inc.StartedAt.Format("20060102-1504")
	return inc
}
