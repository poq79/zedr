package service

import (
	"context"
	"runtime"
	"sort"
	"time"

	"zedr/internal/model"
	"zedr/internal/server/domain"
)

// ---------------------------------------------------------------- /metrics

// MetricsSnapshot 是 /metrics 端点需要的全部数值。
// 一次性取齐，handler 只负责渲染，避免在文本输出里散落数据库调用。
type MetricsSnapshot struct {
	TotalHosts   int
	OnlineHosts  int
	OfflineHosts int
	Alerts24h    int
	OpenAlerts   int
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
	// 离线数从既有的总/在线口径推导，不加专门查询（与函数注释的取数纪律一致）。
	m.OfflineHosts = max(0, m.TotalHosts-m.OnlineHosts)

	m.WebhookSent, m.WebhookFailed, m.WebhookDropped = wh()

	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	m.Goroutines = runtime.NumGoroutine()
	m.HeapAlloc = ms.HeapAlloc
	m.UptimeSec = time.Since(startedAt).Seconds()

	return m
}

// DBMetrics 数据库健康度（/metrics 的 zedr_db_* 指标源）。薄透传——
// 保持控制器不碰 SQL 的分层约束。
func (s *StatsService) DBMetrics(ctx context.Context) (*domain.DBStats, error) {
	return s.repos.Stats.DBStats(ctx)
}

// Versions 查询终端版本分布。
func (s *StatsService) Versions(ctx context.Context) (map[string]int, error) {
	return s.repos.Stats.VersionDist(ctx)
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
	ID           string    `json:"id"`
	Hostname     string    `json:"hostname"`
	AlertCount   int       `json:"alert_count"`
	PeakSeverity string    `json:"peak_severity"`
	MaxScore     int       `json:"max_score"`
	OpenCount    int       `json:"open_count"`
	MITRE        []string  `json:"mitre"`
	Processes    []string  `json:"processes"`
	RuleIDs      []string  `json:"rule_ids"`
	StartedAt    time.Time `json:"started_at"`
	LastAt       time.Time `json:"last_at"`
	DurationSec  int       `json:"duration_sec"`
	AlertIDs     []string  `json:"alert_ids"`
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
		Hostname:   host,
		AlertCount: len(group),
		AlertIDs:   make([]string, 0, len(group)),
		StartedAt:  group[0].CreatedAt,
		LastAt:     group[len(group)-1].CreatedAt,
		MITRE:      []string{},
		Processes:  []string{},
		RuleIDs:    []string{},
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

// ---------------------------------------------------------------- 跨主机爆发

// Burst 是"同一个哈希在多台主机上同时出现"——横向移动 / 蠕虫式投递的强信号。
// 单台主机上无论多可疑都是端问题，同一份载荷同时出现在 N 台机器上
// 就是事件级问题，运营视角完全不同。
type Burst struct {
	Hash         string    `json:"hash"`
	Hosts        []string  `json:"hosts"`
	HostCount    int       `json:"host_count"`
	AlertCount   int       `json:"alert_count"`
	PeakSeverity string    `json:"peak_severity"`
	MaxScore     int       `json:"max_score"`
	TitleSample  string    `json:"title_sample"`
	FirstSeen    time.Time `json:"first_seen"`
}

// burstHostThreshold 是判定"爆发"的最低主机数。取 3 是保守值：
// 2 台可能是同事拷贝了同一个安装包，3 台以上同窗口出现同一份
// 未签名载荷就很难用正常运维解释。
const burstHostThreshold = 3

// ListBursts 在过去 24 小时的未处置告警里找跨主机爆发。
func (s *StatsService) ListBursts(ctx context.Context) ([]Burst, error) {
	alerts, _, err := s.repos.Alerts.List(ctx, domain.AlertFilter{
		Status:   []domain.AlertStatus{model.StatusOpen, model.StatusAcknowledged},
		Page:     1,
		PageSize: 200,
		Sort:     "oldest",
	})
	if err != nil {
		return nil, err
	}

	cutoff := time.Now().Add(-24 * time.Hour)
	type agg struct {
		hosts map[string]bool
		count int
		peak  string
		max   int
		title string
		first time.Time
	}
	byHash := map[string]*agg{}
	rank := map[string]int{"low": 0, "medium": 1, "high": 2, "critical": 3}

	for _, a := range alerts {
		if a.HashSHA256 == "" || a.CreatedAt.Before(cutoff) {
			continue
		}
		g := byHash[a.HashSHA256]
		if g == nil {
			g = &agg{hosts: map[string]bool{}}
			byHash[a.HashSHA256] = g
		}
		g.hosts[a.Hostname] = true
		g.count++
		if rank[string(a.Severity)] >= rank[g.peak] {
			g.peak = string(a.Severity)
		}
		if a.Score > g.max {
			g.max = a.Score
			g.title = a.Title
		}
		if g.first.IsZero() || a.CreatedAt.Before(g.first) {
			g.first = a.CreatedAt
		}
	}

	out := []Burst{}
	for hash, g := range byHash {
		if len(g.hosts) < burstHostThreshold {
			continue
		}
		hosts := make([]string, 0, len(g.hosts))
		for h := range g.hosts {
			hosts = append(hosts, h)
		}
		sort.Strings(hosts)
		out = append(out, Burst{
			Hash: hash, Hosts: hosts, HostCount: len(hosts),
			AlertCount: g.count, PeakSeverity: g.peak,
			MaxScore: g.max, TitleSample: g.title, FirstSeen: g.first,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].HostCount > out[j].HostCount })
	return out, nil
}

// ---------------------------------------------------------------- 规则误报率

// RuleFPStat 是单条规则的处置画像。
// 误报率 = false_positive / (resolved + false_positive)，只统计已处置的——
// 未处置的不该参与分母，否则"没人处理的规则"会显示 0% 误报。
type RuleFPStat struct {
	RuleID      string  `json:"rule_id"`
	Handled     int     `json:"handled"`
	FalsePos    int     `json:"false_pos"`
	FPRate      float64 `json:"fp_rate"`
	HandledRate float64 `json:"-"`
	// TuneCandidate 标记"调优候选"：已处置 ≥5 条且误报率 ≥80%——
	// 调研口径是"每规则 TP 率 <10% 进调优清单"（2026-11-06，
	// 来源见 overview.md），保守取 80% 起标，宁缺毋滥。
	TuneCandidate bool `json:"tune_candidate"`
}

// ListRuleFPStats 统计过去 window 内各规则的误报率，返回误报率最高的前 5 条
// （≥5 次处置才参与排序，避免"1 次误报 = 100%"的小样本噪音）。
func (s *StatsService) ListRuleFPStats(ctx context.Context, window time.Duration) ([]RuleFPStat, error) {
	alerts, _, err := s.repos.Alerts.List(ctx, domain.AlertFilter{
		Status: []domain.AlertStatus{model.StatusResolved, model.StatusFalsePositive},
		Page:   1, PageSize: 200, Sort: "oldest",
	})
	if err != nil {
		return nil, err
	}
	cutoff := time.Now().Add(-window)

	type acc struct{ handled, fp int }
	byRule := map[string]*acc{}
	for _, a := range alerts {
		if a.CreatedAt.Before(cutoff) {
			continue
		}
		for _, id := range a.RuleIDs {
			a2 := byRule[id]
			if a2 == nil {
				a2 = &acc{}
				byRule[id] = a2
			}
			a2.handled++
			if a.Status == model.StatusFalsePositive {
				a2.fp++
			}
		}
	}

	out := []RuleFPStat{}
	for id, a := range byRule {
		if a.handled < 5 {
			continue
		}
		fr := float64(a.fp) / float64(a.handled)
		out = append(out, RuleFPStat{
			RuleID: id, Handled: a.handled, FalsePos: a.fp,
			FPRate: fr, TuneCandidate: a.handled >= 5 && fr >= 0.8,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].FPRate > out[j].FPRate })
	if len(out) > 5 {
		out = out[:5]
	}
	return out, nil
}

// ---------------------------------------------------------------- 运营周报

// WeeklyReport 是给安全管理经理看的周期性汇总。
// 设计目标：一页纸回答四个问题——发生了什么、处置得怎么样、
// 哪些规则在制造噪音、有没有需要上报的爆发。
type WeeklyReport struct {
	WindowDays    int                    `json:"window_days"`
	GeneratedAt   time.Time              `json:"generated_at"`
	AlertsCreated int                    `json:"alerts_created"`
	AlertsHandled int                    `json:"alerts_handled"`
	FalsePositive int                    `json:"false_positive"`
	FPRate        float64                `json:"fp_rate"`
	MTTRMin       float64                `json:"mttr_min"`
	OpenAlerts    int                    `json:"open_alerts"`
	VerdictDist   map[string]int         `json:"verdict_dist"`
	SeverityDist  map[string]int         `json:"severity_dist"`
	TopRules      []domain.RuleStat      `json:"top_rules"`
	TopHosts      []domain.HostAlertStat `json:"top_hosts"`
	Bursts        []Burst                `json:"bursts"`
	FPRanking     []RuleFPStat           `json:"fp_ranking"`
}

// WeeklyReport 组装周期报表（窗口 7 天）。
func (s *StatsService) WeeklyReport(ctx context.Context, window time.Duration) (*WeeklyReport, error) {
	d, err := s.Dashboard(ctx, window, 6*time.Hour)
	if err != nil {
		return nil, err
	}
	bursts, err := s.ListBursts(ctx)
	if err != nil {
		return nil, err
	}
	fp, err := s.ListRuleFPStats(ctx, window)
	if err != nil {
		return nil, err
	}

	handled := 0
	verdicts := map[string]int{}
	// 窗口内画像：复用既有 List（最新 200 条覆盖 7 天足够），时间在 Go 端过滤
	list, _, err := s.repos.Alerts.List(ctx, domain.AlertFilter{Page: 1, PageSize: 200, Sort: "oldest"})
	if err == nil {
		cutoff := time.Now().Add(-window)
		for _, a := range list {
			if a.CreatedAt.Before(cutoff) {
				continue
			}
			verdicts[string(a.Verdict)]++
			if a.Status == model.StatusResolved || a.Status == model.StatusFalsePositive {
				handled++
			}
		}
	}

	r := &WeeklyReport{
		WindowDays:    int(window.Hours() / 24),
		GeneratedAt:   time.Now().UTC(),
		AlertsCreated: d.Alerts24h, // Dashboard 字段名是 24h，语义是"窗口内新增"
		OpenAlerts:    d.OpenAlerts,
		FalsePositive: d.FalsePositive,
		MTTRMin:       d.AvgResponseMin,
		VerdictDist:   verdicts,
		SeverityDist:  d.SeverityDist,
		TopRules:      d.TopRules,
		TopHosts:      d.TopHosts,
		Bursts:        bursts,
		FPRanking:     fp,
	}
	if handled > 0 {
		r.AlertsHandled = handled
		r.FPRate = float64(d.FalsePositive) / float64(handled)
	}
	return r, nil
}

// ---------------------------------------------------------------- 告警完整性链

// DayCheck 是一天告警的完整性校验结果。
type DayCheck struct {
	Day        string `json:"day"`
	Stored     string `json:"stored"`
	Recomputed string `json:"recomputed"`
	StoredN    int    `json:"stored_count"`
	CurrentN   int    `json:"current_count"`
	Status     string `json:"status"` // ok / purged / tampered
}

// EnsureIntegrity 把 day（本地时区日）的告警摘要归档进完整性链。
// 幂等：已归档的日期直接跳过——链的意义在于"归档后不可变"，
// 重复计算只会给事后篡改留口子。
func (s *StatsService) EnsureIntegrity(ctx context.Context, day time.Time) error {
	key := day.Format("2006-01-02")
	if _, n, exists, err := s.repos.Alerts.IntegrityGet(ctx, key); err != nil {
		return err
	} else if exists {
		_ = n
		return nil
	}
	start := time.Date(day.Year(), day.Month(), day.Day(), 0, 0, 0, 0, time.Local)
	end := start.Add(24 * time.Hour)
	digest, n, err := s.repos.Alerts.IntegrityDigest(ctx, start, end)
	if err != nil {
		return err
	}
	// 零告警的日子也归档：空日的存在本身是证据（"那天确实没有告警"）
	return s.repos.Alerts.IntegrityPut(ctx, key, digest, n)
}

// VerifyIntegrity 重算链中每一天的摘要并与归档值比对。
//
// 边界要诚实：retention 清理会移除旧告警，那些天重算必然不一致，
// 但特征是"条目数变少"，与"被篡改"（条目数不变而内容变）可区分——
// 两种情况分别标记为 purged 与 tampered，不做含糊的 fail。
func (s *StatsService) VerifyIntegrity(ctx context.Context) ([]DayCheck, error) {
	days, err := s.repos.Alerts.IntegrityDays(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]DayCheck, 0, len(days))
	for _, day := range days {
		d, err := time.ParseInLocation("2006-01-02", day, time.Local)
		if err != nil {
			continue
		}
		stored, storedN, _, err := s.repos.Alerts.IntegrityGet(ctx, day)
		if err != nil {
			return nil, err
		}
		start := time.Date(d.Year(), d.Month(), d.Day(), 0, 0, 0, 0, time.Local)
		recomputed, n, err := s.repos.Alerts.IntegrityDigest(ctx, start, start.Add(24*time.Hour))
		if err != nil {
			return nil, err
		}
		status := "ok"
		switch {
		case recomputed == stored:
			status = "ok"
		case n < storedN:
			status = "purged" // retention 正常清理
		default:
			status = "tampered"
		}
		out = append(out, DayCheck{
			Day: day, Stored: stored, Recomputed: recomputed,
			StoredN: storedN, CurrentN: n, Status: status,
		})
	}
	return out, nil
}
