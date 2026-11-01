package sqlite

import (
	"context"
	"fmt"
	"time"

	"hostguard/internal/server/domain"
)

type statsRepo struct{ s *Store }

func (r *statsRepo) Dashboard(ctx context.Context, since time.Time, bucketMinutes int) (*domain.DashboardSummary, error) {
	if bucketMinutes <= 0 {
		bucketMinutes = 60
	}
	out := &domain.DashboardSummary{
		SeverityDist: map[string]int{},
		Timeline:     []domain.TimelinePoint{},
		TopHosts:     []domain.HostAlertStat{},
		TopRules:     []domain.RuleStat{},
		TopMITRE:     []domain.MITREStat{},
	}

	// 主机总量 / 在线数
	if err := r.s.db.QueryRowContext(ctx,
		`SELECT COUNT(1), COALESCE(SUM(CASE WHEN status = 'online' THEN 1 ELSE 0 END), 0) FROM agents`).
		Scan(&out.TotalHosts, &out.OnlineHosts); err != nil {
		return nil, fmt.Errorf("统计主机失败: %w", err)
	}

	// 24h 告警量、未处置、严重未处置、恶意判定、误报
	sinceMs := millis(since)
	if err := r.s.db.QueryRowContext(ctx,
		`SELECT
		   COALESCE(SUM(CASE WHEN created_at >= ? THEN 1 ELSE 0 END), 0),
		   COALESCE(SUM(CASE WHEN status = 'open' THEN 1 ELSE 0 END), 0),
		   COALESCE(SUM(CASE WHEN status = 'open' AND severity = 'critical' THEN 1 ELSE 0 END), 0),
		   COALESCE(SUM(CASE WHEN verdict = 'malicious' THEN 1 ELSE 0 END), 0),
		   COALESCE(SUM(CASE WHEN status = 'false_positive' THEN 1 ELSE 0 END), 0),
		   COALESCE(AVG(score), 0)
		 FROM alerts`, sinceMs).
		Scan(&out.Alerts24h, &out.OpenAlerts, &out.CriticalOpen, &out.MaliciousCount,
			&out.FalsePositive, &out.AvgScore); err != nil {
		return nil, fmt.Errorf("统计告警失败: %w", err)
	}

	// MTTR：过去 7 天已处置告警的平均处置时长（分钟）。
	// handled_at - created_at 直接在 SQL 里算，避免把全部告警拉回内存。
	if err := r.s.db.QueryRowContext(ctx,
		`SELECT COALESCE(AVG((handled_at - created_at) / 60000.0), 0)
		 FROM alerts
		 WHERE handled_at IS NOT NULL AND created_at >= ?`, millis(time.Now().Add(-7*24*time.Hour))).
		Scan(&out.AvgResponseMin); err != nil {
		return nil, fmt.Errorf("统计 MTTR 失败: %w", err)
	}

	// 严重度分布
	rows, err := r.s.db.QueryContext(ctx, `SELECT severity, COUNT(1) FROM alerts GROUP BY severity`)
	if err != nil {
		return nil, fmt.Errorf("统计严重度失败: %w", err)
	}
	for rows.Next() {
		var sev string
		var n int
		if err := rows.Scan(&sev, &n); err != nil {
			rows.Close()
			return nil, err
		}
		out.SeverityDist[sev] = n
	}
	rows.Close()

	// 时间轴（按 bucket 聚合）
	rowsl, err := r.s.db.QueryContext(ctx,
		`SELECT (created_at / ?) * ? AS bucket, COUNT(1),
		        COALESCE(SUM(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END), 0)
		 FROM alerts WHERE created_at >= ?
		 GROUP BY bucket ORDER BY bucket ASC`,
		int64(bucketMinutes)*60*1000, int64(bucketMinutes)*60*1000, sinceMs)
	if err != nil {
		return nil, fmt.Errorf("统计时间轴失败: %w", err)
	}
	for rowsl.Next() {
		var (
			bucket int64
			total  int
			crit   int
		)
		if err := rowsl.Scan(&bucket, &total, &crit); err != nil {
			rowsl.Close()
			return nil, err
		}
		out.Timeline = append(out.Timeline, domain.TimelinePoint{
			Bucket:   fromMillis(bucket).Format(time.RFC3339),
			Total:    total,
			Critical: crit,
		})
	}
	rowsl.Close()

	// 主机排行
	rowsh, err := r.s.db.QueryContext(ctx,
		`SELECT agent_id, hostname, COUNT(1) AS c,
		        COALESCE(SUM(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END), 0)
		 FROM alerts GROUP BY agent_id ORDER BY c DESC LIMIT 8`)
	if err != nil {
		return nil, fmt.Errorf("统计主机排行失败: %w", err)
	}
	for rowsh.Next() {
		var st domain.HostAlertStat
		if err := rowsh.Scan(&st.AgentID, &st.Hostname, &st.Count, &st.Critical); err != nil {
			rowsh.Close()
			return nil, err
		}
		out.TopHosts = append(out.TopHosts, st)
	}
	rowsh.Close()

	// 规则排行：rule_ids 是逗号分隔串，在应用层聚合
	rowsr, err := r.s.db.QueryContext(ctx, `SELECT rule_ids FROM alerts WHERE rule_ids <> ''`)
	if err != nil {
		return nil, fmt.Errorf("统计规则命中失败: %w", err)
	}
	ruleCount := map[string]int{}
	for rowsr.Next() {
		var ids string
		if err := rowsr.Scan(&ids); err != nil {
			rowsr.Close()
			return nil, err
		}
		for _, id := range splitCSV(ids) {
			ruleCount[id]++
		}
	}
	rowsr.Close()

	ruleNames := map[string]string{}
	rowsn, err := r.s.db.QueryContext(ctx, `SELECT id, name FROM rules`)
	if err == nil {
		for rowsn.Next() {
			var id, name string
			if err := rowsn.Scan(&id, &name); err == nil {
				ruleNames[id] = name
			}
		}
		rowsn.Close()
	}
	for id, n := range ruleCount {
		name := ruleNames[id]
		if name == "" {
			name = id
		}
		out.TopRules = append(out.TopRules, domain.RuleStat{RuleID: id, Name: name, Count: n})
	}
	out.TopRules = sortRuleStats(out.TopRules, 10)

	// MITRE 排行
	rowsm, err := r.s.db.QueryContext(ctx, `SELECT mitre FROM alerts WHERE mitre <> ''`)
	if err != nil {
		return nil, fmt.Errorf("统计 MITRE 失败: %w", err)
	}
	mitreCount := map[string]int{}
	for rowsm.Next() {
		var m string
		if err := rowsm.Scan(&m); err != nil {
			rowsm.Close()
			return nil, err
		}
		for _, t := range splitCSV(m) {
			mitreCount[t]++
		}
	}
	rowsm.Close()
	for t, n := range mitreCount {
		out.TopMITRE = append(out.TopMITRE, domain.MITREStat{Tech: t, Count: n})
	}
	out.TopMITRE = sortMITREStats(out.TopMITRE, 10)

	return out, nil
}

func sortRuleStats(s []domain.RuleStat, limit int) []domain.RuleStat {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j].Count > s[j-1].Count; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
	if len(s) > limit {
		return s[:limit]
	}
	return s
}

func sortMITREStats(s []domain.MITREStat, limit int) []domain.MITREStat {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j].Count > s[j-1].Count; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
	if len(s) > limit {
		return s[:limit]
	}
	return s
}


// VersionDist 统计各终端探针版本分布。
// 版本碎片化是企业部署最现实的问题：旧版本终端的检测能力矩阵
// 与新版本不同，管理经理需要一眼看到"还有多少台在旧版本"。
func (r *statsRepo) VersionDist(ctx context.Context) (map[string]int, error) {
	rows, err := r.s.db.QueryContext(ctx,
		`SELECT COALESCE(version,''), COUNT(1) FROM agents GROUP BY version`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var v string
		var n int
		if err := rows.Scan(&v, &n); err != nil {
			return nil, err
		}
		if v == "" {
			v = "unknown"
		}
		out[v] = n
	}
	return out, rows.Err()
}
