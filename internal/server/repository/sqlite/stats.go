package sqlite

import (
	"context"
	"fmt"
	"os"
	"time"

	"zedr/internal/server/domain"
)

type statsRepo struct{ s *Store }

// Dashboard 返回管理台首页聚合。
//
// 口径分两类，改字段前先确认属于哪类：
//   - 窗口内（created_at >= since，管理台默认传 24h）：告警量/未处置/MTTR、
//     时间轴、主机排行、规则命中、MITRE 排行。这些查询必须带时间下界——
//     告警表只增不减，无下界的聚合是全表扫，是服务端越跑越慢的主因之一。
//   - 全量：主机总数/在线数（agents 是小表）；严重度分布 SeverityDist 是
//     "库存"语义（全部历史告警的构成），刻意不随窗口收敛，见查询处注释。
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

	// 严重度分布（全量口径，刻意不加时间下界）：这是"库存"语义——
	// 管理台要回答的是"库里所有告警的严重度构成"，与排行类查询的
	// 窗口语义不同；加下界反而会让分布随时间漂移，失去库存含义。
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

	// 主机排行（窗口内）：排行关心的是"最近谁在报警"，全量口径没有运营价值；
	// 不带时间下界就是全表扫，库越大越慢，故随 since 收敛。
	rowsh, err := r.s.db.QueryContext(ctx,
		`SELECT agent_id, hostname, COUNT(1) AS c,
		        COALESCE(SUM(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END), 0)
		 FROM alerts WHERE created_at >= ?
		 GROUP BY agent_id ORDER BY c DESC LIMIT 8`, sinceMs)
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

	// 规则排行（窗口内）：rule_ids 是逗号分隔串，在应用层聚合。
	// 这条本来就逐行扫 rule_ids 列，加时间下界后扫描量随窗口收敛，
	// 老库上曾是无界全扫（规模债）。
	rowsr, err := r.s.db.QueryContext(ctx,
		`SELECT rule_ids FROM alerts WHERE rule_ids <> '' AND created_at >= ?`, sinceMs)
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

	// MITRE 排行（窗口内）：与 MitreAgg 同口径（created_at >= since），
	// 老的无界扫描同样随库增长退化成全表扫。
	rowsm, err := r.s.db.QueryContext(ctx,
		`SELECT mitre FROM alerts WHERE mitre <> '' AND created_at >= ?`, sinceMs)
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

// MitreAgg 按技术编号聚合时间窗内的告警计数。
// mitre 列是 CSV（如 "T1059.001,T1027"），在应用层拆分后合并——
// 与 Dashboard 的 TopMITRE 同一策略：SQLite 侧不做字符串拆分，
// 避免 CSV 解析语义散落进 SQL。
// alertTotal 是窗口内带 MITRE 的告警条数（一条告警可命中多个技术，
// 按技术求和会重复计数，告警数必须单独统计）。
func (r *statsRepo) MitreAgg(ctx context.Context, since time.Time) (map[string]domain.MitreAgg, int, error) {
	rows, err := r.s.db.QueryContext(ctx,
		`SELECT mitre, COUNT(1),
		        COALESCE(SUM(CASE WHEN status = 'open' THEN 1 ELSE 0 END), 0),
		        COALESCE(SUM(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END), 0),
		        MAX(created_at)
		 FROM alerts WHERE mitre <> '' AND created_at >= ?
		 GROUP BY mitre`, millis(since))
	if err != nil {
		return nil, 0, fmt.Errorf("聚合 MITRE 统计失败: %w", err)
	}
	defer rows.Close()

	out := map[string]domain.MitreAgg{}
	for rows.Next() {
		var (
			mitre    string
			agg      domain.MitreAgg
			lastSeen int64
		)
		if err := rows.Scan(&mitre, &agg.Count, &agg.Open, &agg.Critical, &lastSeen); err != nil {
			return nil, 0, err
		}
		for _, t := range splitCSV(mitre) {
			if t == "" {
				continue
			}
			cur := out[t]
			cur.Count += agg.Count
			cur.Open += agg.Open
			cur.Critical += agg.Critical
			if ts := fromMillis(lastSeen); ts.After(cur.LastSeen) {
				cur.LastSeen = ts
			}
			out[t] = cur
		}
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}

	var alertTotal int
	if err := r.s.db.QueryRowContext(ctx,
		`SELECT COUNT(1) FROM alerts WHERE mitre <> '' AND created_at >= ?`, millis(since)).
		Scan(&alertTotal); err != nil {
		return nil, 0, fmt.Errorf("统计 MITRE 告警总数失败: %w", err)
	}
	return out, alertTotal, nil
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

// DBStats 数据库健康度快照（/metrics 的 zedr_db_* 指标源）。
// 全部是 O(1)/覆盖索引口径的只读查询：PRAGMA page_count/freelist_count
// 是头信息读取；按状态计数与 MIN(created_at) WHERE status='open' 走
// idx_alerts_status_created，不用全表扫。
func (r *statsRepo) DBStats(ctx context.Context) (*domain.DBStats, error) {
	out := &domain.DBStats{AlertsByStatus: map[string]int64{}}

	if fi, err := os.Stat(r.s.path); err == nil {
		out.FileBytes = fi.Size()
	}
	// WAL 文件可能不存在（刚 checkpoint 或库空闲后 SQLite 自删），缺省即 0
	if fi, err := os.Stat(r.s.path + "-wal"); err == nil {
		out.WALBytes = fi.Size()
	}

	var pageSize, pageCount, freePages int64
	for _, p := range []struct {
		name string
		dst  *int64
	}{{"page_size", &pageSize}, {"page_count", &pageCount}, {"freelist_count", &freePages}} {
		if err := r.s.db.QueryRowContext(ctx, "PRAGMA "+p.name).Scan(p.dst); err != nil {
			return nil, fmt.Errorf("PRAGMA %s: %w", p.name, err)
		}
	}
	out.FreeBytes = freePages * pageSize

	rows, err := r.s.db.QueryContext(ctx, `SELECT status, COUNT(*) FROM alerts GROUP BY status`)
	if err != nil {
		return nil, fmt.Errorf("统计告警行数: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var st string
		var n int64
		if err := rows.Scan(&st, &n); err != nil {
			return nil, err
		}
		if st == "" {
			st = "unknown"
		}
		out.AlertsByStatus[st] = n
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	var oldest int64
	if err := r.s.db.QueryRowContext(ctx,
		`SELECT COALESCE(MIN(created_at), 0) FROM alerts WHERE status = 'open'`).Scan(&oldest); err != nil {
		return nil, fmt.Errorf("查询最老 open 告警: %w", err)
	}
	if oldest > 0 {
		out.OldestOpenAgeSeconds = int64(time.Since(time.UnixMilli(oldest)).Seconds())
	} else {
		out.OldestOpenAgeSeconds = -1
	}
	return out, nil
}
