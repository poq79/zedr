package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"zedr/internal/server/domain"
)

type incidentRepo struct{ s *Store }

const incidentCols = `id, agent_id, hostname, title, peak_severity, max_score, alert_count,
	open_count, status, processes, rule_ids, mitre, first_seen, last_seen,
	first_action_at, resolved_at, note, updated_at`

func scanIncident(sc interface{ Scan(...any) error }) (*domain.Incident, error) {
	var (
		inc        domain.Incident
		peak, st   string
		procs, rls, mitre string
		first, last, updated int64
		firstAction, resolved sql.NullInt64
	)
	if err := sc.Scan(&inc.ID, &inc.AgentID, &inc.Hostname, &inc.Title, &peak, &inc.MaxScore,
		&inc.AlertCount, &inc.OpenCount, &st, &procs, &rls, &mitre,
		&first, &last, &firstAction, &resolved, &inc.Note, &updated); err != nil {
		return nil, err
	}
	inc.PeakSeverity = peak
	inc.Status = domain.IncidentStatus(st)
	inc.Processes = splitCSV(procs)
	inc.RuleIDs = splitCSV(rls)
	inc.MITRE = splitCSV(mitre)
	inc.FirstSeen = fromMillis(first)
	inc.LastSeen = fromMillis(last)
	inc.FirstActionAt = fromNullMillis(firstAction)
	inc.ResolvedAt = fromNullMillis(resolved)
	inc.UpdatedAt = fromMillis(updated)
	return &inc, nil
}

// UpsertBatch 批量同步事件。状态保护语义：
//   - 已离开 open 的事件（investigating/contained/resolved）只刷新观测字段
//     （告警计数/last_seen/max_score 等），人工状态、first_action_at、
//     resolved_at、note 一律保留——同步永远不能覆盖人工处置；
//   - 不存在或仍处 open 的事件整体覆盖。
func (r *incidentRepo) UpsertBatch(ctx context.Context, items []domain.Incident) error {
	if len(items) == 0 {
		return nil
	}
	tx, err := r.s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("开启事件同步事务失败: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	for i := range items {
		inc := &items[i]
		var curStatus string
		err := tx.QueryRowContext(ctx, `SELECT status FROM incidents WHERE id = ?`, inc.ID).Scan(&curStatus)
		switch {
		case errors.Is(err, sql.ErrNoRows):
			if _, err := tx.ExecContext(ctx,
				`INSERT INTO incidents(`+incidentCols+`) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
				inc.ID, inc.AgentID, inc.Hostname, inc.Title, inc.PeakSeverity, inc.MaxScore,
				inc.AlertCount, inc.OpenCount, string(inc.Status), joinCSV(inc.Processes),
				joinCSV(inc.RuleIDs), joinCSV(inc.MITRE), millis(inc.FirstSeen), millis(inc.LastSeen),
				nil, nil, inc.Note, millis(inc.UpdatedAt)); err != nil {
				return fmt.Errorf("写入事件失败: %w", err)
			}
		case err != nil:
			return fmt.Errorf("查询事件状态失败: %w", err)
		case domain.IncidentStatus(curStatus) == domain.IncidentOpen:
			if _, err := tx.ExecContext(ctx,
				`UPDATE incidents SET title=?, peak_severity=?, max_score=?, alert_count=?,
				 open_count=?, processes=?, rule_ids=?, mitre=?, last_seen=?, updated_at=? WHERE id=?`,
				inc.Title, inc.PeakSeverity, inc.MaxScore, inc.AlertCount, inc.OpenCount,
				joinCSV(inc.Processes), joinCSV(inc.RuleIDs), joinCSV(inc.MITRE),
				millis(inc.LastSeen), millis(inc.UpdatedAt), inc.ID); err != nil {
				return fmt.Errorf("刷新事件失败: %w", err)
			}
		default:
			// 人工已介入：只刷新观测字段，状态与处置时间戳不动
			if _, err := tx.ExecContext(ctx,
				`UPDATE incidents SET alert_count=?, open_count=?, last_seen=?, updated_at=? WHERE id=?`,
				inc.AlertCount, inc.OpenCount, millis(inc.LastSeen), millis(inc.UpdatedAt), inc.ID); err != nil {
				return fmt.Errorf("刷新已处置事件失败: %w", err)
			}
		}
	}
	return tx.Commit()
}

func (r *incidentRepo) List(ctx context.Context, status string, page, pageSize int) ([]domain.Incident, int, error) {
	if page <= 0 {
		page = 1
	}
	if pageSize <= 0 || pageSize > 200 {
		pageSize = 50
	}
	where := ""
	args := []any{}
	if status != "" {
		where = " WHERE status = ?"
		args = append(args, status)
	}
	var total int
	if err := r.s.db.QueryRowContext(ctx, `SELECT COUNT(1) FROM incidents`+where, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("统计事件失败: %w", err)
	}
	rows, err := r.s.db.QueryContext(ctx,
		`SELECT `+incidentCols+` FROM incidents`+where+
			` ORDER BY last_seen DESC LIMIT ? OFFSET ?`,
		append(args, pageSize, (page-1)*pageSize)...)
	if err != nil {
		return nil, 0, fmt.Errorf("查询事件失败: %w", err)
	}
	defer rows.Close()
	var out []domain.Incident
	for rows.Next() {
		inc, err := scanIncident(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, *inc)
	}
	return out, total, rows.Err()
}

func (r *incidentRepo) ByID(ctx context.Context, id string) (*domain.Incident, error) {
	row := r.s.db.QueryRowContext(ctx, `SELECT `+incidentCols+` FROM incidents WHERE id = ?`, id)
	inc, err := scanIncident(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("查询事件失败: %w", err)
	}
	return inc, nil
}

// UpdateStatus 推进状态机。首次离开 open 记 first_action_at（MTTA 分子），
// 进入 resolved 记 resolved_at。非法回退由服务层拦截，这里只管写。
func (r *incidentRepo) UpdateStatus(ctx context.Context, id string, status domain.IncidentStatus, note string, at time.Time) error {
	res, err := r.s.db.ExecContext(ctx,
		`UPDATE incidents SET
		   status = ?,
		   first_action_at = COALESCE(first_action_at, CASE WHEN ? <> 'open' THEN ? END),
		   resolved_at = CASE WHEN ? = 'resolved' THEN ? ELSE resolved_at END,
		   note = CASE WHEN ? <> '' THEN ? ELSE note END,
		   updated_at = ?
		 WHERE id = ?`,
		string(status), string(status), millis(at), string(status), millis(at),
		note, note, millis(at), id)
	if err != nil {
		return fmt.Errorf("更新事件状态失败: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (r *incidentRepo) CountByStatus(ctx context.Context) (map[string]int, error) {
	rows, err := r.s.db.QueryContext(ctx, `SELECT status, COUNT(1) FROM incidents GROUP BY status`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var st string
		var n int
		if err := rows.Scan(&st, &n); err != nil {
			return nil, err
		}
		out[st] = n
	}
	return out, rows.Err()
}

// AvgFirstActionMinutes 计算"事件创建→首次人工动作"的平均分钟数（MTTA）。
// 只统计时间窗内已有 first_action_at 的事件——没有动作就没有时延可言。
func (r *incidentRepo) AvgFirstActionMinutes(ctx context.Context, since time.Time) (float64, error) {
	var avg float64
	err := r.s.db.QueryRowContext(ctx,
		`SELECT COALESCE(AVG((first_action_at - first_seen) / 60000.0), 0)
		 FROM incidents WHERE first_action_at IS NOT NULL AND first_seen >= ?`,
		millis(since)).Scan(&avg)
	if err != nil && !strings.Contains(err.Error(), "no rows") {
		return 0, fmt.Errorf("统计 MTTA 失败: %w", err)
	}
	return avg, nil
}
