package sqlite

import (
	"context"
	"database/sql"
	"time"

	"zedr/internal/server/domain"
)

// aiTriageRepo 是 AI 判定台账的 SQLite 实现。
// 按 (alert_id, source) UPSERT——同一条告警的 AI 结论重评会覆盖，
// 台账里每行都是"该来源当前怎么看这条告警"，不是历史流水
// （历史在审计日志里，这里是质量对账的"当前态"）。
type aiTriageRepo struct {
	s *Store
}

func (r *aiTriageRepo) Upsert(ctx context.Context, log *domain.AITriageLog) error {
	const q = `INSERT INTO ai_triage_log (alert_id, source, verdict, confidence, engine, created_at)
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT (alert_id, source) DO UPDATE SET
			verdict = excluded.verdict,
			confidence = excluded.confidence,
			engine = excluded.engine,
			created_at = excluded.created_at`
	_, err := r.s.db.ExecContext(ctx, q,
		log.AlertID, log.Source, log.Verdict, log.Confidence, log.Engine,
		log.CreatedAt.Unix())
	return err
}

func (r *aiTriageRepo) List(ctx context.Context, limit int) ([]domain.AITriageLog, error) {
	const q = `SELECT alert_id, source, verdict, confidence, engine, created_at
		FROM ai_triage_log ORDER BY created_at DESC LIMIT ?`
	rows, err := r.s.db.QueryContext(ctx, q, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []domain.AITriageLog{}
	for rows.Next() {
		var l domain.AITriageLog
		var unix int64
		var conf sql.NullFloat64
		if err := rows.Scan(&l.AlertID, &l.Source, &l.Verdict, &conf, &l.Engine, &unix); err != nil {
			return nil, err
		}
		l.Confidence = conf.Float64
		l.CreatedAt = time.Unix(unix, 0)
		out = append(out, l)
	}
	return out, rows.Err()
}
