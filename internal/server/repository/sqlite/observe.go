package sqlite

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// observeRepo 是 rule/ioc/allow 三张命中快照表的通用实现。
// 快照 REPLACE 语义的设计动机见 ObserveRepo 接口注释。
type observeRepo struct {
	s     *Store
	table string
}

func (r *observeRepo) ReplaceForAgent(ctx context.Context, agentID string, stats map[string]int64, at time.Time) error {
	tx, err := r.s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("开启命中计数事务失败: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	for key, hits := range stats {
		if key == "" || hits < 0 {
			continue
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO `+r.table+`(agent_id, obs_key, hits, updated_at) VALUES(?,?,?,?)
			 ON CONFLICT(agent_id, obs_key) DO UPDATE SET hits = excluded.hits, updated_at = excluded.updated_at`,
			agentID, key, hits, millis(at)); err != nil {
			return fmt.Errorf("写入命中计数失败: %w", err)
		}
	}
	// 清理该终端不再上报的 key（转正/删除/停用后残留行会让汇总虚高）
	if len(stats) > 0 {
		phs := make([]string, 0, len(stats))
		args := make([]any, 0, len(stats)+1)
		for key := range stats {
			phs = append(phs, "?")
			args = append(args, key)
		}
		args = append(args, agentID)
		q := `DELETE FROM ` + r.table + ` WHERE obs_key NOT IN (` + strings.Join(phs, ",") + `) AND agent_id = ?`
		if _, err := tx.ExecContext(ctx, q, args...); err != nil {
			return fmt.Errorf("清理命中计数失败: %w", err)
		}
	} else {
		if _, err := tx.ExecContext(ctx, `DELETE FROM `+r.table+` WHERE agent_id = ?`, agentID); err != nil {
			return fmt.Errorf("清理命中计数失败: %w", err)
		}
	}
	return tx.Commit()
}

func (r *observeRepo) SumByKey(ctx context.Context) (map[string]int64, error) {
	rows, err := r.s.db.QueryContext(ctx,
		`SELECT obs_key, SUM(hits) FROM `+r.table+` GROUP BY obs_key`)
	if err != nil {
		return nil, fmt.Errorf("汇总命中计数失败: %w", err)
	}
	defer rows.Close()
	out := make(map[string]int64)
	for rows.Next() {
		var key string
		var hits int64
		if err := rows.Scan(&key, &hits); err != nil {
			return nil, fmt.Errorf("解析命中计数失败: %w", err)
		}
		out[key] = hits
	}
	return out, rows.Err()
}
