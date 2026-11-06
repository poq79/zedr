package sqlite

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// ruleObserveRepo 观察模式命中计数（migration 009）。
// 快照 REPLACE 语义的设计动机见 RuleObserveRepo 接口注释。
type ruleObserveRepo struct{ s *Store }

func (r *ruleObserveRepo) ReplaceForAgent(ctx context.Context, agentID string, stats map[string]int64, at time.Time) error {
	tx, err := r.s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("开启观察计数事务失败: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	for id, hits := range stats {
		if id == "" || hits < 0 {
			continue
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO rule_observations(agent_id, rule_id, hits, updated_at) VALUES(?,?,?,?)
			 ON CONFLICT(agent_id, rule_id) DO UPDATE SET hits = excluded.hits, updated_at = excluded.updated_at`,
			agentID, id, hits, millis(at)); err != nil {
			return fmt.Errorf("写入观察计数失败: %w", err)
		}
	}
	// 清理该终端不再上报的规则（转正/删除/停用后残留行会让汇总虚高）
	if len(stats) > 0 {
		ids := make([]string, 0, len(stats))
		args := make([]any, 0, len(stats)+1)
		for id := range stats {
			ids = append(ids, "?")
			args = append(args, id)
		}
		args = append(args, agentID)
		q := `DELETE FROM rule_observations WHERE rule_id NOT IN (` + strings.Join(ids, ",") + `) AND agent_id = ?`
		if _, err := tx.ExecContext(ctx, q, args...); err != nil {
			return fmt.Errorf("清理观察计数失败: %w", err)
		}
	} else {
		// 空快照 = 该终端当前没有任何观察规则：清空其全部计数行
		if _, err := tx.ExecContext(ctx, `DELETE FROM rule_observations WHERE agent_id = ?`, agentID); err != nil {
			return fmt.Errorf("清理观察计数失败: %w", err)
		}
	}
	return tx.Commit()
}

func (r *ruleObserveRepo) SumByRule(ctx context.Context) (map[string]int64, error) {
	rows, err := r.s.db.QueryContext(ctx,
		`SELECT rule_id, SUM(hits) FROM rule_observations GROUP BY rule_id`)
	if err != nil {
		return nil, fmt.Errorf("汇总观察计数失败: %w", err)
	}
	defer rows.Close()
	out := make(map[string]int64)
	for rows.Next() {
		var id string
		var hits int64
		if err := rows.Scan(&id, &hits); err != nil {
			return nil, fmt.Errorf("解析观察计数失败: %w", err)
		}
		out[id] = hits
	}
	return out, rows.Err()
}
