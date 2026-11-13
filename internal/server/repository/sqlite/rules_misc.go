package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"zedr/internal/server/domain"
)

// ---------------------------------------------------------------- rules

type ruleRepo struct{ s *Store }

const ruleCols = `id, name, description, severity, mitre, score, enabled, mode, builtin, definition, version, updated_at`

func scanRule(sc interface{ Scan(...any) error }) (*domain.Rule, error) {
	var (
		r        domain.Rule
		severity string
		mitre    string
		enabled  int
		mode     string
		builtin  int
		updated  int64
	)
	err := sc.Scan(&r.ID, &r.Name, &r.Description, &severity, &mitre, &r.Score, &enabled, &mode, &builtin,
		&r.Definition, &r.Version, &updated)
	if err != nil {
		return nil, err
	}
	r.Severity = domain.Severity(severity)
	r.MITRE = splitCSV(mitre)
	r.Enabled = enabled != 0
	// 空值归一为 active：migration 之前的行与显式置空都按正常模式处理
	if mode == "" {
		mode = "active"
	}
	r.Mode = mode
	r.Builtin = builtin != 0
	r.UpdatedAt = fromMillis(updated)
	return &r, nil
}

func (r *ruleRepo) List(ctx context.Context) ([]domain.Rule, error) {
	return r.query(ctx, `SELECT `+ruleCols+` FROM rules ORDER BY builtin DESC, id ASC`)
}

func (r *ruleRepo) ListEnabled(ctx context.Context) ([]domain.Rule, error) {
	return r.query(ctx, `SELECT `+ruleCols+` FROM rules WHERE enabled = 1 ORDER BY id ASC`)
}

func (r *ruleRepo) query(ctx context.Context, q string, args ...any) ([]domain.Rule, error) {
	rows, err := r.s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("查询规则失败: %w", err)
	}
	defer rows.Close()

	var out []domain.Rule
	for rows.Next() {
		rr, err := scanRule(rows)
		if err != nil {
			return nil, fmt.Errorf("解析规则失败: %w", err)
		}
		out = append(out, *rr)
	}
	return out, rows.Err()
}

func (r *ruleRepo) ByID(ctx context.Context, id string) (*domain.Rule, error) {
	row := r.s.db.QueryRowContext(ctx, `SELECT `+ruleCols+` FROM rules WHERE id = ?`, id)
	rr, err := scanRule(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("查询规则失败: %w", err)
	}
	return rr, nil
}

func (r *ruleRepo) Upsert(ctx context.Context, rr *domain.Rule) error {
	if rr.Mode == "" {
		rr.Mode = "active"
	}
	_, err := r.s.db.ExecContext(ctx,
		`INSERT INTO rules(`+ruleCols+`) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
		 ON CONFLICT(id) DO UPDATE SET
		   name=excluded.name, description=excluded.description, severity=excluded.severity,
		   mitre=excluded.mitre, score=excluded.score, enabled=excluded.enabled, mode=excluded.mode,
		   definition=excluded.definition, version=excluded.version, updated_at=excluded.updated_at`,
		rr.ID, rr.Name, rr.Description, string(rr.Severity), joinCSV(rr.MITRE), rr.Score,
		boolInt(rr.Enabled), rr.Mode, boolInt(rr.Builtin), rr.Definition, rr.Version, millis(rr.UpdatedAt))
	if err != nil {
		return fmt.Errorf("保存规则失败: %w", err)
	}
	return nil
}

func (r *ruleRepo) Delete(ctx context.Context, id string) error {
	res, err := r.s.db.ExecContext(ctx, `DELETE FROM rules WHERE id = ? AND builtin = 0`, id)
	if err != nil {
		return fmt.Errorf("删除规则失败: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (r *ruleRepo) MaxVersion(ctx context.Context) (int, error) {
	var v sql.NullInt64
	if err := r.s.db.QueryRowContext(ctx, `SELECT MAX(version) FROM rules`).Scan(&v); err != nil {
		return 0, err
	}
	if !v.Valid {
		return 0, nil
	}
	return int(v.Int64), nil
}

// ---------------------------------------------------------------- allowlist

type allowlistRepo struct{ s *Store }

func (r *allowlistRepo) List(ctx context.Context) ([]domain.AllowlistEntry, error) {
	rows, err := r.s.db.QueryContext(ctx,
		`SELECT id, type, value, note, created_by, created_at, hits FROM allowlist ORDER BY created_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("查询白名单失败: %w", err)
	}
	defer rows.Close()

	var out []domain.AllowlistEntry
	for rows.Next() {
		var (
			e       domain.AllowlistEntry
			created int64
		)
		if err := rows.Scan(&e.ID, &e.Type, &e.Value, &e.Note, &e.CreatedBy, &created, &e.Hits); err != nil {
			return nil, fmt.Errorf("解析白名单失败: %w", err)
		}
		e.CreatedAt = fromMillis(created)
		out = append(out, e)
	}
	return out, rows.Err()
}

func (r *allowlistRepo) Add(ctx context.Context, e *domain.AllowlistEntry) error {
	_, err := r.s.db.ExecContext(ctx,
		`INSERT INTO allowlist(id, type, value, note, created_by, created_at, hits) VALUES(?,?,?,?,?,?,0)
		 ON CONFLICT(type, value) DO UPDATE SET note = excluded.note`,
		e.ID, e.Type, e.Value, e.Note, e.CreatedBy, millis(e.CreatedAt))
	if err != nil {
		return fmt.Errorf("写入白名单失败: %w", err)
	}
	return nil
}

func (r *allowlistRepo) Delete(ctx context.Context, id string) error {
	res, err := r.s.db.ExecContext(ctx, `DELETE FROM allowlist WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("删除白名单失败: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (r *allowlistRepo) Exists(ctx context.Context, typ, value string) (bool, error) {
	var n int
	err := r.s.db.QueryRowContext(ctx, `SELECT COUNT(1) FROM allowlist WHERE type = ? AND value = ?`, typ, value).Scan(&n)
	return n > 0, err
}

func (r *allowlistRepo) BumpHit(ctx context.Context, typ, value string) error {
	_, err := r.s.db.ExecContext(ctx, `UPDATE allowlist SET hits = hits + 1 WHERE type = ? AND value = ?`, typ, value)
	return err
}

// ---------------------------------------------------------------- commands

type commandRepo struct{ s *Store }

const cmdCols = `id, agent_id, type, payload, status, result, created_by, created_at, delivered_at, finished_at`

func (r *commandRepo) Create(ctx context.Context, c *domain.AgentCommand) error {
	_, err := r.s.db.ExecContext(ctx,
		`INSERT INTO agent_commands(`+cmdCols+`) VALUES(?,?,?,?,?,?,?,?,?,?)`,
		c.ID, c.AgentID, c.Type, c.Payload, c.Status, c.Result, c.CreatedBy,
		millis(c.CreatedAt), nil, nil)
	if err != nil {
		return fmt.Errorf("创建指令失败: %w", err)
	}
	return nil
}

func (r *commandRepo) PendingForAgent(ctx context.Context, agentID string, limit int) ([]domain.AgentCommand, error) {
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	rows, err := r.s.db.QueryContext(ctx,
		`SELECT `+cmdCols+` FROM agent_commands WHERE agent_id = ? AND status = 'pending'
		 ORDER BY created_at ASC LIMIT ?`, agentID, limit)
	if err != nil {
		return nil, fmt.Errorf("查询待下发指令失败: %w", err)
	}
	defer rows.Close()

	var out []domain.AgentCommand
	for rows.Next() {
		c, err := scanCmd(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *c)
	}
	return out, rows.Err()
}

func scanCmd(sc interface{ Scan(...any) error }) (*domain.AgentCommand, error) {
	var (
		c         domain.AgentCommand
		created   int64
		delivered sql.NullInt64
		finished  sql.NullInt64
	)
	err := sc.Scan(&c.ID, &c.AgentID, &c.Type, &c.Payload, &c.Status, &c.Result, &c.CreatedBy,
		&created, &delivered, &finished)
	if err != nil {
		return nil, fmt.Errorf("解析指令失败: %w", err)
	}
	c.CreatedAt = fromMillis(created)
	c.DeliveredAt = fromNullMillis(delivered)
	c.FinishedAt = fromNullMillis(finished)
	return &c, nil
}

func (r *commandRepo) MarkDelivered(ctx context.Context, ids []string, at time.Time) error {
	if len(ids) == 0 {
		return nil
	}
	tx, err := r.s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	for _, id := range ids {
		if _, err := tx.ExecContext(ctx,
			`UPDATE agent_commands SET status = 'delivered', delivered_at = ? WHERE id = ? AND status = 'pending'`,
			millis(at), id); err != nil {
			return fmt.Errorf("标记指令已投递失败: %w", err)
		}
	}
	return tx.Commit()
}

func (r *commandRepo) Complete(ctx context.Context, id, status, result string, at time.Time) error {
	_, err := r.s.db.ExecContext(ctx,
		`UPDATE agent_commands SET status = ?, result = ?, finished_at = ? WHERE id = ?`,
		status, result, millis(at), id)
	return err
}

func (r *commandRepo) ListRecent(ctx context.Context, limit int) ([]domain.AgentCommand, error) {
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	rows, err := r.s.db.QueryContext(ctx,
		`SELECT `+cmdCols+` FROM agent_commands ORDER BY created_at DESC LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("查询指令失败: %w", err)
	}
	defer rows.Close()

	var out []domain.AgentCommand
	for rows.Next() {
		c, err := scanCmd(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *c)
	}
	return out, rows.Err()
}

func (r *commandRepo) ListByAgentType(ctx context.Context, agentID, typ string, offset, limit int) ([]domain.AgentCommand, int, error) {
	var total int
	if err := r.s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM agent_commands WHERE agent_id = ? AND type = ?`,
		agentID, typ).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("统计指令失败: %w", err)
	}
	if limit <= 0 || limit > 200 {
		limit = 20
	}
	if offset < 0 {
		offset = 0
	}
	rows, err := r.s.db.QueryContext(ctx,
		`SELECT `+cmdCols+` FROM agent_commands WHERE agent_id = ? AND type = ?
		 ORDER BY created_at DESC LIMIT ? OFFSET ?`, agentID, typ, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("查询指令失败: %w", err)
	}
	defer rows.Close()

	out := make([]domain.AgentCommand, 0, limit)
	for rows.Next() {
		c, err := scanCmd(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, *c)
	}
	return out, total, rows.Err()
}
