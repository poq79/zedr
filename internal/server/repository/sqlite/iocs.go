package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"zedr/internal/server/domain"
)

type iocRepo struct{ s *Store }

const iocCols = `id, hash, note, created_by, created_at`

func scanIOC(sc interface{ Scan(...any) error }) (*domain.IOC, error) {
	var (
		e      domain.IOC
		created int64
	)
	if err := sc.Scan(&e.ID, &e.Hash, &e.Note, &e.CreatedBy, &created); err != nil {
		return nil, err
	}
	e.CreatedAt = fromMillis(created)
	return &e, nil
}

func (r *iocRepo) List(ctx context.Context) ([]domain.IOC, error) {
	rows, err := r.s.db.QueryContext(ctx,
		`SELECT `+iocCols+` FROM iocs ORDER BY created_at DESC, id`)
	if err != nil {
		return nil, fmt.Errorf("查询 IOC 失败: %w", err)
	}
	defer rows.Close()
	var out []domain.IOC
	for rows.Next() {
		e, err := scanIOC(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *e)
	}
	return out, rows.Err()
}

func (r *iocRepo) ByHash(ctx context.Context, hash string) (*domain.IOC, error) {
	row := r.s.db.QueryRowContext(ctx,
		`SELECT `+iocCols+` FROM iocs WHERE hash = ?`, hash)
	e, err := scanIOC(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("查询 IOC 失败: %w", err)
	}
	return e, nil
}

func (r *iocRepo) Add(ctx context.Context, e *domain.IOC) error {
	_, err := r.s.db.ExecContext(ctx,
		`INSERT INTO iocs(id, hash, note, created_by, created_at) VALUES(?,?,?,?,?)`,
		e.ID, e.Hash, e.Note, e.CreatedBy, millis(e.CreatedAt))
	if err != nil {
		return fmt.Errorf("写入 IOC 失败: %w", err)
	}
	return nil
}

func (r *iocRepo) Delete(ctx context.Context, id string) error {
	res, err := r.s.db.ExecContext(ctx, `DELETE FROM iocs WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("删除 IOC 失败: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (r *iocRepo) Count(ctx context.Context) (int, error) {
	var n int
	if err := r.s.db.QueryRowContext(ctx, `SELECT COUNT(1) FROM iocs`).Scan(&n); err != nil {
		return 0, err
	}
	return n, nil
}

// iocVersionKey 是 settings 表里的版本计数键。
const iocVersionKey = "ioc_version"

func (r *iocRepo) Version(ctx context.Context) (int, error) {
	var v int
	err := r.s.db.QueryRowContext(ctx,
		`SELECT COALESCE((SELECT CAST(value AS INTEGER) FROM settings WHERE key = ?), 0)`,
		iocVersionKey).Scan(&v)
	if err != nil {
		return 0, fmt.Errorf("读取 IOC 版本失败: %w", err)
	}
	return v, nil
}

func (r *iocRepo) BumpVersion(ctx context.Context) (int, error) {
	cur, err := r.Version(ctx)
	if err != nil {
		return 0, err
	}
	next := cur + 1
	_, err = r.s.db.ExecContext(ctx,
		`INSERT INTO settings(key, value) VALUES(?, ?)
		 ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
		iocVersionKey, fmt.Sprintf("%d", next))
	if err != nil {
		return 0, fmt.Errorf("递增 IOC 版本失败: %w", err)
	}
	return next, nil
}
