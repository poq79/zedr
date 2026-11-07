package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"zedr/internal/server/domain"
)

// intelRepo 非哈希威胁情报（ip/path/keyword）。
// hash 留在 iocs 表走独立 IOC 包管线（老探针兼容不动），见 migration 010。
type intelRepo struct{ s *Store }

const intelVersionKey = "intel_version"

const intelCols = `id, type, value, score, name, note, mitre, created_by, created_at`

func scanIntel(sc interface{ Scan(...any) error }) (*domain.IntelItem, error) {
	var (
		e       domain.IntelItem
		mitre   string
		created int64
	)
	if err := sc.Scan(&e.ID, &e.Type, &e.Value, &e.Score, &e.Name, &e.Note, &mitre, &e.CreatedBy, &created); err != nil {
		return nil, err
	}
	e.MITRE = mitre
	e.CreatedAt = fromMillis(created)
	return &e, nil
}

func (r *intelRepo) List(ctx context.Context, typ string) ([]domain.IntelItem, error) {
	q := `SELECT ` + intelCols + ` FROM intel_items`
	args := []any{}
	if typ != "" {
		q += ` WHERE type = ?`
		args = append(args, typ)
	}
	q += ` ORDER BY type, created_at DESC`
	return r.query(ctx, q, args...)
}

func (r *intelRepo) query(ctx context.Context, q string, args ...any) ([]domain.IntelItem, error) {
	rows, err := r.s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("查询情报失败: %w", err)
	}
	defer rows.Close()
	var out []domain.IntelItem
	for rows.Next() {
		e, err := scanIntel(rows)
		if err != nil {
			return nil, fmt.Errorf("解析情报失败: %w", err)
		}
		out = append(out, *e)
	}
	return out, rows.Err()
}

func (r *intelRepo) ByID(ctx context.Context, id string) (*domain.IntelItem, error) {
	row := r.s.db.QueryRowContext(ctx, `SELECT `+intelCols+` FROM intel_items WHERE id = ?`, id)
	e, err := scanIntel(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("查询情报失败: %w", err)
	}
	return e, nil
}

func (r *intelRepo) ByValue(ctx context.Context, typ, value string) (*domain.IntelItem, error) {
	row := r.s.db.QueryRowContext(ctx,
		`SELECT `+intelCols+` FROM intel_items WHERE type = ? AND value = ?`, typ, value)
	e, err := scanIntel(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("查询情报失败: %w", err)
	}
	return e, nil
}

func (r *intelRepo) Add(ctx context.Context, e *domain.IntelItem) error {
	_, err := r.s.db.ExecContext(ctx,
		`INSERT INTO intel_items(`+intelCols+`) VALUES(?,?,?,?,?,?,?,?,?)
		 ON CONFLICT(type, value) DO UPDATE SET
		   score = excluded.score, name = excluded.name, note = excluded.note,
		   mitre = excluded.mitre, created_by = excluded.created_by, created_at = excluded.created_at`,
		e.ID, e.Type, e.Value, e.Score, e.Name, e.Note, e.MITRE, e.CreatedBy, millis(e.CreatedAt))
	if err != nil {
		return fmt.Errorf("写入情报失败: %w", err)
	}
	return nil
}

func (r *intelRepo) Delete(ctx context.Context, id string) error {
	res, err := r.s.db.ExecContext(ctx, `DELETE FROM intel_items WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("删除情报失败: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (r *intelRepo) Count(ctx context.Context) (int, error) {
	var n int
	if err := r.s.db.QueryRowContext(ctx, `SELECT COUNT(1) FROM intel_items`).Scan(&n); err != nil {
		return 0, err
	}
	return n, nil
}

func (r *intelRepo) Version(ctx context.Context) (int, error) {
	var v int
	err := r.s.db.QueryRowContext(ctx,
		`SELECT COALESCE((SELECT CAST(value AS INTEGER) FROM settings WHERE key = ?), 0)`,
		intelVersionKey).Scan(&v)
	if err != nil {
		return 0, fmt.Errorf("读取情报版本失败: %w", err)
	}
	return v, nil
}

func (r *intelRepo) BumpVersion(ctx context.Context, floor int) (int, error) {
	cur, err := r.Version(ctx)
	if err != nil {
		return 0, err
	}
	// 版本下限：情报版本必须越过规则 MaxVersion，否则规则包版本
	// （取两者 max）不变，探针的 ETag/单调校验都感知不到情报变更。
	next := cur + 1
	if floor+1 > next {
		next = floor + 1
	}
	_, err = r.s.db.ExecContext(ctx,
		`INSERT INTO settings(key, value) VALUES(?, ?)
		 ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
		intelVersionKey, fmt.Sprintf("%d", next))
	if err != nil {
		return 0, fmt.Errorf("递增情报版本失败: %w", err)
	}
	return next, nil
}
