package sqlite

import (
	"context"
	"fmt"

	"zedr/internal/server/domain"
)

type inventoryRepo struct{ s *Store }

func scanInventorySection(sc interface{ Scan(...any) error }) (*domain.HostInventorySection, error) {
	var (
		e   domain.HostInventorySection
		upd int64
	)
	if err := sc.Scan(&e.Name, &e.Hash, &e.Payload, &upd); err != nil {
		return nil, err
	}
	e.UpdatedAt = fromMillis(upd)
	return &e, nil
}

// Upsert 保存一个清单节。(agent_id, section) 主键冲突时整体覆盖——
// 同一节永远只保留最新一份，updated_at 由服务层给（写不写由 hash 比对决定）。
func (r *inventoryRepo) Upsert(ctx context.Context, agentID string, sec domain.HostInventorySection) error {
	_, err := r.s.db.ExecContext(ctx,
		`INSERT INTO host_inventory(agent_id, section, hash, payload, updated_at) VALUES(?,?,?,?,?)
		 ON CONFLICT(agent_id, section) DO UPDATE SET
		   hash = excluded.hash, payload = excluded.payload, updated_at = excluded.updated_at`,
		agentID, sec.Name, sec.Hash, sec.Payload, millis(sec.UpdatedAt))
	if err != nil {
		return fmt.Errorf("写入资产清单失败: %w", err)
	}
	return nil
}

// ListByAgent 返回某主机的全部清单节，按节名排序保证响应稳定。
func (r *inventoryRepo) ListByAgent(ctx context.Context, agentID string) ([]domain.HostInventorySection, error) {
	rows, err := r.s.db.QueryContext(ctx,
		`SELECT section, hash, payload, updated_at FROM host_inventory WHERE agent_id = ? ORDER BY section`, agentID)
	if err != nil {
		return nil, fmt.Errorf("查询资产清单失败: %w", err)
	}
	defer rows.Close()
	var out []domain.HostInventorySection
	for rows.Next() {
		e, err := scanInventorySection(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *e)
	}
	return out, rows.Err()
}

// DeleteByAgent 删除某主机的全部清单节（主机删除时的孤儿数据清理）。
func (r *inventoryRepo) DeleteByAgent(ctx context.Context, agentID string) error {
	if _, err := r.s.db.ExecContext(ctx, `DELETE FROM host_inventory WHERE agent_id = ?`, agentID); err != nil {
		return fmt.Errorf("删除资产清单失败: %w", err)
	}
	return nil
}
