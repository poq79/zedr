package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"zedr/internal/server/domain"
)

// aiConfigRepo 实现 repository.AIConfigRepo。
//
// 模型槽位配置走 settings 通用 KV（服务层负责序列化与加密）；
// 本文件只新增提示词版本历史与技能包两张表的存取。
type aiConfigRepo struct{ s *Store }

// promptHistoryCap 是提示词历史版本保留上限。
// 版本历史的价值是"改坏了能退回"，不是无限审计——超过 20 版后
// 最早的内容对回滚已无现实意义，却会让每次保存线性变慢。
const promptHistoryCap = 20

func (r *aiConfigRepo) GetSetting(ctx context.Context, key string) (string, bool, error) {
	var v string
	err := r.s.db.QueryRowContext(ctx, `SELECT value FROM settings WHERE key = ?`, key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("读取配置 %s 失败: %w", key, err)
	}
	return v, true, nil
}

func (r *aiConfigRepo) SetSetting(ctx context.Context, key, value string) error {
	_, err := r.s.db.ExecContext(ctx,
		`INSERT INTO settings(key, value) VALUES(?, ?)
		 ON CONFLICT(key) DO UPDATE SET value = excluded.value`, key, value)
	if err != nil {
		return fmt.Errorf("写入配置 %s 失败: %w", key, err)
	}
	return nil
}

func (r *aiConfigRepo) Prompt(ctx context.Context, task string) (*domain.AIPrompt, error) {
	return r.promptFull(ctx, task)
}

// promptFull 一次性读取当前生效版本与全部历史。
func (r *aiConfigRepo) promptFull(ctx context.Context, task string) (*domain.AIPrompt, error) {
	p := &domain.AIPrompt{Task: task}
	rows, err := r.s.db.QueryContext(ctx,
		`SELECT version, content, created_by, created_at FROM ai_prompt_versions
		 WHERE task = ? ORDER BY version DESC`, task)
	if err != nil {
		return nil, fmt.Errorf("读取提示词失败: %w", err)
	}
	defer rows.Close()
	first := true
	for rows.Next() {
		var (
			v     domain.AIPromptVersion
			at    int64
			ver   int
		)
		if err := rows.Scan(&ver, &v.Content, &v.CreatedBy, &at); err != nil {
			return nil, err
		}
		v.Version = ver
		v.CreatedAt = fromMillis(at)
		if first {
			// 最高版本即当前生效内容（SavePrompt/Rollback 都以追加方式写入）
			p.Content = v.Content
			p.UpdatedBy = v.CreatedBy
			t := v.CreatedAt
			p.UpdatedAt = &t
			first = false
		}
		p.Versions = append(p.Versions, v)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return p, nil
}

func (r *aiConfigRepo) SavePrompt(ctx context.Context, task, content, by string, at time.Time) (int, error) {
	tx, err := r.s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()

	var cur int
	if err := tx.QueryRowContext(ctx,
		`SELECT COALESCE(MAX(version), 0) FROM ai_prompt_versions WHERE task = ?`, task).Scan(&cur); err != nil {
		return 0, fmt.Errorf("读取当前版本失败: %w", err)
	}
	next := cur + 1
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO ai_prompt_versions(task, version, content, created_by, created_at) VALUES(?,?,?,?,?)`,
		task, next, content, by, millis(at)); err != nil {
		return 0, fmt.Errorf("写入提示词版本失败: %w", err)
	}
	// 历史上限：删除最老的（version 最小）多余版本
	if _, err := tx.ExecContext(ctx,
		`DELETE FROM ai_prompt_versions WHERE task = ? AND version <= ?`,
		task, next-promptHistoryCap); err != nil {
		return 0, fmt.Errorf("清理提示词历史失败: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return next, nil
}

func (r *aiConfigRepo) RollbackPrompt(ctx context.Context, task string, version int, by string, at time.Time) (int, error) {
	var content string
	err := r.s.db.QueryRowContext(ctx,
		`SELECT content FROM ai_prompt_versions WHERE task = ? AND version = ?`, task, version).Scan(&content)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, fmt.Errorf("版本 %d 不存在", version)
	}
	if err != nil {
		return 0, fmt.Errorf("读取历史版本失败: %w", err)
	}
	return r.SavePrompt(ctx, task, content, by, at)
}

func (r *aiConfigRepo) Skills(ctx context.Context) ([]domain.AISkill, error) {
	rows, err := r.s.db.QueryContext(ctx,
		`SELECT id, task, name, content, enabled, sort, created_by, created_at, updated_at
		 FROM ai_skills ORDER BY sort ASC, name ASC`)
	if err != nil {
		return nil, fmt.Errorf("查询技能包失败: %w", err)
	}
	defer rows.Close()
	var out []domain.AISkill
	for rows.Next() {
		s, err := scanSkill(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *s)
	}
	return out, rows.Err()
}

func (r *aiConfigRepo) Skill(ctx context.Context, id string) (*domain.AISkill, error) {
	row := r.s.db.QueryRowContext(ctx,
		`SELECT id, task, name, content, enabled, sort, created_by, created_at, updated_at
		 FROM ai_skills WHERE id = ?`, id)
	s, err := scanSkill(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("查询技能包失败: %w", err)
	}
	return s, nil
}

func (r *aiConfigRepo) UpsertSkill(ctx context.Context, s *domain.AISkill) error {
	_, err := r.s.db.ExecContext(ctx,
		`INSERT INTO ai_skills(id, task, name, content, enabled, sort, created_by, created_at, updated_at)
		 VALUES(?,?,?,?,?,?,?,?,?)
		 ON CONFLICT(id) DO UPDATE SET
		   task = excluded.task, name = excluded.name, content = excluded.content,
		   enabled = excluded.enabled, sort = excluded.sort, updated_at = excluded.updated_at`,
		s.ID, string(s.Task), s.Name, s.Content, boolInt(s.Enabled), s.Sort,
		s.CreatedBy, millis(s.CreatedAt), millis(s.UpdatedAt))
	if err != nil {
		return fmt.Errorf("写入技能包失败: %w", err)
	}
	return nil
}

func (r *aiConfigRepo) DeleteSkill(ctx context.Context, id string) error {
	res, err := r.s.db.ExecContext(ctx, `DELETE FROM ai_skills WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("删除技能包失败: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func scanSkill(sc interface{ Scan(...any) error }) (*domain.AISkill, error) {
	var (
		s            domain.AISkill
		task         string
		enabled      int
		created, upd int64
	)
	if err := sc.Scan(&s.ID, &task, &s.Name, &s.Content, &enabled, &s.Sort, &s.CreatedBy, &created, &upd); err != nil {
		return nil, err
	}
	s.Task = domain.AISkillTask(task)
	s.Enabled = enabled == 1
	s.CreatedAt = fromMillis(created)
	s.UpdatedAt = fromMillis(upd)
	return &s, nil
}
