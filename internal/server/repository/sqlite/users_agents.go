package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"zedr/internal/server/domain"
)

type userRepo struct{ s *Store }

func (r *userRepo) Create(ctx context.Context, u *domain.User) error {
	_, err := r.s.db.ExecContext(ctx,
		`INSERT INTO users(id, username, display_name, password_hash, role, disabled, created_at)
		 VALUES(?,?,?,?,?,?,?)`,
		u.ID, u.Username, u.DisplayName, u.PasswordHash, string(u.Role), boolInt(u.Disabled), millis(u.CreatedAt))
	if err != nil {
		return fmt.Errorf("创建用户失败: %w", err)
	}
	return nil
}

const userCols = `id, username, display_name, password_hash, role, disabled, created_at, last_login_at`

func scanUser(sc interface{ Scan(...any) error }) (*domain.User, error) {
	var (
		u        domain.User
		role     string
		disabled int
		created  int64
		last     sql.NullInt64
	)
	if err := sc.Scan(&u.ID, &u.Username, &u.DisplayName, &u.PasswordHash, &role, &disabled, &created, &last); err != nil {
		return nil, err
	}
	u.Role = domain.Role(role)
	u.Disabled = disabled != 0
	u.CreatedAt = fromMillis(created)
	u.LastLoginAt = fromNullMillis(last)
	return &u, nil
}

func (r *userRepo) ByUsername(ctx context.Context, username string) (*domain.User, error) {
	row := r.s.db.QueryRowContext(ctx, `SELECT `+userCols+` FROM users WHERE username = ?`, username)
	u, err := scanUser(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("查询用户失败: %w", err)
	}
	return u, nil
}

func (r *userRepo) ByID(ctx context.Context, id string) (*domain.User, error) {
	row := r.s.db.QueryRowContext(ctx, `SELECT `+userCols+` FROM users WHERE id = ?`, id)
	u, err := scanUser(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("查询用户失败: %w", err)
	}
	return u, nil
}

func (r *userRepo) TouchLogin(ctx context.Context, id string, at time.Time) error {
	_, err := r.s.db.ExecContext(ctx, `UPDATE users SET last_login_at = ? WHERE id = ?`, millis(at), id)
	return err
}

func (r *userRepo) Count(ctx context.Context) (int, error) {
	var n int
	err := r.s.db.QueryRowContext(ctx, `SELECT COUNT(1) FROM users`).Scan(&n)
	return n, err
}

func (r *userRepo) List(ctx context.Context) ([]domain.User, error) {
	rows, err := r.s.db.QueryContext(ctx, `SELECT `+userCols+` FROM users ORDER BY created_at ASC`)
	if err != nil {
		return nil, fmt.Errorf("列出用户失败: %w", err)
	}
	defer rows.Close()

	var out []domain.User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, fmt.Errorf("解析用户失败: %w", err)
		}
		out = append(out, *u)
	}
	return out, rows.Err()
}

func (r *userRepo) UpdatePassword(ctx context.Context, id, hash string) error {
	_, err := r.s.db.ExecContext(ctx, `UPDATE users SET password_hash = ? WHERE id = ?`, hash, id)
	return err
}

func (r *userRepo) SetDisabled(ctx context.Context, id string, disabled bool) error {
	_, err := r.s.db.ExecContext(ctx, `UPDATE users SET disabled = ? WHERE id = ?`, boolInt(disabled), id)
	return err
}

// ---------------------------------------------------------------- tokens

type tokenRepo struct{ s *Store }

func (r *tokenRepo) Create(ctx context.Context, t *domain.RefreshToken) error {
	_, err := r.s.db.ExecContext(ctx,
		`INSERT INTO refresh_tokens(id, user_id, token_hash, expires_at, revoked, created_at, user_agent, ip)
		 VALUES(?,?,?,?,?,?,?,?)`,
		t.ID, t.UserID, t.TokenHash, millis(t.ExpiresAt), boolInt(t.Revoked), millis(t.CreatedAt), t.UserAgent, t.IP)
	if err != nil {
		return fmt.Errorf("保存刷新令牌失败: %w", err)
	}
	return nil
}

func (r *tokenRepo) ByHash(ctx context.Context, hash string) (*domain.RefreshToken, error) {
	var (
		t       domain.RefreshToken
		expires int64
		revoked int
		created int64
	)
	err := r.s.db.QueryRowContext(ctx,
		`SELECT id, user_id, token_hash, expires_at, revoked, created_at, user_agent, ip
		 FROM refresh_tokens WHERE token_hash = ?`, hash).
		Scan(&t.ID, &t.UserID, &t.TokenHash, &expires, &revoked, &created, &t.UserAgent, &t.IP)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("查询刷新令牌失败: %w", err)
	}
	t.ExpiresAt = fromMillis(expires)
	t.Revoked = revoked != 0
	t.CreatedAt = fromMillis(created)
	return &t, nil
}

func (r *tokenRepo) Revoke(ctx context.Context, id string) error {
	_, err := r.s.db.ExecContext(ctx, `UPDATE refresh_tokens SET revoked = 1 WHERE id = ?`, id)
	return err
}

func (r *tokenRepo) RevokeAllForUser(ctx context.Context, userID string) error {
	_, err := r.s.db.ExecContext(ctx, `UPDATE refresh_tokens SET revoked = 1 WHERE user_id = ?`, userID)
	return err
}

func (r *tokenRepo) DeleteExpired(ctx context.Context, before time.Time) (int64, error) {
	res, err := r.s.db.ExecContext(ctx, `DELETE FROM refresh_tokens WHERE expires_at < ?`, millis(before))
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// ---------------------------------------------------------------- agents

type agentRepo struct{ s *Store }

const agentCols = `id, hostname, os_version, arch, username, ip, tags, version, machine_id,
	secret_hash, status, enrolled_at, last_seen_at, proc_count, cpu_percent, mem_mb, rule_version`

func scanAgent(sc interface{ Scan(...any) error }) (*domain.Agent, error) {
	var (
		a        domain.Agent
		tags     string
		status   string
		enrolled int64
		lastSeen int64
	)
	err := sc.Scan(&a.ID, &a.Hostname, &a.OSVersion, &a.Arch, &a.Username, &a.IP, &tags, &a.Version,
		&a.MachineID, &a.SecretHash, &status, &enrolled, &lastSeen,
		&a.ProcCount, &a.CPUPercent, &a.MemMB, &a.RuleVersion)
	if err != nil {
		return nil, err
	}
	a.Tags = splitCSV(tags)
	a.Status = domain.AgentStatus(status)
	a.EnrolledAt = fromMillis(enrolled)
	a.LastSeenAt = fromMillis(lastSeen)
	return &a, nil
}

func (r *agentRepo) Upsert(ctx context.Context, a *domain.Agent) error {
	_, err := r.s.db.ExecContext(ctx,
		`INSERT INTO agents(`+agentCols+`) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
		 ON CONFLICT(id) DO UPDATE SET
		   hostname=excluded.hostname, os_version=excluded.os_version, arch=excluded.arch,
		   username=excluded.username, ip=excluded.ip, tags=excluded.tags, version=excluded.version,
		   machine_id=excluded.machine_id, secret_hash=excluded.secret_hash, status=excluded.status,
		   last_seen_at=excluded.last_seen_at`,
		a.ID, a.Hostname, a.OSVersion, a.Arch, a.Username, a.IP, joinCSV(a.Tags), a.Version,
		a.MachineID, a.SecretHash, string(a.Status), millis(a.EnrolledAt), millis(a.LastSeenAt),
		a.ProcCount, a.CPUPercent, a.MemMB, a.RuleVersion)
	if err != nil {
		return fmt.Errorf("保存终端失败: %w", err)
	}
	return nil
}

func (r *agentRepo) ByID(ctx context.Context, id string) (*domain.Agent, error) {
	row := r.s.db.QueryRowContext(ctx, `SELECT `+agentCols+` FROM agents WHERE id = ?`, id)
	a, err := scanAgent(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("查询终端失败: %w", err)
	}
	return a, nil
}

func (r *agentRepo) ByMachineID(ctx context.Context, machineID string) (*domain.Agent, error) {
	if machineID == "" {
		return nil, nil
	}
	row := r.s.db.QueryRowContext(ctx, `SELECT `+agentCols+` FROM agents WHERE machine_id = ?`, machineID)
	a, err := scanAgent(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("查询终端失败: %w", err)
	}
	return a, nil
}

func (r *agentRepo) List(ctx context.Context) ([]domain.Agent, error) {
	rows, err := r.s.db.QueryContext(ctx, `SELECT `+agentCols+` FROM agents ORDER BY last_seen_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("列出终端失败: %w", err)
	}
	defer rows.Close()

	var out []domain.Agent
	for rows.Next() {
		a, err := scanAgent(rows)
		if err != nil {
			return nil, fmt.Errorf("解析终端失败: %w", err)
		}
		out = append(out, *a)
	}
	return out, rows.Err()
}

func (r *agentRepo) UpdateHeartbeat(ctx context.Context, id string, at time.Time, procCount int, cpu, mem float64, ruleVersion int, ip, version string) error {
	_, err := r.s.db.ExecContext(ctx,
		`UPDATE agents SET last_seen_at = ?, status = 'online', proc_count = ?, cpu_percent = ?,
		 mem_mb = ?, rule_version = CASE WHEN ? > 0 THEN ? ELSE rule_version END,
		 ip = CASE WHEN ? <> '' THEN ? ELSE ip END,
		 version = CASE WHEN ? <> '' THEN ? ELSE version END
		 WHERE id = ?`,
		millis(at), procCount, cpu, mem, ruleVersion, ruleVersion, ip, ip, version, version, id)
	if err != nil {
		return fmt.Errorf("更新心跳失败: %w", err)
	}
	return nil
}

func (r *agentRepo) MarkOfflineBefore(ctx context.Context, threshold time.Time) (int64, error) {
	res, err := r.s.db.ExecContext(ctx,
		`UPDATE agents SET status = 'offline' WHERE status = 'online' AND last_seen_at < ?`, millis(threshold))
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func (r *agentRepo) Delete(ctx context.Context, id string) error {
	_, err := r.s.db.ExecContext(ctx, `DELETE FROM agents WHERE id = ?`, id)
	return err
}

func (r *agentRepo) Count(ctx context.Context) (int, error) {
	var n int
	err := r.s.db.QueryRowContext(ctx, `SELECT COUNT(1) FROM agents`).Scan(&n)
	return n, err
}
