// Package sqlite 是仓储层的 SQLite 实现（modernc.org/sqlite，纯 Go 无 CGO）。
package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"

	"hostguard/internal/server/repository"
)

// Store 持有 *sql.DB 并实现所有仓储接口。
type Store struct {
	db *sql.DB

	users     userRepo
	tokens    tokenRepo
	agents    agentRepo
	alerts    alertRepo
	rules     ruleRepo
	allowlist allowlistRepo
	audit     auditRepo
	commands  commandRepo
	stats     statsRepo
}

var _ = (*Store)(nil)

// Open 打开数据库、应用迁移并返回仓储集合。
func Open(ctx context.Context, path string) (*Store, repository.Repos, error) {
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return nil, repository.Repos{}, fmt.Errorf("创建数据库目录失败: %w", err)
		}
	}

	q := url.Values{}
	q.Add("_pragma", "busy_timeout(5000)")
	q.Add("_pragma", "journal_mode(WAL)")
	q.Add("_pragma", "foreign_keys(1)")
	q.Add("_pragma", "synchronous(NORMAL)")
	dsn := "file:" + filepath.ToSlash(path) + "?" + q.Encode()

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, repository.Repos{}, fmt.Errorf("打开数据库失败: %w", err)
	}
	// 写并发交给 busy_timeout，连接数保持克制（SQLite 单写者）
	db.SetMaxOpenConns(8)
	db.SetMaxIdleConns(8)
	db.SetConnMaxLifetime(time.Hour)

	pingCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := db.PingContext(pingCtx); err != nil {
		_ = db.Close()
		return nil, repository.Repos{}, fmt.Errorf("数据库连接失败: %w", err)
	}

	s := &Store{db: db}
	if err := s.migrate(ctx); err != nil {
		_ = db.Close()
		return nil, repository.Repos{}, err
	}

	s.users = userRepo{s}
	s.tokens = tokenRepo{s}
	s.agents = agentRepo{s}
	s.alerts = alertRepo{s}
	s.rules = ruleRepo{s}
	s.allowlist = allowlistRepo{s}
	s.audit = auditRepo{s}
	s.commands = commandRepo{s}
	s.stats = statsRepo{s}

	repos := repository.Repos{
		Users:     &s.users,
		Tokens:    &s.tokens,
		Agents:    &s.agents,
		Alerts:    &s.alerts,
		Rules:     &s.rules,
		Allowlist: &s.allowlist,
		Audit:     &s.audit,
		Commands:  &s.commands,
		Stats:     &s.stats,
	}
	return s, repos, nil
}

// Close 关闭连接池。
func (s *Store) Close() error { return s.db.Close() }

// DB 暴露底层句柄（仅供运维脚本与测试）。
func (s *Store) DB() *sql.DB { return s.db }

// migrated 是顺序应用的迁移脚本集合；只允许追加，不允许修改历史条目。
var migrations = []struct {
	name string
	sql  string
}{
	{
		name: "001_init",
		sql: `
CREATE TABLE IF NOT EXISTS users (
  id            TEXT PRIMARY KEY,
  username      TEXT NOT NULL UNIQUE,
  display_name  TEXT NOT NULL DEFAULT '',
  password_hash TEXT NOT NULL,
  role          TEXT NOT NULL DEFAULT 'viewer',
  disabled      INTEGER NOT NULL DEFAULT 0,
  created_at    INTEGER NOT NULL,
  last_login_at INTEGER
);

CREATE TABLE IF NOT EXISTS refresh_tokens (
  id         TEXT PRIMARY KEY,
  user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash TEXT NOT NULL UNIQUE,
  expires_at INTEGER NOT NULL,
  revoked    INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL,
  user_agent TEXT NOT NULL DEFAULT '',
  ip         TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_rt_user ON refresh_tokens(user_id);

CREATE TABLE IF NOT EXISTS agents (
  id           TEXT PRIMARY KEY,
  hostname     TEXT NOT NULL,
  os_version   TEXT NOT NULL DEFAULT '',
  arch         TEXT NOT NULL DEFAULT '',
  username     TEXT NOT NULL DEFAULT '',
  ip           TEXT NOT NULL DEFAULT '',
  tags         TEXT NOT NULL DEFAULT '',
  version      TEXT NOT NULL DEFAULT '',
  machine_id   TEXT NOT NULL DEFAULT '',
  secret_hash  TEXT NOT NULL,
  status       TEXT NOT NULL DEFAULT 'online',
  enrolled_at  INTEGER NOT NULL,
  last_seen_at INTEGER NOT NULL,
  proc_count   INTEGER NOT NULL DEFAULT 0,
  cpu_percent  REAL NOT NULL DEFAULT 0,
  mem_mb       REAL NOT NULL DEFAULT 0,
  rule_version INTEGER NOT NULL DEFAULT 0
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_agents_machine ON agents(machine_id);

CREATE TABLE IF NOT EXISTS alerts (
  id           TEXT PRIMARY KEY,
  agent_id     TEXT NOT NULL,
  hostname     TEXT NOT NULL,
  fingerprint  TEXT NOT NULL,
  title        TEXT NOT NULL,
  summary      TEXT NOT NULL DEFAULT '',
  verdict      TEXT NOT NULL,
  severity     TEXT NOT NULL,
  score        INTEGER NOT NULL DEFAULT 0,
  pid          INTEGER NOT NULL DEFAULT 0,
  ppid         INTEGER NOT NULL DEFAULT 0,
  process_name TEXT NOT NULL DEFAULT '',
  image_path   TEXT NOT NULL DEFAULT '',
  cmdline      TEXT NOT NULL DEFAULT '',
  proc_user    TEXT NOT NULL DEFAULT '',
  hash_sha256  TEXT NOT NULL DEFAULT '',
  signer       TEXT NOT NULL DEFAULT '',
  signed       INTEGER NOT NULL DEFAULT 0,
  rule_ids     TEXT NOT NULL DEFAULT '',
  mitre        TEXT NOT NULL DEFAULT '',
  evidence     TEXT NOT NULL DEFAULT '{}',
  status       TEXT NOT NULL DEFAULT 'open',
  handled_by   TEXT NOT NULL DEFAULT '',
  handled_at   INTEGER,
  note         TEXT NOT NULL DEFAULT '',
  duplicate    INTEGER NOT NULL DEFAULT 0,
  occurred_at  INTEGER NOT NULL,
  created_at   INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_alerts_created ON alerts(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status, severity);
CREATE INDEX IF NOT EXISTS idx_alerts_fp ON alerts(fingerprint);
CREATE INDEX IF NOT EXISTS idx_alerts_agent ON alerts(agent_id);

CREATE TABLE IF NOT EXISTS rules (
  id          TEXT PRIMARY KEY,
  name        TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  severity    TEXT NOT NULL DEFAULT 'medium',
  mitre       TEXT NOT NULL DEFAULT '',
  score       INTEGER NOT NULL DEFAULT 30,
  enabled     INTEGER NOT NULL DEFAULT 1,
  builtin     INTEGER NOT NULL DEFAULT 0,
  definition  TEXT NOT NULL DEFAULT '{}',
  version     INTEGER NOT NULL DEFAULT 1,
  updated_at  INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS allowlist (
  id         TEXT PRIMARY KEY,
  type       TEXT NOT NULL,
  value      TEXT NOT NULL,
  note       TEXT NOT NULL DEFAULT '',
  created_by TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL,
  hits       INTEGER NOT NULL DEFAULT 0
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_allow_uniq ON allowlist(type, value);

CREATE TABLE IF NOT EXISTS audit_logs (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id    TEXT NOT NULL DEFAULT '',
  username   TEXT NOT NULL DEFAULT '',
  action     TEXT NOT NULL,
  target     TEXT NOT NULL DEFAULT '',
  detail     TEXT NOT NULL DEFAULT '',
  ip         TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_logs(created_at DESC);

CREATE TABLE IF NOT EXISTS agent_commands (
  id           TEXT PRIMARY KEY,
  agent_id     TEXT NOT NULL,
  type         TEXT NOT NULL,
  payload      TEXT NOT NULL DEFAULT '',
  status       TEXT NOT NULL DEFAULT 'pending',
  result       TEXT NOT NULL DEFAULT '',
  created_by   TEXT NOT NULL DEFAULT '',
  created_at   INTEGER NOT NULL,
  delivered_at INTEGER,
  finished_at  INTEGER
);
CREATE INDEX IF NOT EXISTS idx_cmd_agent ON agent_commands(agent_id, status);

CREATE TABLE IF NOT EXISTS settings (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
`,
	},
	{
		name: "002_indexes",
		sql: `
-- 告警列表的主查询是 "status IN (...) ORDER BY created_at DESC"，
-- 原有的 (status, severity) 复合索引对排序没有帮助，会退化成临时排序。
CREATE INDEX IF NOT EXISTS idx_alerts_status_created ON alerts(status, created_at DESC);
-- 主机列表按最后心跳排序/过滤
CREATE INDEX IF NOT EXISTS idx_agents_last_seen ON agents(last_seen_at DESC);
-- 按主机+状态统计未处置告警
CREATE INDEX IF NOT EXISTS idx_alerts_agent_status ON alerts(agent_id, status);
`,
	},
	{
		name: "003_integrity",
		sql: `
-- 告警完整性链：每天对前一日全部告警计算摘要并入库。
-- 目的是让"内部人员事后删改告警"变得可发现——合规审计里
-- 「日志防篡改」几乎是必答题，单文件数据库尤其需要这层保障。
CREATE TABLE IF NOT EXISTS integrity_chain (
  day          TEXT PRIMARY KEY,
  digest       TEXT NOT NULL,
  alert_count  INTEGER NOT NULL,
  created_at   INTEGER NOT NULL
);
`,
	},
}

func (s *Store) migrate(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		name TEXT PRIMARY KEY, applied_at INTEGER NOT NULL)`); err != nil {
		return fmt.Errorf("初始化迁移表失败: %w", err)
	}

	for _, m := range migrations {
		var exists int
		err := s.db.QueryRowContext(ctx, `SELECT COUNT(1) FROM schema_migrations WHERE name = ?`, m.name).Scan(&exists)
		if err != nil {
			return fmt.Errorf("读取迁移状态失败: %w", err)
		}
		if exists > 0 {
			continue
		}

		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return fmt.Errorf("开启迁移事务失败: %w", err)
		}
		if _, err := tx.ExecContext(ctx, m.sql); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("迁移 %s 执行失败: %w", m.name, err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO schema_migrations(name, applied_at) VALUES(?, ?)`,
			m.name, time.Now().UnixMilli()); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("记录迁移 %s 失败: %w", m.name, err)
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("提交迁移 %s 失败: %w", m.name, err)
		}
	}
	return nil
}

// ---------------------------------------------------------------- helpers

func millis(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.UnixMilli()
}

func fromMillis(v int64) time.Time {
	if v == 0 {
		return time.Time{}
	}
	return time.UnixMilli(v).UTC()
}

func fromNullMillis(v sql.NullInt64) *time.Time {
	if !v.Valid || v.Int64 == 0 {
		return nil
	}
	t := time.UnixMilli(v.Int64).UTC()
	return &t
}

func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func joinCSV(v []string) string {
	cleaned := make([]string, 0, len(v))
	for _, s := range v {
		if s = strings.TrimSpace(s); s != "" {
			cleaned = append(cleaned, s)
		}
	}
	return strings.Join(cleaned, ",")
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
