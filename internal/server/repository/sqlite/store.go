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

	"zedr/internal/server/repository"
)

// Store 持有 *sql.DB 并实现所有仓储接口。
type Store struct {
	db *sql.DB

	users     userRepo
	tokens    tokenRepo
	agents    agentRepo
	alerts    alertRepo
	rules     ruleRepo
	robserve  ruleObserveRepo
	allowlist allowlistRepo
	iocs      iocRepo
	audit     auditRepo
	commands  commandRepo
	stats     statsRepo
		inventory inventoryRepo
		incidents incidentRepo
		aicfg     aiConfigRepo
		aitriage  aiTriageRepo
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
	s.robserve = ruleObserveRepo{s}
	s.allowlist = allowlistRepo{s}
	s.iocs = iocRepo{s}
	s.audit = auditRepo{s}
	s.commands = commandRepo{s}
	s.stats = statsRepo{s}
		s.inventory = inventoryRepo{s}
		s.incidents = incidentRepo{s}
		s.aicfg = aiConfigRepo{s}
		s.aitriage = aiTriageRepo{s}

	repos := repository.Repos{
		Users:     &s.users,
		Tokens:    &s.tokens,
		Agents:    &s.agents,
		Alerts:    &s.alerts,
		Rules:     &s.rules,
		RuleObserve: &s.robserve,
		Allowlist: &s.allowlist,
		IOCs:      &s.iocs,
		Audit:     &s.audit,
		Commands:  &s.commands,
		Stats:     &s.stats,
		Inventory: &s.inventory,
		Incidents: &s.incidents,
		AIConfig:  &s.aicfg,
		ATriage:   &s.aitriage,
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
	{
		name: "004_iocs",
		sql: `
-- 威胁指标库（当前仅 SHA256 哈希）。版本计数存 settings.ioc_version，
-- 随内容变更递增，终端据此判断是否需要重拉整包。
CREATE TABLE IF NOT EXISTS iocs (
  id         TEXT PRIMARY KEY,
  hash       TEXT NOT NULL UNIQUE,
  note       TEXT NOT NULL DEFAULT '',
  created_by TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL
);
`,
	},
	{
		name: "005_inventory",
		sql: `
-- 主机资产清单：探针分节上报（system/adapters/listeners/services/tasks/startup/agent），
-- 服务端不解析 payload 内容（JSON 进 JSON 出），hash 用于幂等去重——
-- 探针按心跳周期重发全量是常态，内容不变就不落库，避免写放大。
-- (agent_id, section) 主键保证同一节只保留最新一份。
CREATE TABLE IF NOT EXISTS host_inventory (
  agent_id   TEXT NOT NULL, section TEXT NOT NULL, hash TEXT NOT NULL,
  payload    TEXT NOT NULL, updated_at INTEGER NOT NULL,
  PRIMARY KEY (agent_id, section));
CREATE INDEX IF NOT EXISTS idx_inventory_agent ON host_inventory(agent_id);
`,
	},
	{
		name: "006_incidents",
		sql: `
-- 持久化事件表：告警聚类 + 处置状态机（open→investigating→contained→resolved）。
-- 替代"每次查询取 200 条内存聚合"的临时方案；ID 由主机+簇内最老告警锚定，
-- 跨同步周期稳定，人工处置不因新告警加入而丢失。
CREATE TABLE IF NOT EXISTS incidents (
  id              TEXT PRIMARY KEY,
  agent_id        TEXT NOT NULL DEFAULT '',
  hostname        TEXT NOT NULL,
  title           TEXT NOT NULL DEFAULT '',
  peak_severity   TEXT NOT NULL DEFAULT 'medium',
  max_score       INTEGER NOT NULL DEFAULT 0,
  alert_count     INTEGER NOT NULL DEFAULT 0,
  open_count      INTEGER NOT NULL DEFAULT 0,
  status          TEXT NOT NULL DEFAULT 'open',
  processes       TEXT NOT NULL DEFAULT '',
  rule_ids        TEXT NOT NULL DEFAULT '',
  mitre           TEXT NOT NULL DEFAULT '',
  first_seen      INTEGER NOT NULL,
  last_seen       INTEGER NOT NULL,
  first_action_at INTEGER,
  resolved_at     INTEGER,
  note            TEXT NOT NULL DEFAULT '',
  updated_at      INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_incidents_agent ON incidents(agent_id, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status, updated_at DESC);
`,
	},
	{
		name: "007_ai_config",
		sql: `
-- AI 配置中心：提示词模板版本历史 + 技能包。
-- 模型槽位/预算等标量配置存 settings.ai_config（JSON，敏感字段已静态加密），
-- 只有"内容型"数据（提示词、技能）值得独立建表——它们需要版本化与审计。
CREATE TABLE IF NOT EXISTS ai_prompt_versions (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  task       TEXT NOT NULL,
  version    INTEGER NOT NULL,
  content    TEXT NOT NULL,
  created_by TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL,
  UNIQUE (task, version)
);
CREATE INDEX IF NOT EXISTS idx_ai_prompt_task ON ai_prompt_versions(task, version DESC);

CREATE TABLE IF NOT EXISTS ai_skills (
  id         TEXT PRIMARY KEY,
  task       TEXT NOT NULL,
  name       TEXT NOT NULL,
  content    TEXT NOT NULL,
  enabled    INTEGER NOT NULL DEFAULT 1,
  sort       INTEGER NOT NULL DEFAULT 0,
  created_by TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
`,
	},
	{
		name: "008_ai_triage_log",
		sql: `
-- AI 判定台账：每次研判/调查对一条告警的结论快照（按 alert_id+source
-- UPSERT，只留最新）。这是"研判质量运营闭环"的数据基础——AI 说有问题
-- 还是没有问题，最终要和分析师的处置结论对账，一致率/误报/漏报才有出处。
-- 刻意不塞进 alerts 表：AI 结论有自己的生命周期（重评会覆盖），
-- 和探针上报的引擎判定（verdict 字段）是两回事，混在一行会互相覆盖。
CREATE TABLE IF NOT EXISTS ai_triage_log (
  alert_id   TEXT NOT NULL,
  source     TEXT NOT NULL,           -- ai(模型研判/agentic) | heuristic(确定性五步)
  verdict    TEXT NOT NULL,
  confidence REAL NOT NULL DEFAULT 0,
  engine     TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL,
  UNIQUE (alert_id, source)
);
CREATE INDEX IF NOT EXISTS idx_ai_triage_alert ON ai_triage_log(alert_id, created_at DESC);
`,
	},
	{
		name: "009_rule_ops",
		sql: `
-- 规则运营：观察模式 + 观察命中台账。
-- rules.mode：active（正常告警，历史数据默认值）| observe（探针照常
-- 求值但只计数不告警）——新规则先观察再转正，是上线安全阀。
-- rule_observations：探针按心跳上报的观察命中计数（agent_id+rule_id
-- 主键，REPLACE 快照语义）。规则转正/删除后旧计数行随整包替换语义
-- 自动清理，跨终端 SUM 即"这条规则如果生效会在现网打多少分"。
ALTER TABLE rules ADD COLUMN mode TEXT NOT NULL DEFAULT 'active';

CREATE TABLE IF NOT EXISTS rule_observations (
  agent_id   TEXT NOT NULL,
  rule_id    TEXT NOT NULL,
  hits       INTEGER NOT NULL DEFAULT 0,
  updated_at INTEGER NOT NULL,
  PRIMARY KEY (agent_id, rule_id)
);
CREATE INDEX IF NOT EXISTS idx_rule_obs_rule ON rule_observations(rule_id);
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
