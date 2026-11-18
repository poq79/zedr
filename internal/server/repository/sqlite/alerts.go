package sqlite

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"zedr/internal/server/domain"
	"zedr/internal/server/repository"
)

type alertRepo struct{ s *Store }

const alertCols = `id, agent_id, hostname, fingerprint, title, summary, verdict, severity, score,
	pid, ppid, process_name, image_path, cmdline, proc_user, hash_sha256, signer, signed,
	rule_ids, mitre, evidence, status, handled_by, handled_at, note, duplicate, occurred_at, created_at`

func (r *alertRepo) insert(ctx context.Context, a *domain.Alert) error {
	ev, err := json.Marshal(a.Evidence)
	if err != nil {
		ev = []byte("{}")
	}
	_, err = r.s.db.ExecContext(ctx,
		`INSERT INTO alerts(`+alertCols+`) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		a.ID, a.AgentID, a.Hostname, a.Fingerprint, a.Title, a.Summary, string(a.Verdict),
		string(a.Severity), a.Score, a.PID, a.PPID, a.ProcessName, a.ImagePath, a.CmdLine,
		a.ProcUser, a.HashSHA256, a.Signer, boolInt(a.Signed), joinCSV(a.RuleIDs), joinCSV(a.MITRE),
		string(ev), string(a.Status), a.HandledBy, nil, a.Note, a.Duplicate,
		millis(a.OccurredAt), millis(a.CreatedAt))
	if err != nil {
		return fmt.Errorf("写入告警失败: %w", err)
	}
	return nil
}

func (r *alertRepo) Create(ctx context.Context, a *domain.Alert) error { return r.insert(ctx, a) }

// FindOpenByRule 按终端 + 规则 ID 定位未终态告警。rule_ids 落库为 CSV，
// 规则 ID 全大写带连字符且互不为前缀子串，LIKE 精确匹配足够——
// 主机内单规则 open 告警个位数，不走通用过滤是刻意的（见接口注释）。
func (r *alertRepo) FindOpenByRule(ctx context.Context, agentID, ruleID string) ([]domain.Alert, error) {
	rows, err := r.s.db.QueryContext(ctx,
		`SELECT `+alertCols+` FROM alerts WHERE agent_id = ? AND status IN ('open','acknowledged')
		 AND ','||rule_ids||',' LIKE '%,'||?||',%'`,
		agentID, ruleID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]domain.Alert, 0, 2)
	for rows.Next() {
		a, err := scanAlert(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *a)
	}
	return out, rows.Err()
}

// FindDuplicates 批量查重：一批告警的指纹一次性按窗口查询，返回
// fingerprint → 命中摘要（窗口内行数 / 最近一行 ID / 最近时刻），供上层
// 做自适应抑制分级。为什么批量：上报路径是 500 条串行循环，逐条单查
// （每条一次 SQL prepare + 索引查找）在 modernc 纯 Go 驱动上实测 56ms/次，
// 整批 28s 超过 agent 20s 上报超时（见 ingest_bench_test.go 诊断）；分块
// IN 查询把读侧成本压到常数。bare column id 随 MAX(created_at) 取值是
// SQLite 文档化行为（min/max 聚合的 bare column 来自命中行）——一次查询
// 同时拿到"最近行"三个字段，不用为取行 ID 再发 N 条子查询。
// fp 参数由调用方去重；SQL 参数分块规避 SQLite 变量数上限。
func (r *alertRepo) FindDuplicates(ctx context.Context, agentID string, since time.Time, fingerprints []string) (map[string]repository.DupHit, error) {
	out := make(map[string]repository.DupHit, len(fingerprints))
	const chunk = 400
	for start := 0; start < len(fingerprints); start += chunk {
		end := start + chunk
		if end > len(fingerprints) {
			end = len(fingerprints)
		}
		part := fingerprints[start:end]
		args := make([]any, 0, len(part)+2)
		args = append(args, agentID, millis(since))
		ph := make([]string, 0, len(part))
		for _, fp := range part {
			args = append(args, fp)
			ph = append(ph, "?")
		}
		q := fmt.Sprintf(`SELECT fingerprint, COUNT(*), MAX(created_at), id FROM alerts
			 WHERE agent_id = ? AND created_at >= ? AND fingerprint IN (%s)
			 GROUP BY fingerprint`, strings.Join(ph, ","))
		rows, err := r.s.db.QueryContext(ctx, q, args...)
		if err != nil {
			return nil, fmt.Errorf("批量查重失败: %w", err)
		}
		for rows.Next() {
			var fp, id string
			var cnt int
			var mx int64
			if err := rows.Scan(&fp, &cnt, &mx, &id); err != nil {
				rows.Close()
				return nil, fmt.Errorf("批量查重扫描失败: %w", err)
			}
			out[fp] = repository.DupHit{AlertID: id, Count: cnt, LastSeenAt: time.UnixMilli(mx)}
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return nil, fmt.Errorf("批量查重遍历失败: %w", err)
		}
		rows.Close()
	}
	return out, nil
}

func (r *alertRepo) FindDuplicate(ctx context.Context, fingerprint, agentID string, since time.Time) (*domain.Alert, error) {
	row := r.s.db.QueryRowContext(ctx,
		`SELECT id, duplicate FROM alerts
		 WHERE fingerprint = ? AND agent_id = ? AND created_at >= ?
		 ORDER BY created_at DESC LIMIT 1`,
		fingerprint, agentID, millis(since))
	var id string
	var dup int
	if err := row.Scan(&id, &dup); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("查询重复告警失败: %w", err)
	}
	return &domain.Alert{ID: id, Duplicate: dup}, nil
}

func (r *alertRepo) BumpDuplicate(ctx context.Context, id string, at time.Time) error {
	_, err := r.s.db.ExecContext(ctx,
		`UPDATE alerts SET duplicate = duplicate + 1, created_at = created_at WHERE id = ?`, id)
	return err
}

func scanAlert(sc interface{ Scan(...any) error }) (*domain.Alert, error) {
	var (
		a         domain.Alert
		verdict   string
		severity  string
		signed    int
		ruleIDs   string
		mitre     string
		ev        string
		status    string
		handledAt sql.NullInt64
		occurred  int64
		created   int64
	)
	err := sc.Scan(&a.ID, &a.AgentID, &a.Hostname, &a.Fingerprint, &a.Title, &a.Summary, &verdict,
		&severity, &a.Score, &a.PID, &a.PPID, &a.ProcessName, &a.ImagePath, &a.CmdLine, &a.ProcUser,
		&a.HashSHA256, &a.Signer, &signed, &ruleIDs, &mitre, &ev, &status, &a.HandledBy, &handledAt,
		&a.Note, &a.Duplicate, &occurred, &created)
	if err != nil {
		return nil, err
	}
	a.Verdict = domain.Verdict(verdict)
	a.Severity = domain.Severity(severity)
	a.Signed = signed != 0
	a.RuleIDs = splitCSV(ruleIDs)
	a.MITRE = splitCSV(mitre)
	a.Status = domain.AlertStatus(status)
	a.HandledAt = fromNullMillis(handledAt)
	a.OccurredAt = fromMillis(occurred)
	a.CreatedAt = fromMillis(created)
	if ev != "" {
		_ = json.Unmarshal([]byte(ev), &a.Evidence)
	}
	a.HostCount = 1
	return &a, nil
}

func (r *alertRepo) ByID(ctx context.Context, id string) (*domain.Alert, error) {
	row := r.s.db.QueryRowContext(ctx, `SELECT `+alertCols+` FROM alerts WHERE id = ?`, id)
	a, err := scanAlert(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("查询告警失败: %w", err)
	}
	// 同指纹影响主机数
	var hosts int
	_ = r.s.db.QueryRowContext(ctx, `SELECT COUNT(DISTINCT agent_id) FROM alerts WHERE fingerprint = ?`, a.Fingerprint).Scan(&hosts)
	if hosts > 0 {
		a.HostCount = hosts
	}
	return a, nil
}

func (r *alertRepo) List(ctx context.Context, f domain.AlertFilter) ([]domain.Alert, int, error) {
	f.Normalize()

	var where []string
	var args []any

	if len(f.Status) > 0 {
		ph := make([]string, 0, len(f.Status))
		for _, s := range f.Status {
			ph = append(ph, "?")
			args = append(args, string(s))
		}
		where = append(where, "status IN ("+strings.Join(ph, ",")+")")
	}
	if len(f.Severity) > 0 {
		ph := make([]string, 0, len(f.Severity))
		for _, s := range f.Severity {
			ph = append(ph, "?")
			args = append(args, string(s))
		}
		where = append(where, "severity IN ("+strings.Join(ph, ",")+")")
	}
	if len(f.Verdict) > 0 {
		ph := make([]string, 0, len(f.Verdict))
		for _, s := range f.Verdict {
			ph = append(ph, "?")
			args = append(args, string(s))
		}
		where = append(where, "verdict IN ("+strings.Join(ph, ",")+")")
	}
	if f.AgentID != "" {
		where = append(where, "agent_id = ?")
		args = append(args, f.AgentID)
	}
	// 超期归档用的时间上界（零值=不限）
	if !f.CreatedBefore.IsZero() {
		where = append(where, "created_at < ?")
		args = append(args, millis(f.CreatedBefore))
	}
	if f.Query != "" {
		where = append(where, `(process_name LIKE ? OR image_path LIKE ? OR cmdline LIKE ? OR hostname LIKE ? OR title LIKE ?)`)
		like := "%" + f.Query + "%"
		args = append(args, like, like, like, like, like)
	}

	// ---- AI 查询 DSL 映射的字段 ----
	// 每个字段对应固定 SQL 片段，值全部参数绑定。
	// 模型能影响的只有"值"，碰不到"结构"，因此不存在拼接注入的路径。
	likeFilter := func(col, val string) {
		if val == "" {
			return
		}
		where = append(where, col+" LIKE ?")
		args = append(args, "%"+val+"%")
	}
	likeFilter("process_name", f.ProcessLike)
	likeFilter("image_path", f.PathLike)
	likeFilter("cmdline", f.CmdLike)
	likeFilter("proc_user", f.UserLike)
	likeFilter("hostname", f.HostLike)
	likeFilter("rule_ids", f.RuleLike)
	if f.Hash != "" {
		where = append(where, "hash_sha256 = ?")
		args = append(args, f.Hash)
	}
	// ATT&CK 精确匹配：CSV 列用逗号定界比对，T1059 不会误命中 T1059.001
	if f.Mitre != "" {
		where = append(where, `(',' || mitre || ',') LIKE ?`)
		args = append(args, "%,"+f.Mitre+",%")
	}
	if f.MinScore > 0 {
		where = append(where, "score >= ?")
		args = append(args, f.MinScore)
	}
	if f.Unsigned != nil {
		if *f.Unsigned {
			where = append(where, "signed = 0")
		} else {
			where = append(where, "signed = 1")
		}
	}

	whereSQL := ""
	if len(where) > 0 {
		whereSQL = " WHERE " + strings.Join(where, " AND ")
	}

	var total int
	if err := r.s.db.QueryRowContext(ctx, `SELECT COUNT(1) FROM alerts`+whereSQL, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("统计告警失败: %w", err)
	}

	order := " ORDER BY created_at DESC"
	switch f.Sort {
	case "score":
		order = " ORDER BY score DESC, created_at DESC"
	case "oldest":
		order = " ORDER BY created_at ASC"
	case "severity":
		order = ` ORDER BY CASE severity WHEN 'critical' THEN 5 WHEN 'high' THEN 4
			WHEN 'medium' THEN 3 WHEN 'low' THEN 2 ELSE 1 END DESC, created_at DESC`
	}

	q := `SELECT ` + alertCols + ` FROM alerts` + whereSQL + order + ` LIMIT ? OFFSET ?`
	args = append(args, f.PageSize, (f.Page-1)*f.PageSize)

	rows, err := r.s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("查询告警失败: %w", err)
	}
	defer rows.Close()

	var out []domain.Alert
	for rows.Next() {
		a, err := scanAlert(rows)
		if err != nil {
			return nil, 0, fmt.Errorf("解析告警失败: %w", err)
		}
		out = append(out, *a)
	}
	return out, total, rows.Err()
}

func (r *alertRepo) UpdateStatus(ctx context.Context, id string, status domain.AlertStatus, by, note string, at time.Time) error {
	res, err := r.s.db.ExecContext(ctx,
		`UPDATE alerts SET status = ?, handled_by = ?, handled_at = ?, note = CASE WHEN ? <> '' THEN ? ELSE note END
		 WHERE id = ?`,
		string(status), by, millis(at), note, note, id)
	if err != nil {
		return fmt.Errorf("更新告警状态失败: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (r *alertRepo) CountOpenByAgent(ctx context.Context) (map[string]int, error) {
	rows, err := r.s.db.QueryContext(ctx,
		`SELECT agent_id, COUNT(1) FROM alerts WHERE status = 'open' GROUP BY agent_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := map[string]int{}
	for rows.Next() {
		var id string
		var n int
		if err := rows.Scan(&id, &n); err != nil {
			return nil, err
		}
		out[id] = n
	}
	return out, rows.Err()
}

// RecycleForAllow 实现"加白即回收"：把与白名单对象匹配的未处置告警
// 直接标记为误报，避免运维加白后还要逐条手工作废。
func (r *alertRepo) RecycleForAllow(ctx context.Context, typ, value, by string, at time.Time) (int64, error) {
	var where string
	var arg any

	switch typ {
	case "hash":
		where = "hash_sha256 = ?"
		arg = value
	case "path":
		// 路径白名单是"包含"语义，这里保持一致
		where = "image_path LIKE ?"
		arg = "%" + value + "%"
	case "signer":
		where = "signer = ?"
		arg = value
	default:
		return 0, nil // pair / cmdline 无法用 SQL 精确表达，跳过
	}

	res, err := r.s.db.ExecContext(ctx,
		`UPDATE alerts SET status = 'false_positive', handled_by = ?, handled_at = ?,
		        note = CASE WHEN note = '' THEN '白名单自动回收' ELSE note || ' / 白名单自动回收' END
		 WHERE status IN ('open','acknowledged') AND `+where,
		by, millis(at), arg)
	if err != nil {
		return 0, fmt.Errorf("回收历史告警失败: %w", err)
	}
	return res.RowsAffected()
}

// PurgeBefore 清理超过保留窗的「已处置」告警。acknowledged 必须纳入：
// OpenAlertTTL 归档只是把 open 挪进 ack（incidents.go），ack 再豁免等于
// 把存储黑洞换个桶——11-14 洪水复盘（TEST-REPORT §十九）的教训。
// open 永不在此清理：那是正在处置的工作集，出口只有人工处置与
// 显式开启的 OpenAlertTTL。
func (r *alertRepo) PurgeBefore(ctx context.Context, before time.Time) (int64, error) {
	res, err := r.s.db.ExecContext(ctx,
		`DELETE FROM alerts WHERE created_at < ? AND status IN ('resolved','false_positive','acknowledged')`, millis(before))
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// ListInventoryChanges 返回某终端的资产变更事件（inventory 层信号）。
// 证据列是 JSON，用层标记做 LIKE 定位：单主机事件量小（个位数/天），
// LIKE 的代价可接受；上限由服务层钳制后传入。
func (r *alertRepo) ListInventoryChanges(ctx context.Context, agentID string, limit int) ([]domain.Alert, error) {
	if limit <= 0 || limit > 200 {
		limit = 100
	}
	rows, err := r.s.db.QueryContext(ctx,
		`SELECT `+alertCols+` FROM alerts
		 WHERE agent_id = ? AND evidence LIKE '%"layer":"inventory"%'
		 ORDER BY created_at DESC LIMIT ?`, agentID, limit)
	if err != nil {
		return nil, fmt.Errorf("查询资产变更事件失败: %w", err)
	}
	defer rows.Close()
	var out []domain.Alert
	for rows.Next() {
		a, err := scanAlert(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *a)
	}
	return out, rows.Err()
}

// IntegrityDigest 计算区间内告警的完整性摘要。
// 摘要覆盖 id/fingerprint/score/hash 四个"事后最难抵赖"的字段，
// 按 id 排序保证同一天数据得出同一摘要；流式扫描不设内存上界。
func (r *alertRepo) IntegrityDigest(ctx context.Context, start, end time.Time) (string, int, error) {
	rows, err := r.s.db.QueryContext(ctx,
		`SELECT id, fingerprint, score, hash_sha256 FROM alerts
		 WHERE created_at >= ? AND created_at < ? ORDER BY id`,
		millis(start), millis(end))
	if err != nil {
		return "", 0, err
	}
	defer rows.Close()

	h := sha256.New()
	n := 0
	for rows.Next() {
		var id, fp, hash string
		var score int
		if err := rows.Scan(&id, &fp, &score, &hash); err != nil {
			return "", 0, err
		}
		fmt.Fprintf(h, "%s|%s|%d|%s\n", id, fp, score, hash)
		n++
	}
	if err := rows.Err(); err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

func (r *alertRepo) IntegrityDays(ctx context.Context) ([]string, error) {
	rows, err := r.s.db.QueryContext(ctx, `SELECT day FROM integrity_chain ORDER BY day`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var d string
		if err := rows.Scan(&d); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

func (r *alertRepo) IntegrityGet(ctx context.Context, day string) (string, int, bool, error) {
	var digest string
	var n int
	err := r.s.db.QueryRowContext(ctx,
		`SELECT digest, alert_count FROM integrity_chain WHERE day = ?`, day).
		Scan(&digest, &n)
	if err == sql.ErrNoRows {
		return "", 0, false, nil
	}
	if err != nil {
		return "", 0, false, err
	}
	return digest, n, true, nil
}

func (r *alertRepo) IntegrityPut(ctx context.Context, day, digest string, n int) error {
	_, err := r.s.db.ExecContext(ctx,
		`INSERT OR IGNORE INTO integrity_chain (day, digest, alert_count, created_at)
		 VALUES (?, ?, ?, ?)`, day, digest, n, time.Now().UnixMilli())
	return err
}
