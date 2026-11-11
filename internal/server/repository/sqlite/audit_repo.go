package sqlite

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"zedr/internal/server/domain"
)

// ---------------------------------------------------------------- audit

// auditRepo 写审计并维护 HMAC 防篡改链。
// 链是严格串行的状态机（seal_i 依赖 seal_{i-1}），审计写入本身低频
// （人工操作/登录/MCP 调用），一把互斥锁换确定性，不做无锁快路径。
type auditRepo struct {
	s   *Store
	mu  sync.Mutex
	key []byte // nil = 链未启用（测试/极端降级），按旧路径写入未封印行
}

// EnableSeal 注入封印密钥并回填历史行。app 装配层在启动、对外服务前调用一次。
func (r *auditRepo) EnableSeal(ctx context.Context, key []byte) (int, error) {
	if len(key) == 0 {
		return 0, fmt.Errorf("审计封印密钥为空")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.key = append([]byte(nil), key...)
	return r.backfillLocked(ctx)
}

// backfillLocked 把 seal 为空的历史行按 id 顺序接进链尾。seq 语义是
// "封印顺序"而非"发生顺序"——历史行发生更早但封印更晚，行内容里的
// created_at 不受影响；链证明的是"这行从封印起没被改过"。
func (r *auditRepo) backfillLocked(ctx context.Context) (int, error) {
	rows, err := r.s.db.QueryContext(ctx,
		`SELECT id, user_id, username, action, target, detail, ip, created_at
		 FROM audit_logs WHERE seal = '' ORDER BY id`)
	if err != nil {
		return 0, fmt.Errorf("查询未封印审计行失败: %w", err)
	}
	type legacy struct {
		id      int64
		userID  string
		user    string
		action  string
		target  string
		detail  string
		ip      string
		created int64
	}
	var pending []legacy
	for rows.Next() {
		var l legacy
		if err := rows.Scan(&l.id, &l.userID, &l.user, &l.action, &l.target, &l.detail, &l.ip, &l.created); err != nil {
			rows.Close()
			return 0, fmt.Errorf("解析未封印审计行失败: %w", err)
		}
		pending = append(pending, l)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return 0, fmt.Errorf("遍历未封印审计行失败: %w", err)
	}
	rows.Close()
	if len(pending) == 0 {
		return 0, nil
	}

	tx, err := r.s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("开启审计回填事务失败: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	prevSeq, prevSeal, err := chainHeadLocked(ctx, tx)
	if err != nil {
		return 0, err
	}
	for _, l := range pending {
		prevSeq++
		seal := auditSealMAC(r.key, prevSeal, prevSeq, l.userID, l.user, l.action, l.target, l.detail, l.ip, l.created)
		if _, err := tx.ExecContext(ctx,
			`UPDATE audit_logs SET seq = ?, seal = ? WHERE id = ?`,
			prevSeq, seal, l.id); err != nil {
			return 0, fmt.Errorf("回填审计封印失败: %w", err)
		}
		prevSeal = seal
	}
	if err := writeAnchorLocked(ctx, tx, r.key, prevSeq, prevSeal); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("提交审计回填失败: %w", err)
	}
	return len(pending), nil
}

// chainHeadLocked 返回当前链尾 (seq, seal)；空链返回 (0, "")。
func chainHeadLocked(ctx context.Context, tx *sql.Tx) (int64, string, error) {
	var prevSeq int64
	if err := tx.QueryRowContext(ctx,
		`SELECT COALESCE(MAX(seq), 0) FROM audit_logs WHERE seal <> ''`).Scan(&prevSeq); err != nil {
		return 0, "", fmt.Errorf("读取审计链尾失败: %w", err)
	}
	if prevSeq == 0 {
		return 0, "", nil
	}
	var prevSeal string
	if err := tx.QueryRowContext(ctx,
		`SELECT seal FROM audit_logs WHERE seq = ?`, prevSeq).Scan(&prevSeal); err != nil {
		return 0, "", fmt.Errorf("读取审计链尾封印失败: %w", err)
	}
	return prevSeq, prevSeal, nil
}

func (r *auditRepo) Add(ctx context.Context, l *domain.AuditLog) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	created := millis(l.CreatedAt)
	if r.key == nil {
		// 链未启用：兼容旧路径。VerifyChain 把这些行如实报为未封印，
		// 不静默伪装成"校验通过"。
		if _, err := r.s.db.ExecContext(ctx,
			`INSERT INTO audit_logs(user_id, username, action, target, detail, ip, created_at) VALUES(?,?,?,?,?,?,?)`,
			l.UserID, l.Username, l.Action, l.Target, l.Detail, l.IP, created); err != nil {
			return fmt.Errorf("写入审计日志失败: %w", err)
		}
		return nil
	}

	tx, err := r.s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("开启审计事务失败: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	prevSeq, prevSeal, err := chainHeadLocked(ctx, tx)
	if err != nil {
		return err
	}
	seq := prevSeq + 1
	seal := auditSealMAC(r.key, prevSeal, seq, l.UserID, l.Username, l.Action, l.Target, l.Detail, l.IP, created)
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO audit_logs(user_id, username, action, target, detail, ip, created_at, seq, seal)
		 VALUES(?,?,?,?,?,?,?,?,?)`,
		l.UserID, l.Username, l.Action, l.Target, l.Detail, l.IP, created, seq, seal); err != nil {
		return fmt.Errorf("写入审计日志失败: %w", err)
	}
	if err := writeAnchorLocked(ctx, tx, r.key, seq, seal); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("提交审计日志失败: %w", err)
	}
	l.Seq = seq
	return nil
}

// auditSealMAC 计算链封印。域分隔前缀防跨用途重放；prevSeal 进 MAC 输入，
// 校验时从首行空封印起逐行递推，任何一行被改都会使其后所有 seal 对不上。
func auditSealMAC(key []byte, prevSeal string, seq int64, userID, user, action, target, detail, ip string, created int64) string {
	msg := strings.Join([]string{
		"zedr-audit-v1", prevSeal,
		strconv.FormatInt(seq, 10), strconv.FormatInt(created, 10),
		userID, user, action, target, detail, ip,
	}, "\x00")
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(msg))
	return hex.EncodeToString(mac.Sum(nil))
}

// auditAnchorMAC 链尾锚点的带密钥 MAC。纯 DB 攻击者能读到链尾 seal
// 却没有密钥，删尾后重算不出合法锚点——这是"删末尾行也可发现"的关键。
func auditAnchorMAC(key []byte, seq int64, seal string) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte("zedr-audit-anchor-v1\x00" + strconv.FormatInt(seq, 10) + "\x00" + seal))
	return hex.EncodeToString(mac.Sum(nil))
}

func writeAnchorLocked(ctx context.Context, tx *sql.Tx, key []byte, seq int64, seal string) error {
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO audit_seal_anchor(id, seq, mac) VALUES(1, ?, ?)
		 ON CONFLICT(id) DO UPDATE SET seq = excluded.seq, mac = excluded.mac`,
		seq, auditAnchorMAC(key, seq, seal)); err != nil {
		return fmt.Errorf("更新审计锚点失败: %w", err)
	}
	return nil
}

// VerifyChain 全链校验：逐行重算 HMAC、已封印行序号必须连续、锚点必须等于链尾。
// 未封印行（启用前的历史）跳过并计数，不算断链——兼容期诚实呈现而非伪装通过。
func (r *auditRepo) VerifyChain(ctx context.Context) (domain.AuditChainReport, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	rep := domain.AuditChainReport{VerifiedAt: time.Now().Format(time.RFC3339)}
	rows, err := r.s.db.QueryContext(ctx,
		`SELECT seq, user_id, username, action, target, detail, ip, created_at, seal
		 FROM audit_logs ORDER BY seq ASC, id ASC`)
	if err != nil {
		return rep, fmt.Errorf("查询审计链失败: %w", err)
	}
	defer rows.Close()

	var (
		expect   int64 = 1
		prevSeal string
		headSeq  int64
		headSeal string
	)
	for rows.Next() {
		var (
			seq, created               int64
			userID, user, action, target, detail, ip, seal string
		)
		if err := rows.Scan(&seq, &userID, &user, &action, &target, &detail, &ip, &created, &seal); err != nil {
			return rep, fmt.Errorf("解析审计链失败: %w", err)
		}
		rep.Total++
		if seal == "" {
			rep.Unsealed++
			continue
		}
		rep.Sealed++
		if rep.BrokenAt == 0 {
			switch {
			case seq != expect:
				rep.BrokenAt, rep.Reason = seq, "seq_gap"
			case seal != auditSealMAC(r.key, prevSeal, seq, userID, user, action, target, detail, ip, created):
				rep.BrokenAt, rep.Reason = seq, "seal_mismatch"
			}
		}
		expect = seq + 1
		prevSeal = seal
		headSeq, headSeal = seq, seal
	}
	if err := rows.Err(); err != nil {
		return rep, fmt.Errorf("遍历审计链失败: %w", err)
	}
	rep.HeadSeq = headSeq

	if rep.Sealed > 0 {
		var aSeq int64
		var aMac string
		err := r.s.db.QueryRowContext(ctx, `SELECT seq, mac FROM audit_seal_anchor WHERE id = 1`).Scan(&aSeq, &aMac)
		switch {
		case errors.Is(err, sql.ErrNoRows):
			rep.BrokenAt, rep.Reason = headSeq, "anchor_missing"
		case err != nil:
			return rep, fmt.Errorf("读取审计锚点失败: %w", err)
		case aSeq != headSeq || aMac != auditAnchorMAC(r.key, headSeq, headSeal):
			rep.BrokenAt, rep.Reason = headSeq, "anchor_stale"
			rep.AnchorSeq = aSeq
		default:
			rep.AnchorSeq = aSeq
		}
	}
	rep.OK = rep.BrokenAt == 0
	return rep, nil
}

func (r *auditRepo) List(ctx context.Context, limit int) ([]domain.AuditLog, error) {
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	rows, err := r.s.db.QueryContext(ctx,
		`SELECT id, seq, user_id, username, action, target, detail, ip, created_at
		 FROM audit_logs ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("查询审计日志失败: %w", err)
	}
	defer rows.Close()

	var out []domain.AuditLog
	for rows.Next() {
		var (
			l       domain.AuditLog
			created int64
		)
		if err := rows.Scan(&l.ID, &l.Seq, &l.UserID, &l.Username, &l.Action, &l.Target, &l.Detail, &l.IP, &created); err != nil {
			return nil, fmt.Errorf("解析审计日志失败: %w", err)
		}
		l.CreatedAt = fromMillis(created)
		out = append(out, l)
	}
	return out, rows.Err()
}
