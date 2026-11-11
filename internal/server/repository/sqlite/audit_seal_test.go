package sqlite

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"zedr/internal/server/domain"
	"zedr/internal/server/repository"
)

// openAuditStore 打开临时库并启用封印链，返回 (store, repos)。
func openAuditStore(t *testing.T) (*Store, repository.Repos) {
	t.Helper()
	return openAuditStoreWithKey(t, []byte("test-audit-seal-key-32-bytes-min!!"))
}

func openAuditStoreWithKey(t *testing.T, key []byte) (*Store, repository.Repos) {
	t.Helper()
	store, repos, err := Open(context.Background(), filepath.Join(t.TempDir(), "audit-test.db"))
	if err != nil {
		t.Fatalf("打开测试库失败: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if _, err := repos.Audit.EnableSeal(context.Background(), key); err != nil {
		t.Fatalf("启用封印链失败: %v", err)
	}
	return store, repos
}

func addAudit(t *testing.T, repos repository.Repos, action, detail string) {
	t.Helper()
	err := repos.Audit.Add(context.Background(), &domain.AuditLog{
		UserID: "u1", Username: "admin", Action: action,
		Target: "t", Detail: detail, IP: "127.0.0.1",
		CreatedAt: time.Now(),
	})
	if err != nil {
		t.Fatalf("写入审计失败: %v", err)
	}
}

func mustVerify(t *testing.T, repos repository.Repos) domain.AuditChainReport {
	t.Helper()
	rep, err := repos.Audit.VerifyChain(context.Background())
	if err != nil {
		t.Fatalf("校验失败: %v", err)
	}
	return rep
}

// TestAuditSealRoundtrip 正常写入→校验通过，序号连续、锚点跟住链尾。
func TestAuditSealRoundtrip(t *testing.T) {
	_, repos := openAuditStore(t)
	for i := 0; i < 5; i++ {
		addAudit(t, repos, "test.action", "条目")
	}
	rep := mustVerify(t, repos)
	if !rep.OK || rep.Sealed != 5 || rep.Unsealed != 0 || rep.HeadSeq != 5 || rep.AnchorSeq != 5 {
		t.Fatalf("往返校验不符: %+v", rep)
	}
}

// TestAuditSealTamperUpdate 修改已封印行内容 → seal_mismatch 断在该行。
func TestAuditSealTamperUpdate(t *testing.T) {
	store, repos := openAuditStore(t)
	for i := 0; i < 3; i++ {
		addAudit(t, repos, "test.action", "原样")
	}
	if _, err := store.DB().Exec(`UPDATE audit_logs SET detail = '篡改' WHERE seq = 2`); err != nil {
		t.Fatalf("篡改更新失败: %v", err)
	}
	rep := mustVerify(t, repos)
	if rep.OK || rep.BrokenAt != 2 || rep.Reason != "seal_mismatch" {
		t.Fatalf("篡改未被发现: %+v", rep)
	}
}

// TestAuditSealDeleteMiddle 删除中间行 → 序号出现缺口 → seq_gap。
func TestAuditSealDeleteMiddle(t *testing.T) {
	store, repos := openAuditStore(t)
	for i := 0; i < 4; i++ {
		addAudit(t, repos, "test.action", "")
	}
	if _, err := store.DB().Exec(`DELETE FROM audit_logs WHERE seq = 2`); err != nil {
		t.Fatalf("中间删除失败: %v", err)
	}
	rep := mustVerify(t, repos)
	if rep.OK || rep.Reason != "seq_gap" {
		t.Fatalf("中间删除未被发现: %+v", rep)
	}
}

// TestAuditSealDeleteTail 删掉末尾若干行 → 锚点停在更高序号 → anchor_stale。
// 这是带密钥锚点的核心价值：纯 DB 攻击者读得到链尾 seal、重算不出合法锚点。
func TestAuditSealDeleteTail(t *testing.T) {
	store, repos := openAuditStore(t)
	for i := 0; i < 4; i++ {
		addAudit(t, repos, "test.action", "")
	}
	if _, err := store.DB().Exec(`DELETE FROM audit_logs WHERE seq >= 3`); err != nil {
		t.Fatalf("尾删失败: %v", err)
	}
	rep := mustVerify(t, repos)
	if rep.OK || rep.Reason != "anchor_stale" || rep.HeadSeq != 2 {
		t.Fatalf("尾删未被发现: %+v", rep)
	}
}

// TestAuditSealBackfill 启用前的历史行（seal 空）在 EnableSeal 时回填进链，
// 之后照常追加与校验；重复启用幂等。
func TestAuditSealBackfill(t *testing.T) {
	ctx := context.Background()
	store, repos, err := Open(ctx, filepath.Join(t.TempDir(), "backfill-test.db"))
	if err != nil {
		t.Fatalf("打开测试库失败: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	key := []byte("test-audit-seal-key-32-bytes-min!!")
	// 模拟升级前写入的两条历史行：链未启用 → 未封印路径
	for i := 0; i < 2; i++ {
		if err := repos.Audit.Add(ctx, &domain.AuditLog{Action: "legacy", CreatedAt: time.Now()}); err != nil {
			t.Fatalf("写入历史行失败: %v", err)
		}
	}
	if n, err := repos.Audit.EnableSeal(ctx, key); err != nil || n != 2 {
		t.Fatalf("回填条数不符: n=%d err=%v", n, err)
	}
	addAudit(t, repos, "post.enable", "")
	rep := mustVerify(t, repos)
	if !rep.OK || rep.Sealed != 3 || rep.Unsealed != 0 || rep.HeadSeq != 3 {
		t.Fatalf("回填后校验不符: %+v", rep)
	}
	if n, err := repos.Audit.EnableSeal(ctx, key); err != nil || n != 0 {
		t.Fatalf("重复启用应幂等: n=%d err=%v", n, err)
	}
}
