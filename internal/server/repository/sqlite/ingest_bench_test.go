package sqlite

// ingest_bench_test.go：M1 诊断基准（2026-11-11）——告警入库慢性 500
// （.smoke 日志 3121 次、单次精确 20s）的 DB 层定位。
// 假设链：agent 上报超时 20s（uplink.go:85）→ 服务端一批 500 条的
// FindDuplicate+Create 串行循环超过 20s → ctx 取消 → 500 → spool 重试
// 再超时。本基准回答"DB 层一批 500 条到底要多久"，区分三种结论：
//   a) <2s：DB 层无辜，慢在服务端其他环节（bus/锁/上报并发）；
//   b) 2-20s 且随表增长变慢：批处理设计问题（逐条往返+重复查询）；
//   c) 与并发写相关：单写者锁竞争。
// 结论见各 case 输出；本文件保留为回归基准（阈值宽松，防性能倒退）。

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"zedr/internal/server/domain"
)

func benchAlert(i int, host string) *domain.Alert {
	return &domain.Alert{
		ID: fmt.Sprintf("bench%06d", i), AgentID: "agent-bench", Hostname: host,
		Fingerprint: fmt.Sprintf("fp-%s-%06d", host, i),
		Title:       "S-DIAG 500 基准告警", Summary: "ingest benchmark", Verdict: domain.VerdictSuspicious,
		Severity: domain.SeverityMedium, Score: 40, Status: domain.StatusOpen,
		OccurredAt: time.Now(), CreatedAt: time.Now(), HostCount: 1,
	}
}

func TestBenchIngestBatch500(t *testing.T) {
	ctx := context.Background()
	store, repos, err := Open(ctx, filepath.Join(t.TempDir(), "bench500.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	// 场景 A：空表首批 500 条新告警（spool 重放的常态）
	start := time.Now()
	for i := 0; i < 500; i++ {
		if err := repos.Alerts.Create(ctx, benchAlert(i, "HOST-A")); err != nil {
			t.Fatalf("insert %d: %v", i, err)
		}
	}
	empty := time.Since(start)

	// 场景 B：表已 2 万条时再插 500 条（ chronic 场景：长期运行库）
	for i := 0; i < 20000; i++ {
		a := benchAlert(i, "HOST-SEED")
		a.Fingerprint = fmt.Sprintf("fp-seed-%06d", i)
		a.ID = fmt.Sprintf("seed%06d", i)
		if err := repos.Alerts.Create(ctx, a); err != nil {
			t.Fatalf("seed %d: %v", i, err)
		}
	}
	start = time.Now()
	for i := 500; i < 1000; i++ {
		if err := repos.Alerts.Create(ctx, benchAlert(i, "HOST-A")); err != nil {
			t.Fatalf("grown insert %d: %v", i, err)
		}
	}
	grown := time.Since(start)

	// 场景 C：500 次查重（dup 窗口内命中——上报重放时的常态路径）
	start = time.Now()
	for i := 0; i < 500; i++ {
		if _, err := repos.Alerts.FindDuplicate(ctx, fmt.Sprintf("fp-HOST-A-%06d", i), "agent-bench", time.Now().Add(-time.Hour)); err != nil {
			t.Fatalf("dup %d: %v", i, err)
		}
	}
	dups := time.Since(start)

	// 场景 D：批量查重（修复后路径）——同 C 的指纹集，一次分块 IN 查询
	fps := make([]string, 0, 500)
	for i := 0; i < 500; i++ {
		fps = append(fps, fmt.Sprintf("fp-HOST-A-%06d", i))
	}
	start = time.Now()
	got, err := repos.Alerts.FindDuplicates(ctx, "agent-bench", time.Now().Add(-time.Hour), fps)
	if err != nil {
		t.Fatalf("批量查重: %v", err)
	}
	batched := time.Since(start)
	if len(got) == 0 {
		t.Fatal("批量查重应命中场景 A/B 已插入的指纹")
	}

	t.Logf("A 空表 500 插入: %s (%.2fms/条)", empty, float64(empty.Microseconds())/500/1000)
	t.Logf("B 2 万表 500 插入: %s (%.2fms/条)", grown, float64(grown.Microseconds())/500/1000)
	t.Logf("C 500 次单查重(旧路径): %s (%.2fms/次)", dups, float64(dups.Microseconds())/500/1000)
	t.Logf("D 批量查重(新路径): %s (%d 命中)", batched, len(got))
	if batched > 2*time.Second {
		t.Errorf("批量查重仍超 2s（旧路径 28s 的根因未除）: %s", batched)
	}
}
