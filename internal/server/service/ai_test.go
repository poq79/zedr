package service

import (
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"zedr/internal/ai"
	"zedr/internal/server/domain"
	"zedr/internal/server/repository"
	"zedr/internal/server/repository/sqlite"
)

// newAIServiceTest 开临时 SQLite 库并搭一个最小 AIService。
// 走真实仓储（与 integrity_test 同款基建）而不是假 repo：资产摘要的
// 解析对象是"探针上报落库后的 payload"，用真库能顺带覆盖 Upsert 往返。
func newAIServiceTest(t *testing.T) (*AIService, repository.Repos, context.Context) {
	t.Helper()
	ctx := context.Background()
	store, repos, err := sqlite.Open(ctx, filepath.Join(t.TempDir(), "ai.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := &AIService{repos: repos, eng: ai.NewEngine(ai.Config{Provider: "none"}, log), log: log}
	return svc, repos, ctx
}

func seedAgentAndAlert(t *testing.T, repos repository.Repos, ctx context.Context) *domain.Alert {
	t.Helper()
	if err := repos.Agents.Upsert(ctx, &domain.Agent{
		ID: "ag-1", Hostname: "PC-01", OSVersion: "Windows 11 Pro",
		SecretHash: "test-hash", Status: domain.AgentOnline,
		EnrolledAt: time.Now(), LastSeenAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	if err := repos.Alerts.Create(ctx, &domain.Alert{
		ID: "al-1", AgentID: "ag-1", Hostname: "PC-01", Fingerprint: "fp-1",
		Title: "t", Verdict: domain.VerdictSuspicious, Severity: domain.SeverityMedium,
		Score: 40, ProcessName: "x.exe", CreatedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	// buildInput 只读 ID/AgentID/Hostname，其余字段走仓储取
	return &domain.Alert{ID: "al-1", AgentID: "ag-1", Hostname: "PC-01"}
}

// TestBuildInputAssetSummary 验证资产摘要接入主机上下文：
// 有完整清单 → OS 行带上 监听/服务/任务 计数；任何缺失/损坏/为空 →
// 摘要整体缺席且 OS 保持心跳上报值（研判不得因资产缺失降级）。
func TestBuildInputAssetSummary(t *testing.T) {
	svc, repos, ctx := newAIServiceTest(t)
	alert := seedAgentAndAlert(t, repos, ctx)

	upsertSection := func(name, payload string) {
		t.Helper()
		err := repos.Inventory.Upsert(ctx, "ag-1", domain.HostInventorySection{
			Name:      name,
			Hash:      sha256Hex(payload),
			Payload:   payload,
			UpdatedAt: time.Now(),
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	expectOS := func(want string) {
		t.Helper()
		in, err := svc.buildInput(ctx, alert)
		if err != nil {
			t.Fatal(err)
		}
		if in.Host.OS != want {
			t.Fatalf("主机上下文 OS 不符：\n got=%q\nwant=%q", in.Host.OS, want)
		}
	}

	// 完整清单：监听 3（tcp 2 + udp 1）/ 服务 2 / 任务 1
	upsertSection("listeners", `{"tcp":[{"port":445,"pid":4},{"port":3389,"pid":8}],"udp":[{"port":137,"pid":4}]}`)
	upsertSection("services", `[{"name":"A"},{"name":"B"}]`)
	upsertSection("tasks", `[{"path":"\\X"}]`)
	expectOS("Windows 11 Pro / 监听 3 / 服务 2 / 任务 1")

	// 清单缺失（需要的节没采上来）→ 摘要整体缺席
	if err := repos.Inventory.DeleteByAgent(ctx, "ag-1"); err != nil {
		t.Fatal(err)
	}
	expectOS("Windows 11 Pro")

	// payload 解析失败 → 静默跳过，OS 不被改写
	upsertSection("listeners", `{"tcp":[],"udp":[]}`)
	upsertSection("services", "not-json")
	upsertSection("tasks", `[{"path":"\\X"}]`)
	expectOS("Windows 11 Pro")

	// 解析出 0 条（服务列表为空）→ 同样跳过：给模型 "服务 0" 比不给更糟
	upsertSection("services", `[]`)
	expectOS("Windows 11 Pro")
}
