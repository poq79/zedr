package service

import (
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"zedr/internal/model"
	"zedr/internal/server/domain"
	"zedr/internal/server/repository/sqlite"
)

// 传感器失联告警闭环的纪律：一轮失联周期一条告警（周期内去重靠查
// open 不靠指纹窗口）、恢复自动结案、总开关关掉就静默。
// 走真实仓储（同 ops_test 基建），transition 判定依赖 agents 表真实翻转。

func newSensorTest(t *testing.T, alertsOn bool) (*Services, context.Context) {
	t.Helper()
	ctx := context.Background()
	store, repos, err := sqlite.Open(ctx, filepath.Join(t.TempDir(), "sensor.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := New(repos, nil, Config{
		SensorOfflineAlerts:   alertsOn,
		SensorOfflineSeverity: "medium",
		ScanInterval:          2 * time.Second,
		HeartbeatInterval:     30 * time.Second,
	}, log, nil)
	return svc, ctx
}

// mkOnlineAgent 造一台 last_seen 已超时的在线终端（默认 10 分钟没心跳）。
func mkOnlineAgent(t *testing.T, svc *Services, ctx context.Context, id, host string, lastSeenAgo time.Duration) {
	t.Helper()
	a := &domain.Agent{
		ID: id, Hostname: host, OSVersion: "Windows Server 2022", Arch: "amd64",
		MachineID: "mid-" + id, SecretHash: "h", Status: domain.AgentOnline,
		EnrolledAt: time.Now().Add(-24 * time.Hour),
		LastSeenAt: time.Now().Add(-lastSeenAgo),
		Version:    "v0.9.12", IP: "10.0.0.42",
	}
	if err := svc.Agent.repos.Agents.Upsert(ctx, a); err != nil {
		t.Fatal(err)
	}
}

func TestSensorOfflineRaiseAndDedup(t *testing.T) {
	svc, ctx := newSensorTest(t, true)
	mkOnlineAgent(t, svc, ctx, "agt-1", "ws2022-a", 10*time.Minute)

	stale, err := svc.Agent.MarkOffline(ctx, 3*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if len(stale) != 1 || stale[0].ID != "agt-1" {
		t.Fatalf("转变清单应含 agt-1，got %v", stale)
	}

	n, err := svc.Sensor.RaiseForTransitions(ctx, stale)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("失联应建 1 条告警，got %d", n)
	}

	open, err := svc.Sensor.repos.Alerts.FindOpenByRule(ctx, "agt-1", RuleIDSensorOffline)
	if err != nil {
		t.Fatal(err)
	}
	if len(open) != 1 {
		t.Fatalf("应有 1 条 open 失联告警，got %d", len(open))
	}
	a := open[0]
	if a.Severity != domain.SeverityMedium {
		t.Errorf("severity 应为 medium（可配置默认），got %s", a.Severity)
	}
	if a.Verdict != domain.VerdictSuspicious {
		t.Errorf("verdict 应为 suspicious（无法区分关机与杀死 EDR），got %s", a.Verdict)
	}
	if a.Status != domain.StatusOpen {
		t.Errorf("status 应为 open，got %s", a.Status)
	}
	if a.Hostname != "ws2022-a" {
		t.Errorf("hostname 应继承终端，got %q", a.Hostname)
	}
	if len(a.Evidence.Notes) == 0 {
		t.Error("evidence.notes 应携带 last_seen/静默时长等事实")
	}

	// 周期内去重：同一转变重复进 Raise（重复 tick / 重放）不得新建。
	n, err = svc.Sensor.RaiseForTransitions(ctx, stale)
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("已有 open 失联告警时不应新建，got %d", n)
	}
}

func TestSensorOfflineDisabled(t *testing.T) {
	svc, ctx := newSensorTest(t, false)
	mkOnlineAgent(t, svc, ctx, "agt-2", "ws2022-b", 10*time.Minute)

	stale, err := svc.Agent.MarkOffline(ctx, 3*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	n, err := svc.Sensor.RaiseForTransitions(ctx, stale)
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("总开关关闭时应静默，got %d", n)
	}
}

func TestSensorResolveOnBackOnline(t *testing.T) {
	svc, ctx := newSensorTest(t, true)
	mkOnlineAgent(t, svc, ctx, "agt-3", "ws2022-c", 10*time.Minute)
	stale, _ := svc.Agent.MarkOffline(ctx, 3*time.Minute)
	if _, err := svc.Sensor.RaiseForTransitions(ctx, stale); err != nil {
		t.Fatal(err)
	}

	n, err := svc.Sensor.ResolveOnBackOnline(ctx, "agt-3")
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("恢复应结案 1 条，got %d", n)
	}
	open, err := svc.Sensor.repos.Alerts.FindOpenByRule(ctx, "agt-3", RuleIDSensorOffline)
	if err != nil {
		t.Fatal(err)
	}
	if len(open) != 0 {
		t.Fatalf("结案后不应再有 open 失联告警，got %d", len(open))
	}

	// 再失联是新周期：翻转 → 新建 → 又一条独立告警（指纹带最后心跳时间）。
	mkOnlineAgent(t, svc, ctx, "agt-3", "ws2022-c", 10*time.Minute)
	stale, _ = svc.Agent.MarkOffline(ctx, 3*time.Minute)
	n, _ = svc.Sensor.RaiseForTransitions(ctx, stale)
	if n != 1 {
		t.Fatalf("第二次失联应新建告警，got %d", n)
	}
}

// TestHeartbeatAutoResolve 走真实心跳入口验证恢复闭环：offline 终端发来
// 心跳时，其 open 失联告警被自动结案，状态回到 online。
func TestHeartbeatAutoResolve(t *testing.T) {
	svc, ctx := newSensorTest(t, true)
	mkOnlineAgent(t, svc, ctx, "agt-4", "ws2022-d", 10*time.Minute)
	stale, _ := svc.Agent.MarkOffline(ctx, 3*time.Minute)
	if _, err := svc.Sensor.RaiseForTransitions(ctx, stale); err != nil {
		t.Fatal(err)
	}

	if _, err := svc.Agent.Heartbeat(ctx, "agt-4", model.HeartbeatRequest{
		Hostname: "ws2022-d", ProcCount: 120, CPUPercent: 1.2, MemMB: 35,
	}, "10.0.0.42"); err != nil {
		t.Fatal(err)
	}

	open, err := svc.Sensor.repos.Alerts.FindOpenByRule(ctx, "agt-4", RuleIDSensorOffline)
	if err != nil {
		t.Fatal(err)
	}
	if len(open) != 0 {
		t.Fatalf("心跳恢复后失联告警应自动结案，仍剩 %d 条", len(open))
	}
	got, err := svc.Sensor.repos.Agents.ByID(ctx, "agt-4")
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != domain.AgentOnline {
		t.Errorf("心跳后状态应回到 online，got %s", got.Status)
	}
}

// TestMetricsOfflineHosts 离线主机数从既有总/在线口径推导。
func TestMetricsOfflineHosts(t *testing.T) {
	svc, ctx := newSensorTest(t, true)
	m := svc.Stats.Metrics(ctx, time.Now(), func() (int64, int64, int64) { return 0, 0, 0 })
	if m.OfflineHosts != 0 {
		t.Fatalf("空库离线数应为 0，got %d", m.OfflineHosts)
	}
}
