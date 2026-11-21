package service

// 批量升级编排的状态机单测：真实临时 SQLite + 直接驱动仓储模拟探针行为
// （心跳=版本翻转，Complete=指令回执）。波次参数在测试里调小（pollEvery
// 10ms / waveTimeout 2s）换取可接受的运行时长，语义与生产值完全一致。

import (
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"zedr/internal/server/domain"
	"zedr/internal/server/repository/sqlite"
)

// fleetHarness 是一套最小装配：AgentService 作为指令面 + 调小节奏的编排器。
type fleetHarness struct {
	svc  *UpgradeService
	ups  func(ctx context.Context, id, version string) error // 模拟心跳（版本翻转）
	fail func(ctx context.Context, cmdID, detail string) error // 模拟失败回执
}

func newFleetHarness(t *testing.T, waveSize int, timeout time.Duration) (*fleetHarness, func(ctx context.Context) []domain.AgentCommand) {
	t.Helper()
	ctx := context.Background()
	store, repos, err := sqlite.Open(ctx, filepath.Join(t.TempDir(), "fleet.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	agent := &AgentService{repos: repos, cfg: Config{UpgradeEnabled: true}, log: log}
	svc := NewUpgradeService(repos, Config{UpgradeWaveSize: waveSize, UpgradeWaveTimeout: timeout}, agent, log)
	svc.pollEvery = 10 * time.Millisecond

	return &fleetHarness{
		svc: svc,
		ups: func(_ context.Context, id, version string) error {
			return repos.Agents.UpdateHeartbeat(ctx, id, time.Now(), 10, 1.0, 2.0, 0, "10.0.0.1", version, false)
		},
		fail: func(_ context.Context, cmdID, detail string) error {
			return repos.Commands.Complete(ctx, cmdID, "failed", detail, time.Now())
		},
	}, func(_ context.Context) []domain.AgentCommand {
		cmds, err := repos.Commands.ListRecent(ctx, 100)
		if err != nil {
			t.Fatal(err)
		}
		return cmds
	}
}

// seedAgent 直接经仓储造一台在线探针（版本 version）。
func (h *fleetHarness) seedAgent(t *testing.T, id, version string) {
	t.Helper()
	a := &domain.Agent{ID: id, Hostname: "h-" + id, OSVersion: "Windows Test", Version: version,
		MachineID: "m-" + id, Status: domain.AgentOnline,
		EnrolledAt: time.Now(), LastSeenAt: time.Now()}
	if err := h.svc.repos.Agents.Upsert(context.Background(), a); err != nil {
		t.Fatal(err)
	}
}

// waitTerminal 轮询到批次离开 running/paused 活跃态（或超时）。
func waitTerminal(t *testing.T, svc *UpgradeService) *FleetSnapshot {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		snap := svc.Snapshot()
		if snap != nil && snap.State != "running" && snap.State != "paused" {
			return snap
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("批次 10s 内未收口")
	return nil
}

// simulateSuccess 轮询快照，对所有 pending 且已拿到指令 ID 的主机模拟
// 探针行为（版本翻转）。跨越多波时自动跟进新波。
func (h *fleetHarness) simulateSuccess() {
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		s := h.svc.Snapshot()
		if s == nil {
			time.Sleep(5 * time.Millisecond)
			continue
		}
		for _, w := range s.Waves {
			for _, e := range w.Hosts {
				if e.CommandID != "" && e.Status == "pending" {
					h.ups(context.Background(), e.AgentID, s.TargetVersion)
				}
			}
		}
		if s.State != "running" && s.State != "paused" {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestFleetWaveProgression 3 台、每波 2 台：波 1 两台版本翻转 → 波 2 一台
// → done，三台全部 success，共 3 条 self_upgrade 指令。
func TestFleetWaveProgression(t *testing.T) {
	h, listCmds := newFleetHarness(t, 2, 3*time.Second)
	for _, id := range []string{"a1", "a2", "a3"} {
		h.seedAgent(t, id, "1.0.0")
	}

	snap, err := h.svc.StartFleet(context.Background(), nil, "2.0.0", "admin")
	if err != nil {
		t.Fatal(err)
	}
	if snap.QueueRemain != 3 {
		t.Fatalf("发起快照不对: queue=%d", snap.QueueRemain)
	}

	// 探针模拟器：跨波持续把 pending 主机升到目标版本
	go h.simulateSuccess()
	final := waitTerminal(t, h.svc)
	if final.State != "done" {
		t.Fatalf("批次应 done，实际 %s（%+v）", final.State, final.Summary)
	}
	for id, e := range final.Hosts {
		if e.Status != "success" {
			t.Fatalf("主机 %s 应 success，实际 %s（%s）", id, e.Status, e.Detail)
		}
	}
	if got := len(listCmds(context.Background())); got != 3 {
		t.Fatalf("应下发 3 条指令，实际 %d", got)
	}
}

// TestFleetPauseOnFailures 4 台、每波 2 台：波 1 双双失败 → 熔断 paused；
// resume 后波 2 成功 → done。失败计数只含 failed/timed_out。
func TestFleetPauseOnFailures(t *testing.T) {
	h, _ := newFleetHarness(t, 2, 3*time.Second)
	for _, id := range []string{"a1", "a2", "a3", "a4"} {
		h.seedAgent(t, id, "1.0.0")
	}

	if _, err := h.svc.StartFleet(context.Background(), nil, "2.0.0", "admin"); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		s := h.svc.Snapshot()
		if s == nil {
			time.Sleep(5 * time.Millisecond)
			continue
		}
		// 波 1 主机拿到指令后立即模拟失败回执
		for _, w := range s.Waves {
			for _, e := range w.Hosts {
				if e.CommandID != "" && e.Status == "pending" {
					h.fail(context.Background(), e.CommandID, "下载升级包失败: x")
				}
			}
		}
		if s.State == "paused" {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	snap := h.svc.Snapshot()
	if snap.State != "paused" {
		t.Fatalf("波 1 双失败应熔断 paused，实际 %s", snap.State)
	}
	for _, e := range snap.Waves[0].Hosts {
		if e.Status != "failed" {
			t.Fatalf("波 1 主机应 failed，实际 %s（%s）", e.Status, e.Detail)
		}
	}

	// 人工放行：波 2 两台由模拟器推向成功
	resumed, err := h.svc.Resume()
	if err != nil {
		t.Fatal(err)
	}
	if resumed.State != "running" {
		t.Fatalf("resume 后应 running，实际 %s", resumed.State)
	}
	go h.simulateSuccess()
	final := waitTerminal(t, h.svc)
	if final.State != "done" {
		t.Fatalf("resume 后应推到 done，实际 %s", final.State)
	}
}

// TestFleetAbort 波进行中中止：批次转 aborted，波内 pending 如实保留，
// 后续主机不再发起（queue 不清空也不跳过——aborted 就是冻结现场）。
func TestFleetAbort(t *testing.T) {
	h, _ := newFleetHarness(t, 1, 3*time.Second)
	for _, id := range []string{"a1", "a2", "a3"} {
		h.seedAgent(t, id, "1.0.0")
	}

	snap, err := h.svc.StartFleet(context.Background(), nil, "2.0.0", "admin")
	if err != nil {
		t.Fatal(err)
	}
	_ = snap

	// 等波 1 挂起（指令已入队、等待回执中）再中止：断言 pending 如实保留
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if s := h.svc.Snapshot(); s != nil && len(s.Waves) > 0 && s.Waves[0].Hosts[0].CommandID != "" {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	// 不给波 1 回执（保持 pending 等待中），直接中止
	aborted, err := h.svc.Abort()
	if err != nil {
		t.Fatal(err)
	}
	if aborted.State != "aborted" {
		t.Fatalf("应 aborted，实际 %s", aborted.State)
	}
	w1 := aborted.Waves[0]
	if len(w1.Hosts) != 1 || w1.Hosts[0].Status != "pending" {
		t.Fatalf("波 1 应保留 pending，实际 %+v", w1.Hosts)
	}
	if aborted.QueueRemain != 2 {
		t.Fatalf("中止后剩余队列应保留 2 台，实际 %d", aborted.QueueRemain)
	}
	_ = snap

	// 中止后再发起 → 上一批次已结束，可以重新发起
	if _, err := h.svc.StartFleet(context.Background(), nil, "2.0.0", "admin"); err != nil {
		t.Fatalf("aborted 后应可重新发起: %v", err)
	}
	if _, err := h.svc.Abort(); err != nil {
		t.Fatal(err)
	}
}

// TestFleetOfflineSkip 离线主机不预排队指令：1 在线 1 离线，在线的升级
// 成功，离线的在宽限窗后记 skipped_offline 收尾（宽限窗=测试调小的
// waveTimeout）。
func TestFleetOfflineSkip(t *testing.T) {
	h, listCmds := newFleetHarness(t, 2, 400*time.Millisecond)
	h.seedAgent(t, "online1", "1.0.0")
	offline := &domain.Agent{ID: "offline1", Hostname: "h-off", OSVersion: "Windows Test",
		Version: "1.0.0", MachineID: "m-off", Status: domain.AgentOffline,
		EnrolledAt: time.Now(), LastSeenAt: time.Now().Add(-time.Hour)}
	if err := h.svc.repos.Agents.Upsert(context.Background(), offline); err != nil {
		t.Fatal(err)
	}

	final := func() *FleetSnapshot {
		if _, err := h.svc.StartFleet(context.Background(), nil, "2.0.0", "admin"); err != nil {
			t.Fatal(err)
		}
		// 在线那台升级成功（快照拿到指令 ID 后立即回执+翻转）
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			s := h.svc.Snapshot()
			if s == nil {
				break
			}
			for _, w := range s.Waves {
				for _, e := range w.Hosts {
					if e.AgentID == "online1" && e.CommandID != "" && e.Status == "pending" {
						h.ups(context.Background(), "online1", "2.0.0")
					}
				}
			}
			if s.State != "running" && s.State != "paused" {
				return s
			}
			time.Sleep(5 * time.Millisecond)
		}
		t.Fatal("批次未收口")
		return nil
	}()

	if final.State != "done" {
		t.Fatalf("应 done，实际 %s", final.State)
	}
	if final.Hosts["offline1"].Status != "skipped_offline" {
		t.Fatalf("离线主机应 skipped_offline，实际 %+v", final.Hosts["offline1"])
	}
	if final.Hosts["online1"].Status != "success" {
		t.Fatalf("在线主机应 success，实际 %+v", final.Hosts["online1"])
	}
	for _, c := range listCmds(context.Background()) {
		if c.AgentID == "offline1" {
			t.Fatalf("离线主机不应有指令下发")
		}
	}
}

// TestFleetStartFilters 发起时的分流：已是目标版本=already_latest（零指令）、
// 更新=skipped_newer、Linux=skipped_linux——三类都不占波次、不下指令。
func TestFleetStartFilters(t *testing.T) {
	h, listCmds := newFleetHarness(t, 10, 2*time.Second)
	h.seedAgent(t, "same", "2.0.0")
	h.seedAgent(t, "newer", "3.0.0")
	linux := &domain.Agent{ID: "linux1", Hostname: "h-lx", OSVersion: "Linux 6.1 kali",
		Version: "1.0.0", MachineID: "m-lx", Status: domain.AgentOnline,
		EnrolledAt: time.Now(), LastSeenAt: time.Now()}
	if err := h.svc.repos.Agents.Upsert(context.Background(), linux); err != nil {
		t.Fatal(err)
	}

	if _, err := h.svc.StartFleet(context.Background(), nil, "2.0.0", "admin"); err != nil {
		t.Fatal(err)
	}

	snap := waitTerminal(t, h.svc)
	if snap.State != "done" {
		t.Fatalf("全跳过批次应立即 done，实际 %s", snap.State)
	}
	if snap.Hosts["same"].Status != "already_latest" {
		t.Fatalf("同版本应 already_latest，实际 %+v", snap.Hosts["same"])
	}
	if snap.Hosts["newer"].Status != "skipped_newer" {
		t.Fatalf("更新版本应 skipped_newer，实际 %+v", snap.Hosts["newer"])
	}
	if snap.Hosts["linux1"].Status != "skipped_linux" {
		t.Fatalf("Linux 应 skipped_linux，实际 %+v", snap.Hosts["linux1"])
	}
	if got := len(listCmds(context.Background())); got != 0 {
		t.Fatalf("全跳过批次不应下发任何指令，实际 %d", got)
	}
}

// TestFleetSingleHostNoPause 单主机批次失败直接收尾（没有下一波可保护），
// 不进 paused 空转。
func TestFleetSingleHostNoPause(t *testing.T) {
	h, _ := newFleetHarness(t, 5, 2*time.Second)
	h.seedAgent(t, "solo", "1.0.0")

	if _, err := h.svc.StartFleet(context.Background(), nil, "2.0.0", "admin"); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		s := h.svc.Snapshot()
		if s != nil {
			for _, w := range s.Waves {
				for _, e := range w.Hosts {
					if e.CommandID != "" && e.Status == "pending" {
						h.fail(context.Background(), e.CommandID, "拉取升级清单失败: x")
					}
				}
			}
			if s.State != "running" && s.State != "paused" {
				break
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	final := h.svc.Snapshot()
	if final.State != "done" {
		t.Fatalf("单主机失败应直接 done，实际 %s", final.State)
	}
	if final.Hosts["solo"].Status != "failed" {
		t.Fatalf("主机应 failed，实际 %+v", final.Hosts["solo"])
	}
}

// TestCompareVersionsNumeric 锁数值比较语义（VERSIONING §2）：0.10 > 0.9、
// 缺位补 0、v 前缀、预发布段退化字符串比较。
func TestCompareVersionsNumeric(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"0.10", "0.9", 1}, {"0.9.14", "0.9.15", -1}, {"1.2", "1.2.0", 0},
		{"v2.0.0", "2.0.0", 0}, {"2.0.0", "2.0.1", -1},
		{"1.0.0-rc1", "1.0.0-rc2", -1},
	}
	for _, c := range cases {
		if got := compareVersions(c.a, c.b); got != c.want {
			t.Fatalf("compareVersions(%s,%s)=%d, want %d", c.a, c.b, got, c.want)
		}
	}
}
