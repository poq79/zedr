package service

// 探针批量升级编排（2026-11-19）。方案对标（联网调研，查阅日期 2026-11-19，
// 关键来源：SentinelOne CISO 指南 / hackersonlineclub EDR deployment checklist /
// AWS IoT 博客 FOTA 波次编排 / Hubble 社区 SpaceX 固件发布手册 / Rancher Fleet
// rolloutStrategy）——业界在 CrowdStrike 2024-07 事故后收敛于同一套纪律：
//
//   1. 波次/环式滚动发布（canary → 小批量 → 全量），爆炸半径优先于速度；
//   2. 波间放自动闸门：更新成功率越限自动暂停，冻结现场等人工放行
//      （"make the halt automatic and loud"，暂停成本=延迟，漏判成本=全舰队）；
//   3. 每波结束做健康评估：以"版本翻转"为成功事实源，回执只做辅助判定。
//
// 落地形态：服务端按波次向在线主机下发 self_upgrade 指令（完全复用既有
// agent_commands 管线与探针侧换装逻辑，探针侧零改动），每波收口后统计
// 失败率（failed+timed_out 占比 ≥1/2 且队列未清空）自动转 paused；管理员
// 经管理台 abort/resume。
//
// 诚实边界：批次状态是内存态——服务重启丢批次进度（已下发的指令仍会照常
// 执行，指令历史可查），不入库是刻意的 v1 取舍：批次生命周期以分钟计，
// 持久化需要"断点续跑 + 状态机落盘"两个新概念，等真实运维需求出现再加。
// 离线主机不预排队指令（避免"abort 之后离线机上线又执行"的惊吓语义），
// 收尾时统一记 skipped_offline，漏掉的由下一轮批次覆盖。

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"time"

	"zedr/internal/platform/idgen"
	"zedr/internal/server/domain"
	"zedr/internal/server/repository"
)

// 批次状态机：running → (paused ↔ running) → done | aborted。
const (
	fleetRunning = "running"
	fleetPaused  = "paused"
	fleetDone    = "done"
	fleetAborted = "aborted"
)

// 单主机结局。pending 只在 aborted 批次里出现（指令已下发、编排已停止，
// 探针后续仍可能执行——指令历史可查，批次快照如实保留未知态）。
const (
	hostPending        = "pending"
	hostSuccess        = "success"
	hostAlreadyLatest  = "already_latest"
	hostFailed         = "failed"
	hostTimedOut       = "timed_out"
	hostSkippedOffline = "skipped_offline"
	hostSkippedLinux   = "skipped_linux"
	hostSkippedNewer   = "skipped_newer"
)

// fleetPauseFailRatio 是波内熔断线：失败（failed+timed_out）占比 ≥1/2 且
// 队列未清空 → 自动暂停。硬编码不做配置项：它不是可调参数而是安全底线
// （对标 AWS IoT 95% 分界与 SpaceX "halt automatic and loud"，放宽只会
// 把事故放大），真有环境需要调的时候再评估进 Config。
const fleetPauseFailRatio = 2 // 失败数*2 >= 波内主机数 即暂停

// UpgradeService 编排探针批量升级。单主机升级不经过这里（走
// AgentService.EnqueueCommand 常规指令面），这里只管"对一批主机按波次推进"。
type UpgradeService struct {
	repos repository.Repos
	log   *slog.Logger
	// persistOn 控制批次状态是否落 settings KV（S6）：重启后恢复为
	// 暂停态等人工 resume——批次不丢，推进不自动重启（安全口径）
	enqueuer commandEnqueuer

	waveSize    int           // 每波下发的在线主机数上限
	waveTimeout time.Duration // 单波收口预算（含版本翻转等待）
	pollEvery   time.Duration // 波内轮询节奏；测试调小加速

	mu    sync.Mutex
	batch *fleetBatch // nil = 没有批次

	// 批次持久化（S6，2026-11-21）：批次状态落 settings KV——server
	// 重启后恢复批次（主机重新排队继续推进），而不是静默丢进度。
	// 内存态仍是运行事实源（aborted 通道等不可序列化），KV 只存
	// 可恢复子集；生命周期分钟级，真实运维需求出现再做全持久化。
	persistOn bool
}

// commandEnqueuer 是单机指令面的最小接口（实现：AgentService）。
type commandEnqueuer interface {
	EnqueueCommand(ctx context.Context, agentID, typ, payload, by string) (*domain.AgentCommand, error)
}

// FleetSnapshot 是批次对外的只读投影（GET /upgrade/fleet 的响应体）。
type FleetSnapshot struct {
	ID            string                 `json:"id"`
	TargetVersion string                 `json:"target_version"`
	State         string                 `json:"state"`
	CreatedBy     string                 `json:"created_by"`
	CreatedAt     time.Time              `json:"created_at"`
	Total         int                    `json:"total"`
	QueueRemain   int                    `json:"queue_remain"`
	Waves         []FleetWaveView        `json:"waves"`
	Summary       map[string]int         `json:"summary"`
	Hosts         map[string]*FleetEntry `json:"hosts"`
}

// FleetWaveView 是单波的只读投影。
type FleetWaveView struct {
	Index int            `json:"index"`
	Hosts []FleetEntryID `json:"hosts"`
}

// FleetEntryID 是波内主机引用（详情在 Hosts 映射里，避免重复展开）。
type FleetEntryID struct {
	AgentID   string `json:"agent_id"`
	Status    string `json:"status"`
	CommandID string `json:"command_id,omitempty"`
	Detail    string `json:"detail,omitempty"`
}

// FleetEntry 是单主机结局详情（Hosts 映射值）。
type FleetEntry = FleetEntryID

// fleetBatch 是批次内部态（mu 保护）。
type fleetBatch struct {
	id        string
	target    string
	by        string
	createdAt time.Time
	state     string
	queue     []string
	waves     []*fleetWave
	hosts     map[string]*FleetEntry
	aborted   chan struct{} // Abort 时关闭；波内等待据此提前退出
}

// fleetWave 单波内部态。
type fleetWave struct {
	index int
	order []string
}

// persistedBatch 是批次可恢复子集的 KV 形态（内存态的投影）。
type persistedBatch struct {
	ID     string                 `json:"id"`
	Target string                 `json:"target"`
	By     string                 `json:"by"`
	State  string                 `json:"state"`
	Queue  []string               `json:"queue"`
	Hosts  map[string]*FleetEntry `json:"hosts"`
}

const upgradeBatchKey = "upgrade_fleet_batch"

func (s *UpgradeService) saveBatch(b *fleetBatch) {
	if !s.persistOn {
		return
	}
	pb := persistedBatch{
		ID: b.id, Target: b.target, By: b.by, State: b.state,
		Queue: append([]string{}, b.queue...),
		Hosts: b.hosts,
	}
	raw, err := json.Marshal(pb)
	if err != nil {
		return
	}
	_ = s.repos.AIConfig.SetSetting(context.Background(), upgradeBatchKey, string(raw))
}

func (s *UpgradeService) clearBatch() {
	if !s.persistOn {
		return
	}
	_ = s.repos.AIConfig.SetSetting(context.Background(), upgradeBatchKey, "")
}

// loadBatch 重启后从 KV 恢复批次（波次推进从当前队列继续）；
// 无持久化批次/解析失败返回 nil——恢复失败不该阻断新批次发起。
func (s *UpgradeService) loadBatch() *fleetBatch {
	raw, ok, err := s.repos.AIConfig.GetSetting(context.Background(), upgradeBatchKey)
	if err != nil || !ok || strings.TrimSpace(raw) == "" {
		return nil
	}
	var pb persistedBatch
	if json.Unmarshal([]byte(raw), &pb) != nil || pb.ID == "" {
		return nil
	}
	aborted := make(chan struct{})
	close(aborted) // 恢复的批次视为已中止推进：队列保留，人工 Resume 重启推进
	return &fleetBatch{
		id: pb.ID, target: pb.Target, by: pb.By, state: pb.State,
		queue: pb.Queue, hosts: pb.Hosts, aborted: aborted,
	}
}

// NewUpgradeService 组装。waveSize/waveTimeout 非法值回退默认——配置错误
// 不该阻断启动，升级编排总比没有编排安全。
func NewUpgradeService(repos repository.Repos, cfg Config, enqueuer commandEnqueuer, log *slog.Logger) *UpgradeService {
	waveSize := cfg.UpgradeWaveSize
	if waveSize <= 0 {
		waveSize = 10
	}
	persistOn := cfg.UpgradeBatchPersist
	waveTimeout := cfg.UpgradeWaveTimeout
	if waveTimeout <= 0 {
		waveTimeout = 10 * time.Minute
	}
	return &UpgradeService{
		repos:       repos,
		enqueuer:    enqueuer,
		log:         log,
		persistOn:   persistOn,
		waveSize:    waveSize,
		waveTimeout: waveTimeout,
		pollEvery:   2 * time.Second,
	}
}

// StartFleet 发起批量升级。agentIDs 为空 = 全部终端。目标版本由调用方
// （api 层）从升级包物料传入并保证文件可读——本层不摸文件系统。
// 已是目标版本/更新的主机不入队（记 already_latest/skipped_newer），Linux
// 探针记 skipped_linux（v1 诚实边界，回执也会写明，提前分流省一轮空跑）。
func (s *UpgradeService) StartFleet(ctx context.Context, agentIDs []string, targetVersion, by string) (*FleetSnapshot, error) {
	if strings.TrimSpace(targetVersion) == "" {
		return nil, errors.New("目标版本为空：服务端未配置升级包版本")
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.batch != nil && (s.batch.state == fleetRunning || s.batch.state == fleetPaused) {
		return nil, errors.New("已有升级批次进行中（可先 GET /upgrade/fleet 查看进度，或 abort 后重发）")
	}

	agents, err := s.resolveAgents(ctx, agentIDs)
	if err != nil {
		return nil, err
	}
	if len(agents) == 0 {
		return nil, errors.New("没有匹配的终端")
	}

	b := &fleetBatch{
		id:        newBatchID(),
		target:    targetVersion,
		by:        by,
		createdAt: time.Now(),
		state:     fleetRunning,
		aborted:   make(chan struct{}),
		hosts:     map[string]*FleetEntry{},
	}
	for _, a := range agents {
		switch {
		case strings.Contains(strings.ToLower(a.OSVersion), "linux"):
			b.hosts[a.ID] = &FleetEntry{AgentID: a.ID, Status: hostSkippedLinux,
				Detail: "Linux 探针暂不支持自升级（v1 边界）"}
		case compareVersions(a.Version, targetVersion) > 0:
			b.hosts[a.ID] = &FleetEntry{AgentID: a.ID, Status: hostSkippedNewer,
				Detail: fmt.Sprintf("终端版本 %s 比目标 %s 新，跳过", a.Version, targetVersion)}
		case compareVersions(a.Version, targetVersion) == 0:
			b.hosts[a.ID] = &FleetEntry{AgentID: a.ID, Status: hostAlreadyLatest,
				Detail: "已是目标版本"}
		default:
			// 排队主机也建 pending 条目：快照必须覆盖每一台参与主机，
			// 否则"离线机收尾跳过"没有落点、Total 对不上参与总数
			b.hosts[a.ID] = &FleetEntry{AgentID: a.ID, Status: hostPending}
			b.queue = append(b.queue, a.ID)
		}
	}
	s.batch = b
	s.saveBatch(b)
	s.log.Info("upgrade_fleet_started", "batch", b.id, "target", targetVersion,
		"queued", len(b.queue), "total", len(agents), "by", by)

	go s.runBatch(b)
	return s.snapshotLocked(b), nil
}

// resolveAgents 把请求里的 ID 列表解析成终端（保持顺序、去重）；空列表 =
// 全部终端。ID 不存在整体拒绝——批量操作里的静默漏配比显式报错危险。
func (s *UpgradeService) resolveAgents(ctx context.Context, agentIDs []string) ([]domain.Agent, error) {
	if len(agentIDs) == 0 {
		list, err := s.repos.Agents.List(ctx)
		if err != nil {
			return nil, err
		}
		return list, nil
	}
	seen := map[string]bool{}
	var out []domain.Agent
	for _, id := range agentIDs {
		if seen[id] {
			continue
		}
		seen[id] = true
		a, err := s.repos.Agents.ByID(ctx, id)
		if err != nil {
			return nil, err
		}
		if a == nil {
			return nil, fmt.Errorf("终端不存在: %s", id)
		}
		out = append(out, *a)
	}
	return out, nil
}

// runBatch 波次主循环。ctx 用 Background：批次生命周期独立于发起请求
// （请求返回后编排要继续跑），终止路径只有两条——Abort / 进程退出。
func (s *UpgradeService) runBatch(b *fleetBatch) {
	for {
		select {
		case <-b.aborted:
			return
		default:
		}
		if s.batchState(b) != fleetRunning {
			return
		}

		picked := s.pickOnline(b)
		if len(picked) == 0 {
			if s.queueLen(b) == 0 {
				s.finish(b, fleetDone)
				return
			}
			// 剩余全部离线：给一个波超时的宽限窗（瞬态掉线自愈），窗内
			// 每个轮询周期重新点名，有人上线就继续推进；窗满仍无人上线
			// → 余量记 skipped_offline 收尾，漏掉的由下一轮批次覆盖。
			if !s.waitForOnline(b) {
				s.skipRemaining(b, hostSkippedOffline, "批次收尾时仍离线")
				s.finish(b, fleetDone)
				return
			}
			continue
		}

		if !s.runWave(b, picked) {
			return // aborted
		}
		if s.batchState(b) == fleetPaused {
			return
		}
		if s.queueLen(b) == 0 {
			s.finish(b, fleetDone)
			return
		}
	}
}

// pickOnline 从队列头部取最多 waveSize 台当前在线的终端（离线留在队列）。
func (s *UpgradeService) pickOnline(b *fleetBatch) []string {
	s.mu.Lock()
	pending := append([]string(nil), b.queue...)
	s.mu.Unlock()

	var picked []string
	ctx := context.Background()
	for _, id := range pending {
		if len(picked) >= s.waveSize {
			break
		}
		a, err := s.repos.Agents.ByID(ctx, id)
		if err != nil || a == nil {
			continue
		}
		if a.Status == domain.AgentOnline {
			picked = append(picked, id)
		}
	}
	if len(picked) > 0 {
		s.mu.Lock()
		kept := b.queue[:0:0]
		drop := map[string]bool{}
		for _, id := range picked {
			drop[id] = true
		}
		for _, id := range b.queue {
			if !drop[id] {
				kept = append(kept, id)
			}
		}
		b.queue = kept
		s.mu.Unlock()
	}
	return picked
}

// waitForOnline 离线宽限窗：总窗长 waveTimeout，每 pollEvery 重新点名一次。
// 返回 false=窗满仍无人上线（调用方收尾），true=有人上线（继续主循环）。
// Abort 提前返回 false（主循环的状态检查会接住）。
func (s *UpgradeService) waitForOnline(b *fleetBatch) bool {
	deadline := time.Now().Add(s.waveTimeout)
	for time.Now().Before(deadline) {
		select {
		case <-b.aborted:
			return false
		default:
		}
		time.Sleep(s.pollEvery)
		if s.batchState(b) != fleetRunning {
			return false
		}
		if len(s.pickOnline(b)) > 0 {
			return true
		}
	}
	return false
}

// runWave 执行一波：下发指令 → 轮询等收口（版本翻转/回执）→ 熔断评估。
// 返回 false 表示批次已中止。
func (s *UpgradeService) runWave(b *fleetBatch, picked []string) bool {
	ctx := context.Background()
	wave := &fleetWave{order: picked}

	s.mu.Lock()
	wave.index = len(b.waves) + 1
	b.waves = append(b.waves, wave)
	for _, id := range picked {
		b.hosts[id] = &FleetEntry{AgentID: id, Status: hostPending}
	}
	s.mu.Unlock()
	s.log.Info("upgrade_wave_started", "batch", b.id, "wave", wave.index, "hosts", len(picked))

	// 逐台入队：复用 EnqueueCommand 让单机闸门（开关/白名单）照常生效，
	// 入队失败只影响该台（记 failed），不放大成整波失败。
	for _, id := range picked {
		c, err := s.enqueue(ctx, id, b.by)
		entry := s.hostEntry(b, id)
		s.mu.Lock()
		if err != nil {
			entry.Status = hostFailed
			entry.Detail = err.Error()
			s.log.Warn("upgrade_enqueue_failed", "batch", b.id, "agent_id", id, "err", err)
		} else {
			entry.CommandID = c.ID
		}
		s.mu.Unlock()
	}

	// 收口等待：成功事实源是"心跳版本翻转"；回执做辅助判定（failed 立判、
	// "已是最新/无可用更新"计 no-op 成功）。done 回执但版本未翻转继续等
	// （SCM 5s 拉起 + 心跳 30s，翻转滞后回执是常态）。
	deadline := time.Now().Add(s.waveTimeout)
	for time.Now().Before(deadline) {
		select {
		case <-b.aborted:
			return false
		default:
		}
		time.Sleep(s.pollEvery)
		if s.batchState(b) != fleetRunning {
			return false
		}
		s.settlePending(b, wave)
		if s.pendingCount(b, wave) == 0 {
			break
		}
	}
	// 超时未收口的记 timed_out（回执详情带进 detail 排查用）
	s.timeOutPending(b, wave)

	// 熔断评估：失败率 ≥1/2 且队列未清空 → paused。单主机批次失败直接
	// 收尾（没有下一波可保护），不进暂停态空转。
	failures := s.countStatus(b, wave, hostFailed) + s.countStatus(b, wave, hostTimedOut)
	if failures > 0 && failures*fleetPauseFailRatio >= len(picked) && s.queueLen(b) > 0 {
		s.mu.Lock()
		if s.batch.state == fleetRunning {
			s.batch.state = fleetPaused
		}
		state := s.batch.state
		s.mu.Unlock()
		if state == fleetPaused {
			s.log.Warn("upgrade_fleet_paused", "batch", b.id, "wave", wave.index,
				"failures", failures, "wave_size", len(picked),
				"hint", "失败率过半，已冻结后续波次；排查后 resume 或 abort")
			return true
		}
	}
	return true
}

// settlePending 把能判定的 pending 主机落成终态（轮询周期调用）。
// 只看本波主机：排队中的主机还没入队指令，它们的落点在
// pickOnline/runWave/skipRemaining，不归波内收口管。
func (s *UpgradeService) settlePending(b *fleetBatch, w *fleetWave) {
	ctx := context.Background()
	s.mu.Lock()
	var pendingIDs []string
	for _, id := range w.order {
		if e := b.hosts[id]; e != nil && e.Status == hostPending {
			pendingIDs = append(pendingIDs, id)
		}
	}
	s.mu.Unlock()

	for _, id := range pendingIDs {
		a, err := s.repos.Agents.ByID(ctx, id)
		if err == nil && a != nil && compareVersions(a.Version, b.target) == 0 {
			s.setHost(b, id, hostSuccess, "版本已翻转到 "+b.target)
			continue
		}
		cmdID := s.commandID(b, id)
		if cmdID == "" {
			continue
		}
		c, err := s.repos.Commands.ByID(ctx, cmdID)
		if err != nil || c == nil {
			continue
		}
		switch c.Status {
		case "failed":
			s.setHost(b, id, hostFailed, c.Result)
		case "done":
			// 探针侧明确回答"没东西可升"（发起后版本被手动换装/清单未变）
			// 也是安全终态：批次目标（ fleet 与服务端物料对齐）已达成。
			if strings.Contains(c.Result, "已是最新版本") || strings.Contains(c.Result, "无可用更新") {
				s.setHost(b, id, hostAlreadyLatest, c.Result)
			}
			// 其余 done 回执=换装完成待重启，等版本翻转，不在此落终态
		}
	}
}

// timeOutPending 收口超时的 pending → timed_out（只限本波主机）。
func (s *UpgradeService) timeOutPending(b *fleetBatch, w *fleetWave) {
	ctx := context.Background()
	s.mu.Lock()
	var pendingIDs []string
	for _, id := range w.order {
		if e := b.hosts[id]; e != nil && e.Status == hostPending {
			pendingIDs = append(pendingIDs, id)
		}
	}
	s.mu.Unlock()

	for _, id := range pendingIDs {
		detail := "波超时内未观测到版本翻转或回执"
		if cmdID := s.commandID(b, id); cmdID != "" {
			if c, err := s.repos.Commands.ByID(ctx, cmdID); err == nil && c != nil && c.Result != "" {
				detail += "；回执: " + c.Result
			}
		}
		s.setHost(b, id, hostTimedOut, detail)
	}
}

// skipRemaining 把队列余量整体落到指定跳过态（收尾用）。
func (s *UpgradeService) skipRemaining(b *fleetBatch, status, detail string) {
	s.mu.Lock()
	rest := append([]string(nil), b.queue...)
	b.queue = nil
	s.mu.Unlock()
	for _, id := range rest {
		s.setHost(b, id, status, detail)
	}
}

// Abort 中止批次：running/paused 都可以中止。已下发未执行的指令不召回
// （agent_commands 没有召回语义）——探针拿到照常执行，快照里如实保留
// pending，由指令历史追踪。
func (s *UpgradeService) Abort() (*FleetSnapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.batch == nil {
		return nil, errors.New("没有升级批次")
	}
	switch s.batch.state {
	case fleetRunning, fleetPaused:
		s.batch.state = fleetAborted
		close(s.batch.aborted)
		s.clearBatch()
		s.log.Warn("upgrade_fleet_aborted", "batch", s.batch.id, "by", s.batch.by)
		return s.snapshotLocked(s.batch), nil
	default:
		return nil, fmt.Errorf("批次已结束（%s），无需中止", s.batch.state)
	}
}

// Restore 重启后从 settings KV 恢复批次：队列/主机结局保留，状态置为
// paused——推进不自动重启（重启后 runBatch 上下文已断），人工 Resume
// 继续（安全口径：升级影响面必须有人放行）。
func (s *UpgradeService) Restore() {
	b := s.loadBatch()
	if b == nil {
		return
	}
	s.mu.Lock()
	if s.batch != nil {
		s.mu.Unlock()
		return
	}
	b.state = fleetPaused
	s.batch = b
	s.mu.Unlock()
	if s.log != nil {
		s.log.Info("upgrade_fleet_restored", "batch", b.id, "target", b.target,
			"queue_remain", len(b.queue))
	}
}

// Resume 恢复暂停的批次（熔断后人工放行）。
func (s *UpgradeService) Resume() (*FleetSnapshot, error) {
	s.mu.Lock()
	if s.batch == nil {
		s.mu.Unlock()
		return nil, errors.New("没有升级批次")
	}
	if s.batch.state != fleetPaused {
		st := s.batch.state
		s.mu.Unlock()
		return nil, fmt.Errorf("批次不在暂停态（当前 %s）", st)
	}
	s.batch.state = fleetRunning
	b := s.batch
	s.mu.Unlock()

	s.log.Info("upgrade_fleet_resumed", "batch", b.id)
	go s.runBatch(b)
	return s.Snapshot(), nil
}

// Snapshot 当前批次快照；没有批次返回 nil（API 层按 null 透传）。
func (s *UpgradeService) Snapshot() *FleetSnapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.batch == nil {
		return nil
	}
	return s.snapshotLocked(s.batch)
}

// ---------------------------------------------------------------- 内部工具

func newBatchID() string { return "up-" + idgen.Hex(12) }

// enqueue 经 AgentService 的常规指令面入队 self_upgrade：波内逐台复用
// 同一套开关/白名单闸门，本服务不复制门禁逻辑。
func (s *UpgradeService) enqueue(ctx context.Context, id, by string) (*domain.AgentCommand, error) {
	if s.enqueuer == nil {
		return nil, errors.New("指令面未接线")
	}
	return s.enqueuer.EnqueueCommand(ctx, id, "self_upgrade", "", by)
}

func (s *UpgradeService) finish(b *fleetBatch, state string) {
	s.mu.Lock()
	s.batch.state = state
	s.mu.Unlock()
	s.clearBatch()
	summary := s.summarize(b)
	s.log.Info("upgrade_fleet_finished", "batch", b.id, "state", state,
		"success", summary[hostSuccess], "already_latest", summary[hostAlreadyLatest],
		"failed", summary[hostFailed], "timed_out", summary[hostTimedOut],
		"skipped_offline", summary[hostSkippedOffline])
}

func (s *UpgradeService) batchState(b *fleetBatch) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return b.state
}

func (s *UpgradeService) queueLen(b *fleetBatch) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(b.queue)
}

func (s *UpgradeService) hostEntry(b *fleetBatch, id string) *FleetEntry {
	s.mu.Lock()
	defer s.mu.Unlock()
	return b.hosts[id]
}

func (s *UpgradeService) setHost(b *fleetBatch, id, status, detail string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := b.hosts[id]; e != nil && e.Status == hostPending {
		e.Status = status
		e.Detail = detail
	}
}

func (s *UpgradeService) commandID(b *fleetBatch, id string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := b.hosts[id]; e != nil {
		return e.CommandID
	}
	return ""
}

func (s *UpgradeService) pendingCount(b *fleetBatch, w *fleetWave) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, id := range w.order {
		if e := b.hosts[id]; e != nil && e.Status == hostPending {
			n++
		}
	}
	return n
}

func (s *UpgradeService) countStatus(b *fleetBatch, w *fleetWave, status string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, id := range w.order {
		if e := b.hosts[id]; e != nil && e.Status == status {
			n++
		}
	}
	return n
}

func (s *UpgradeService) summarize(b *fleetBatch) map[string]int {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[string]int{
		hostPending: 0, hostSuccess: 0, hostAlreadyLatest: 0, hostFailed: 0,
		hostTimedOut: 0, hostSkippedOffline: 0, hostSkippedLinux: 0, hostSkippedNewer: 0,
	}
	for _, e := range b.hosts {
		out[e.Status]++
	}
	return out
}

func (s *UpgradeService) snapshotLocked(b *fleetBatch) *FleetSnapshot {
	snap := &FleetSnapshot{
		ID:            b.id,
		TargetVersion: b.target,
		State:         b.state,
		CreatedBy:     b.by,
		CreatedAt:     b.createdAt,
		Total:         len(b.hosts),
		QueueRemain:   len(b.queue),
		Hosts:         map[string]*FleetEntry{},
	}
	for id, e := range b.hosts {
		snap.Hosts[id] = &FleetEntry{AgentID: e.AgentID, Status: e.Status,
			CommandID: e.CommandID, Detail: e.Detail}
	}
	for _, w := range b.waves {
		view := FleetWaveView{Index: w.index}
		for _, id := range w.order {
			e := b.hosts[id]
			view.Hosts = append(view.Hosts, FleetEntryID{AgentID: id,
				Status: e.Status, CommandID: e.CommandID, Detail: e.Detail})
		}
		snap.Waves = append(snap.Waves, view)
	}
	snap.Summary = s.summarizeLocked(b)
	return snap
}

func (s *UpgradeService) summarizeLocked(b *fleetBatch) map[string]int {
	out := map[string]int{
		hostPending: 0, hostSuccess: 0, hostAlreadyLatest: 0, hostFailed: 0,
		hostTimedOut: 0, hostSkippedOffline: 0, hostSkippedLinux: 0, hostSkippedNewer: 0,
	}
	for _, e := range b.hosts {
		out[e.Status]++
	}
	return out
}

// compareVersions 与探针侧 internal/agent/app/upgrade.go 的 compareVersions
// 逐段数值语义对齐（VERSIONING.md §2：版本比较一律数值化，禁止字典序）。
// 不直接复用的原因：那个包 windows 标签构建且属探针组合根，服务端引入
// 会绑死平台并破坏分层——对齐实现 + 注释互指是本仓库既有纪律。
func compareVersions(a, b string) int {
	seg := func(v string) []string { return strings.Split(strings.TrimPrefix(strings.TrimSpace(v), "v"), ".") }
	as, bs := seg(a), seg(b)
	for i := 0; i < len(as) || i < len(bs); i++ {
		av, bv := "0", "0"
		if i < len(as) {
			av = as[i]
		}
		if i < len(bs) {
			bv = bs[i]
		}
		ai, aerr := strconv.Atoi(av)
		bi, berr := strconv.Atoi(bv)
		if aerr == nil && berr == nil {
			if ai != bi {
				if ai > bi {
					return 1
				}
				return -1
			}
			continue
		}
		if c := strings.Compare(av, bv); c != 0 {
			return c
		}
	}
	return 0
}
