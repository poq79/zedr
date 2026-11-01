// Package agentapp 组装探针运行时：配置 → 采集 → 富化 → 检测 → 上报 → 本地 API。
package agentapp

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"hostguard/internal/agent/allow"
	"hostguard/internal/agent/baseline"
	"hostguard/internal/agent/collect"
	"hostguard/internal/agent/detect"
	"hostguard/internal/agent/enrich"
	"hostguard/internal/agent/localapi"
	"hostguard/internal/agent/state"
	"hostguard/internal/agent/uplink"
	"hostguard/internal/agent/winapi"
	"hostguard/internal/platform/httpx"
	"hostguard/internal/platform/idgen"
	"hostguard/internal/platform/logx"
	"hostguard/internal/model"
)

// Agent 是探针实例。
type Agent struct {
	cfg   *Config
	log   *slog.Logger
	store *state.Store

	coll *collect.Collector
	enr  *enrich.Enricher
	base *baseline.Model
	alw  *allow.List
	eng  *detect.Engine
	up   *uplink.Client
	cpu  *winapi.CPUSampler

	local     *httpx.Server
	localAPI  *localapi.Server
	startedAt time.Time

	scanReq chan bool // 手动触发重扫
	online  bool
}

// New 装配探针。
func New(version string) (*Agent, error) {
	cfg, err := LoadConfig(version)
	if err != nil {
		return nil, err
	}

	log := logx.New(logx.Options{Level: cfg.LogLevel, Format: cfg.LogFormat})
	log.Info("agent_starting", "version", version, "data_dir", cfg.DataDir, "server", cfg.ServerURL)

	store := state.New(500)

	// 采集引擎可插拔：默认 auto（NtQuery 优先、失败回退 Toolhelp32）
	// 之所以保留两套实现，是因为不同 Windows 版本 / 安全软件干预下
	// 某一种枚举方式可能失效，需要能不改代码就切回去。
	coll, err := collect.New(cfg.Collector, cfg.FullRescan)
	if err != nil {
		return nil, fmt.Errorf("初始化采集引擎失败: %w", err)
	}
	log.Info("collector_selected", "source", coll.SourceName(), "note", coll.SourceNote())
	enr := enrich.New(cfg.MaxHashMB)
	base := baseline.Load(cfg.Path("baseline.json"))
	alw := allow.New(cfg.Path("allowlist.json"))

	eng := detect.New(enr, base, alw, detect.Config{
		WarmupUntil: time.Now().Add(cfg.Warmup),
	})

	up := uplink.New(cfg.ServerURL, cfg.EnrollToken, cfg.DataDir, cfg.OfflineQueue)
	if up.LoadCredentials() {
		log.Info("agent_credentials_loaded", "agent_id", up.AgentID())
	}

	// 自豁免：安全产品不应把自己（安装目录、数据目录）当成可疑对象，
	// 否则每次升级换目录都会凭空产生一批"未签名程序在可写目录"的噪声。
	if exe, err := os.Executable(); err == nil {
		if dir := filepath.Dir(exe); dir != "" {
			if err := alw.EnsureLocal(allow.TypePath, dir, "HostGuard 安装目录自豁免"); err != nil {
				log.Warn("self_allow_failed", "err", err)
			}
		}
	}
	if err := alw.EnsureLocal(allow.TypePath, cfg.DataDir, "HostGuard 数据目录自豁免"); err != nil {
		log.Warn("self_allow_failed", "err", err)
	}

	a := &Agent{
		cfg: cfg, log: log, store: store,
		coll: coll, enr: enr, base: base, alw: alw, eng: eng, up: up,
		cpu:       &winapi.CPUSampler{},
		startedAt: time.Now(),
		scanReq:   make(chan bool, 1),
	}

	a.store.SetRuntime(func(ri *state.RuntimeInfo) {
		ri.Hostname = winapi.Hostname()
		ri.OSVersion = winapi.OSVersion()
		ri.AgentVersion = version
		ri.ServerURL = cfg.ServerURL
		ri.ScanInterval = cfg.ScanInterval.String()
		ri.Collector = coll.SourceName()
		ri.WarmupUntil = time.Now().Add(cfg.Warmup)
		ri.AgentID = up.AgentID()
		ri.Enrolled = up.Enrolled()
	})
	return a, nil
}

// Run 启动全部循环，阻塞直到 ctx 取消。
func (a *Agent) Run(ctx context.Context) error {
	// 本地 API 供桌面 UI 使用
	api := localapi.New(localapi.Deps{
		Backend: a,
		Log:     a.log,
		Addr:    a.cfg.LocalAddr,
	})
	a.localAPI = api
	if err := api.Start(); err != nil {
		return fmt.Errorf("本地 API 启动失败: %w", err)
	}
	defer func() {
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = api.Shutdown(shutCtx)
	}()

	// 注册与规则同步在后台进行，不阻塞采集
	go a.enrollLoop(ctx)
	go a.scanLoop(ctx)
	go a.heartbeatLoop(ctx)
	go a.flushLoop(ctx)
	go a.persistLoop(ctx)

	<-ctx.Done()
	a.log.Info("agent_stopping")
	_ = a.base.Save()

	a.store.SetRuntime(func(ri *state.RuntimeInfo) { ri.Online = false })
	return nil
}

// ---------------------------------------------------------------- 注册

func (a *Agent) enrollLoop(ctx context.Context) {
	for {
		if a.up.Enrolled() {
			a.syncRules(ctx, true)
			return
		}
		if a.cfg.EnrollToken == "" {
			a.log.Error("agent_not_enrolled",
				"reason", "未配置 HG_AGENT_ENROLL_TOKEN，探针将以纯本地模式运行（不上报服务端）")
			return
		}

		machineID := a.machineID()
		req := model.EnrollRequest{
			MachineID: machineID,
			Hostname:  winapi.Hostname(),
			OSVersion: winapi.OSVersion(),
			Arch:      runtime.GOARCH,
			Username:  winapi.CurrentUser(),
			Version:   a.cfg.Version,
			Tags:      a.cfg.Tags,
		}
		cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
		resp, err := a.up.Enroll(cctx, req)
		cancel()
		if err != nil {
			a.log.Warn("enroll_failed", "err", err, "retry_in", "30s")
			select {
			case <-ctx.Done():
				return
			case <-time.After(30 * time.Second):
				continue
			}
		}

		a.log.Info("agent_enrolled", "agent_id", resp.AgentID,
			"heartbeat_sec", resp.HeartbeatIntervalSec, "rule_version", resp.RuleVersion)
		a.store.SetRuntime(func(ri *state.RuntimeInfo) {
			ri.AgentID = resp.AgentID
			ri.Enrolled = true
			ri.Online = true
		})
		a.syncRules(ctx, true)
		return
	}
}

// machineID 读取/生成持久化的机器指纹（随机 ID，不采集硬件隐私信息）。
func (a *Agent) machineID() string {
	path := a.cfg.Path("machine.id")
	if raw, err := os.ReadFile(path); err == nil {
		if id := strings.TrimSpace(string(raw)); id != "" {
			return id
		}
	}
	id := idgen.MachineID()
	_ = os.WriteFile(path, []byte(id), 0o600)
	return id
}

// syncRules 拉取规则整包并热加载到引擎。
func (a *Agent) syncRules(ctx context.Context, force bool) {
	cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()

	bundle, notModified, err := a.up.FetchRules(cctx)
	if err != nil {
		a.log.Warn("rules_fetch_failed", "err", err)
		return
	}
	if notModified && !force {
		return
	}

	ok, bad := a.eng.SetRules(bundle.Rules)
	entries := make([]allow.Entry, 0, len(bundle.Allowlist))
	for _, e := range bundle.Allowlist {
		entries = append(entries, allow.Entry{Type: e.Type, Value: e.Value, Source: "server"})
	}
	a.alw.ReplaceServer(entries)

	a.store.SetRuntime(func(ri *state.RuntimeInfo) {
		ri.RuleCount = ok
		ri.Whitelist = a.alw.Size()
	})
	a.log.Info("rules_applied", "version", bundle.Version, "rules", ok, "allow", len(entries), "bad", len(bad))
}

// ---------------------------------------------------------------- 采集

func (a *Agent) scanLoop(ctx context.Context) {
	ticker := time.NewTicker(a.cfg.ScanInterval)
	defer ticker.Stop()

	a.scan(true) // 首轮做全量，建立基线

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			a.scan(false)
		case force := <-a.scanReq:
			a.scan(true)
			_ = force
		}
	}
}

// scan 执行一轮采集 + 检测。
func (a *Agent) scan(deep bool) {
	start := time.Now()

	newProcs, snap, err := a.coll.Poll(deep)
	if err != nil {
		a.log.Warn("scan_failed", "err", err)
		return
	}

	alive := make(map[uint32]struct{}, len(snap.Procs))
	for pid := range snap.Procs {
		alive[pid] = struct{}{}
	}

	for _, pi := range newProcs {
		if pi.PID == uint32(os.Getpid()) {
			continue // 不检测自己
		}

		ancestry, parentAlive := a.coll.Ancestry(snap, pi.PID)
		conns := a.coll.ConnectionsOf(snap, pi.PID)

		// 模块枚举成本高：只对"有网络连接"或"位于可写目录"的进程做
		var modules []model.ModuleInfo
		if len(conns) > 0 || shouldInspectModules(pi) {
			modules = a.coll.Modules(pi.PID)
		}

		in := detect.Input{
			Proc: detect.ProcessInfo{
				PID: pi.PID, PPID: pi.PPID, Name: pi.Name, Path: pi.Path,
				CmdLine: pi.CmdLine, User: pi.User, SessionID: pi.SessionID,
				Elevated: pi.Elevated, IsWow64: pi.IsWow64, StartTime: pi.StartTime,
			},
			Ancestry:    ancestry,
			ParentAlive: parentAlive,
			Connections: conns,
			Modules:     modules,
		}

		res := a.eng.Analyze(in)

		// 基线学习：无论是否告警都要学，阴性样本才是"正常"的定义
		if a.cfg.BaselineLearn {
			parent := ""
			if len(ancestry) > 0 {
				parent = ancestry[0].Name
			}
			a.base.Learn(parent, pi.Name)
		}

		a.store.UpsertProc(pi, res, len(conns), len(modules))

		// 只有真正需要上报的结果才产生告警；低于阈值/被抑制的仍保留评分供 UI 展示
		if res != nil && res.Alert {
			a.emit(pi, res)
		}
	}

	a.store.Reap(alive)

	cpu := a.cpu.Sample()
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)

	stats := a.eng.Stats()
	a.store.SetRuntime(func(ri *state.RuntimeInfo) {
		ri.ProcCount = snap.Count
		ri.CPUPercent = cpu
		ri.MemMB = float64(mem.Sys) / 1024 / 1024
		ri.Stats = stats
		ri.LastScanAt = start
		ri.PendingAlerts = a.up.Pending()
		ri.DroppedAlerts = a.up.Dropped()
		ri.BaselineSize = a.base.Len()
		ri.Warmup = a.eng.IsWarmup(time.Now())
		ri.RuleCount = a.eng.RuleCount()
	})
}

// emit 生成告警：写入本地存储 + 入上报队列。
func (a *Agent) emit(pi collect.ProcessInfo, res *detect.Result) {
	now := time.Now()
	local := &state.Alert{
		ID:       idgen.Hex(8),
		Title:    res.Title,
		Summary:  res.Summary,
		Verdict:  string(res.Verdict),
		Severity: string(res.Severity),
		Score:    res.Score,
		PID:      pi.PID,
		PPID:     pi.PPID,
		ProcessName: pi.Name,
		ImagePath:   pi.Path,
		CmdLine:     pi.CmdLine,
		User:        pi.User,
		Hash:        res.Evidence.Process.HashSHA256,
		Signer:      res.Evidence.Process.Signer,
		Signed:      res.Evidence.Process.Signed,
		RuleIDs:     res.RuleIDs,
		MITRE:       res.MITRE,
		Evidence:    res.Evidence,
		OccurredAt:  now,
	}
	a.store.AddAlert(local)

	a.up.Enqueue(model.AlertEnvelope{
		Fingerprint: res.Fingerprint,
		Title:       res.Title,
		Summary:     res.Summary,
		Verdict:     res.Verdict,
		Severity:    res.Severity,
		Score:       res.Score,
		PID:         pi.PID,
		PPID:        pi.PPID,
		ProcessName: pi.Name,
		ImagePath:   pi.Path,
		CmdLine:     pi.CmdLine,
		ProcUser:    pi.User,
		HashSHA256:  res.Evidence.Process.HashSHA256,
		Signer:      res.Evidence.Process.Signer,
		Signed:      res.Evidence.Process.Signed,
		RuleIDs:     res.RuleIDs,
		MITRE:       res.MITRE,
		Evidence:    res.Evidence,
		OccurredAt:  now,
	})

	a.log.Warn("alert_raised",
		"title", res.Title, "verdict", res.Verdict, "severity", res.Severity,
		"score", res.Score, "process", pi.Name, "pid", pi.PID, "rules", res.RuleIDs)
}

// shouldInspectModules 判断是否值得花成本枚举模块。
func shouldInspectModules(pi collect.ProcessInfo) bool {
	if pi.Path == "" {
		return false
	}
	_, writable, depth := enrich.DescribeFast(pi.Path)
	if writable {
		return true
	}
	// 深层伪装目录也值得看一眼
	return depth >= 7
}

// ---------------------------------------------------------------- 心跳与上报

func (a *Agent) heartbeatLoop(ctx context.Context) {
	interval := time.Duration(a.cfg.HeartbeatSec) * time.Second
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if !a.up.Enrolled() {
				continue
			}
			ri := a.store.Runtime()
			req := model.HeartbeatRequest{
				Hostname:    ri.Hostname,
				Version:     a.cfg.Version,
				ProcCount:   ri.ProcCount,
				CPUPercent:  ri.CPUPercent,
				MemMB:       ri.MemMB,
				UptimeSec:   int64(time.Since(a.startedAt).Seconds()),
				RuleVersion: 0,
				Detector: model.DetectorStats{
					EventsScanned: ri.Stats.Scanned,
					AlertsFired:   ri.Stats.Fired,
					Suppressed:    ri.Stats.Suppressed,
					Whitelisted:   ri.Stats.Whitelisted,
					AvgLatencyMs:  ri.Stats.AvgLatencyMs,
				},
				Samples: ri.Stats.Scanned,
			}
			hctx, cancel := context.WithTimeout(ctx, 15*time.Second)
			resp, err := a.up.Heartbeat(hctx, req)
			cancel()
			if err != nil {
				a.log.Debug("heartbeat_failed", "err", err)
				a.store.SetRuntime(func(x *state.RuntimeInfo) { x.Online = false })
				continue
			}
			a.store.SetRuntime(func(x *state.RuntimeInfo) {
				x.Online = true
				x.LastHeartbeat = time.Now()
			})
			a.handleCommands(ctx, resp.Commands)
		}
	}
}

// handleCommands 执行服务端下发的指令。
func (a *Agent) handleCommands(ctx context.Context, cmds []model.Command) {
	if len(cmds) == 0 {
		return
	}
	results := make([]model.CommandResult, 0, len(cmds))

	for _, c := range cmds {
		res := model.CommandResult{CommandID: c.ID, Status: "done"}
		switch c.Type {
		case "rescan":
			select {
			case a.scanReq <- true:
			default:
			}
			res.Result = "已触发全量重扫"
		case "sync_rules":
			a.syncRules(ctx, true)
			res.Result = fmt.Sprintf("规则已同步，当前 %d 条", a.eng.RuleCount())
		case "terminate":
			res = a.handleTerminate(c)
		case "collect":
			res.Result = fmt.Sprintf("进程 %d 个", a.store.Runtime().ProcCount)
		default:
			res.Status = "failed"
			res.Result = "不支持的指令类型: " + c.Type
		}
		results = append(results, res)
	}

	rctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	if err := a.up.ReportCommandResults(rctx, results); err != nil {
		a.log.Warn("command_result_report_failed", "err", err)
	}
}

// handleTerminate 处理终止进程指令（需服务端与终端双重开启）。
func (a *Agent) handleTerminate(c model.Command) model.CommandResult {
	res := model.CommandResult{CommandID: c.ID}
	if !a.cfg.KillEnabled {
		res.Status = "failed"
		res.Result = "终端未启用主动处置（HG_AGENT_KILL_ENABLED=false）"
		return res
	}

	var payload struct {
		PID  uint32 `json:"pid"`
		Name string `json:"name"`
	}
	if err := json.Unmarshal([]byte(c.Payload), &payload); err != nil {
		res.Status = "failed"
		res.Result = "指令参数解析失败"
		return res
	}
	if payload.PID <= 4 {
		res.Status = "failed"
		res.Result = "拒绝终止系统关键进程"
		return res
	}

	// 二次校验：进程名必须与告警记录一致，避免 PID 复用导致误杀
	name, err := winapi.ImageNameOf(payload.PID)
	if err != nil {
		res.Status = "failed"
		res.Result = "进程已不存在"
		return res
	}
	if payload.Name != "" && !strings.EqualFold(name, payload.Name) {
		res.Status = "failed"
		res.Result = fmt.Sprintf("PID 复用保护：当前 %s 与目标 %s 不一致", name, payload.Name)
		return res
	}

	if err := winapi.TerminatePID(payload.PID); err != nil {
		res.Status = "failed"
		res.Result = "终止失败: " + err.Error()
		return res
	}
	res.Result = fmt.Sprintf("已终止 %s (PID %d)", name, payload.PID)
	a.log.Warn("process_terminated", "pid", payload.PID, "name", name, "command", c.ID)
	return res
}

// flushLoop 周期性批量上报告警。
func (a *Agent) flushLoop(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if !a.up.Enrolled() || a.up.Pending() == 0 {
				continue
			}
			fctx, cancel := context.WithTimeout(ctx, 30*time.Second)
			n, err := a.up.Flush(fctx)
			cancel()
			if err != nil {
				a.log.Warn("alert_flush_failed", "err", err, "pending", a.up.Pending())
				continue
			}
			if n > 0 {
				a.log.Info("alerts_flushed", "count", n)
				a.store.SetRuntime(func(ri *state.RuntimeInfo) { ri.PendingAlerts = a.up.Pending() })
			}
		}
	}
}

// persistLoop 周期性落盘基线与规则。
func (a *Agent) persistLoop(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := a.base.Save(); err != nil {
				a.log.Warn("baseline_save_failed", "err", err)
			}
			// 定期尝试同步规则（服务端可能更新了规则）
			if a.up.Enrolled() {
				a.syncRules(ctx, false)
			}
		}
	}
}

// ---------------------------------------------------------------- localapi.Backend 实现

// Runtime 返回探针运行状态。
func (a *Agent) Runtime() state.RuntimeInfo { return a.store.Runtime() }

// Procs 返回进程视图。
func (a *Agent) Procs(limit int) []state.ProcRow { return a.store.Procs(limit) }

// Alerts 返回本地告警。
func (a *Agent) Alerts(limit int) []*state.Alert { return a.store.Alerts(limit) }

// AlertByID 查询单条告警。
func (a *Agent) AlertByID(id string) *state.Alert { return a.store.AlertByID(id) }

// Rescan 触发一次全量重扫。
func (a *Agent) Rescan() {
	select {
	case a.scanReq <- true:
	default:
	}
}

// AllowHash 把文件哈希加入本地白名单。
func (a *Agent) AllowHash(hash, note string) error {
	if len(hash) != 64 {
		return fmt.Errorf("哈希必须是 64 位十六进制")
	}
	return a.alw.AddLocal(allow.TypeHash, hash, note)
}

// AllowPath 把路径加入本地白名单。
func (a *Agent) AllowPath(path, note string) error {
	if strings.TrimSpace(path) == "" {
		return fmt.Errorf("路径不能为空")
	}
	return a.alw.AddLocal(allow.TypePath, path, note)
}

// Allowlist 返回本地白名单。
func (a *Agent) Allowlist() []allow.Entry { return a.alw.Local() }

// RemoveAllow 删除本地白名单项。
func (a *Agent) RemoveAllow(typ, value string) error { return a.alw.RemoveLocal(typ, value) }

// WhitelistSize 返回白名单条目数。
func (a *Agent) WhitelistSize() map[string]int { return a.alw.Size() }
