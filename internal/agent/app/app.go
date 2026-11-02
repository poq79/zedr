// Package agentapp 组装探针运行时：配置 → 采集 → 富化 → 检测 → 上报 → 本地 API。
package agentapp

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"sync/atomic"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"zedr/internal/agent/allow"
	"zedr/internal/agent/baseline"
	"zedr/internal/agent/collect"
	"zedr/internal/agent/detect"
	"zedr/internal/agent/enrich"
	"zedr/internal/agent/inventory"
	"zedr/internal/agent/liveapi"
	"zedr/internal/agent/localapi"
	"zedr/internal/agent/persist"
	"zedr/internal/agent/quarantine"
	"zedr/internal/agent/state"
	"zedr/internal/agent/tunnel"
	"zedr/internal/agent/uplink"
	"zedr/internal/agent/winapi"
	"zedr/internal/platform/httpx"
	"zedr/internal/platform/idgen"
	"zedr/internal/platform/logx"
	"zedr/internal/model"
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
	qtn  *quarantine.Store

	// 行为采集层：文件落地监控 + 持久化项监控
	fw *winapi.FileWatcher
	pm *persist.Monitor

	// 资产清单：inventoryLoop 赋值；invReady 之后才对可 diff 节做
	// 条目级变更告警（首轮是建基线，不是"全是新增"）。
	// 两个字段只在 inventoryLoop 自己的 goroutine 上读写，无需加锁。
	inv      *inventory.Manager
	invReady bool

	local     *httpx.Server
	localAPI  *localapi.Server
	startedAt time.Time

	scanReq chan bool // 手动触发重扫
	online  bool

	// policyInterval 是服务端策略下发的扫描间隔（纳秒），0=用本地配置
	policyInterval atomic.Int64

	// upgradeExit 由 self_upgrade 指令置位：回执上报完成后退出进程，
	// 让 SCM 拉起新版本（磁盘换装已在指令处理时完成）。
	upgradeExit atomic.Bool
}

// New 装配探针。
func New(version string) (*Agent, error) {
	cfg, err := LoadConfig(version)
	if err != nil {
		return nil, err
	}

	log := logx.New(logx.Options{Level: cfg.LogLevel, Format: cfg.LogFormat})
	log.Info("agent_starting", "version", version, "data_dir", cfg.DataDir, "server", cfg.ServerURL)

	// 自升级换装必须在一切初始化之前完成：如果上次运行留下了
	// "已校验待换装"的标记，现在把新二进制换到当前 exe 的位置，
	// 然后本次启动用的还是旧镜像——由调用方感知版本变化后自行退出，
	// 让 SCM 重启拿到新版本（见 applyPendingUpgrade 的返回语义）。
	applyPendingUpgrade(cfg, log)

	store := state.New(500)

	// 采集引擎可插拔：默认 auto（NtQuery 优先、失败回退 Toolhelp32）
	// 之所以保留两套实现，是因为不同 Windows 版本 / 安全软件干预下
	// 某一种枚举方式可能失效，需要能不改代码就切回去。
	cfg.LocalToken = loadOrCreateLocalToken(cfg.Path("local.token"), log)

	// 采集引擎选择的优先级：终端本地显式环境变量 > 服务端下发策略 > 本地默认。
	// 服务端策略缓存于 policy.json（随规则包下发、签名保护），冷生效。
	collector := cfg.Collector
	if _, explicit := os.LookupEnv("HG_AGENT_COLLECTOR"); !explicit {
		if pc := readCollectorPolicy(cfg.Path("policy.json")); pc != "" {
			collector = pc
			log.Info("collector_from_server_policy", "collector", pc)
		}
	}
	coll, err := collect.New(collector, cfg.FullRescan)
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

	// 先用内置规则启动：即使服务端暂时不可达、或下发包验签失败，
	// 行为检测层也不该是空的。
	if n := eng.SetBuiltinRules(); n > 0 {
		log.Info("builtin_rules_loaded", "rules", n, "note", "服务端规则下发成功后会整包替换")
	}

	up := uplink.New(cfg.ServerURL, cfg.EnrollToken, cfg.DataDir, cfg.OfflineQueue)
	if up.LoadCredentials() {
		log.Info("agent_credentials_loaded", "agent_id", up.AgentID())
	}
	if cfg.RuleSignKey != "" {
		up.SetRuleSignKey([]byte(cfg.RuleSignKey))
		log.Info("rule_signature_verification_enabled")
	} else {
		log.Warn("rule_signature_verification_disabled",
			"hint", "未配置 HG_AGENT_RULE_SIGN_KEY，将信任服务端下发的任何规则包")
	}

	// 自豁免：安全产品不应把自己（安装目录、数据目录）当成可疑对象，
	// 否则每次升级换目录都会凭空产生一批"未签名程序在可写目录"的噪声。
	if exe, err := os.Executable(); err == nil {
		if dir := filepath.Dir(exe); dir != "" {
			if err := alw.EnsureLocal(allow.TypePath, dir, "Z-EDR 安装目录自豁免"); err != nil {
				log.Warn("self_allow_failed", "err", err)
			}
		}
	}
	if err := alw.EnsureLocal(allow.TypePath, cfg.DataDir, "Z-EDR 数据目录自豁免"); err != nil {
		log.Warn("self_allow_failed", "err", err)
	}

	// 持久化项监控：首次只建基线不告警，避免一上线就刷几百条
	pm := persist.New(cfg.Path("persist-baseline.json"), enr)
	if err := pm.Load(); err != nil {
		log.Warn("persist_baseline_load_failed", "err", err)
	}

	// 隔离区初始化失败不阻塞启动：后续隔离指令会得到明确失败回执
	qtn, err := quarantine.New(cfg.DataDir, installDir())
	if err != nil {
		log.Warn("quarantine_init_failed", "err", err, "hint", "文件隔离指令将不可用")
	}

	a := &Agent{
		cfg: cfg, log: log, store: store,
		coll: coll, enr: enr, base: base, alw: alw, eng: eng, up: up,
		pm: pm,
		qtn: qtn,
		cpu:       &winapi.CPUSampler{},
		startedAt: time.Now(),
		scanReq:   make(chan bool, 1),
	}
	// IOC 表先从落盘缓存恢复（重启空窗补位），服务端可达后再被整包覆盖
	a.loadIOCsCache()

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
		Token:   a.cfg.LocalToken,
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

	// 文件落地监控必须先于首轮扫描启动，否则启动瞬间落地的样本会被当成"老文件"
	if a.cfg.FileWatch {
		dirs := winapi.WatchDirs()
		if fw, err := winapi.StartFileWatcher(dirs); err != nil {
			a.log.Warn("file_watch_disabled", "err", err)
		} else {
			a.fw = fw
			a.log.Info("file_watch_started", "dirs", len(fw.WatchedDirs()))
		}
	}
	defer func() {
		if a.fw != nil {
			a.fw.Close()
		}
	}()

	// USN 断点补采：必须在 scanLoop 之前完成，首轮扫描才能用上
	// 停机窗口内的落地信号。非管理员/非 NTFS 时只记 warn。
	if a.fw != nil && a.cfg.USNCatchup {
		a.usnCatchup()
	}

	// 注册与规则同步在后台进行，不阻塞采集
	go a.enrollLoop(ctx)
	go a.scanLoop(ctx)
	go a.heartbeatLoop(ctx)
	go a.flushLoop(ctx)
	go a.persistLoop(ctx)
	go a.persistenceWatchLoop(ctx)
	if a.cfg.InventoryEnabled {
		go a.inventoryLoop(ctx)
	}
	// 实时隧道（只读调查通道，docs/LIVE-TUNNEL.md）：零监听、纯出站，
	// 服务端经隧道发起只读查询、探针在流上应答。失败自动退避重连，
	// 对端不支持（老 server）进每小时静默模式，不影响上方任何链路。
	// StartTime 用 a.startedAt（与 /status 的 uptime 同源）——不要放进
	// scan 回调：state.SetRuntime 只有最后一个回调生效（踩过的坑）。
	if a.cfg.TunnelEnabled {
		mgr := tunnel.New(a.log, tunnel.Options{
			ServerURL: a.cfg.ServerURL,
			Creds:     a.up.TunnelCreds,
			Handler: liveapi.New(liveapi.Deps{
					Version:   a.cfg.Version,
					Hostname:  winapi.Hostname(),
					StartTime: a.startedAt,
					Procs:     a.Procs,
					Modules:   a.coll.Modules,
					Snapshot: func() []state.ProcRow {
						// procinfo 需要全量快照做 PID 定位与 netstat join；
						// 2000 与 localapi/processes 的钳制口径一致
						return a.store.Procs(2000)
					},
					Runtime: a.store.Runtime,
					Netstat: func() []winapi.NetRow {
						// GetNetstat 带错误返回而 Deps 收敛为行切片：
						// 失败时记日志返回空表，让端点保持 200 语义
						rows, err := winapi.GetNetstat()
						if err != nil {
							a.log.Warn("netstat_query_failed", "err", err)
						}
						return rows
					},
				}),
		})
		go mgr.Start(ctx)
		defer mgr.Stop()
	}

	<-ctx.Done()
	a.log.Info("agent_stopping", "pending_alerts", a.up.Pending())

	// 优雅停机：退出前把队列里剩余的告警尽量送出去。
	// 不做这一步的话，进程一停就等于丢掉最后一批告警——恰恰是最新、
	// 最可能对应"正在发生"的那批。
	if n := a.up.Pending(); n > 0 && a.up.Enrolled() {
		fctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		sent, err := a.up.Flush(fctx)
		cancel()
		if err != nil {
			a.log.Warn("alert_flush_on_exit_failed", "sent", sent, "remaining", a.up.Pending(), "err", err)
		} else {
			a.log.Info("alerts_flushed_on_exit", "count", sent, "remaining", a.up.Pending())
		}
	}

	_ = a.base.Save()
	_ = a.pm.Save()
	a.store.SetRuntime(func(ri *state.RuntimeInfo) { ri.Online = false })
	return nil
}

// loadOrCreateLocalToken 读取或生成本地接口访问令牌。
//
// 令牌写进数据目录、权限 0600：同机其它用户的进程读不到。
// 同用户的进程仍可读——这在用户态无法彻底解决（那是操作系统的信任边界），
// 但配合 Origin 校验已经切断了"浏览器里的恶意网页调本地接口"这条最现实的路径。
func loadOrCreateLocalToken(path string, log *slog.Logger) string {
	if raw, err := os.ReadFile(path); err == nil {
		if t := strings.TrimSpace(string(raw)); t != "" {
			return t
		}
	}
	t := idgen.Hex(24)
	if err := os.WriteFile(path, []byte(t), 0o600); err != nil {
		log.Warn("local_token_write_failed", "err", err,
			"hint", "本地接口将只保留 Origin 防护，不带令牌校验")
		return ""
	}
	log.Info("local_token_created", "path", path)
	return t
}

// ---------------------------------------------------------------- 注册

func (a *Agent) enrollLoop(ctx context.Context) {
	for {
		if a.up.Enrolled() {
			a.syncRules(ctx, true)
			a.syncIOCs(ctx, true)
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
		a.syncIOCs(ctx, true)
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
	// force=true 且服务端版本未变时 FetchRules 返回 (nil, true, nil)——
	// 此时无包可应用。此前直接解引用 bundle.Rules，任何一条
	// "规则未变化的 sync_rules 指令"都会空指针 panic 杀死探针。
	if bundle == nil {
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
		ri.RuleVersion = bundle.Version
		ri.Whitelist = a.alw.Size()
	})
	a.log.Info("rules_applied", "version", bundle.Version, "rules", ok, "allow", len(entries), "bad", len(bad))

	a.applyServerPolicy(bundle.AgentPolicy)
}

// syncIOCs 拉取威胁指标整包并热加载到引擎。
// 与规则同节奏触发（注册后/指令/周期），但独立拉取、独立验签——
// 老服务端没有此端点时 404 只会记 warn，不影响主链路。
func (a *Agent) syncIOCs(ctx context.Context, force bool) {
	cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	bundle, notModified, err := a.up.FetchIOCs(cctx)
	if err != nil {
		a.log.Warn("iocs_fetch_failed", "err", err)
		return
	}
	if notModified && !force {
		return
	}
	if bundle == nil { // 同 syncRules：force 且未变化时无包可应用
		return
	}

	m := make(map[string]string, len(bundle.IOCs))
	for _, e := range bundle.IOCs {
		m[e.Hash] = e.Note
	}
	a.eng.SetIOCs(m)
	a.saveIOCsCache(bundle)
	a.log.Info("iocs_applied", "version", bundle.Version, "count", len(m))
}

// saveIOCsCache 把已验签的 IOC 表落盘，重启后无需等首轮拉取即生效。
func (a *Agent) saveIOCsCache(bundle *model.IOCBundle) {
	type cache struct {
		Version int            `json:"version"`
		SavedAt time.Time      `json:"saved_at"`
		IOCs    map[string]string `json:"iocs"`
	}
	m := make(map[string]string, len(bundle.IOCs))
	for _, e := range bundle.IOCs {
		m[e.Hash] = e.Note
	}
	raw, err := json.Marshal(cache{Version: bundle.Version, SavedAt: time.Now(), IOCs: m})
	if err != nil {
		a.log.Warn("iocs_cache_marshal_failed", "err", err)
		return
	}
	if err := os.WriteFile(a.cfg.Path("iocs.json"), raw, 0o600); err != nil {
		a.log.Warn("iocs_cache_write_failed", "err", err)
	}
}

// loadIOCsCache 从落盘缓存恢复 IOC 表（重启后的空窗补位）。
func (a *Agent) loadIOCsCache() {
	raw, err := os.ReadFile(a.cfg.Path("iocs.json"))
	if err != nil {
		return
	}
	var cache struct {
		Version int               `json:"version"`
		IOCs    map[string]string `json:"iocs"`
	}
	if err := json.Unmarshal(raw, &cache); err != nil || len(cache.IOCs) == 0 {
		return
	}
	a.eng.SetIOCs(cache.IOCs)
	a.log.Info("iocs_cache_loaded", "version", cache.Version, "count", len(cache.IOCs))
}

// ---------------------------------------------------------------- 采集

// 自适应扫描的参数。
//
// 取舍说明：安全产品最怕的两个极端是"占满 CPU"和"漏掉短命进程"。
// 固定 2 秒轮询意味着即使整机十小时没有任何新进程，也要持续做全进程表枚举，
// 这是纯浪费；而一味拉长间隔又会漏掉"落地即执行"的样本。
//
// 折中方案是：安静时逐步退避到上限，一旦发现新进程立刻回到基础间隔。
// 攻击者真正活动时进程创建是连续的，退避不会持续生效；
// 而空闲时段（夜间、无人值守）CPU 占用可以降到四分之一以下。
const (
	adaptiveQuietRounds = 6                // 连续多少轮无新进程视为"安静"
	adaptiveMaxInterval = 6 * time.Second  // 退避上限
)

func (a *Agent) scanLoop(ctx context.Context) {
	base := a.baseInterval()
	interval := base
	quiet := 0

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	a.scan(true) // 首轮做全量，建立基线

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			fresh := a.scan(false)

			if !a.cfg.AdaptiveScan {
				continue
			}
			if fresh > 0 {
				quiet = 0
				if interval != a.baseInterval() {
					interval = a.baseInterval()
					ticker.Reset(interval)
					a.store.SetRuntime(func(ri *state.RuntimeInfo) { ri.ScanInterval = interval.String() })
				}
				continue
			}
			quiet++
			if quiet >= adaptiveQuietRounds && interval < adaptiveMaxInterval {
				interval += time.Second
				if interval > adaptiveMaxInterval {
					interval = adaptiveMaxInterval
				}
				ticker.Reset(interval)
				a.log.Debug("scan_interval_backoff", "interval", interval.String())
				a.store.SetRuntime(func(ri *state.RuntimeInfo) { ri.ScanInterval = interval.String() })
			}
		case force := <-a.scanReq:
			a.scan(true)
			_ = force
			quiet = 0
			interval = a.baseInterval()
			ticker.Reset(interval)
			a.store.SetRuntime(func(ri *state.RuntimeInfo) { ri.ScanInterval = interval.String() })
		}
	}
}

// scan 执行一轮采集 + 检测，返回本轮新增进程数（用于自适应调频）。
func (a *Agent) scan(deep bool) int {
	start := time.Now()

	newProcs, snap, err := a.coll.Poll(deep)
	if err != nil {
		a.log.Warn("scan_failed", "err", err)
		return 0
	}

	alive := make(map[uint32]struct{}, len(snap.Procs))
	for pid := range snap.Procs {
		alive[pid] = struct{}{}
	}

	// 模块枚举是整轮扫描里最贵的操作（每个进程一次快照）。
	// 给每轮一个预算：正常情况远用不满，但遇到"大量进程同时从可写目录启动"
	// （安装器、解包、恶意批量释放）时不会把一轮扫描拖到分钟级。
	// 超出预算的进程其模块信息留空，其余各层照常判定——
	// 少一个证据维度，好过整轮卡死导致后续进程全部漏检。
	moduleBudget := maxModuleInspectPerScan

	for _, pi := range newProcs {
		if pi.PID == uint32(os.Getpid()) {
			continue // 不检测自己
		}

		ancestry, parentAlive := a.coll.Ancestry(snap, pi.PID)
		conns := a.coll.ConnectionsOf(snap, pi.PID)

		// 模块枚举成本高：只对"有网络连接"或"位于可写目录"的进程做
		var modules []model.ModuleInfo
		if moduleBudget > 0 && (len(conns) > 0 || shouldInspectModules(pi)) {
			modules = a.coll.Modules(pi.PID)
			moduleBudget--
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
			LandedAt:    a.landedAt(pi.Path),
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

	// 慢扫描告警：一轮扫描耗时明显超过间隔，说明采集或富化出了问题
	// （大文件哈希、模块枚举、安全软件拦截系统调用等）。
	// 不记录的话，表现就是"检测越来越迟钝"，却没有任何线索。
	if elapsed := time.Since(start); elapsed > a.cfg.ScanInterval*3 {
		a.log.Warn("scan_slow", "elapsed_ms", elapsed.Milliseconds(),
			"interval_ms", a.cfg.ScanInterval.Milliseconds(), "new_procs", len(newProcs))
	}

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

		// 下发数据落地情况：inventoryLoop 未启动（开关关）时 Count() 为 0
		// 是真实语义（"终端没在用"），不是缺数据。
		ri.IOCCount = a.eng.IOCCount()
		if a.inv != nil {
			ri.InventorySections = a.inv.Count()
		}

		// 这些字段只在扫描回调里维护：New() 里注册的回调会被这里覆盖，
		// 放两处只会让其中一处永远不生效（UptimeSec 之前恒为 0 就是这么来的）。
		ri.UptimeSec = int64(time.Since(a.startedAt).Seconds())
		ri.PersistCount = a.pm.Size()
		if a.fw != nil {
			ri.FileWatch = true
			ri.WatchedDirs = len(a.fw.WatchedDirs())
			ri.DropEvents = a.fw.Events()
		} else {
			ri.FileWatch = false
		}
	})

	return len(newProcs)
}

// emit 生成进程类告警。
func (a *Agent) emit(pi collect.ProcessInfo, res *detect.Result) {
	a.emitAlert(model.AlertEnvelope{
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
		OccurredAt:  time.Now(),
	})
}

// emitAlert 是所有告警的统一出口：本地存储 + 上报队列 + 结构化日志。
//
// 之所以收敛成一个入口：告警来源已经不止"进程检测"（还有持久化变更），
// 如果每个来源各自写一套入队逻辑，很容易漏掉去重、截断或日志字段。
func (a *Agent) emitAlert(env model.AlertEnvelope) {
	local := &state.Alert{
		ID:          idgen.Hex(8),
		Title:       env.Title,
		Summary:     env.Summary,
		Verdict:     string(env.Verdict),
		Severity:    string(env.Severity),
		Score:       env.Score,
		PID:         env.PID,
		PPID:        env.PPID,
		ProcessName: env.ProcessName,
		ImagePath:   env.ImagePath,
		CmdLine:     env.CmdLine,
		User:        env.ProcUser,
		Hash:        env.HashSHA256,
		Signer:      env.Signer,
		Signed:      env.Signed,
		RuleIDs:     env.RuleIDs,
		MITRE:       env.MITRE,
		Evidence:    env.Evidence,
		OccurredAt:  env.OccurredAt,
	}
	a.store.AddAlert(local)
	a.up.Enqueue(env)

	a.log.Warn("alert_raised",
		"title", env.Title, "verdict", env.Verdict, "severity", env.Severity,
		"score", env.Score, "process", env.ProcessName, "pid", env.PID,
		"rules", env.RuleIDs, "source", env.ProcUser)
}

// landedAt 查询镜像文件的落地时间（用于"落地即执行"关联）。
func (a *Agent) landedAt(path string) time.Time {
	if a.fw == nil || path == "" {
		return time.Time{}
	}
	if d, ok := a.fw.Recent(path, 15*time.Minute); ok {
		return d.When
	}
	return time.Time{}
}

// ---------------------------------------------------------------- 持久化监控

// persistenceWatchLoop 周期性对比自启动项基线。
func (a *Agent) persistenceWatchLoop(ctx context.Context) {
	// 首轮建立基线（首次运行不产生任何告警）
	a.scanPersistence()

	ticker := time.NewTicker(a.cfg.PersistCheck)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			a.scanPersistence()
		}
	}
}

// scanPersistence 执行一轮持久化项扫描并产出告警。
func (a *Agent) scanPersistence() {
	start := time.Now()
	res, err := a.pm.Scan()
	if err != nil {
		a.log.Warn("persist_scan_failed", "err", err)
		return
	}
	for _, e := range res.Errs {
		a.log.Debug("persist_scan_partial", "err", e)
	}
	if res.Initial {
		a.log.Info("persist_baseline_built", "items", res.Total,
			"note", "首次运行只建立基线，不产生告警")
		return
	}

	seen := 0
	for _, f := range res.Added {
		seen += a.emitPersistFinding(f)
	}
	for _, f := range res.Changed {
		seen += a.emitPersistFinding(f)
	}
	if seen > 0 || len(res.Removed) > 0 {
		a.log.Info("persist_scan_done",
			"added", len(res.Added), "changed", len(res.Changed),
			"removed", len(res.Removed), "alerts", seen,
			"elapsed_ms", time.Since(start).Milliseconds())
	}
}

// emitPersistFinding 把一条持久化变更转成告警；返回是否真的产生了告警。
func (a *Agent) emitPersistFinding(f persist.Finding) int {
	// 白名单优先：用户明确信任的对象不再打扰
	if hit, _ := a.alw.Match(f.Hash, f.Path, f.Signer, "", f.Item.Name, f.Item.Command); hit {
		a.log.Debug("persist_whitelisted", "key", f.Item.Key)
		return 0
	}

	// 低于阈值的变更只记录，不告警——否则"某个软件升级改了自启动参数"
	// 这类事件会把队列刷满
	if f.Score < 38 {
		a.log.Info("persist_changed_low_score",
			"type", f.Item.Type, "name", f.Item.Name, "score", f.Score)
		return 0
	}

	a.emitAlert(f.ToAlert(winapi.Hostname()))
	return 1
}

// maxModuleInspectPerScan 是单轮扫描允许枚举模块的进程数上限。
const maxModuleInspectPerScan = 30

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
				AgentTime:  time.Now(),
				Hostname:    ri.Hostname,
				Version:     a.cfg.Version,
				ProcCount:   ri.ProcCount,
				CPUPercent:  ri.CPUPercent,
				MemMB:       ri.MemMB,
				UptimeSec:   int64(time.Since(a.startedAt).Seconds()),
				// 上报终端实际应用的版本（0 = 尚未成功拉取）。
				// 规则包版本由 uplink 在验签/版本单调检查通过后记录，
				// 服务端据此判断灰度是否真正落地。
				RuleVersion: a.up.RuleVersion(),
				Detector: model.DetectorStats{
					EventsScanned: ri.Stats.Scanned,
					AlertsFired:   ri.Stats.Fired,
					Suppressed:    ri.Stats.Suppressed,
					Whitelisted:   ri.Stats.Whitelisted,
					AvgLatencyMs:  ri.Stats.AvgLatencyMs,
				},
				Samples: ri.Stats.Scanned,
				QueueDropped: a.up.Dropped(),
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
			a.syncIOCs(ctx, true)
			res.Result = fmt.Sprintf("规则已同步，当前 %d 条；IOC %d 条", a.eng.RuleCount(), a.eng.IOCCount())
		case "terminate":
			res = a.handleTerminate(c)
		case "quarantine_file":
			res = a.handleQuarantineFile(c)
		case "quarantine_restore":
			res = a.handleQuarantineRestore(c)
		case "self_upgrade":
			res = a.handleSelfUpgrade(ctx, c)
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

	// 回执送达后才允许为升级退出：进程在回执前消失，指令会永远
	// 挂在"已下发、无回执"（见 maybeExitForUpgrade 注释）
	a.maybeExitForUpgrade()
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

// handleQuarantineFile 处理文件隔离指令（需终端侧显式开启）。
// 运行中的程序镜像通常因文件锁无法移出，此时如实回执失败——
// 正确的处置顺序是先 terminate 再 quarantine，这也是业界惯例。
func (a *Agent) handleQuarantineFile(c model.Command) model.CommandResult {
	res := model.CommandResult{CommandID: c.ID}
	if !a.cfg.QuarantineEnabled {
		res.Status = "failed"
		res.Result = "终端未启用文件隔离（HG_AGENT_QUARANTINE_ENABLED=false）"
		return res
	}
	if a.qtn == nil {
		res.Status = "failed"
		res.Result = "隔离区不可用（初始化失败）"
		return res
	}
	var payload struct {
		Path  string `json:"path"`
		Reason string `json:"reason"`
	}
	if err := json.Unmarshal([]byte(c.Payload), &payload); err != nil {
		res.Status = "failed"
		res.Result = "指令参数解析失败"
		return res
	}
	if strings.TrimSpace(payload.Path) == "" {
		res.Status = "failed"
		res.Result = "缺少 path 参数"
		return res
	}

	e, err := a.qtn.Quarantine(payload.Path, payload.Reason, c.ID)
	if err != nil {
		res.Status = "failed"
		res.Result = "隔离失败: " + err.Error()
		a.log.Warn("file_quarantine_failed", "path", redactPath(payload.Path), "err", err)
		return res
	}
	res.Result = fmt.Sprintf("已隔离 %s → 隔离记录 %s（可用 quarantine_restore 恢复）",
		redactPath(payload.Path), e.ID)
	a.log.Warn("file_quarantined", "entry_id", e.ID,
		"path", redactPath(e.OriginalPath), "size", e.Size, "command", c.ID)
	return res
}

// handleQuarantineRestore 处理隔离文件恢复指令。
func (a *Agent) handleQuarantineRestore(c model.Command) model.CommandResult {
	res := model.CommandResult{CommandID: c.ID}
	if !a.cfg.QuarantineEnabled {
		res.Status = "failed"
		res.Result = "终端未启用文件隔离（HG_AGENT_QUARANTINE_ENABLED=false）"
		return res
	}
	if a.qtn == nil {
		res.Status = "failed"
		res.Result = "隔离区不可用（初始化失败）"
		return res
	}
	var payload struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal([]byte(c.Payload), &payload); err != nil || payload.ID == "" {
		res.Status = "failed"
		res.Result = "缺少隔离记录 ID"
		return res
	}
	e, err := a.qtn.Restore(payload.ID, c.ID)
	if err != nil {
		res.Status = "failed"
		res.Result = "恢复失败: " + err.Error()
		return res
	}
	res.Result = fmt.Sprintf("已恢复 %s", redactPath(e.OriginalPath))
	a.log.Warn("file_restored", "entry_id", e.ID, "path", redactPath(e.OriginalPath), "command", c.ID)
	return res
}

// installDir 返回探针可执行文件所在目录（自保护边界之一）。
func installDir() string {
	if exe, err := os.Executable(); err == nil {
		return filepath.Dir(exe)
	}
	return ""
}

// redactPath 日志里的路径只保留文件名与上级目录名，不写全路径
// （与 redact.Path 的策略一致，避免日志本身成为敏感信息泄漏面）。
func redactPath(p string) string {
	return filepath.Base(p)
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
				a.syncIOCs(ctx, false)
			}
		}
	}
}

// ---------------------------------------------------------------- 资产清单

// inventoryInterval 是资产清单快照周期。清单类数据（服务/任务/网卡）
// 变化频率远低于进程创建，30s 足够及时；差量协议（按节 hash 比对）
// 保证稳定态下每轮几乎零流量。
const inventoryInterval = 30 * time.Second

// inventoryLoop 周期采集资产清单快照并差量上报；发生变化的节随后做
// 条目级 diff，把"新增/移除/变更了哪个服务、哪个计划任务"转成告警。
//
// 数据源全部以 SnapshotFn 闭包注入（依赖倒置）：清单的差量/上报逻辑
// 不接触任何系统调用，winapi 采集函数的增改不会传染到这条链路，
// 测试也可以用假函数覆盖全部行为。
func (a *Agent) inventoryLoop(ctx context.Context) {
	m := inventory.New(a.log)
	a.inv = m

	m.Register("system", a.invSystemSection)
	m.Register("adapters", a.invAdaptersSection)
	m.Register("listeners", a.invListenersSection)
	m.Register("services", a.invServicesSection)
	m.Register("tasks", a.invTasksSection)
	// startup：真实自启动项，来自 persist.Monitor 的持久化基线（7 类位置）
	m.Register("startup", a.invStartupSection)
	m.Register("agent", a.invAgentSection)
	// 安全姿态三节：检测价值最高的一组——排除项新增/防火墙关闭/管理员组
	// 变更都会经变更管线直接产生 critical 告警（见 classifyInventoryEvent）。
	m.Register("defender", a.invDefenderSection)
	m.Register("firewall", a.invFirewallSection)
	m.Register("accounts", a.invAccountsSection)

	// 可 diff 节的条目主键。system/agent/defender 是标量与聚合快照节，
	// 没有稳定的条目主键（defender 的排除列表作为整节 changed 处理），
	// 不做条目级 diff。
	keyFns := map[string]func(map[string]any) string{
		"services":  inventoryFieldKey("name"),
		"tasks":     inventoryFieldKey("path"),
		"adapters":  inventoryFieldKey("name"),
		// listeners 的 payload 是 {"tcp":[...],"udp":[...]}，Diff 会合并
		// 两个表并给条目注入列表名作为 proto 字段，key 形如 "tcp|8080"。
		"listeners": inventoryFieldKey("proto", "port"),
		"startup":   inventoryFieldKey("kind", "location"),
		"firewall":  inventoryFieldKey("name"),
		"accounts":  inventoryFieldKey("name"),
	}

	m.Run(ctx, inventoryInterval, func(sections []model.InventorySection) ([]string, error) {
		// 未注册时 uplink 直接报错返回——正好让 Run 回滚 hash，
		// 注册成功后的下一轮把首轮全量补上，不会丢节。
		cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
		applied, err := a.up.PostInventory(cctx, sections)
		cancel()

		// 事件发射挂在快照成功之后（此时 Manager 里正好保有本轮"变化前"
		// payload）。只在 post 成功后 diff：post 失败 Run 会回滚 payload
		// 状态并在下一轮重试同一节，若失败轮也发事件，重试轮会把同一批
		// 变更重复告警一次。diff 出错只记日志，绝不影响上报结果。
		if err == nil {
			a.diffInventoryEvents(ctx, sections, keyFns)
		}
		return applied, err
	})
}

// diffInventoryEvents 对本轮差量节做条目级 diff，把变更交给告警策略层。
// 首轮（invReady=false）只建基线不发事件——首轮对任何节都是"全是新增"，
// 那是基线而不是攻击面。
func (a *Agent) diffInventoryEvents(ctx context.Context, sections []model.InventorySection, keyFns map[string]func(map[string]any) string) {
	wasReady := a.invReady
	a.invReady = true
	if !wasReady {
		return
	}

	var changes []inventory.ChangeEvent
	for _, s := range sections {
		keyFn, ok := keyFns[s.Name]
		if !ok {
			continue
		}
		prev, ok := a.inv.LastPayload(s.Name)
		if !ok {
			// 该节本轮没有"变化前"payload（首次成功采集、或采集失败后
			// 恢复的第一轮），没有可比对象，跳过，下轮起恢复正常 diff。
			continue
		}
		evs, err := inventory.Diff(prev, s.Payload, keyFn)
		if err != nil {
			a.log.Warn("inventory_diff_failed", "section", s.Name, "err", err)
			continue
		}
		for i := range evs {
			evs[i].Section = s.Name
		}
		changes = append(changes, evs...)
	}
	a.emitInventoryEvents(ctx, changes)
}

// invStartupItem 是 startup 节的一条自启动项（字段名即线协议）。
type invStartupItem struct {
	Kind     string `json:"kind"`
	Location string `json:"location"`
	Value    string `json:"value"`
}

// invStartupSection 从 persist.Monitor 基线组装 startup 节。
// 基线为空是正常情况（干净机器），返回空列表而不是错误——
// 空节不算采集失败，否则干净机器永远报 startup 采集异常。
func (a *Agent) invStartupSection() (any, error) {
	items := a.pm.Items()
	list := make([]invStartupItem, 0, len(items))
	for _, it := range items {
		list = append(list, invStartupItem{Kind: it.Kind, Location: it.Location, Value: it.Value})
	}
	// 按 kind+location 排序保证 hash 稳定：枚举顺序不稳定会让差量协议
	// 退化成每轮全量（与 services/tasks 各节同一条纪律）。
	sort.Slice(list, func(i, j int) bool {
		if list[i].Kind != list[j].Kind {
			return list[i].Kind < list[j].Kind
		}
		if list[i].Location != list[j].Location {
			return list[i].Location < list[j].Location
		}
		return list[i].Value < list[j].Value
	})
	return map[string]any{"items": list}, nil
}

// inventory 各节的本地 payload 类型：字段名即线协议（snake_case）。
// adapters/services/tasks 三节从 winapi 类型显式映射——winapi 结构体不带
// json tag（那是采集层的自由），线协议字段名必须收敛在一处；winapi
// 增删字段时在这里同步，映射处就是唯一的翻译点。
type invAdapter struct {
	Name      string   `json:"name"`
	MAC       string   `json:"mac"`
	IPs       []string `json:"ips"`
	Gateway   string   `json:"gateway"`
	DNS       []string `json:"dns"`
	OperState string   `json:"oper_state"`
}

type invService struct {
	Name        string `json:"name"`
	DisplayName string `json:"display_name"`
	State       string `json:"state"`
	StartMode   string `json:"start_mode"`
	PathName    string `json:"path_name"`
	Account     string `json:"account"`
}

type invTask struct {
	Path  string `json:"path"`
	Name  string `json:"name"`
	State string `json:"state"`
}

type invDisk struct {
	Drive   string `json:"drive"`
	TotalMB uint64 `json:"total_mb"`
	FreeMB  uint64 `json:"free_mb"`
}

type invListener struct {
	Port    uint16 `json:"port"`
	PID     uint32 `json:"pid"`
	Process string `json:"process,omitempty"`
}

type invUDPListener struct {
	Port uint16 `json:"port"`
	PID  uint32 `json:"pid"`
}

type invAgentInfo struct {
	Version         string `json:"version"`
	Collector       string `json:"collector"`
	ScanIntervalSec int    `json:"scan_interval_sec"`
	RuleCount       int    `json:"rule_count"`
	IOCCount        int    `json:"ioc_count"`
	QueueDropped    int64  `json:"queue_dropped"`
	UptimeSec       int64  `json:"uptime_sec"`
}

// invSystemSection 组装 system 节。子项失败只少字段不拖垮整节——
// 诚实缺席好过用 0 冒充真实值；唯独 BootTime 失败时整节跳过，
// 没有开机时间 uptime 无从谈起，半个 system 节反而误导。
func (a *Agent) invSystemSection() (any, error) {
	boot, err := winapi.BootTime()
	if err != nil {
		return nil, err
	}
	out := map[string]any{
		"boot_time":  boot.UTC().Format(time.RFC3339),
		"uptime_sec": int64(time.Since(boot).Seconds()),
	}
	if name, cores, err := winapi.CPUInfo(); err == nil {
		out["cpu_name"] = name
		out["cpu_cores"] = cores
	}
	if total, free, err := winapi.MemoryStats(); err == nil {
		out["mem_total_mb"] = total
		out["mem_free_mb"] = free
	}
	if disks, err := winapi.DiskVolumes(); err == nil {
		list := make([]invDisk, 0, len(disks))
		for _, d := range disks {
			list = append(list, invDisk{Drive: d.Drive, TotalMB: d.TotalMB, FreeMB: d.FreeMB})
		}
		sort.Slice(list, func(i, j int) bool { return list[i].Drive < list[j].Drive })
		out["disks"] = list
	}
	return out, nil
}

// invAdaptersSection 网卡列表。按名称排序保证 hash 稳定：枚举顺序
// 稍有变化就会让差量协议退化成每轮全量。
func (a *Agent) invAdaptersSection() (any, error) {
	src, err := winapi.Adapters()
	if err != nil {
		return nil, err
	}
	list := make([]invAdapter, 0, len(src))
	for _, ai := range src {
		list = append(list, invAdapter{
			Name: ai.Name, MAC: ai.MAC, IPs: ai.IPs,
			Gateway: ai.Gateway, DNS: ai.DNS, OperState: ai.OperState,
		})
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Name < list[j].Name })
	return list, nil
}

// invServicesSection 服务列表（按名称排序，理由同上）。
func (a *Agent) invServicesSection() (any, error) {
	src, err := winapi.ServiceList()
	if err != nil {
		return nil, err
	}
	list := make([]invService, 0, len(src))
	for _, s := range src {
		list = append(list, invService{
			Name: s.Name, DisplayName: s.DisplayName, State: s.State,
			StartMode: s.StartMode, PathName: s.PathName, Account: s.Account,
		})
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Name < list[j].Name })
	return list, nil
}

// invTasksSection 计划任务列表（按 path+name 排序，理由同上）。
func (a *Agent) invTasksSection() (any, error) {
	src, err := winapi.TaskList()
	if err != nil {
		return nil, err
	}
	list := make([]invTask, 0, len(src))
	for _, t := range src {
		list = append(list, invTask{Path: t.Path, Name: t.Name, State: t.State})
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].Path != list[j].Path {
			return list[i].Path < list[j].Path
		}
		return list[i].Name < list[j].Name
	})
	return list, nil
}

// invListenersSection 监听端口：TCP 复用现有连接表（筛 LISTEN），UDP 走
// 新契约。进程名逐 PID 查询——监听条目通常个位数，成本可忽略，查不到留空。
// 输出按 (port, pid) 排序：顺序不稳定会让同样的数据每轮算出不同 hash，
// 差量协议就退化成每轮全量。
func (a *Agent) invListenersSection() (any, error) {
	out := map[string]any{
		"tcp": []invListener{},
		"udp": []invUDPListener{},
	}

	if conns, err := winapi.TCPConnections(); err == nil {
		tcp := make([]invListener, 0, 8)
		procNames := make(map[uint32]string, 8)
		for pid, list := range conns {
			for _, c := range list {
				if c.State != "LISTEN" {
					continue
				}
				name, ok := procNames[pid]
				if !ok {
					if n, err := winapi.ImageNameOf(pid); err == nil {
						name = n
					}
					procNames[pid] = name
				}
				tcp = append(tcp, invListener{Port: c.LocalPort, PID: pid, Process: name})
			}
		}
		sort.Slice(tcp, func(i, j int) bool {
			if tcp[i].Port != tcp[j].Port {
				return tcp[i].Port < tcp[j].Port
			}
			return tcp[i].PID < tcp[j].PID
		})
		out["tcp"] = tcp
	}

	if udp, err := winapi.UDPListeners(); err == nil {
		list := make([]invUDPListener, 0, len(udp))
		for _, e := range udp {
			list = append(list, invUDPListener{Port: e.Port, PID: e.PID})
		}
		sort.Slice(list, func(i, j int) bool {
			if list[i].Port != list[j].Port {
				return list[i].Port < list[j].Port
			}
			return list[i].PID < list[j].PID
		})
		out["udp"] = list
	}
	return out, nil
}

// invAgentSection 探针自身状态。uptime/queue_dropped 每轮必变，所以这节
// 天然"每轮必报"——探针健康度搭清单通道的顺风车，服务端可据此做
// 探针存活与配置漂移的旁路核对。
func (a *Agent) invAgentSection() (any, error) {
	return invAgentInfo{
		Version:         a.cfg.Version,
		Collector:       a.coll.SourceName(),
		ScanIntervalSec: int(a.baseInterval().Seconds()),
		RuleCount:       a.eng.RuleCount(),
		IOCCount:        a.eng.IOCCount(),
		QueueDropped:    a.up.Dropped(),
		UptimeSec:       int64(time.Since(a.startedAt).Seconds()),
	}, nil
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


// ---------------------------------------------------------------- 服务端策略

// baseInterval 返回当前应使用的扫描基础间隔：
// 服务端策略（热生效）> 本地配置。自适应退避都在此基础上进行。
func (a *Agent) baseInterval() time.Duration {
	if v := a.policyInterval.Load(); v > 0 {
		return time.Duration(v)
	}
	return a.cfg.ScanInterval
}

// applyServerPolicy 应用随规则包下发的运行策略。
//
// 优先级铁律：终端本地"显式设置"的环境变量永远赢过服务端策略——
// 否则现场排障时想临时改个参数都会被服务端悄悄改回去。
// scan interval 热生效；collector 需要重建采集器，缓存后冷生效。
func (a *Agent) applyServerPolicy(p *model.AgentPolicy) {
	if p == nil {
		return
	}
	if p.ScanIntervalSec >= 2 {
		if _, explicit := os.LookupEnv("HG_AGENT_SCAN_INTERVAL"); !explicit {
			a.policyInterval.Store(int64(time.Duration(p.ScanIntervalSec) * time.Second))
			a.log.Info("policy_scan_interval_applied", "sec", p.ScanIntervalSec)
		}
	}
	if p.Collector != "" && p.Collector != a.coll.SourceName() {
		if _, explicit := os.LookupEnv("HG_AGENT_COLLECTOR"); !explicit {
			switch p.Collector {
			case "auto", "ntquery", "toolhelp":
				if err := saveCollectorPolicy(a.cfg.Path("policy.json"), p.Collector); err != nil {
					a.log.Warn("policy_collector_save_failed", "err", err)
				} else {
					a.log.Warn("policy_collector_pending_restart", "collector", p.Collector,
						"hint", "采集引擎需重启探针后切换")
				}
			default:
				a.log.Warn("policy_collector_invalid", "collector", p.Collector)
			}
		}
	}
}

// policyFile 是 policy.json 的落盘格式。
type policyFile struct {
	Collector string `json:"collector,omitempty"`
}

func readCollectorPolicy(path string) string {
	raw, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	var pf policyFile
	if json.Unmarshal(raw, &pf) != nil {
		return ""
	}
	return pf.Collector
}

func saveCollectorPolicy(path, collector string) error {
	raw, err := json.Marshal(policyFile{Collector: collector})
	if err != nil {
		return err
	}
	return os.WriteFile(path, raw, 0o600)
}
