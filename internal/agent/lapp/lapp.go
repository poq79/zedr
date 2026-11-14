//go:build linux

// Package lapp 是 Linux 探针的组合根。
//
// 为什么独立成包而不是复用 internal/agent/app：Windows 组合根（app 包）
// 深度耦合 winapi（USN/注册表守护/事件日志/内存巡检等 Windows 专属子系统），
// 整体改造风险不对称——运行中的生产实现不应为移植冒险。Linux 侧复用全部
// 可移植引擎层（detect/state/netwatch/chain/ransom/persist/uplink），
// 只重写"子系统装配"这一层；采集差异由 collect.Source 第三实现（procfs）
// 吸收，检测逻辑零分叉。
//
// 与 Windows 版的能力对照（诚实边界，未在 Linux 实机验证）：
//   - 无 USN 补采（inotify 实时事件覆盖运行期；停机窗口事件 v1 不补）
//   - 注册表守护的等价物：inotify 守护 cron/systemd/ld.so.preload 目录，
//     变更触发持久化即时重扫（与 regwatch 同语义、同防抖参数）
//   - 无内存巡检/事件日志/USB/ETW（RESEARCH-LINUX-AGENT §3 诚实不做）
//   - 落地即执行的 MotW 关联恒 false（Linux 无 Zone.Identifier 等价物）
//   - netwatch 的可信进程放大阈值 v1 不启用（无签名验证，False 会更敏感；
//     误报治理现场用 HG_AGENT_NET_* 阈值覆盖兜底）
//   - 本地面板/实时隧道/资产清单由集成阶段接线（fswatch/liveapi/localapi
//     各自就绪后），见包内 TODO(integration) 接缝。
package lapp

import (
	"context"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"zedr/internal/agent/allow"
	agentapp "zedr/internal/agent/app"
	"zedr/internal/agent/baseline"
	"zedr/internal/agent/chain"
	"zedr/internal/agent/collect"
	"zedr/internal/agent/detect"
	"zedr/internal/agent/drill"
	"zedr/internal/agent/enrich"
	"zedr/internal/agent/fswatch"
	"zedr/internal/agent/inventory"
	"zedr/internal/agent/liveapi"
	"zedr/internal/agent/localapi"
	"zedr/internal/agent/nettypes"
	"zedr/internal/agent/netwatch"
	"zedr/internal/agent/persist"
	"zedr/internal/agent/ransom"
	"zedr/internal/agent/state"
	"zedr/internal/agent/tunnel"
	"zedr/internal/agent/uplink"
	"zedr/internal/model"
	"zedr/internal/platform/idgen"
	"zedr/internal/platform/logx"
)

// Agent 是 Linux 探针组合根。
type Agent struct {
	cfg    *agentapp.Config
	log    *slog.Logger
	store  *state.Store
	coll   *collect.Collector
	enr    *enrich.Enricher
	base   *baseline.Model
	alw    *allow.List
	eng    *detect.Engine
	up     *uplink.Client
	pm     *persist.Monitor
	nw     *netwatch.Watch
	chainE *chain.Engine

	// fwatch 是文件落地监控（inotify）；fileDefense 是勒索防御。
	// 两者生命周期绑定：防御关闭时监控也随之停摆（与 Windows 口径一致）。
	fwatch      *fswatch.Watch
	fileDefense *ransom.Defense

	// persistWatch 是持久化目录实时守护（regwatch 的 Linux 等价物）。
	persistWatch   *fswatch.Watch
	persistRescanC chan struct{}

	// landed 是落地时间索引（fwatch 事件回填，"落地即执行"关联依据）。
	landedMu sync.Mutex
	landed   map[string]time.Time

	// 资产清单：inventoryLoop 赋值；invReady 之后才对可 diff 节做
	// 条目级变更告警（首轮是建基线，不是"全是新增"）。
	// 两个字段只在 inventoryLoop 自己的 goroutine 上读写，无需加锁。
	inv      *inventory.Manager
	invReady bool

	// policyInterval 是服务端策略下发的扫描间隔（纳秒），0=用本地配置
	// （applyServerPolicy 热写入，scanLoop 每轮读取）。
	policyInterval atomic.Int64
	// cpu 是进程 CPU 占用采样器（/proc/self/stat 差分，见 policy_linux.go）。
	cpu cpuSampler

	startedAt time.Time
	scanReq   chan bool
}

// watchDirsLinux 是落地监控的目录集合（Linux 口径）：可执行入口与
// 用户可写落地高发区，与 Windows WatchDirs 的选点思路一致——监控
// "样本最可能出现的位置"，不做全盘。诱饵目录必须并入监控面：canary
// 是"动了就告警"的绊线，放在监控面之外等于不设防（2026-11-14 Kali
// 实机验收踩过：/root/Documents 与 /srv/documents 只种不监，删除无感）。
func watchDirsLinux() []string {
	dirs := append(watchDirsLinuxBase(), canaryDirsLinux()...)
	return dedupDirs(dirs)
}

func watchDirsLinuxBase() []string {
	dirs := []string{"/tmp", "/var/tmp", "/dev/shm", "/usr/local/bin", "/opt"}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		dirs = append(dirs,
			filepath.Join(home, ".local", "bin"),
			filepath.Join(home, "Downloads"),
			filepath.Join(home, "Desktop"))
	}
	dirs = append(dirs, "/root/Downloads", "/root/Desktop")
	return dedupDirs(dirs)
}

// canaryDirsLinux 是诱饵放置目录（Linux 口径）：用户文档区。
// 目录不存在则跳过且不代建（ransom.Options 的契约）。
func canaryDirsLinux() []string {
	var dirs []string
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		dirs = append(dirs,
			filepath.Join(home, "Documents"),
			filepath.Join(home, "Downloads"))
	}
	dirs = append(dirs, "/root/Documents", "/srv/documents")
	return dedupDirs(dirs)
}

// persistWatchDirsLinux 是持久化实时守护的目录集合（regwatch 等价物）。
// 刻意不含 /etc 整树：fswatch 递归挂 watch，/etc 全树会烧掉大量 watch
// 配额（上限 2048）且与子目录重复触发。/etc/crontab 与 /etc/ld.so.preload
// 是单文件（inotify 目录 watch 覆盖不到写入它们的父目录变更场景），
// 由 5min 周期扫描兜底——实时面覆盖 cron.d 与 systemd 两个最高价值的
// 持久化位已足够。
func persistWatchDirsLinux() []string {
	return []string{"/etc/cron.d", "/etc/systemd/system"}
}

func dedupDirs(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, d := range in {
		if d == "" {
			continue
		}
		if _, ok := seen[d]; ok {
			continue
		}
		seen[d] = struct{}{}
		out = append(out, d)
	}
	return out
}

// linuxOSVersion 拼一个可读的系统描述（/etc/os-release + 内核版本）。
func linuxOSVersion() string {
	name := ""
	pretty, err := os.ReadFile("/etc/os-release")
	if err == nil {
		for _, line := range strings.Split(string(pretty), "\n") {
			if v, ok := strings.CutPrefix(line, "PRETTY_NAME="); ok {
				name = strings.Trim(strings.TrimSpace(v), `"`)
				break
			}
		}
	}
	if name == "" {
		name = "linux"
	}
	if rel, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
		name += " " + strings.TrimSpace(string(rel))
	}
	return name + " (" + runtime.GOARCH + ")"
}

// New 装配 Linux 探针（与 Windows 版 New 的装配顺序同构）。
func New(version string) (*Agent, error) {
	cfg, err := agentapp.LoadConfig(version)
	if err != nil {
		return nil, err
	}
	log := logx.New(logx.Options{Level: cfg.LogLevel, Format: cfg.LogFormat})
	log.Info("agent_starting", "version", version, "data_dir", cfg.DataDir,
		"server", cfg.ServerURL, "platform", "linux")

	cfg.LocalToken = loadOrCreateLocalToken(cfg.Path("local.token"), log)

	store := state.New(500)

	// 采集引擎选择的优先级：终端本地显式环境变量 > 服务端策略缓存
	//（policy.json，随规则包下发、签名保护，冷生效）> 本地默认。
	// 与 Windows 版同口径。
	collector := cfg.Collector
	if _, explicit := os.LookupEnv("HG_AGENT_COLLECTOR"); !explicit {
		if pc := readCollectorPolicy(cfg.Path("policy.json")); pc != "" {
			collector = pc
			log.Info("collector_from_server_policy", "collector", pc)
		}
	}
	coll, err := collect.New(collectorName(collector), cfg.FullRescan)
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

	// 自豁免：与 Windows 同口径（安装目录 + 数据目录）
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

	pm := persist.New(cfg.Path("persist-baseline.json"), enr)
	if err := pm.Load(); err != nil {
		log.Warn("persist_baseline_load_failed", "err", err)
	}

	a := &Agent{
		cfg: cfg, log: log, store: store,
		coll: coll, enr: enr, base: base, alw: alw, eng: eng, up: up,
		pm:             pm,
		startedAt:      time.Now(),
		scanReq:        make(chan bool, 1),
		persistRescanC: make(chan struct{}, 1),
		landed:         make(map[string]time.Time, 4096),
	}

	// 网络行为检测：消费 /proc/net/tcp 快照，检测逻辑与 Windows 完全同一份
	if cfg.NetWatch {
		nc := netwatch.Default()
		if cfg.NetScanPorts > 0 {
			nc.PortScanPorts = cfg.NetScanPorts
		}
		if cfg.NetSweepIPs > 0 {
			nc.HostSweepIPs = cfg.NetSweepIPs
		}
		if cfg.NetLateralIPs > 0 {
			nc.LateralIPs = cfg.NetLateralIPs
		}
		if len(cfg.NetLateralPortList) > 0 {
			nc.LateralPorts = cfg.NetLateralPortList
		}
		a.nw = netwatch.New(nc, uint32(os.Getpid()))
	}

	// 攻击链关联引擎：与 Windows 同一引擎（纯内存状态机）
	if cfg.ChainEnabled {
		a.chainE = chain.New(chain.Options{
			OnFinding: a.emitChainFinding,
			Allow:     alw,
		})
	}

	a.loadIOCsCache()

	a.store.SetRuntime(func(ri *state.RuntimeInfo) {
		hn, _ := os.Hostname()
		ri.Hostname = hn
		ri.OSVersion = linuxOSVersion()
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

// collectorName 把配置的采集器名映射到 Linux 支持集（auto/procfs）。
func collectorName(v string) string {
	switch v {
	case collect.SourceProcfs:
		return collect.SourceProcfs
	default:
		return collect.SourceAuto
	}
}

// hostName 是本机主机名（os.Hostname 失败退机器 ID 前缀，不冒充）。
func (a *Agent) hostName() string {
	hn, err := os.Hostname()
	if err != nil || hn == "" {
		return a.machineID()[:8]
	}
	return hn
}

// Run 启动全部循环，阻塞直到 ctx 取消。本地面板/实时隧道/资产清单
// 全部接线（与 Windows Run 同构）。
func (a *Agent) Run(ctx context.Context) error {
	// 本地 API 供本地面板/桌面端使用（体检面接 hygiene Linux 采集器）
	api := localapi.New(localapi.Deps{
		Backend: newLocalBackend(a),
		Log:     a.log,
		Addr:    a.cfg.LocalAddr,
		Token:   a.cfg.LocalToken,
	})
	if err := api.Start(); err != nil {
		return fmt.Errorf("本地 API 启动失败: %w", err)
	}
	defer func() {
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = api.Shutdown(shutCtx)
	}()
	// 文件落地监控必须先于首轮扫描启动（与 Windows 同理：启动瞬间
	// 落地的样本不能被当成"老文件"）。
	if a.cfg.FileWatch {
		fw, err := fswatch.New(watchDirsLinux(), a.log)
		if err != nil {
			a.log.Warn("file_watch_disabled", "err", err)
		} else {
			a.fwatch = fw
			fw.SetOnFileEvent(a.onFileEvent)
			a.log.Info("file_watch_started", "dirs", len(watchDirsLinux()))
		}
	}
	defer func() {
		if a.fwatch != nil {
			_ = a.fwatch.Close()
		}
	}()

	// 文件防御（canary 诱饵 + 勒索速率）：消费 fwatch 事件流
	if a.cfg.FileDefense {
		a.fileDefense = ransom.New(ransom.Options{
			CanaryDirs: canaryDirsLinux(),
			Log:        a.log,
			OnFinding:  a.emitFileDefenseFinding,
		})
		a.fileDefense.Start(ctx)
		defer a.fileDefense.Close()
	}

	// 持久化目录实时守护（regwatch 等价物）：变更 → 防抖 3s → 即时重扫
	if a.cfg.RegWatch {
		if pw, err := fswatch.New(persistWatchDirsLinux(), a.log); err == nil {
			a.persistWatch = pw
			pw.SetOnFileEvent(func(fe nettypes.FileEvent) {
				a.persistRescanReq()
			})
			defer func() { _ = pw.Close() }()
		} else {
			a.log.Warn("persist_dir_watch_disabled", "err", err)
		}
	}

	// 实时隧道（只读调查通道）：零监听、纯出站，服务端经隧道发起只读
	// 查询、探针在流上应答；失败自动退避重连，对端不支持进每小时静默
	// 模式。StartTime 用 a.startedAt（与 /info uptime 同源——不要放进
	// scan 回调：SetRuntime 只有最后一个回调生效，踩过的坑）。
	if a.cfg.TunnelEnabled {
		mgr := tunnel.New(a.log, tunnel.Options{
			ServerURL: a.cfg.ServerURL,
			Creds:     a.up.TunnelCreds,
			Handler: liveapi.New(liveapi.Deps{
				Version:   a.cfg.Version,
				Hostname:  a.hostName(),
				StartTime: a.startedAt,
				Procs:     a.store.Procs,
				// Linux v1 无模块枚举（/proc maps 语义不同，诚实 nil）
				Modules: a.coll.Modules,
				Snapshot: func() []state.ProcRow {
					// procinfo 全量快照做 PID 定位与 netstat join
					return a.store.Procs(2000)
				},
				Runtime: a.store.Runtime,
				Netstat: liveapi.ProcfsNetstat,
			}),
		})
		go mgr.Start(ctx)
		defer mgr.Stop()
	}

	go a.enrollLoop(ctx)
	go a.scanLoop(ctx)
	go a.heartbeatLoop(ctx)
	go a.flushLoop(ctx)
	go a.persistLoop(ctx)
	go a.persistScanLoop(ctx)
	go a.persistRescanLoop(ctx)
	go a.inventoryLoop(ctx)

	<-ctx.Done()
	a.log.Info("agent_stopping", "pending_alerts", a.up.Pending())

	// 优雅停机：退出前把队列里剩余的告警尽量送出去（8s 预算，与
	// Windows 同口径——最新一批告警恰恰最可能对应"正在发生"的事）。
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

// ---------------------------------------------------------------- 文件事件

// onFileEvent 是落地监控的统一入口：落地索引（"落地即执行"关联依据）
// 与勒索防御共用同一条事件流（与 Windows RDCW→fileDefense 同构）。
func (a *Agent) onFileEvent(fe nettypes.FileEvent) {
	if fe.Kind == "added" || fe.Kind == "renamed" {
		a.landedMu.Lock()
		a.landed[fe.Path] = fe.When
		// 索引只服务 15 分钟窗口的关联；超量粗淘汰（丢哪条都行，
		// 只是关联窗口变短）
		if len(a.landed) > 8192 {
			for k := range a.landed {
				delete(a.landed, k)
				if len(a.landed) <= 6144 {
					break
				}
			}
		}
		a.landedMu.Unlock()
	}
	if a.fileDefense != nil {
		a.fileDefense.Consume(ransom.Event{
			Kind: fe.Kind, Path: fe.Path, OldPath: fe.OldPath,
			When: fe.When, Source: "inotify",
		})
	}
}

// landedAt 查询镜像文件的落地时间（15 分钟窗口，与 Windows 同口径）。
func (a *Agent) landedAt(path string) time.Time {
	if path == "" {
		return time.Time{}
	}
	a.landedMu.Lock()
	defer a.landedMu.Unlock()
	if d, ok := a.landed[path]; ok && time.Since(d) <= 15*time.Minute {
		return d
	}
	return time.Time{}
}

// ---------------------------------------------------------------- 扫描与检测

func (a *Agent) scanLoop(ctx context.Context) {
	interval := a.baseInterval()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	a.scan(true) // 首轮全量建基线

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			a.scan(false)

			// 服务端策略热更新检查：间隔变了就重置节拍（与 Windows 版
			// 同语义；自适应退避 Linux v1 未启用，见包注释诚实边界）。
			if cur := a.baseInterval(); cur != interval {
				interval = cur
				ticker.Reset(interval)
				a.store.SetRuntime(func(ri *state.RuntimeInfo) { ri.ScanInterval = interval.String() })
			}
		case <-a.scanReq:
			a.scan(true)
			interval = a.baseInterval()
			ticker.Reset(interval)
		}
	}
}

// scan 执行一轮采集 + 检测。判定链路与 Windows 版逐行同构：
// procfs 快照 → 引擎 Analyze → 统一告警出口；网络行为与攻击链消费
// 同一轮连接表。
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

	// 网络行为检测：只消费本轮快照（连接表已随轮拉取，零新增系统调用）
	if a.nw != nil {
		a.netObserve(snap)
	}
	// 攻击链外联阶段：同上，只消费本轮连接表
	if a.chainE != nil {
		a.chainObserveConns(snap)
	}

	selfPID := uint32(os.Getpid())
	for _, pi := range newProcs {
		if pi.PID == selfPID {
			continue // 不检测自己
		}
		ancestry, parentAlive := a.coll.Ancestry(snap, pi.PID)
		conns := a.coll.ConnectionsOf(snap, pi.PID)
		// Linux v1 不做模块枚举（/proc maps 是内存映射不是装载模块，
		// 语义不同不硬凑）——Modules 恒空，引擎按无模块证据判定。

		in := detect.Input{
			Proc: detect.ProcessInfo{
				PID: pi.PID, PPID: pi.PPID, Name: pi.Name, Path: pi.Path,
				CmdLine: pi.CmdLine, User: pi.User, SessionID: pi.SessionID,
				Elevated: pi.Elevated, StartTime: pi.StartTime,
			},
			Ancestry:    ancestry,
			ParentAlive: parentAlive,
			Connections: conns,
			LandedAt:    a.landedAt(pi.Path),
			// LandedFromWeb：Linux 无 Zone.Identifier 等价物，恒 false
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

		a.store.UpsertProc(pi, res, len(conns), 0)

		// 攻击链馈送：进程创建阶段（被抑制的结果也要喂——链消费
		// "实体+时序"事实，与 Windows 同口径）
		if a.chainE != nil {
			a.chainFeedProc(pi, res)
		}

		if res != nil && res.Alert {
			a.emit(pi, res)
		}
	}

	a.store.Reap(alive)

	if elapsed := time.Since(start); elapsed > a.cfg.ScanInterval*3 {
		a.log.Warn("scan_slow", "elapsed_ms", elapsed.Milliseconds(),
			"interval_ms", a.cfg.ScanInterval.Milliseconds(), "new_procs", len(newProcs))
	}

	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)
	cpu := a.cpu.sample()
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
		ri.IOCCount = a.eng.IOCCount()
		ri.UptimeSec = int64(time.Since(a.startedAt).Seconds())
		ri.PersistCount = a.pm.Size()
		if a.fwatch != nil {
			ri.FileWatch = true
		}
		if a.nw != nil {
			ns := a.nw.Stats()
			ri.NetWatchEvents = ns.EventsSeen
			ri.NetWatchAlerts = ns.AlertsFired
			ri.NetWatchTracked = ns.TrackedProcs
			ri.NetWatchDropped = ns.Dropped
		}
		if a.fileDefense != nil {
			ri.CanaryRebuilt = a.fileDefense.Rebuilt()
			ri.FileDefDropped = a.fileDefense.Dropped()
		}
		if a.chainE != nil {
			cs := a.chainE.Stats()
			ri.ChainEnabled = true
			ri.ChainActive = cs.Active
			ri.ChainFired = cs.Fired
		}
		if obs, ok := a.eng.ObserveSnapshot(); ok {
			ri.RuleObserved = obs
		}
	})
	return len(newProcs)
}

// netObserve 消费一轮采集快照，驱动网络行为检测并把命中转为告警
// （与 Windows 版 netObserve 逐行同构）。
func (a *Agent) netObserve(snap *collect.Snapshot) {
	now := time.Now()

	// 只为"本轮有连接"的进程构造标识（netwatch 只评估有连接的进程）；
	// 启动时间来自采集器最完整口径，用于 PID 复用清窗。
	procs := make(map[uint32]netwatch.ProcIdent, len(snap.Conns))
	for pid := range snap.Conns {
		if pid == uint32(os.Getpid()) {
			continue // 探针自身到服务端的上报连接是常态，不参与检测
		}
		name, start := a.coll.IdentOf(snap, pid)
		ppid := uint32(0)
		if p, ok := snap.Procs[pid]; ok {
			ppid = p.PPID
		}
		procs[pid] = netwatch.ProcIdent{
			PID: pid, PPID: ppid, Name: name, StartTime: start,
			// Linux v1 无签名验证，可信放大不启用（见包注释诚实边界）
			Trusted: false,
		}
	}

	findings := a.nw.Observe(netwatch.Tick{
		TakenAt: now,
		Conns:   snap.Conns,
		Procs:   procs,
	})
	if len(findings) == 0 {
		return
	}
	// 冷启动静默期与进程检测引擎同口径：窗口数据刚建立不久，
	// "第一分钟的扇出"既不完整也不可信，宁可漏这一窗。
	if a.eng.IsWarmup(now) {
		a.log.Debug("netwatch_warmup_suppressed", "findings", len(findings))
		return
	}
	for _, f := range findings {
		a.emitNetFinding(f, snap)
	}
}

// emitNetFinding 单条行为告警：白名单 → 富化 → 组装统一信封（与
// Windows 版 emitNetFinding 同构；进程用户从 /proc 现场解析）。
func (a *Agent) emitNetFinding(f netwatch.Finding, snap *collect.Snapshot) {
	path := f.Ident.Path

	var meta enrich.Meta
	if path != "" {
		meta = a.enr.Describe(path)
	}

	// 白名单优先：运维明确信任的镜像不产生行为告警
	if hit, _ := a.alw.Match(meta.Hash, path, meta.Signer, "", f.Ident.Name, ""); hit {
		a.log.Debug("netwatch_whitelisted", "pid", f.Ident.PID, "rule", f.RuleID)
		return
	}

	// 指纹先算：链阶段的来源回指与告警本体必须同值
	bucket := time.Now().Truncate(15 * time.Minute).Unix()
	fp := fmt.Sprintf("nw:%s:%d:%d:%d",
		f.RuleID, f.Ident.PID, f.Ident.StartTime.Unix(), bucket)

	// 攻击链馈送：NW 命中作为链的外联证据（DROP-EXEC-C2 的第二环）。
	// 对端样例从同轮快照补齐。
	if a.chainE != nil {
		ip, port := chainSamplePeer(snap.Conns[f.Ident.PID])
		a.chainE.Feed(chain.Stage{
			Kind: chain.KindNet, When: time.Now(),
			PID: f.Ident.PID, StartTime: f.Ident.StartTime,
			Name: f.Ident.Name, Path: path,
			Hash: meta.Hash, Signed: meta.Signed,
			PeerIP: ip, PeerPort: uint32(port),
			RefRuleID: f.RuleID, RefScore: f.Score, RefFingerprint: fp,
			MITRE: chainFirstMITRE(f.MITRE), Note: f.Summary,
		})
	}

	procUser := procUserLinux(f.Ident.PID)

	evidence := model.Evidence{
		Process: model.ProcEvidence{
			PID: f.Ident.PID, PPID: f.Ident.PPID, Name: f.Ident.Name, Path: path,
			User:       procUser,
			StartTime:  f.Ident.StartTime,
			HashSHA256: meta.Hash, Signer: meta.Signer,
			Signed: meta.Signed, SignatureOK: meta.SignatureOK,
		},
		Signals: []model.Signal{{
			Layer: "netwatch", ID: f.RuleID, Name: "网络行为检测",
			Score: f.Score, Note: f.Summary, MITRE: strings.Join(f.MITRE, ","),
		}},
		Notes: f.Notes,
	}
	// 网络证据：该进程当前连接（钳制 20 条，防超大连接表撑爆告警体）
	if conns := snap.Conns[f.Ident.PID]; len(conns) > 0 {
		nc := make([]model.NetConn, 0, 20)
		for _, c := range conns {
			if len(nc) >= 20 {
				break
			}
			nc = append(nc, model.NetConn{
				Proto: c.Proto, LocalIP: c.LocalIP, LocalPort: uint32(c.LocalPort),
				RemoteIP: c.RemoteIP, RemotePort: uint32(c.RemotePort), State: c.State,
			})
		}
		evidence.Network = nc
	}

	// 指纹带 15 分钟桶：持续扫描按桶重复送达（证据会更新），
	// 同一桶内的重复命中交给服务端指纹去重吸收
	a.emitAlert(model.AlertEnvelope{
		Fingerprint: fp,
		Title:       f.Title,
		Summary:     f.Summary,
		Verdict:     f.Verdict,
		Severity:    f.Severity,
		Score:       f.Score,
		PID:         f.Ident.PID,
		ProcessName: f.Ident.Name,
		ImagePath:   path,
		ProcUser:    procUser,
		RuleIDs:     []string{f.RuleID},
		MITRE:       f.MITRE,
		Evidence:    evidence,
		OccurredAt:  time.Now(),
	})
}

// ---------------------------------------------------------------- 攻击链馈送

// chainFeedProc 进程创建阶段馈送（与 Windows 版 chainFeedProc 同构：
// 完整身份 + DROP-001 判定 + 白名单豁免）。
func (a *Agent) chainFeedProc(pi collect.ProcessInfo, res *detect.Result) {
	if a.chainE == nil || res == nil || res.Suppressed == "whitelist" {
		return
	}
	dropped := false
	for _, sg := range res.Evidence.Signals {
		if sg.ID == "DROP-001" {
			dropped = true
			break
		}
	}
	a.chainE.Feed(chain.Stage{
		Kind: chain.KindProc, When: time.Now(),
		PID: pi.PID, StartTime: pi.StartTime,
		Name: pi.Name, Path: pi.Path, CmdLine: pi.CmdLine, User: pi.User,
		Hash:    res.Evidence.Process.HashSHA256,
		Signer:  res.Evidence.Process.Signer,
		Signed:  res.Evidence.Process.Signed,
		Dropped: dropped,
	})
}

// chainObserveConns 外联阶段馈送（与 Windows 版同构：自进程跳过，
// key 是 O(1) 丢弃不需要预筛）。
func (a *Agent) chainObserveConns(snap *collect.Snapshot) {
	if a.chainE == nil {
		return
	}
	now := time.Now()
	self := uint32(os.Getpid())
	for pid, conns := range snap.Conns {
		if pid == self {
			continue
		}
		ip, port, ok := chainFirstOutbound(conns)
		if !ok {
			continue
		}
		name, start := a.coll.IdentOf(snap, pid)
		a.chainE.Feed(chain.Stage{
			Kind: chain.KindConn, When: now,
			PID: pid, StartTime: start, Name: name,
			PeerIP: ip, PeerPort: uint32(port),
		})
	}
}

// chainFirstOutbound 取连接表里第一条非回环外联对端。SYN_SENT 也算——
// 被丢弃的扫描与被墙的 C2 都到不了 ESTABLISHED，尝试本身就是行为证据。
func chainFirstOutbound(conns []nettypes.TCPConn) (string, uint16, bool) {
	for _, c := range conns {
		if c.State == "LISTEN" {
			continue
		}
		if c.RemoteIP == "" || !isChainOutboundIP(c.RemoteIP) {
			continue
		}
		return c.RemoteIP, c.RemotePort, true
	}
	return "", 0, false
}

// isChainOutboundIP 过滤非外联地址（未指定/回环）。
func isChainOutboundIP(ip string) bool {
	if ip == "0.0.0.0" || ip == "::" || ip == "::1" {
		return false
	}
	return !strings.HasPrefix(ip, "127.")
}

// chainSamplePeer 为 net 阶段取对端样例。
func chainSamplePeer(conns []nettypes.TCPConn) (string, uint16) {
	ip, port, ok := chainFirstOutbound(conns)
	if !ok {
		return "", 0
	}
	return ip, port
}

func chainFirstMITRE(m []string) string {
	if len(m) > 0 {
		return m[0]
	}
	return ""
}

// ---------------------------------------------------------------- 告警出口

// emitAlert 是所有告警的统一出口（本地存储 + 上报队列 + 结构化日志）。
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

// emitChainFinding 把攻击链发现转成告警（阶段回指来源告警指纹，与
// Windows 版同构——服务端事件叙事/AI 研判靠它对账）。
func (a *Agent) emitChainFinding(f chain.Finding) {
	env := model.AlertEnvelope{
		Fingerprint: fmt.Sprintf("chain:%s:%x:%d", f.RuleID, chainKeyHash(f.Key), f.Started.Unix()),
		Title:       f.Title,
		Summary:     f.Summary,
		Verdict:     f.Verdict,
		Severity:    f.Severity,
		Score:       f.Score,
		RuleIDs:     []string{f.RuleID},
		MITRE:       f.MITRE,
		ProcUser:    "SYSTEM/CHAIN",
		OccurredAt:  time.Now(),
	}
	if f.Root != nil {
		env.PID = f.Root.PID
		env.ProcessName = f.Root.Name
		env.ImagePath = f.Root.Path
		env.CmdLine = f.Root.CmdLine
		env.HashSHA256 = f.Root.Hash
		env.Signer = f.Root.Signer
		env.Signed = f.Root.Signed
		if f.Root.User != "" {
			env.ProcUser = f.Root.User
		}
	}
	sigs := make([]model.Signal, 0, len(f.Stages))
	notes := []string{
		"chain_rule=" + f.RuleID,
		"chain_key=" + f.Key,
		"chain_started=" + f.Started.Format(time.RFC3339),
		"confidence=high（全确定性环节）",
	}
	for i, st := range f.Stages {
		line := ""
		if i < len(f.Lines) {
			line = f.Lines[i]
		}
		sigs = append(sigs, model.Signal{
			Layer: "chain",
			ID:    fmt.Sprintf("%s#%d", f.RuleID, i+1),
			Name:  chain.KindLabel(st.Kind),
			Score: st.RefScore,
			Note:  line,
			MITRE: st.MITRE,
		})
		notes = append(notes, line)
		if st.RefFingerprint != "" {
			notes = append(notes, fmt.Sprintf("stage%d_ref=%s %s",
				i+1, st.RefRuleID, st.RefFingerprint))
		}
	}
	env.Evidence = model.Evidence{Signals: sigs, Notes: notes}
	if f.Root != nil {
		env.Evidence.Process = model.ProcEvidence{
			PID: f.Root.PID, Name: f.Root.Name, Path: f.Root.Path,
			CmdLine: f.Root.CmdLine, User: f.Root.User, StartTime: f.Root.StartTime,
			HashSHA256: f.Root.Hash, Signer: f.Root.Signer, Signed: f.Root.Signed,
		}
	}
	a.emitAlert(env)
}

// chainKeyHash 把链 key 压成短哈希（key 可能含完整路径，指纹不携带原文）。
func chainKeyHash(key string) uint64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(key))
	return h.Sum64()
}

// emitFileDefenseFinding 把勒索防御发现转成统一告警（指纹带路径锚，
// 与 Windows 同构——同目录反复触发时指纹相同，服务端按指纹去重）。
func (a *Agent) emitFileDefenseFinding(f ransom.Finding) {
	fp := f.RuleID
	for _, n := range f.Notes {
		for _, prefix := range []string{"path=", "dir="} {
			if v, ok := strings.CutPrefix(n, prefix); ok && v != "" {
				fp += ":" + strings.ToLower(v)
				break
			}
		}
		if fp != f.RuleID {
			break
		}
	}
	a.emitAlert(model.AlertEnvelope{
		Fingerprint: fp,
		Title:       f.Title,
		Summary:     f.Summary,
		Verdict:     f.Verdict,
		Severity:    f.Severity,
		Score:       f.Score,
		ProcUser:    "SYSTEM/FILE-DEFENSE",
		RuleIDs:     []string{f.RuleID},
		MITRE:       f.MITRE,
		Evidence: model.Evidence{
			Signals: []model.Signal{{
				Layer: "filedefense", ID: f.RuleID, Name: f.Title,
				Score: f.Score, MITRE: strings.Join(f.MITRE, ","),
			}},
			Notes: f.Notes,
		},
		OccurredAt: time.Now(),
	})
}

// ---------------------------------------------------------------- 持久化

// persistScanLoop 周期性全量扫描持久化项并与基线 diff。
func (a *Agent) persistScanLoop(ctx context.Context) {
	ticker := time.NewTicker(a.cfg.PersistCheck)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			a.persistScanOnce()
		}
	}
}

// persistRescanReq 持久化目录实时守护的防抖重扫请求（regwatch 等价物）。
func (a *Agent) persistRescanReq() {
	select {
	case a.persistRescanC <- struct{}{}:
	default:
	}
}

// persistRescanLoop 消费防抖请求：连续写多个文件的批量变更只重扫一次。
func (a *Agent) persistRescanLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-a.persistRescanC:
			// 防抖 3s（与 Windows regwatch 同参数）
			time.Sleep(3 * time.Second)
			a.persistScanOnce()
		}
	}
}

// persistScanOnce 执行一轮持久化扫描并把越阈值项转成统一告警。
func (a *Agent) persistScanOnce() {
	res, err := a.pm.Scan()
	if err != nil {
		a.log.Warn("persist_scan_failed", "err", err)
		return
	}
	if res.Initial {
		a.log.Info("persist_baseline_built", "items", res.Total)
		return
	}
	hn, _ := os.Hostname()
	for i := range res.Added {
		if res.Added[i].Score >= 38 {
			a.emitAlert(res.Added[i].ToAlert(hn))
		}
	}
	for i := range res.Changed {
		if res.Changed[i].Score >= 38 {
			a.emitAlert(res.Changed[i].ToAlert(hn))
		}
	}
	if len(res.Added)+len(res.Changed) > 0 {
		a.log.Info("persist_changes", "added", len(res.Added), "changed", len(res.Changed),
			"removed", len(res.Removed), "errors", len(res.Errs))
	}
}

// ---------------------------------------------------------------- 心跳/指令/规则

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
				Hostname:   ri.Hostname,
				Version:    a.cfg.Version,
				ProcCount:  ri.ProcCount,
				CPUPercent: ri.CPUPercent,
				MemMB:      ri.MemMB,
				UptimeSec:  int64(time.Since(a.startedAt).Seconds()),
				// 上报终端实际应用的版本（0 = 尚未成功拉取）
				RuleVersion: a.up.RuleVersion(),
				Detector: model.DetectorStats{
					EventsScanned: ri.Stats.Scanned,
					AlertsFired:   ri.Stats.Fired,
					Suppressed:    ri.Stats.Suppressed,
					Whitelisted:   ri.Stats.Whitelisted,
					AvgLatencyMs:  ri.Stats.AvgLatencyMs,
				},
				Samples:      ri.Stats.Scanned,
				QueueDropped: a.up.Dropped(),
			}
			if obs, ok := a.eng.ObserveSnapshot(); ok {
				req.RuleObserved = obs
			}
			if ih, ok := a.eng.IntelHitsSnapshot(); ok {
				req.IocHits = ih
			}
			if ah, ok := a.alw.EntryHitsSnapshot(); ok {
				req.AllowHits = ah
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

// handleCommands 执行服务端下发的指令（Linux 支持集：只读类 + 演练；
// terminate/quarantine/self_upgrade 属处置与换装类，v1 未接线——
// 诚实不支持，回执写明边界）。
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
		case "collect":
			res.Result = fmt.Sprintf("进程 %d 个", a.store.Runtime().ProcCount)
		case "drill":
			res = a.handleDrill(ctx, c)
		case "terminate", "quarantine_file", "quarantine_restore", "self_upgrade":
			res.Status = "failed"
			res.Result = "Linux 探针暂不支持该指令（v1 诚实边界，见 RESEARCH-LINUX-AGENT §3）"
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

// handleDrill 处理检测演练指令（与 Windows 版 handleDrill 同构：终端
// 闸门 + payload 校验 + Deps 注入，报告 JSON 随回执回传）。
func (a *Agent) handleDrill(ctx context.Context, c model.Command) model.CommandResult {
	res := model.CommandResult{CommandID: c.ID}
	if !a.cfg.DrillEnabled {
		res.Status = "failed"
		res.Result = "终端未启用检测演练（HG_AGENT_DRILL_ENABLED=false）"
		return res
	}
	steps, err := drill.ParsePayload(c.Payload)
	if err != nil {
		res.Status = "failed"
		res.Result = err.Error()
		return res
	}
	deps := drill.Deps{
		AlertsSince: func(t time.Time) []drill.AlertView {
			all := a.store.Alerts(512)
			out := make([]drill.AlertView, 0, len(all))
			for _, al := range all {
				if al.OccurredAt.Before(t) {
					continue
				}
				out = append(out, drill.AlertView{ID: al.ID, RuleIDs: al.RuleIDs, OccurredAt: al.OccurredAt})
			}
			return out
		},
		ProcSnapshot: func() []drill.ProcView {
			rows := a.store.Procs(1024)
			out := make([]drill.ProcView, 0, len(rows))
			for _, r := range rows {
				out = append(out, drill.ProcView{PID: r.PID, Name: r.Name})
			}
			return out
		},
		CanaryFile: func() string {
			if a.fileDefense == nil {
				return ""
			}
			return a.fileDefense.OneCanaryPath()
		},
		// Linux v1 无事件日志层（E1），service_event 步骤本就 skip
		EvtLogEnabled:   false,
		NetWatchEnabled: a.cfg.NetWatch,
		Log:             a.log,
		SelfPID:         uint32(os.Getpid()),
	}
	report := drill.BuildReport(drill.Run(ctx, steps, deps))
	res.Result = drill.MarshalReport(report)
	return res
}

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
		hn, _ := os.Hostname()
		req := model.EnrollRequest{
			EnrollToken: a.cfg.EnrollToken,
			MachineID:   machineID,
			Hostname:    hn,
			OSVersion:   linuxOSVersion(),
			Arch:        runtime.GOARCH,
			Username:    currentUserLinux(),
			Version:     a.cfg.Version,
			Tags:        a.cfg.Tags,
		}
		cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
		resp, err := a.up.Enroll(cctx, req)
		cancel()
		if err != nil {
			a.log.Warn("enroll_failed", "err", err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(15 * time.Second):
			}
			continue
		}
		a.store.SetRuntime(func(ri *state.RuntimeInfo) {
			ri.AgentID = resp.AgentID
			ri.Enrolled = true
		})
		a.log.Info("enrolled", "agent_id", resp.AgentID)
		a.syncRules(ctx, true)
		a.syncIOCs(ctx, true)
		return
	}
}

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

// currentUserLinux 从 /proc/self/status 读 uid 并投影到 /etc/passwd 用户名。
// 解析失败退化为 uid 数字串（诚实降级）。
func currentUserLinux() string {
	uid := ""
	if data, err := os.ReadFile("/proc/self/status"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if rest, ok := strings.CutPrefix(line, "Uid:"); ok {
				f := strings.Fields(rest)
				if len(f) > 0 {
					uid = f[0]
				}
				break
			}
		}
	}
	if pw, err := os.ReadFile("/etc/passwd"); err == nil {
		for _, line := range strings.Split(string(pw), "\n") {
			f := strings.Split(line, ":")
			if len(f) >= 3 && f[2] == uid {
				return f[0]
			}
		}
	}
	return "uid:" + uid
}

// procUserLinux 现场解析某进程的运行用户（行为告警的证据面与进程告警
// 对齐——"谁在跑"；解析失败留空，不冒充 root）。
func procUserLinux(pid uint32) string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return ""
	}
	uid := ""
	for _, line := range strings.Split(string(data), "\n") {
		if rest, ok := strings.CutPrefix(line, "Uid:"); ok {
			f := strings.Fields(rest)
			if len(f) > 0 {
				uid = f[0]
			}
			break
		}
	}
	if uid == "" {
		return ""
	}
	if pw, err := os.ReadFile("/etc/passwd"); err == nil {
		for _, line := range strings.Split(string(pw), "\n") {
			f := strings.Split(line, ":")
			if len(f) >= 3 && f[2] == uid {
				return f[0]
			}
		}
	}
	return "uid:" + uid
}

// syncRules 拉取规则整包并热加载（与 Windows 版逐行同构）。
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
	if bundle == nil {
		return
	}
	ok, bad := a.eng.SetRules(bundle.Rules)
	entries := make([]allow.Entry, 0, len(bundle.Allowlist))
	for _, e := range bundle.Allowlist {
		entries = append(entries, allow.Entry{Type: e.Type, Value: e.Value, Source: "server"})
	}
	a.alw.ReplaceServer(entries)
	a.eng.SetIntel(bundle.Intel)
	// 加白即回收（链侧）：服务端下发白名单时同样回收含该实体的进行中链
	a.purgeChainsOnAllowlist()
	// 服务端运行策略（扫描间隔热生效 / 采集器冷生效缓存）
	a.applyServerPolicy(bundle.AgentPolicy)

	a.store.SetRuntime(func(ri *state.RuntimeInfo) {
		ri.RuleCount = ok
		ri.RuleVersion = bundle.Version
		ri.Whitelist = a.alw.Size()
	})
	a.log.Info("rules_applied", "version", bundle.Version, "rules", ok, "allow", len(entries),
		"intel", len(bundle.Intel), "bad", len(bad))
}

// syncIOCs 拉取威胁指标整包并热加载。
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
	if bundle == nil {
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

func (a *Agent) saveIOCsCache(bundle *model.IOCBundle) {
	type cache struct {
		Version int               `json:"version"`
		SavedAt time.Time         `json:"saved_at"`
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

func (a *Agent) loadIOCsCache() {
	raw, err := os.ReadFile(a.cfg.Path("iocs.json"))
	if err != nil {
		return
	}
	var c struct {
		IOCs map[string]string `json:"iocs"`
	}
	if err := json.Unmarshal(raw, &c); err != nil {
		return
	}
	a.eng.SetIOCs(c.IOCs)
	a.log.Info("iocs_cache_restored", "count", len(c.IOCs))
}

// flushLoop 周期性把告警队列冲到服务端。
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

// persistLoop 周期性落盘基线并周期同步规则。
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
			if a.up.Enrolled() {
				a.syncRules(ctx, false)
				a.syncIOCs(ctx, false)
			}
		}
	}
}

// loadOrCreateLocalToken 读取或生成本地接口访问令牌（与 Windows 同口径）。
func loadOrCreateLocalToken(path string, log *slog.Logger) string {
	if raw, err := os.ReadFile(path); err == nil {
		if t := strings.TrimSpace(string(raw)); t != "" {
			return t
		}
	}
	t := idgen.Hex(24)
	if err := os.WriteFile(path, []byte(t), 0o600); err != nil {
		log.Warn("local_token_write_failed", "err", err)
		return ""
	}
	log.Info("local_token_created", "path", path)
	return t
}

// purgeChainsOnAllowlist 是加白即回收的链侧动作（本地加白入口共用；
// 服务端下发白名单的回收在 syncRules 接线时对齐 Windows 版）。
// 失败静默——回收是降噪动作，不该让加白操作本身失败。
func (a *Agent) purgeChainsOnAllowlist() {
	if a.chainE == nil {
		return
	}
	if n := a.chainE.PurgeAllowlisted(); n > 0 {
		a.log.Info("chain_purged_on_allowlist", "machines", n)
	}
}
