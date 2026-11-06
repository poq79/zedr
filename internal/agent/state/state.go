// Package state 维护探针的内存视图，供本地 API / 桌面 UI 查询。
//
// 与业务逻辑分离：本包只做"存取"，不做判定；写入方是 app 的采集循环。
package state

import (
	"sort"
	"sync"
	"time"

	"zedr/internal/agent/collect"
	"zedr/internal/agent/detect"
	"zedr/internal/model"
)

// ProcRow 是本地 UI 展示用的进程行。
type ProcRow struct {
	PID       uint32    `json:"pid"`
	PPID      uint32    `json:"ppid"`
	Name      string    `json:"name"`
	Path      string    `json:"path"`
	CmdLine   string    `json:"cmdline"`
	User      string    `json:"user"`
	Score     int       `json:"score"`
	Verdict   string    `json:"verdict"`
	Severity  string    `json:"severity"`
	Title     string    `json:"title"`
	FirstSeen time.Time `json:"first_seen"`
	ConnCount int       `json:"conn_count"`
	Modules   int       `json:"modules"`
	// Suppressed 说明该进程为何没有成为告警（whitelist/warmup/duplicate/below_threshold）
	Suppressed string `json:"suppressed,omitempty"`
}

// Alert 是本地告警记录（服务端会再分配全局 ID）。
type Alert struct {
	ID          string         `json:"id"`
	Title       string         `json:"title"`
	Summary     string         `json:"summary"`
	Verdict     string         `json:"verdict"`
	Severity    string         `json:"severity"`
	Score       int            `json:"score"`
	PID         uint32         `json:"pid"`
	PPID        uint32         `json:"ppid"`
	ProcessName string         `json:"process_name"`
	ImagePath   string         `json:"image_path"`
	CmdLine     string         `json:"cmdline"`
	User        string         `json:"user"`
	Hash        string         `json:"hash_sha256"`
	Signer      string         `json:"signer"`
	Signed      bool           `json:"signed"`
	RuleIDs     []string       `json:"rule_ids"`
	MITRE       []string       `json:"mitre"`
	Evidence    model.Evidence `json:"evidence"`
	OccurredAt  time.Time      `json:"occurred_at"`
	Sent        bool           `json:"sent"`
}

// RuntimeInfo 是探针自身运行状态。
type RuntimeInfo struct {
	Hostname      string    `json:"hostname"`
	OSVersion     string    `json:"os_version"`
	AgentVersion  string    `json:"agent_version"`
	AgentID       string    `json:"agent_id"`
	Enrolled      bool      `json:"enrolled"`
	ServerURL     string    `json:"server_url"`
	Online        bool      `json:"online"`
	LastHeartbeat time.Time `json:"last_heartbeat"`
	UptimeSec     int64     `json:"uptime_sec"`
	ProcCount     int       `json:"proc_count"`
	CPUPercent    float64   `json:"cpu_percent"`
	MemMB         float64   `json:"mem_mb"`
	RuleCount     int       `json:"rule_count"`
	// RuleVersion 是终端实际应用的规则包版本（0=尚未成功拉取）。
	// 与心跳上报同源，本地 UI 和服务端看到的是同一个事实。
	RuleVersion   int            `json:"rule_version"`
	BaselineSize  int64          `json:"baseline_size"`
	PendingAlerts int            `json:"pending_alerts"`
	DroppedAlerts int64          `json:"dropped_alerts"`
	ScanInterval  string         `json:"scan_interval"`
	Collector     string         `json:"collector"`
	LastScanAt    time.Time      `json:"last_scan_at"`
	Warmup        bool           `json:"warmup"`
	WarmupUntil   time.Time      `json:"warmup_until"`
	Stats         detect.Stats   `json:"stats"`
	Whitelist     map[string]int `json:"whitelist"`

	// 行为采集层状态：文件落地监控与持久化项监控。
	FileWatch    bool  `json:"file_watch"`
	WatchedDirs  int   `json:"watched_dirs"`
	DropEvents   int64 `json:"drop_events"`
	PersistCount int   `json:"persist_count"`

	// 行为检测器健康度（v0.9.10 深化）：计数全部来自各检测器的诚实
	// 计数器——运维/面板据此判断"检测器活着吗、有没有在丢数据"，
	// 而不是只能翻日志。
	// NetWatch* 是网络行为检测的事件/告警/内存护栏计数；
	// FileWatchOverflow>0 说明 RDCW 缓冲溢出丢过整批（事件有空洞）；
	// USNPollLagging 表示 USN 卷产量超过追赶预算（事件将滞后）；
	// CanaryRebuilt/FileDefDropped 是诱饵重建与防御窗口丢弃计数；
	// EvtLogChannels 是事件日志接入的活跃通道数（0=未启用/全降级）。
	NetWatchEvents    int64 `json:"netwatch_events"`
	NetWatchAlerts    int64 `json:"netwatch_alerts"`
	NetWatchTracked   int   `json:"netwatch_tracked"`
	NetWatchDropped   int64 `json:"netwatch_dropped"`
	FileWatchOverflow int64 `json:"filewatch_overflow"`
	USNPollLagging    bool  `json:"usn_poll_lagging"`
	CanaryRebuilt     int64 `json:"canary_rebuilt"`
	FileDefDropped    int64 `json:"filedef_dropped"`
	EvtLogChannels    int   `json:"evtlog_channels"`
	UsbVolumes        int   `json:"usb_volumes"`
	// MemWatch* 是内存威胁巡检的轮次计数（0=未启用或尚无轮次）
	MemWatchScans int64 `json:"memwatch_scans"`
	MemWatchHits  int64 `json:"memwatch_hits"`

	// 攻击链关联引擎（CHAIN-*）：Enabled=false 表示开关关闭或引擎未装配；
	// Active 是当前 pending 的链数（正常个位数，持续高位说明有行为在
	// 反复触发链首）；Fired 是累计完成的链数。
	ChainEnabled bool  `json:"chain_enabled"`
	ChainActive  int   `json:"chain_active"`
	ChainFired   int64 `json:"chain_fired"`

	// 下发数据的落地情况：IOC 表与资产清单是否真的在本探针生效。
	// 没有这两项，"服务端下发了"和"终端在用"之间隔着一次静默失败
	// （验签拒绝/版本回退都发生在终端侧），排障时只能翻日志。
	IOCCount          int `json:"ioc_count"`
	InventorySections int `json:"inventory_sections"`

	// 观察模式命中计数（规则 ID → 本次运行期累计，重启清零）。
	// 仅当当前规则包里存在 observe 规则时非 nil——nil 与空 map 是
	// 两个不同语义（无观察规则 vs 有观察规则但还没命中）。
	RuleObserved map[string]int64 `json:"rule_observed,omitempty"`
}

// Store 是线程安全的内存视图。
type Store struct {
	mu       sync.RWMutex
	procs    map[uint32]*ProcRow
	alerts   []*Alert // 新的在前
	maxAlert int
	info     RuntimeInfo
}

// New 创建 Store。
func New(maxAlerts int) *Store {
	if maxAlerts <= 0 {
		maxAlerts = 500
	}
	return &Store{
		procs:    make(map[uint32]*ProcRow, 512),
		alerts:   make([]*Alert, 0, 128),
		maxAlert: maxAlerts,
		info:     RuntimeInfo{Whitelist: map[string]int{}},
	}
}

// SetRuntime 更新运行状态字段。
func (s *Store) SetRuntime(fn func(*RuntimeInfo)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fn(&s.info)
}

// Runtime 返回运行状态副本。
func (s *Store) Runtime() RuntimeInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()
	cp := s.info
	cp.Whitelist = make(map[string]int, len(s.info.Whitelist))
	for k, v := range s.info.Whitelist {
		cp.Whitelist[k] = v
	}
	return cp
}

// UpsertProc 记录/更新一个进程行。
func (s *Store) UpsertProc(pi collect.ProcessInfo, res *detect.Result, connCount, modules int) {
	s.mu.Lock()
	defer s.mu.Unlock()

	row, ok := s.procs[pi.PID]
	if !ok {
		row = &ProcRow{PID: pi.PID, FirstSeen: time.Now()}
		s.procs[pi.PID] = row
	}
	row.PPID = pi.PPID
	row.Name = pi.Name
	row.Path = pi.Path
	row.CmdLine = pi.CmdLine
	row.User = pi.User
	row.ConnCount = connCount
	if modules > 0 {
		row.Modules = modules
	}
	if res != nil {
		row.Score = res.Score
		row.Verdict = string(res.Verdict)
		row.Severity = string(res.Severity)
		row.Title = res.Title
		row.Suppressed = res.Suppressed
	}
}

// Reap 移除已消失的进程。
func (s *Store) Reap(alive map[uint32]struct{}) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for pid := range s.procs {
		if _, ok := alive[pid]; !ok {
			delete(s.procs, pid)
		}
	}
}

// Procs 返回进程列表（按评分降序）。
func (s *Store) Procs(limit int) []ProcRow {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]ProcRow, 0, len(s.procs))
	for _, r := range s.procs {
		out = append(out, *r)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Score != out[j].Score {
			return out[i].Score > out[j].Score
		}
		return out[i].Name < out[j].Name
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

// AddAlert 追加一条本地告警。
func (s *Store) AddAlert(a *Alert) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.alerts = append([]*Alert{a}, s.alerts...)
	if len(s.alerts) > s.maxAlert {
		s.alerts = s.alerts[:s.maxAlert]
	}
}

// MarkAlertSent 标记告警已上报。
func (s *Store) MarkAlertSent(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, a := range s.alerts {
		if a.ID == id {
			a.Sent = true
			return
		}
	}
}

// Alerts 返回最近告警。
func (s *Store) Alerts(limit int) []*Alert {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if limit <= 0 || limit > len(s.alerts) {
		limit = len(s.alerts)
	}
	out := make([]*Alert, limit)
	copy(out, s.alerts[:limit])
	return out
}

// AlertByID 按 ID 查告警。
func (s *Store) AlertByID(id string) *Alert {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, a := range s.alerts {
		if a.ID == id {
			cp := *a
			return &cp
		}
	}
	return nil
}

// Counters 返回本地统计数字。
func (s *Store) Counters() (procs int, alerts int, critical int) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	procs = len(s.procs)
	alerts = len(s.alerts)
	for _, a := range s.alerts {
		if a.Severity == string(model.SeverityCritical) {
			critical++
		}
	}
	return
}
