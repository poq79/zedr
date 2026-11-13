// Package netwatch 实现基于连接表快照的进程级网络行为检测（扫描/横向移动）。
//
// 数据来源：探针每轮扫描本来就在拉取 GetExtendedTcpTable 全表（带 PID 归属），
// 本包不产生任何新的系统调用，只对已有快照做内存 diff 与滑动窗口聚合。
// 这是"保证性能"的关键：检测的边际成本 = 每轮一次 O(窗口内事件数) 的内存遍历，
// 无轮询、无线程、无内核交互。
//
// 检测语义与诚实边界（快照采样 ≠ 事件流）：
//   - 能看到：采样间隔内仍存在的连接（ESTABLISHED/TIME_WAIT/CLOSE_WAIT，
//     TIME_WAIT 在现代 Windows 上保留归属 PID）、以及 SYN_SENT 存量
//     （对"被防火墙丢弃/无响应"目标的尝试会停留数秒到数十秒）；
//   - 看不到：对"立即 RST"目标的连接尝试（SYN_SENT 存活小于一个采样间隔），
//     UDP 扫描（UDP 表没有连接状态），以及入站扫描（SYN_RCVD 语义未纳入）；
//   - 因此"快速失败型"端口扫描会漏检——这是用户态轮询路线的固有盲区，
//     补齐需要事件流（ETW Kernel-Network / WFP net events），见 TRADEOFFS。
//
// 规则族 NW-001~005 走旁路告警链路（与 persist/inventory 同模式），
// 不进 detect.Engine 打分：网络行为是随时间演化的过程量，而引擎只吃
// "进程创建时刻"的上下文，两者评估时机不同，硬塞进规则层反而丢失语义。
package netwatch

import (
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"zedr/internal/agent/nettypes"
	"zedr/internal/model"
)

// Config 是全部阈值；零值字段用 Default 补齐。
// 默认值取自业界公开检测规则的量级（fanout>10/30s、单 IP≥10 端口/5min），
// 并按"宁可漏报不打扰"的口径整体上调一档——扫描检测的误报成本
// （值班信任度）远高于漏报成本（还有关键词/规则/血缘层兜底）。
// 2026-11-14 用户裁决：NW-001 再上调一档（12→40）——资产盘点/监控探测/
// 下载器类正常软件对单 IP 开十几个端口并不罕见，扫描要"明显"才值得报。
type Config struct {
	// PortScanPorts：NW-001，长窗口内对同一目的 IP 的不同端口数阈值。
	// 40 = 5min 内对同一 IP 摸 40 个端口才报：真实扫描器（nmap top-1000
	// 起步）轻松越过，正常多端口应用（代理/下载器/集群客户端）够不到。
	PortScanPorts int
	// HostSweepIPs：NW-002，短窗口内"非常见端口"的不同目的 IP 数阈值。
	HostSweepIPs int
	// LateralIPs：NW-003，短窗口内横向服务端口的不同内网 IP 数阈值。
	LateralIPs int
	// NoRespFails / NoRespRatio：NW-004，短窗口内无响应尝试的次数下限与失败占比。
	NoRespFails int
	NoRespRatio float64
	// SynFloodConns：NW-004 的并行触发口径，单进程并发 SYN_SENT 存量。
	SynFloodConns int
	// RatePer10s / RateUncommonRatio / RateTicks：NW-005，滚动 10s 新建连接数、
	// 非常见端口占比、以及需要连续满足的周期数。
	RatePer10s        int
	RateUncommonRatio float64
	RateTicks         int
	// Cooldown 是同一（规则,进程）的告警冷却期。
	Cooldown time.Duration
	// WindowShort / WindowLong 是两个滑动窗口宽度。
	WindowShort time.Duration
	WindowLong  time.Duration
	// MaxProcs / MaxEventsPerProc 是内存护栏：跟踪的进程数上限与
	// 单进程窗口内事件数上限。超限丢最旧并计数，不无界增长。
	MaxProcs         int
	MaxEventsPerProc int
	// TrustedScale 是可信进程（系统目录+签名有效）的阈值放大倍数。
	// svchost/BITS/Windows Update 这类系统组件天然有大量合法扇出，
	// 用同一阈值会误报；放大而不是豁免，是因为它们也是被滥用的首选载体。
	TrustedScale int
	// LateralPorts 覆盖横向服务端口集（NW-003 用）；空 = 默认集
	//（22/135/139/445/3389/5985/5986）。企业自有管理端口在此补充。
	LateralPorts []uint16
}

// Default 返回默认配置。
func Default() Config {
	return Config{
		PortScanPorts:     40,
		HostSweepIPs:      15,
		LateralIPs:        8,
		NoRespFails:       15,
		NoRespRatio:       0.8,
		SynFloodConns:     50,
		RatePer10s:        60,
		RateUncommonRatio: 0.3,
		RateTicks:         3,
		Cooldown:          15 * time.Minute,
		WindowShort:       time.Minute,
		WindowLong:        5 * time.Minute,
		MaxProcs:          512,
		MaxEventsPerProc:  512,
		TrustedScale:      3,
	}
}

// ProcIdent 是检测对象进程的标识信息（由调用方从采集快照填入）。
type ProcIdent struct {
	PID uint32
	// PPID 随告警证据输出：网络行为的主体判断经常要看父进程
	//（浏览器拉起的下载器 vs 计划任务拉起的扫描器，语义完全不同）。
	PPID uint32
	// Name/Path 是告警富化用的展示信息；Path 可为空（进程已退出时）。
	Name string
	Path string
	// StartTime 用于 PID 复用判定；采集源不提供时为零值
	// （Toolhelp32 引擎没有创建时间，此场景下复用检测退化为按 PID）。
	StartTime time.Time
	// Trusted 标记"系统目录 + 签名有效"的进程，阈值放大 TrustedScale 倍。
	// 由调用方用 enrich 缓存判定，netwatch 不做系统调用。
	Trusted bool
}

// Tick 是一轮观测输入。
type Tick struct {
	// TakenAt 是快照时刻：全部窗口/冷却计算只用它，不用 wall clock——
	// 单测可以合成时间线，回放诊断也可复现。
	TakenAt time.Time
	// Conns 是全系统 TCP 连接表（快照），按 PID 分组。
	Conns map[uint32][]nettypes.TCPConn
	// Procs 是当前存活进程的标识信息；不在表里的 PID（刚退出）沿用
	// netwatch 内部记住的最后一次身份。
	Procs map[uint32]ProcIdent
}

// Finding 是一条网络行为告警（由调用方转成 model.AlertEnvelope 走统一出口）。
type Finding struct {
	RuleID   string
	Title    string
	Summary  string
	Severity model.Severity
	Score    int
	Verdict  model.Verdict
	MITRE    []string
	Notes    []string
	Ident    ProcIdent
}

// Stats 是可观测性计数（进日志/状态页）。
type Stats struct {
	Ticks        int64
	TrackedProcs int
	EventsSeen   int64
	AlertsFired  int64
	Suppressed   int64 // 冷却期内的重复命中
	Dropped      int64 // 超内存护栏丢弃的事件
}

// ---------------------------------------------------------------- 端口分类

// commonPorts 是"常见服务端口"：对这些端口的扇出通常是浏览器/更新/解析类
// 正常行为，不参与 NW-002 的"非常见端口扇出"计数。
// 22 刻意不在内：SSH 扇出本身就该走横向规则。
var commonPorts = map[uint16]bool{
	25: true, 53: true, 80: true, 110: true, 123: true, 143: true,
	443: true, 587: true, 853: true, 993: true, 995: true,
	1900: true, 5353: true, 5355: true, 8080: true,
}

// defaultLateralPorts 是横向移动服务端口默认集：对多台内网主机的这些
// 端口扇出是蠕虫传播/横向枚举的教科书信号。可用 Config.LateralPorts
// 覆盖——企业环境常有自有管理端口（如 47001/5985 之外的自研 agent 端口）。
var defaultLateralPorts = []uint16{22, 135, 139, 445, 3389, 5985, 5986}

// privateNets 是 RFC1918/环回/链路本地判定（与 winapi.IsPublicRemote 同口径，
// 但这里需要"是内网"而非"是公网"，独立实现避免语义倒置的耦合）。
var privateNets = func() []*net.IPNet {
	var out []*net.IPNet
	for _, cidr := range []string{
		"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
		"127.0.0.0/8", "169.254.0.0/16", "fc00::/7", "fe80::/10",
	} {
		if _, n, err := net.ParseCIDR(cidr); err == nil {
			out = append(out, n)
		}
	}
	return out
}()

// ---------------------------------------------------------------- 内部状态

// ev 是窗口内的一条"新连接"证据。
type ev struct {
	t        time.Time
	ip       string
	port     uint16
	lateral  bool // 内网 + 横向端口
	uncommon bool // 非常见服务端口
}

// procState 是单个进程的行为窗口。
// synPend 是一条未决 SYN_SENT 尝试。
type synPend struct {
	first    time.Time
	uncommon bool // 目标端口非常见服务端口（NW-004 的占比条件用）
}

// failRec 是一次无响应尝试；uncommon 随失败记录固化——DNS/断网场景
// 的失败几乎全落在 53/80/443 这类常用端口上，与扫描（多样非常见端口）
// 的失败形态正交，NW-004 靠占比区分两者。
type failRec struct {
	at       time.Time
	uncommon bool
}

type procState struct {
	ident  ProcIdent
	events []ev                 // 按 t 升序的滚动窗口（≤ MaxEventsPerProc）
	seen   map[string]time.Time // "ip|port" -> 首次记录时间（去重，窗口 2 倍后过期）
	syn    map[string]synPend   // 未决 SYN_SENT："ip|port" -> 首次观测
	fails  []failRec            // 短窗口内的无响应尝试
	succ   []time.Time          // 短窗口内 SYN_SENT→ESTABLISHED 的成功转化
	// rateStreak 是 NW-005 连续达标周期数；lastRate 是上一周期的新建连接数。
	rateStreak int
	lastSeen   time.Time
	// touched 标记本轮是否有活动（有快照 / 有未决尝试结算）。
	// 只有 touched 的状态才参与规则评估：防止陈旧窗口在冷却过期后被
	// 旧数据重复触发，也让"进程消失那一轮"的 SYN 结算能被评估到。
	touched bool
	// baselined：首次 sighting 不计数，只记基线。
	// 没有它，探针启动/进程首现的那一轮会把全部存量连接当成"新事件"
	// （浏览器一恢复就有几十个 CDN 连接 → 立即误报 NW-002）。
	// 代价：进程在我们首次观测到它时已有的连接永远不参与计数——
	// 这是"宁可漏掉存量、绝不误报存量"的取舍，新增连接才是信号。
	baselined bool
}

// Watch 是网络行为检测器。Observe 由扫描循环单 goroutine 调用；
// 加锁是防御性的（测试与未来多消费者），成本可忽略。
type Watch struct {
	mu      sync.Mutex
	cfg     Config
	selfPID uint32
	// lateral 是生效的横向端口集（默认集或 Config 覆盖）
	lateral map[uint16]bool
	states  map[uint32]*procState
	cools   map[alertKey]time.Time

	ownIPs     map[string]bool
	ownIPsAt   time.Time
	ownIPsOnce sync.Once

	st Stats
}

type alertKey struct {
	rule   string
	pid    uint32
	bucket int64 // Cooldown 对齐的时间桶，持续行为按桶重复告警
}

// New 构造检测器；selfPID 是探针自身进程（自升级/隧道连接不参与检测）。
func New(cfg Config, selfPID uint32) *Watch {
	d := Default()
	if cfg.PortScanPorts <= 0 {
		cfg.PortScanPorts = d.PortScanPorts
	}
	if cfg.HostSweepIPs <= 0 {
		cfg.HostSweepIPs = d.HostSweepIPs
	}
	if cfg.LateralIPs <= 0 {
		cfg.LateralIPs = d.LateralIPs
	}
	if cfg.NoRespFails <= 0 {
		cfg.NoRespFails = d.NoRespFails
	}
	if cfg.NoRespRatio <= 0 {
		cfg.NoRespRatio = d.NoRespRatio
	}
	if cfg.SynFloodConns <= 0 {
		cfg.SynFloodConns = d.SynFloodConns
	}
	if cfg.RatePer10s <= 0 {
		cfg.RatePer10s = d.RatePer10s
	}
	if cfg.RateUncommonRatio <= 0 {
		cfg.RateUncommonRatio = d.RateUncommonRatio
	}
	if cfg.RateTicks <= 0 {
		cfg.RateTicks = d.RateTicks
	}
	if cfg.Cooldown <= 0 {
		cfg.Cooldown = d.Cooldown
	}
	if cfg.WindowShort <= 0 {
		cfg.WindowShort = d.WindowShort
	}
	if cfg.WindowLong <= 0 {
		cfg.WindowLong = d.WindowLong
	}
	if cfg.MaxProcs <= 0 {
		cfg.MaxProcs = d.MaxProcs
	}
	if cfg.MaxEventsPerProc <= 0 {
		cfg.MaxEventsPerProc = d.MaxEventsPerProc
	}
	if cfg.TrustedScale <= 1 {
		cfg.TrustedScale = d.TrustedScale
	}
	lateral := map[uint16]bool{}
	ports := cfg.LateralPorts
	if len(ports) == 0 {
		ports = defaultLateralPorts
	}
	for _, p := range ports {
		lateral[p] = true
	}
	return &Watch{
		cfg:     cfg,
		selfPID: selfPID,
		lateral: lateral,
		states:  make(map[uint32]*procState, 64),
		cools:   make(map[alertKey]time.Time, 64),
		ownIPs:  map[string]bool{},
	}
}

// Observe 处理一轮快照，返回本次触发的告警（已做冷却去重）。
func (w *Watch) Observe(t Tick) []Finding {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.st.Ticks++

	now := t.TakenAt
	if now.IsZero() {
		now = time.Now()
	}
	w.refreshOwnIPs(now)

	// 第一遍：把本轮快照折叠成 pid → pair 集合，登记连接证据。
	// 注意快照里没有的 PID（进程已退出/本轮零连接）不在本 pass——
	// 它们的未决 SYN 结算在第二遍做。
	pairsByPID := make(map[uint32]map[string][2]bool, len(t.Conns)) // "ip|port" -> {syn, est}
	baselining := make(map[uint32]bool, 8)
	for pid, conns := range t.Conns {
		if pid == w.selfPID || len(conns) == 0 {
			continue
		}
		st := w.stateFor(pid, t.Procs, now)
		st.lastSeen = now

		firstSight := !st.baselined
		st.baselined = true
		if firstSight {
			baselining[pid] = true
		} else {
			st.touched = true
		}

		pairs := make(map[string][2]bool, len(conns))
		for _, c := range conns {
			ip, ok := classifyRemote(c.RemoteIP)
			if !ok || w.ownIPs[ip] {
				// 环回/链路本地/组播/未指定，以及"连自己"（服务经本机
				// LAN IP 回环访问）都不构成扫描语义
				continue
			}
			pair := pairKey(ip, c.RemotePort)
			ps := pairs[pair]
			switch c.State {
			case "SYN_SENT":
				ps[0] = true
			case "ESTABLISHED":
				ps[1] = true
			}
			pairs[pair] = ps

			if firstSight {
				// 基线轮：只记 seen（防止下一轮同一连接被当成"新"），
				// 不产生事件、不登记未决尝试
				if _, dup := st.seen[pair]; !dup {
					st.seen[pair] = now
				}
				continue
			}

			// 连接证据（含 TIME_WAIT/CLOSE_WAIT——快速开合的连接只有
			// 这些残留状态可采样到）。去重窗口 = 长窗口 ×2：同一条
			// 长连接只在首次入窗时计一次，过期后的重连按新连接计。
			if !st.seenEvent(pair, now, w.cfg.WindowLong*2) {
				continue
			}
			port := c.RemotePort
			private := isPrivateIP(ip)
			st.events = append(st.events, ev{
				t:        now,
				ip:       ip,
				port:     port,
				lateral:  private && w.lateral[port],
				uncommon: !commonPorts[port],
			})
			w.st.EventsSeen++
		}
		pairsByPID[pid] = pairs

		st.prune(now, &w.cfg)
	}

	// 第二遍：未决 SYN_SENT 的去向判定（NW-004 的数据来源）。
	// 必须对所有状态做而不是只在有快照的进程内做：扫描进程被杀、
	// 或一轮内连接全部消失时，快照里已经没有这个 PID，
	// "尝试石沉大海"恰恰只在这一轮才能被观测到。
	for pid, st := range w.states {
		if pid == w.selfPID {
			continue
		}
		pairs := pairsByPID[pid]
		if len(st.syn) > 0 {
			st.touched = true
		}
		for pair := range st.syn {
			ps, alive := pairs[pair]
			switch {
			case alive && ps[0]:
				// 仍在尝试
			case alive && ps[1]:
				st.succ = append(st.succ, now)
				delete(st.syn, pair)
			case alive:
				// 进入其他状态（如 SYN_RCVD/fin 系），语义不明，保留观察
			default:
				st.fails = append(st.fails, failRec{at: now, uncommon: st.syn[pair].uncommon})
				delete(st.syn, pair)
			}
		}
		if pairs != nil {
			if baselining[pid] {
				// 基线轮不登记未决尝试：启动瞬间已存在的 SYN_SENT
				// 不是本进程"刚开始扫"的证据
				continue
			}
			for pair, ps := range pairs {
				if ps[0] {
					if _, ok := st.syn[pair]; !ok {
						port := portOfPair(pair)
						st.syn[pair] = synPend{first: now, uncommon: !commonPorts[port]}
					}
				}
			}
		} else if st.lastSeen != now {
			// 本轮没有快照的进程：窗口冻结，速率连击按中断清零
			// （"连续 N 个周期"的语义不允许跨中断累计）
			st.rateStreak = 0
		}
	}

	// 第三遍：逐进程评估规则（只评估本轮有活动的状态）。
	var findings []Finding
	for pid, st := range w.states {
		if pid == w.selfPID || !st.touched {
			continue
		}
		st.touched = false
		for _, f := range w.evaluate(pid, st, now) {
			if w.cool(f.RuleID, pid, now) {
				w.st.Suppressed++
				continue
			}
			f.Ident = st.ident
			findings = append(findings, f)
			w.st.AlertsFired++
		}
	}

	w.evictStale(now)
	w.st.TrackedProcs = len(w.states)

	// 单轮告警上限：异常风暴时保住上报队列（与 inventory 单轮上限同思路）
	if len(findings) > 10 {
		w.st.Dropped += int64(len(findings) - 10)
		findings = findings[:10]
	}
	return findings
}

// Stats 返回计数快照。
func (w *Watch) Stats() Stats {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.st
}

// ---------------------------------------------------------------- 状态管理

func (w *Watch) stateFor(pid uint32, procs map[uint32]ProcIdent, now time.Time) *procState {
	st := w.states[pid]
	ident := procs[pid]
	if st == nil {
		st = &procState{
			ident: ident,
			seen:  map[string]time.Time{},
			syn:   map[string]synPend{},
		}
		w.states[pid] = st
		return st
	}
	// 身份刷新 + PID 复用判定：创建时间变了 = 新进程，行为窗口必须清零，
	// 否则旧进程的扫描扇出会算到复用者头上。
	if ident.PID != 0 {
		if !ident.StartTime.IsZero() && !st.ident.StartTime.IsZero() &&
			!ident.StartTime.Equal(st.ident.StartTime) {
			*st = procState{ident: ident, seen: map[string]time.Time{}, syn: map[string]synPend{}}
			return st
		}
		if ident.Name != "" {
			st.ident.Name = ident.Name
		}
		if ident.Path != "" {
			st.ident.Path = ident.Path
		}
		st.ident.Trusted = ident.Trusted
		if st.ident.StartTime.IsZero() {
			st.ident.StartTime = ident.StartTime
		}
	}
	return st
}

// seenEvent 返回 true 表示这是窗口内首次出现的 pair（需要记账）。
func (s *procState) seenEvent(pair string, now time.Time, ttl time.Duration) bool {
	if first, ok := s.seen[pair]; ok {
		if now.Sub(first) < ttl {
			return false
		}
	}
	s.seen[pair] = now
	return true
}

// prune 清理过期数据，硬上限兜底防内存无界。
func (s *procState) prune(now time.Time, cfg *Config) {
	cutLong := now.Add(-cfg.WindowLong)
	cutShort := now.Add(-cfg.WindowShort)

	k := 0
	for _, e := range s.events {
		if e.t.After(cutLong) {
			s.events[k] = e
			k++
		}
	}
	s.events = s.events[:k]

	k = 0
	for _, f := range s.fails {
		if f.at.After(cutShort) {
			s.fails[k] = f
			k++
		}
	}
	s.fails = s.fails[:k]
	k = 0
	for _, t := range s.succ {
		if t.After(cutShort) {
			s.succ[k] = t
			k++
		}
	}
	s.succ = s.succ[:k]

	for pair, first := range s.seen {
		if now.Sub(first) >= cfg.WindowLong*2 {
			delete(s.seen, pair)
		}
	}
	for pair, pend := range s.syn {
		// 正常尝试几十秒内必有去向；留 10 分钟余量防快照抖动
		if now.Sub(pend.first) > 10*time.Minute {
			delete(s.syn, pair)
		}
	}

	// 硬上限：窗口清理漏掉的超大突发（如瞬时数千连接）在这里截断
	if len(s.events) > cfg.MaxEventsPerProc {
		drop := len(s.events) - cfg.MaxEventsPerProc
		s.events = append([]ev(nil), s.events[drop:]...)
	}
	if len(s.seen) > cfg.MaxEventsPerProc*4 {
		s.seen = map[string]time.Time{} // 极端情况整体重建，宁可重计不可泄漏
	}
}

func (w *Watch) evictStale(now time.Time) {
	for pid, st := range w.states {
		if now.Sub(st.lastSeen) > 15*time.Minute {
			delete(w.states, pid)
		}
	}
	for len(w.states) > w.cfg.MaxProcs {
		oldest := uint32(0)
		var oldestAt time.Time
		first := true
		for pid, st := range w.states {
			if first || st.lastSeen.Before(oldestAt) {
				oldest, oldestAt, first = pid, st.lastSeen, false
			}
		}
		delete(w.states, oldest)
	}
	// 冷却表同步瘦身
	if len(w.cools) > w.cfg.MaxProcs*4 {
		for k, at := range w.cools {
			if now.Sub(at) > w.cfg.Cooldown {
				delete(w.cools, k)
			}
		}
	}
}

// ---------------------------------------------------------------- 地址工具

// classifyRemote 归一化目的地址；返回 false 表示不参与检测
// （环回/链路本地/未指定/组播/解析失败）。
func classifyRemote(ipStr string) (string, bool) {
	ip := net.ParseIP(ipStr)
	if ip == nil || ip.IsLoopback() || ip.IsUnspecified() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() {
		return "", false
	}
	return ip.String(), true
}

func isPrivateIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	for _, n := range privateNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// refreshOwnIPs 周期刷新本机地址表（排除"服务连自己"的噪声）。
// 用 Go 标准库 net.Interfaces，零 Win32 调用。
func (w *Watch) refreshOwnIPs(now time.Time) {
	if !w.ownIPsAt.IsZero() && now.Sub(w.ownIPsAt) < time.Minute {
		return
	}
	w.ownIPsAt = now
	next := make(map[string]bool, 8)
	ifaces, err := net.Interfaces()
	if err != nil {
		return // 刷新失败沿用旧表
	}
	for _, ifc := range ifaces {
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			if ipnet, ok := a.(*net.IPNet); ok {
				next[ipnet.IP.String()] = true
			} else if ip, _, err := net.ParseCIDR(a.String()); err == nil {
				next[ip.String()] = true
			}
		}
	}
	w.ownIPs = next
}

func pairKey(ip string, port uint16) string {
	return ip + "|" + strconv.Itoa(int(port))
}

// portOfPair 从 "ip|port" 键里还原端口（未决尝试的端口固化用）。
func portOfPair(pair string) uint16 {
	_, p, ok := strings.Cut(pair, "|")
	if !ok {
		return 0
	}
	n, err := strconv.Atoi(p)
	if err != nil {
		return 0
	}
	return uint16(n)
}

// ---------------------------------------------------------------- 规则评估

func (w *Watch) cool(rule string, pid uint32, now time.Time) bool {
	k := alertKey{rule: rule, pid: pid, bucket: now.Truncate(w.cfg.Cooldown).Unix()}
	if at, ok := w.cools[k]; ok && now.Sub(at) < w.cfg.Cooldown {
		return true
	}
	w.cools[k] = now
	return false
}

// scale 返回进程适用的阈值（可信进程放大）。
func (st *procState) scale(cfg *Config) int {
	if st.ident.Trusted {
		return cfg.TrustedScale
	}
	return 1
}

func (w *Watch) evaluate(pid uint32, st *procState, now time.Time) []Finding {
	if len(st.events) == 0 && len(st.fails) == 0 && len(st.syn) == 0 {
		return nil
	}
	scale := st.scale(&w.cfg)
	short := now.Add(-w.cfg.WindowShort)
	long := now.Add(-w.cfg.WindowLong)

	var (
		ips60         = map[string]bool{}
		uncommonIPs   = map[string]bool{}
		lateralIPs    = map[string]bool{}
		portSets      = map[string]map[uint16]bool{}
		uncommon10s   = 0
		total10s      = 0
		sampleTargets []string
	)
	for _, e := range st.events {
		if e.t.After(short) {
			ips60[e.ip] = true
			if e.uncommon {
				uncommonIPs[e.ip] = true
			}
			if e.lateral {
				lateralIPs[e.ip] = true
			}
		}
		if e.t.After(long) {
			ps := portSets[e.ip]
			if ps == nil {
				ps = map[uint16]bool{}
				portSets[e.ip] = ps
			}
			ps[e.port] = true
		}
		if now.Sub(e.t) <= 10*time.Second {
			total10s++
			if e.uncommon {
				uncommon10s++
			}
		}
	}
	// 目标样例：窗口内最近出现的若干 ip:port（供证据展示）
	for i := len(st.events) - 1; i >= 0 && len(sampleTargets) < 6; i-- {
		sampleTargets = append(sampleTargets, pairKey(st.events[i].ip, st.events[i].port))
	}

	var out []Finding

	// NW-001 端口扫描：单 IP 端口扇出
	topIP := ""
	topPorts := map[uint16]bool{}
	for ip, ps := range portSets {
		if len(ps) > len(topPorts) {
			topIP, topPorts = ip, ps
		}
	}
	thr := w.cfg.PortScanPorts * scale
	if len(topPorts) >= thr {
		ports := make([]int, 0, len(topPorts))
		for p := range topPorts {
			ports = append(ports, int(p))
		}
		sort.Ints(ports)
		out = append(out, Finding{
			RuleID: "NW-001",
			Title:  fmt.Sprintf("网络行为：端口扫描（%s 在 5 分钟内连接 %d 个端口）", topIP, len(ports)),
			Summary: fmt.Sprintf("进程 %s(PID %d) 在 %s 内对 %s 尝试连接 %d 个不同端口（阈值 %d）。"+
				"这是网络服务发现（T1046）的典型形态。",
				st.ident.Name, pid, w.cfg.WindowLong, topIP, len(ports), thr),
			Severity: model.SeverityHigh,
			Score:    60,
			Verdict:  model.VerdictSuspicious,
			MITRE:    []string{"T1046"},
			Notes: append([]string{"样例目标: " + joinSample(sampleTargets)},
				fmt.Sprintf("端口列表: %v", ports)),
		})
	}

	// NW-002 主机扫探：非常见端口的 IP 扇出。
	thr = w.cfg.HostSweepIPs * scale
	if len(uncommonIPs) >= thr {
		out = append(out, Finding{
			RuleID: "NW-002",
			Title:  fmt.Sprintf("网络行为：主机扫探（60 秒内连接 %d 台主机的非常见端口）", len(uncommonIPs)),
			Summary: fmt.Sprintf("进程 %s(PID %d) 在 %s 内对 %d 台不同主机的非常见服务端口发起连接（阈值 %d）。"+
				"常见端口（80/443/53 等）不计数，浏览器/更新类流量不会触发；这一形态指向远程系统发现或服务探测（T1018/T1046）。",
				st.ident.Name, pid, w.cfg.WindowShort, len(uncommonIPs), thr),
			Severity: model.SeverityHigh,
			Score:    55,
			Verdict:  model.VerdictSuspicious,
			MITRE:    []string{"T1018", "T1046"},
			Notes:    []string{"样例目标: " + joinSample(sampleTargets)},
		})
	}

	// NW-003 横向服务扫探：内网横向端口扇出
	thr = w.cfg.LateralIPs * scale
	if len(lateralIPs) >= thr {
		out = append(out, Finding{
			RuleID: "NW-003",
			Title:  fmt.Sprintf("网络行为：横向服务扫探（60 秒内触及 %d 台内网主机）", len(lateralIPs)),
			Summary: fmt.Sprintf("进程 %s(PID %d) 在 %s 内对 %d 台内网主机的横向服务端口（22/135/445/3389/5985 等）发起连接（阈值 %d）。"+
				"这是蠕虫传播、凭证滥用横向移动（T1021）与网络服务发现（T1046）的强信号。",
				st.ident.Name, pid, w.cfg.WindowShort, len(lateralIPs), thr),
			Severity: model.SeverityCritical,
			Score:    70,
			Verdict:  model.VerdictSuspicious,
			MITRE:    []string{"T1021", "T1046"},
			Notes:    []string{"样例目标: " + joinSample(sampleTargets)},
		})
	}

	// NW-004 无响应扫描 / SYN 压力。
	// 失败占比之外还要求"非常见端口占比 ≥50%"：DNS 服务器故障/断网时
	// 全机的失败都集中在 53/80/443 这类常用端口，形态与扫描（多样非常见
	// 端口）正交——不加这个条件，网络故障会变成全网扫描误报。
	att := len(st.fails) + len(st.succ)
	ratio := 0.0
	uncommonFail := 0
	for _, f := range st.fails {
		if f.uncommon {
			uncommonFail++
		}
	}
	uncommonFailRatio := 0.0
	if len(st.fails) > 0 {
		uncommonFailRatio = float64(uncommonFail) / float64(len(st.fails))
	}
	if att > 0 {
		ratio = float64(len(st.fails)) / float64(att)
	}
	thr = w.cfg.NoRespFails * scale
	if (att >= thr && ratio >= w.cfg.NoRespRatio && uncommonFailRatio >= 0.5) ||
		len(st.syn) >= w.cfg.SynFloodConns {
		out = append(out, Finding{
			RuleID: "NW-004",
			Title: fmt.Sprintf("网络行为：无响应连接扫描（%d 次尝试无响应，并发 SYN_SENT %d）",
				len(st.fails), len(st.syn)),
			Summary: fmt.Sprintf("进程 %s(PID %d) 的连接尝试大量得不到响应：%s 内 %d 次尝试中 %.0f%% 无响应"+
				"（其中 %.0f%% 打向非常见服务端口；当前并发 SYN_SENT %d）。"+
				"阈值：尝试≥%d 且失败比≥%.0f%% 且非常见端口占比≥50%%，或并发≥%d。"+
				"SYN 发出后石沉大海指向被防火墙静默丢弃的目标段——防火墙探测/隐蔽扫描（T1046）的典型残留。",
				st.ident.Name, pid, w.cfg.WindowShort, att, ratio*100,
				uncommonFailRatio*100, len(st.syn),
				thr, w.cfg.NoRespRatio*100, w.cfg.SynFloodConns),
			Severity: model.SeverityHigh,
			Score:    55,
			Verdict:  model.VerdictSuspicious,
			MITRE:    []string{"T1046"},
			Notes:    []string{"样例目标: " + joinSample(sampleTargets)},
		})
	}

	// NW-005 连接速率异常（连续周期）
	uncommonRatio := 0.0
	if total10s > 0 {
		uncommonRatio = float64(uncommon10s) / float64(total10s)
	}
	if total10s >= w.cfg.RatePer10s && uncommonRatio >= w.cfg.RateUncommonRatio {
		st.rateStreak++
	} else {
		st.rateStreak = 0
	}
	if st.rateStreak >= w.cfg.RateTicks {
		out = append(out, Finding{
			RuleID: "NW-005",
			Title:  fmt.Sprintf("网络行为：连接速率异常（连续 %d 个周期高速新建连接）", st.rateStreak),
			Summary: fmt.Sprintf("进程 %s(PID %d) 连续 %d 个采样周期保持每 10s ≥%d 次新建连接"+
				"（当前 %d 次/s10，非常见端口占比 %.0f%%，阈值：≥%d 且占比≥%.0f%% 连续 %d 周期）。"+
				"持续的非常见端口连接洪流指向蠕虫传播或大范围外联（T1046/T1071）。",
				st.ident.Name, pid, st.rateStreak, w.cfg.RatePer10s,
				total10s, uncommonRatio*100, w.cfg.RatePer10s,
				w.cfg.RateUncommonRatio*100, w.cfg.RateTicks),
			Severity: model.SeverityMedium,
			Score:    45,
			Verdict:  model.VerdictSuspicious,
			MITRE:    []string{"T1046", "T1071"},
			Notes:    []string{"样例目标: " + joinSample(sampleTargets)},
		})
	}

	return out
}

func joinSample(targets []string) string {
	if len(targets) == 0 {
		return "(无)"
	}
	const max = 6
	if len(targets) > max {
		targets = targets[:max]
	}
	out := ""
	for i, t := range targets {
		if i > 0 {
			out += ", "
		}
		out += t
	}
	return out
}
