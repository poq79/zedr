// Package chain 实现探针侧攻击链关联引擎（CHAIN-* 告警族）。
//
// 定位：把**已经产出的多源信号**（进程创建/外联/登录事件/持久化项/
// 内存巡检/网络行为）按"实体 + 时间窗"串成确定性攻击链。对标
// SentinelOne Storyline 的单机形态：信号挂到进程实体上、多阶段命中
// 才出一条带叙事的链告警；规则语义取 Elastic EQL sequence（by 实体
// key + maxspan + 每状态仅保留最新 pending）与 Wazuh if_matched
// （前驱信号已触发 + same_field 实体约束）的交集——全部是端侧内存
// 可实现的廉价原语，不引入任何新采集面。
//
// 设计取舍（调研结论存内部安全档案，
// 2026-11-06 联网核实）：
//   - 不做通用溯源图：GNN/学习路线需要训练集与 GPU 量级资源，且学界
//     复现研究（ATLASv2 审计）表明"词汇新颖性"占固定阈值收益大头、
//     溯源图异常检测公认"高误报+粗粒度告警"——端侧只做确定性链，
//     弱信号不独立成链；
//   - 每条链规则 = 一个阶段序列状态机。链 key 按规则口径提取（单进程
//     链 = PID:启动时间，与采集器同源；跨进程链 = 主机 / 归一化路径）；
//   - 内存有界：活跃链上限 maxMachines，超限淘汰最旧；触发后
//     (规则, key) 进入 firedIgnore 防洪（Wazuh ignore 语义）；过期链在
//     每次 Feed 时惰性回收——轮询语义下没有进程退出事件，"窗口过期
//     即回收"与"退出即回收"在检测语义上等价。
//
// 并发模型：Feed 可从任意 goroutine 调用（scan 循环 / evtlog 循环 /
// memwatch 循环 / persist 扫描），引擎自持锁；OnFinding 回调在锁外
// 触发（回调会走 emitAlert → store/uplink，各自的锁不在这里持有）。
package chain

import (
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"zedr/internal/agent/allow"
	"zedr/internal/model"
)

// 阶段种类：与馈送方（app 接线层）的信号源一一对应。
const (
	KindProc    = "proc"     // 新进程首次被观察（含"落地即执行"标记）
	KindConn    = "conn"     // 进程对外连接（非回环）
	KindNet     = "net"      // netwatch NW-* 行为命中
	KindBrute   = "brute"    // 4625 聚合超阈（EVT-BRUTE 触发点）
	KindLogonOK = "logon_ok" // 暴破成功序列（EVT-BRUTE-SUCCESS 触发点）
	KindSvcInst = "svc_inst" // 新服务安装（7045）
	KindPersist = "persist"  // 持久化项新增/改写（P-001）
	KindMem     = "mem"      // 内存威胁巡检命中（MEM-1055）
)

const (
	// procChainMaxSpan 是单进程链窗口。与 DROP-001 的落地关联窗口
	// （15min）对齐：链首证据本身就是"15 分钟内落地"的镜像，窗口再长
	// 只是把无关外联拼进链里，放大误报面而不增加检出。
	procChainMaxSpan = 15 * time.Minute
	// hostChainMaxSpan 是跨进程链（登录→执行、持久化→执行）的整链窗口。
	// 跨越登录会话建立与工具投放，需要更宽；窗口内未走完即视为链断裂。
	hostChainMaxSpan = 30 * time.Minute
	// firedIgnore 是链完成后的防洪窗口：同 (规则, key) 60s 内不重新起链。
	firedIgnore = 60 * time.Second
	// stageSkew 容忍阶段间的时间倒挂：事件时间（evtlog TimeCreated）与
	// 消费/观察时间（scan tick）存在 30s 轮询 + 采样粒度的固有偏差，
	// 链时间线以行为时刻为准时允许小幅回拨。
	stageSkew = 2 * time.Minute
	// maxMachines 是活跃链上限（内存硬闸）。正常机器同时活跃的链是个位数
	// ——暴破/落地/持久化都是小概率事件；512 已是"大规模运维脚本批量
	// 装软件"级别的极端值，到顶先淘汰最旧，不丢 Feed（丢阶段才会漏链）。
	maxMachines = 512
	// maxIgnores 是防洪表上限，超限先清过期再淘汰最旧。
	maxIgnores = 1024
	// sweepInterval 是过期链惰性回收的最小间隔。回收是纯内存释放——
	// 链的正确性由推进时的窗口检查保证，过期机器本来就推不动；
	// 每次 Feed 全表扫描在 512 链规模下是 15µs/op 的纯浪费
	// （BenchmarkFeedHot 实测），节流到 30s 一次。
	sweepInterval = 30 * time.Second
)

// Stage 是喂给关联引擎的一条信号。字段按 Kind 取用，不用的留零值；
// 结构体按值传递，禁止内嵌锁。
type Stage struct {
	Kind string
	When time.Time // 行为发生时刻（事件时间优先于消费时刻）

	// 进程实体（proc/conn/net/mem 阶段尽量带全；PID 复用由 StartTime 区分）
	PID       uint32
	StartTime time.Time
	Name      string
	Path      string
	CmdLine   string
	User      string
	Hash      string
	Signer    string
	Signed    bool
	// Dropped 表示引擎对该进程命中过 DROP-001 判定（镜像 15min 内落地）。
	// 复用引擎判定而不是链引擎重算：落地窗口/目录风险/MotW 的口径只有一份。
	Dropped bool
	MotW    bool

	// conn/net 阶段：外联对端样例
	PeerIP   string
	PeerPort uint32

	// 登录阶段
	LoginUser string
	SrcIP     string
	LogonType string
	FailCount int

	// persist/svc_inst 阶段：持久化指向的可执行与来源语义
	ItemPath string
	ItemKind string
	ItemName string

	// MITRE 是该阶段自身的技术映射（persist/svc 阶段决定链告警的 MITRE）
	MITRE string
	// RefRuleID/RefScore/RefFingerprint/Note 是阶段来源告警的引用（阶段
	// 已产出独立告警时填写）。Fingerprint 让服务端与 AI 研判能把链阶段
	// 精确回指到原始告警（事件叙事的 A1..An 引用天然可对账）。
	RefRuleID      string
	RefScore       int
	RefFingerprint string
	Note           string
}

// Finding 是关联引擎产出的一条攻击链告警（emit 前的中间结构，
// app 接线层负责转成统一 AlertEnvelope）。
type Finding struct {
	RuleID   string
	Title    string
	Summary  string
	Verdict  model.Verdict
	Severity model.Severity
	Score    int
	MITRE    []string
	Stages   []Stage  // 依序的阶段证据
	Lines    []string // 每阶段一行的人话叙事（与 Stages 一一对应）
	Root     *Stage   // 根因进程（有进程实体的阶段里取第一个）
	Key      string   // 链 key（审计/指纹用）
	Started  time.Time
}

// Options 是引擎构造参数。
type Options struct {
	// OnFinding 在链完成时触发（锁外）。nil 时链照常完成但不产出。
	OnFinding func(Finding)
	// Allow 非空时，命中白名单的实体不参与任何链（降级为 telemetry）。
	Allow *allow.List
	// Now 可注入时钟（单测用），nil = time.Now。
	Now func() time.Time
}

// Engine 是攻击链关联引擎。
type Engine struct {
	opts Options

	mu        sync.Mutex
	machines  map[string]*machine // ruleID \x00 key -> machine
	ignores   map[string]time.Time
	dropped   int64 // 超上限淘汰的链数（mu 保护）
	lastSweep time.Time

	fired       atomic.Int64
	firedByRule map[string]int64 // mu 保护
}

// machine 是一条进行中的链（EQL 语义：每 key 每状态只保留最新 pending——
// 这里每个 key 至多一条 machine，阶段严格按序推进）。
type machine struct {
	rule    *rule
	key     string
	stages  []Stage
	created time.Time
	updated time.Time
}

// New 创建引擎。
func New(opts Options) *Engine {
	if opts.Now == nil {
		opts.Now = time.Now
	}
	return &Engine{
		opts:        opts,
		machines:    make(map[string]*machine, 64),
		ignores:     make(map[string]time.Time, 64),
		firedByRule: make(map[string]int64, 8),
	}
}

// Stats 是引擎健康度快照（本地面板/心跳可见）。
type Stats struct {
	Active  int              // 当前活跃链数
	Fired   int64            // 累计完成的链数
	Dropped int64            // 超上限淘汰的链数
	ByRule  map[string]int64 // 按规则累计完成数（运营视角"哪条链在响"）
}

// Stats 返回健康度快照。
func (e *Engine) Stats() Stats {
	if e == nil {
		return Stats{}
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	byRule := make(map[string]int64, len(e.firedByRule))
	for k, v := range e.firedByRule {
		byRule[k] = v
	}
	return Stats{
		Active:  len(e.machines),
		Fired:   e.fired.Load(),
		Dropped: e.dropped,
		ByRule:  byRule,
	}
}

// Feed 喂入一条信号。引擎自持锁，任意 goroutine 可调用。
func (e *Engine) Feed(s Stage) {
	if e == nil || s.Kind == "" {
		return
	}
	now := e.opts.Now()
	if s.When.IsZero() {
		s.When = now
	}
	// 白名单优先（与引擎/旁路模块同口径）：链的任何环节来自被明确信任
	// 的实体 → 该环节不参与链也不起链。这是"链告警天然继承加白语义"
	// 的单点实现，馈送方无需各自判断。
	if e.allowlisted(s) {
		return
	}

	e.mu.Lock()
	e.sweepLocked(now)

	var completed []Finding
	for i := range allRules {
		r := &allRules[i]
		key := r.keyOf(s)
		if key == "" {
			continue
		}
		id := ruleKey(r.id, key)
		if until, ok := e.ignores[id]; ok && now.Before(until) {
			continue // 防洪窗口内：既不起链也不推进
		}
		m := e.machines[id]
		if m == nil {
			// 起链：仅当该阶段是链首
			if r.length > 1 && r.match(0, s, nil) {
				if len(e.machines) >= maxMachines {
					e.evictOldestLocked()
				}
				e.machines[id] = &machine{
					rule: r, key: key,
					stages:  []Stage{s},
					created: now, updated: now,
				}
			}
			continue
		}
		// 推进：阶段序号 = 已收集数；窗口约束 = 整链跨度 + 小幅时间倒挂容忍
		next := len(m.stages)
		if next >= r.length {
			continue
		}
		dt := s.When.Sub(m.stages[0].When)
		if dt < -stageSkew || dt > r.span {
			continue
		}
		if !r.match(next, s, m) {
			continue
		}
		m.stages = append(m.stages, s)
		m.updated = now
		if len(m.stages) == r.length {
			completed = append(completed, r.build(m))
			delete(e.machines, id)
			e.ignores[id] = now.Add(firedIgnore)
			e.firedByRule[r.id]++
			if len(e.ignores) > maxIgnores {
				e.pruneIgnoresLocked(now)
			}
		}
	}
	e.mu.Unlock()

	if len(completed) > 0 {
		e.fired.Add(int64(len(completed)))
	}
	if e.opts.OnFinding != nil {
		for _, f := range completed {
			e.opts.OnFinding(f)
		}
	}
}

// sweepLocked 回收过期链（窗口内未走完即断裂）。节流到 sweepInterval
// 一次：回收只释放内存，链推进的正确性由 Feed 内的窗口检查独立保证，
// 过期机器最多多活一个节流周期。Feed 频率远高于链建立频率，全表扫描
// 每次 Feed 都做是纯浪费。
func (e *Engine) sweepLocked(now time.Time) {
	if !e.lastSweep.IsZero() && now.Sub(e.lastSweep) < sweepInterval {
		return
	}
	e.lastSweep = now
	for id, m := range e.machines {
		if now.Sub(m.created) > m.rule.span {
			delete(e.machines, id)
		}
	}
}

// evictOldestLocked 在达到上限时淘汰最久未推进的链。
func (e *Engine) evictOldestLocked() {
	oldestID := ""
	var oldest time.Time
	for id, m := range e.machines {
		if oldestID == "" || m.updated.Before(oldest) {
			oldestID, oldest = id, m.updated
		}
	}
	if oldestID != "" {
		delete(e.machines, oldestID)
		e.dropped++
	}
}

// pruneIgnoresLocked 防洪表超限时先清过期，仍超限淘汰最旧。
func (e *Engine) pruneIgnoresLocked(now time.Time) {
	for id, until := range e.ignores {
		if now.After(until) {
			delete(e.ignores, id)
		}
	}
	for len(e.ignores) > maxIgnores {
		oldestID := ""
		var oldest time.Time
		for id, until := range e.ignores {
			if oldestID == "" || until.Before(oldest) {
				oldestID, oldest = id, until
			}
		}
		if oldestID == "" {
			break
		}
		delete(e.ignores, oldestID)
	}
}

// allowlisted 判断阶段实体是否命中白名单（按阶段携带的字段尽力匹配，
// 与 allow.Match 的五类型语义一致）。
func (e *Engine) allowlisted(s Stage) bool {
	if e.opts.Allow == nil {
		return false
	}
	if hit, _ := e.opts.Allow.Match(s.Hash, s.Path, s.Signer, "", s.Name, s.CmdLine); hit {
		return true
	}
	// 持久化阶段：信任判断针对"指向的可执行"，不是登记项名字
	if s.ItemPath != "" {
		if hit, _ := e.opts.Allow.Match(s.Hash, s.ItemPath, s.Signer, "", s.ItemName, ""); hit {
			return true
		}
	}
	return false
}

// PurgeAllowlisted 在白名单更新后回收"含被信任实体"的进行中链。
//
// 与服务端 AddAllowlist 的"加白即回收"语义对齐：白名单在 Feed 时只拦
// 新阶段，已经收集进 pending 链的阶段不受影响——不回收的话，"运维刚
// 加白、下一秒链告警照样发出"的滞后误报就成了流程破洞。加白生效的
// 瞬间，任何环节命中白名单的未完成链整体作废。返回回收的链数。
func (e *Engine) PurgeAllowlisted() int {
	if e == nil || e.opts.Allow == nil {
		return 0
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	removed := 0
	for id, m := range e.machines {
		purge := false
		for _, s := range m.stages {
			if e.allowlisted(s) {
				purge = true
				break
			}
		}
		if purge {
			delete(e.machines, id)
			removed++
		}
	}
	return removed
}

// ruleKey 拼规则级 map key（\x00 分隔避免规则名与 key 混淆）。
func ruleKey(ruleID, key string) string {
	return ruleID + "\x00" + key
}

// procKey 是单进程链的实体口径：PID + 启动时间（与采集器 isNewProcess
// 同源的 PID 复用防线）。任一字段缺失仍可成 key（StartTime 为零时退化为
// PID 粒度，采集源不提供 CreateTime 的机器上如此）。
func procKey(s Stage) string {
	if s.PID == 0 {
		return ""
	}
	return strconv.FormatUint(uint64(s.PID), 10) + ":" +
		strconv.FormatInt(s.StartTime.Unix(), 10)
}

// pidKey 仅按 PID 关联（INJECT-OUT 用）：mem 阶段的 StartTime 是
// "首次观察到"口径、conn 阶段是采集器真实启动时间口径，两者不同源，
// 做进 key 会把同一进程劈成两个 key 导致链永不闭合。PID 复用窗口
// （15min）内撞号的概率远低于口径不一致造成的漏检。
func pidKey(s Stage) string {
	if s.PID == 0 {
		return ""
	}
	return strconv.FormatUint(uint64(s.PID), 10)
}

// normPath 归一化路径用于 PERSIST-RUN 的链 key：持久化项解析出的路径与
// 进程镜像路径要能对上（大小写、斜杠方向差异）。
func normPath(p string) string {
	if p == "" {
		return ""
	}
	p = strings.ReplaceAll(p, "/", "\\")
	return strings.ToLower(strings.TrimSpace(p))
}

// outboundPeer 判断对端是否算"外联"：排除回环与未指定地址。
// 广播/组播不区分——单进程对非常规远端发起流量本身就是链的证据。
func outboundPeer(ip string) bool {
	if ip == "" || ip == "0.0.0.0" || ip == "::" || ip == "::1" {
		return false
	}
	return !strings.HasPrefix(ip, "127.")
}
