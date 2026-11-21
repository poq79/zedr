// Package ransom 实现探针侧的勒索软件诱饵（canary）与删除/改名速率检测。
//
// 检测思路（对标业界 canary file 实践，但坚持透明原则）：
//  1. 在指定目录放置内容透明的诱饵文件——勒索软件加密/删除时必然碰到它们，
//     误报面小、无需内容特征；诱饵内容写明用途，不做隐形诱饵（隐私透明
//     是本产品的产品原则，用户有权知道自己机器上多出来的文件是什么）；
//  2. 统计 60s 滑动窗口内的删除/改名加权速率——批量改后缀（a.docx →
//     a.encrypted）是加密器的强特征，权重高于普通删除。
//
// 诚实边界（做不到什么就说什么）：
//   - 无法归因到进程：USN 记录与 ReadDirectoryChangesW 都不带发起者 PID，
//     告警只能说明"发生了什么"，不能说明"谁干的"——判定为 suspicious
//     而非 malicious 就是这个原因，进程归因留给上层关联引擎；
//   - 只覆盖诱饵文件与删除/改名速率两类信号，不做全盘内容加密检测
//     （读盘比对内容哈希的成本与用户态低侵入原则冲突）；诱饵本体由
//     周期自检做内容比对（v0.9.10 深化：RDCW 覆盖不到的 Documents
//     诱饵被原地改写也能抓到），发现不符只告警不恢复（覆盖=销毁证据）；
//   - 人工删除诱饵会触发 medium 观察级告警（"可能是人工删除，请人工确认"），
//     透明内容已尽量降低这种概率，但无法杜绝；
//   - USN 来源只有 leaf name，不知道完整路径（解析完整路径需要 OpenFileById
//     提权遍历，见 winapi/usn.go 的取舍），摘要中如实标注；
//   - 窗口统计是内存态，探针重启后从零开始。重启瞬间正是攻击窗口，但
//     诱饵缺失会被静默重建（计数不告警），启动补采会把停机窗口内的删除
//     事件补投进来，不会双重告警也不会漏掉窗口内的诱饵篡改。
//
// 并发纪律：Consume 可被多个 goroutine 同时调用（RDCW 回调 goroutine +
// USN 轮询 goroutine）；Defense 内部一把互斥锁保护窗口与冷却表，回调
// OnFinding 在锁外调用，消费方再自己的线程安全由自己保证。
package ransom

import (
	"context"
	"crypto/sha256"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"zedr/internal/model"
)

// 诱饵文件名集合。覆盖常见文档类型（office/文本/PDF），数量刻意少：
// 每个目录 4 个，噪声面与检测面平衡。改这份名单会让已部署机器上的旧诱饵
// 变成"孤儿文件"，增删前先想清楚。
var canaryNames = []string{
	"backup_report.docx",
	"预算汇总.xlsx",
	"server_notes.txt",
	"project_brief.pdf",
}

// canaryContent 是诱饵文件的统一内容。必须透明：写明是谁放的、干什么用、
// 删了会怎样。内容恒定才能用 sha256 判"被篡改"。
const canaryContent = "本文件由 Z-EDR 探针放置，用于篡改检测，请勿删除。\r\n" +
	"This is a decoy file placed by Z-EDR for tamper detection. Do not delete.\r\n" +
	"删除、改名或加密本文件会触发安全告警。\r\n" +
	"Deleting, renaming or encrypting this file will raise a security alert.\r\n"

const (
	// RuleID 前缀固定的两条规则，服务端按此关联展示与统计。
	RuleCanary = "FILE-CANARY"
	RuleRansom = "FILE-RANSOM"

	// windowDur 是速率统计窗口。60s 足够覆盖加密器的爆发期（真实加密
	// 通常是秒级万级文件），又不至于让慢速"软删除"工具积累到阈值。
	windowDur = 60 * time.Second
	// windowCap 是窗口事件环形队列容量上限：4096 条 × ~100B ≈ 0.4MB，
	// 触顶说明事件速率远超检测设计（正常 60s 内远到不了），丢最旧并
	// 用 Dropped() 诚实计数，绝不静默膨胀内存。
	windowCap = 4096

	// selfCheckInterval 周期自检：诱饵缺失重建 + 窗口过期修剪。
	selfCheckInterval = 30 * time.Second

	// 冷却键：速率检测器全局共用一个键。
	rateCooldownKey = "ransom-rate"
)

// Event 是喂给 Defense 的一条文件事件，来源有两个：
//   - rdcw：winapi.FileWatcher 的 OnFileEvent（完整路径，Kind 原样透传）；
//   - usn：winapi.ReadUSNJournal 轮询/补采（Path 只有 leaf name）。
type Event struct {
	Kind    string // "added"/"removed"/"modified"/"renamed"/"renamed_old"
	Path    string // 完整路径；USN 来源只有 leaf name
	OldPath string // renamed 时旧路径（可为空=旧名未知）
	When    time.Time
	Source  string // "rdcw" | "usn"
}

// Finding 是产出给统一告警出口的检测结论。
type Finding struct {
	RuleID   string
	Severity model.Severity
	Score    int
	Verdict  model.Verdict
	Title    string
	Summary  string
	MITRE    []string
	Notes    []string // 证据明细（路径/计数/来源），直接进告警证据链
	// HourlyFP 置位时接线层把指纹按小时分桶（规则+小时），替代默认的
	// "规则+证据路径"。观察级速率发现用：持续构建/churn 场景下 Top 目录
	// 随批次漂移，路径指纹互不去重，等于每个冷却周期（15min）都出一行
	// 新告警（实测 13 天 888 行）；按小时分桶交给服务端窗口合并，强度
	// 仍由 duplicate 计数保留。升级级（同目录集中/诱饵关联）不置位——
	// 真实信号值得按目标路径独立成行。
	HourlyFP bool
}

// Options 是 Defense 的构造参数。
type Options struct {
	// CanaryDirs 放置诱饵的目录。不存在的目录跳过且不代建——探针不应在
	// 用户机器上凭空造目录，目录选择是部署策略的事。
	CanaryDirs []string
	// RateThreshold 60s 窗口加权删除/改名计数的触发阈值，<=0 用默认 20。
	RateThreshold int
	// Cooldown 同一冷却键的告警冷却时长，<=0 用默认 15 分钟。
	Cooldown time.Duration
	Log      *slog.Logger
	// OnFinding 检测结论出口（主线接线到统一告警出口）。在锁外同步调用。
	OnFinding func(Finding)
	// Now 供测试注入合成时钟；nil 用 time.Now。
	Now func() time.Time
	// ChurnMarkers 覆盖高频增删目录特征清单（nil 用内置 churnMarkers）。
	// 测试注入空切片：测试的临时目录在 CI 上恰是 %TEMP%（命中内置
	// \appdata\local\temp\ 特征 → 速率事件被全滤，2026-11-21 首次
	// GitHub Actions 实测抓出），而测试语义就是"目录不在 churn 特征区"。
	ChurnMarkers []string
}

type canarySpec struct {
	key     string // 规范化小写路径（匹配键）
	display string // 原始大小写路径（摘要显示）
	name    string // 小写 leaf name
}

type windowEvent struct {
	at     time.Time
	weight int
	kind   string
	path   string // 完整路径（rdcw）或 leaf name（usn）
	source string
}

// Defense 是勒索检测器：诱饵管理 + 速率窗口 + 冷却。
// 一律指针使用，禁止按值拷贝（内含锁与 atomic 字段）。
type Defense struct {
	log       *slog.Logger
	onFinding func(Finding)
	now       func() time.Time
	cooldown  time.Duration
	threshold int
	churn     []string

	// canaries/names 在 New 里一次成型后只读（重建只补文件不登记新键），
	// 因此 Consume 读它们不需要额外同步。
	canaries map[string]canarySpec // 规范化路径 -> 诱饵
	names    map[string][]string   // 小写 leaf name -> 候选规范化路径（USN 只有文件名，同名诱饵可分布在多个目录）
	dirs     []string              // 原始 CanaryDirs（usnPollVolumes 圈卷用）

	contentHash [sha256.Size]byte

	mu      sync.Mutex
	lastHit map[string]time.Time // 冷却键 -> 上次产出 Finding 的时刻
	// canaryRecent 记录每个诱饵 24h 内已发射 Finding 的时刻，驱动
	// "杀软隔离循环"的递进冷却（canaryFinding；速率键 rateCooldownKey
	// 不进这个表——速率告警有自己的小时分桶指纹）。
	canaryRecent map[string][]time.Time
	window       []windowEvent
	// usnWeight 是窗口内 USN 来源事件的权重和（与 weightSum 同步维护）。
	// USN 事件只有 leaf 文件名，churn 目录过滤对它天然失效——安全软件
	// 引擎更新风暴（实测火绒单分钟 3000+ 删除）经 USN 灌进窗口，既能
	// 触发 FILE-RANSOM 又能把 rateActive 推过半阈值把诱饵告警升级成假
	// critical。封顶后：USN 单源永远够不到任何一条门控线，真实爆发由
	// RDCW（目录可知、可过滤、不受限）驱动，USN 只作小幅助推。
	usnWeight int
	usnCap    int
	weightSum int // 窗口内权重和的增量维护：爆发期每秒数千次 Consume，
	// 每次都 O(n) 扫窗口会烧掉探针的 CPU 预算
	lastRate time.Time // 速率检测器最近一次触发的时刻（canary 分级用）
	// rateEscalated：当前速率冷却窗口内已补发过升级告警（每窗口最多
	// 一次，见 rateFinding 的升级分支重排注释）。
	rateEscalated bool
	dropped       atomic.Int64
	rebuilt       atomic.Int64
	usnCapped     atomic.Int64 // 因 USN 封顶未进速率窗的事件数（可观测口径）

	stop     chan struct{}
	stopOnce sync.Once
	wg       sync.WaitGroup
}

// New 构造 Defense 并完成首次诱饵落盘：
//   - 缺失 → 静默创建（重启/清理是正常路径，计数不告警）；
//   - 存在且内容一致 → 不动（不重写，避免自身触发 modified 事件）；
//   - 存在但内容不一致 → 视为已被篡改，产出 medium 级 canary Finding
//     （此时窗口为空、速率未触发，按分级规则只能是 medium）。
func New(opt Options) *Defense {
	d := &Defense{
		log:          opt.Log,
		onFinding:    opt.OnFinding,
		now:          opt.Now,
		cooldown:     opt.Cooldown,
		threshold:    opt.RateThreshold,
		canaries:     make(map[string]canarySpec, len(opt.CanaryDirs)*len(canaryNames)),
		names:        make(map[string][]string, len(canaryNames)),
		lastHit:      make(map[string]time.Time),
		canaryRecent: make(map[string][]time.Time, len(canaryNames)),
		stop:         make(chan struct{}),
	}
	if d.now == nil {
		d.now = time.Now
	}
	if opt.ChurnMarkers == nil {
		d.churn = churnMarkers
	} else {
		d.churn = opt.ChurnMarkers
	}
	if d.cooldown <= 0 {
		d.cooldown = 15 * time.Minute
	}
	if d.threshold <= 0 {
		d.threshold = 20
	}
	// USN 贡献封顶 = 阈值/2 - 1：低于 rateActive 的半阈值线（canary
	// 升级门控）也低于触发阈值本身——目录盲源在这两条线上都没有
	// 单独表决权。threshold ≤ 3 时封顶取 0（USN 完全不进速率窗）。
	d.usnCap = d.threshold/2 - 1
	if d.usnCap < 0 {
		d.usnCap = 0
	}
	if d.log == nil {
		d.log = slog.Default()
	}
	d.contentHash = sha256.Sum256([]byte(canaryContent))

	for _, dir := range opt.CanaryDirs {
		if dir == "" {
			continue
		}
		d.dirs = append(d.dirs, dir)
		for _, name := range canaryNames {
			d.plant(filepath.Join(dir, name))
		}
	}
	return d
}

// plant 校验/创建单个诱饵并登记到只读集合。New 期单 goroutine 调用。
func (d *Defense) plant(path string) {
	key := normPath(path)
	if _, dup := d.canaries[key]; dup {
		return
	}
	display := filepath.Clean(path)
	name := strings.ToLower(filepath.Base(path))

	raw, err := os.ReadFile(path)
	switch {
	case err == nil:
		if sha256.Sum256(raw) != d.contentHash {
			// 存在但内容不匹配：可能是用户改过，也可能是攻击者已经来过。
			// 按透明原则不悄悄覆盖（那会销毁证据），登记后照常检测。
			d.canaries[key] = canarySpec{key: key, display: display, name: name}
			d.names[name] = append(d.names[name], key)
			d.emitFinding(d.canaryFinding(tamperHit{
				key: key, display: display,
				kind: "modified", source: "self-check",
				when: d.now(),
				note: "启动自检发现诱饵内容与预期不符（可能被篡改，请人工确认）",
			}))
			return
		}
	case os.IsNotExist(err):
		// 静默重建：重启/清理场景是正常路径，绝不能变成告警源
		if werr := os.WriteFile(path, []byte(canaryContent), 0o644); werr != nil {
			d.log.Warn("canary_plant_failed", "path", display, "err", werr)
			return
		}
		d.rebuilt.Add(1)
	default:
		// 权限等其他错误：跳过该诱饵，不假装它存在
		d.log.Warn("canary_plant_skipped", "path", display, "err", err)
		return
	}
	d.canaries[key] = canarySpec{key: key, display: display, name: name}
	d.names[name] = append(d.names[name], key)
}

// Start 启动周期自检 goroutine（诱饵缺失重建 + 窗口过期修剪）。
// ctx 取消或 Close 都会退出。
func (d *Defense) Start(ctx context.Context) {
	if d == nil {
		return
	}
	d.wg.Add(1)
	go func() {
		defer d.wg.Done()
		t := time.NewTicker(selfCheckInterval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-d.stop:
				return
			case <-t.C:
				d.maintain()
			}
		}
	}()
}

// Close 停止自检 goroutine 并等待退出。可重复调用。
func (d *Defense) Close() {
	if d == nil {
		return
	}
	d.stopOnce.Do(func() { close(d.stop) })
	d.wg.Wait()
}

// CanaryDirs 返回原始诱饵目录列表（app 层圈 USN 轮询卷用）。
func (d *Defense) CanaryDirs() []string {
	if d == nil {
		return nil
	}
	return d.dirs
}

// OneCanaryPath 返回一个当前真实存在的诱饵文件路径（检测演练自测用）。
// 全部不存在时返回空串——演练步骤据此记 skipped 而不是失败；
// 只做存在性探测，不动诱饵内容，删除/改写由演练步骤自己执行并负责。
// canaries 键集在 New 后只读，无锁遍历是安全的（与 Consume 同口径）。
func (d *Defense) OneCanaryPath() string {
	if d == nil {
		return ""
	}
	for key := range d.canaries {
		if _, err := os.Stat(key); err == nil {
			return key
		}
	}
	return ""
}

// Dropped 返回速率窗口触顶后被丢弃的事件数（诚实计数器）。
func (d *Defense) Dropped() int64 {
	if d == nil {
		return 0
	}
	return d.dropped.Load()
}

// Rebuilt 返回启动与自检累计重建的诱饵数（运维观察用，不进告警）。
func (d *Defense) Rebuilt() int64 {
	if d == nil {
		return 0
	}
	return d.rebuilt.Load()
}

// USNCapped 返回因 USN 封顶未进速率窗的事件数（运维观察用：AV 更新
// 风暴期该值会显著增长，是"误报被挡在门外"的直接证据）。
func (d *Defense) USNCapped() int64 {
	if d == nil {
		return 0
	}
	return d.usnCapped.Load()
}

// Consume 接收一条文件事件，线程安全。canary 命中与速率触发可能在同一次
// 调用里各产出一条 Finding（规则不同，都该报）。
func (d *Defense) Consume(ev Event) {
	if d == nil {
		return
	}
	when := ev.When
	if when.IsZero() {
		when = d.now()
	}

	d.mu.Lock()
	d.pruneLocked(d.now())

	var findings []Finding
	if hit := d.matchCanary(ev); hit != nil {
		if f := d.canaryFinding(*hit); f.RuleID != "" {
			findings = append(findings, f)
		}
	}
	// 速率窗口只收新鲜事件：补采来的陈旧删除对"此刻正在爆发"没有意义，
	// 但对 canary 命中仍然有效（上面已处理），两个用途分开看。
	// USN 来源在此封顶（usnCap 的依据见 Defense.usnWeight 注释）：超出
	// 封顶的 USN 事件直接不进窗——省掉窗口 churn，也不挤占 RDCW 证据
	// 的窗口容量（windowCap 触顶会按 FIFO 淘汰，风暴期 USN 会把真正
	// 带目录信息的 rdcw 事件顶出去）。
	if w := d.rateWeight(ev); w > 0 && !when.Before(d.now().Add(-windowDur)) {
		if ev.Source == "usn" && d.usnWeight+w > d.usnCap {
			d.usnCapped.Add(1)
		} else {
			d.pushLocked(when, w, ev)
			if f := d.rateFinding(when); f.RuleID != "" {
				findings = append(findings, f)
			}
		}
	}
	d.mu.Unlock()

	for _, f := range findings {
		if d.onFinding != nil {
			d.onFinding(f)
		}
	}
}

// maintain 是周期自检：内容校验 + 缺失诱饵静默重建 + 窗口修剪。
//
// 内容校验（v0.9.10 深化新增）收口一个漏报盲区：Documents 不在 RDCW
// 监控目录内，那里的诱饵被"原地改写不删不改名"时（少见但存在的加密
// 形态），文件系统事件一路都收不到——16 个小文件每 30s 读一遍比对
// sha256，成本可忽略。发现不符只告警不恢复（覆盖=销毁证据）。
func (d *Defense) maintain() {
	var hits []tamperHit
	for _, spec := range d.canaries {
		raw, err := os.ReadFile(spec.display)
		switch {
		case err == nil:
			if sha256.Sum256(raw) != d.contentHash {
				hits = append(hits, tamperHit{
					key: spec.key, display: spec.display,
					kind: "modified", source: "self-check", when: d.now(),
					note: "周期自检发现诱饵内容与预期不符（可能被篡改，请人工确认）",
				})
			}
		case os.IsNotExist(err):
			if werr := os.WriteFile(spec.display, []byte(canaryContent), 0o644); werr != nil {
				d.log.Warn("canary_rebuild_failed", "path", spec.display, "err", werr)
				continue
			}
			d.rebuilt.Add(1)
			d.log.Info("canary_rebuilt", "path", spec.display)
		default:
			// 权限类错误：不动，下轮再试
			continue
		}
	}
	d.mu.Lock()
	var findings []Finding
	for _, h := range hits {
		if f := d.canaryFinding(h); f.RuleID != "" {
			findings = append(findings, f)
		}
	}
	d.pruneLocked(d.now())
	d.mu.Unlock()
	for _, f := range findings {
		d.emitFinding(f)
	}
}

// ---------------------------------------------------------------- canary

// tamperHit 是一次诱饵命中的归一化描述。
type tamperHit struct {
	key     string // 冷却键（诱饵路径或 usn:leaf）
	display string // 摘要用路径
	kind    string // 事件 Kind 或 "modified"（自检内容不符）
	source  string // "rdcw"/"usn"/"self-check"
	when    time.Time
	path    string // 事件 Path（证据）
	oldPath string // 事件 OldPath（证据）
	note    string // 额外说明（USN 无路径/自检语境）
	cands   []string
}

// matchCanary 判定事件是否命中诱饵。锁内调用。
//
// 匹配口径：rdcw 来源（有完整路径）只做精确路径匹配——leaf name 全局同名
// 文件太多，按名匹配会把别处同名文档的删除算到诱饵头上；usn 来源只有
// leaf name，只能按名匹配（新旧名都试：诱饵被改成 a.encrypted 时新名已
// 不是诱饵名，只有旧名能对上），摘要里如实标注路径未知。
//
// USN 同名碰撞验真（2026-11-18 实测事故）：go test 的勒索夹具在 t.TempDir
// 建删 backup_report.docx，真探针全盘 USN 只认 leaf 名 → 误判真诱饵被篡改
// 且测试 churn 灌进速率窗 → critical（真诱饵 mtime 完好）。验真口径：
// 删除/篡改是事实行为，真被事件碰过的候选此刻必然"缺失，或 mtime 晚于
// 事件时刻被重写"；仍完好（mtime 早于事件）的候选与本事件无关，吸收为
// 碰撞。诚实边界：攻击者删完诱饵立刻回填同内容文件可绕过验真，但那需要
// 先读到透明诱饵的内容，成本远高于换一个目标。
func (d *Defense) matchCanary(ev Event) *tamperHit {
	switch ev.Kind {
	case "removed", "modified", "renamed", "renamed_old":
	default:
		return nil
	}
	hit := &tamperHit{kind: ev.Kind, source: ev.Source, when: ev.When,
		path: ev.Path, oldPath: ev.OldPath}
	if ev.Source == "usn" {
		leaf := strings.ToLower(filepath.Base(strings.TrimSpace(ev.Path)))
		if _, ok := d.names[leaf]; !ok && ev.OldPath != "" {
			leaf = strings.ToLower(filepath.Base(strings.TrimSpace(ev.OldPath)))
		}
		cands, ok := d.names[leaf]
		if !ok {
			return nil
		}
		// 验真：剔除与事件时刻不符的完好候选（锁内 os.Stat 只发生
		// 在 leaf 命中这条罕见路径上，≤诱饵目录数，µs 级）。
		real := make([]string, 0, len(cands))
		for _, k := range cands {
			if d.usnHitReal(k, ev.When) {
				real = append(real, k)
			}
		}
		if len(real) == 0 {
			if d.log != nil {
				d.log.Info("canary_usn_collision_absorbed",
					"leaf", leaf, "candidates", len(cands))
			}
			return nil
		}
		if len(real) == 1 {
			// 验真后唯一候选：归属明确，冷却键/摘要回归诱饵本体
			if spec, ok := d.canaries[real[0]]; ok {
				hit.key = spec.key
				hit.display = spec.display
				hit.note = "USN 记录仅文件名，验真后唯一候选即本诱饵"
				return hit
			}
		}
		// 多个候选仍相符：无法进一步归属，冷却键用 leaf
		hit.key = "usn:" + leaf
		hit.display = strings.Join(d.specDisplays(real), ", ")
		hit.cands = real
		hit.note = "路径未知（USN 记录仅文件名），验真后多个候选仍相符"
		return hit
	}
	if spec, ok := d.canaries[normPath(ev.Path)]; ok {
		hit.key = spec.key
		hit.display = spec.display
		return hit
	}
	// renamed 的旧路径命中也算：诱饵被改名走，Path 已是新名
	if spec, ok := d.canaries[normPath(ev.OldPath)]; ok {
		hit.key = spec.key
		hit.display = spec.display
		hit.note = "诱饵被改名（旧路径命中）"
		return hit
	}
	return nil
}

// usnHitReal 验证候选诱饵是否真被本事件碰过（锁内调用，见 matchCanary
// 头注释的验真口径）。removed/renamed 离开后文件必然不存在；modified/
// renamed_old 原地改写则 mtime ≥ 事件时刻。-2s 容差吸收 USN 记录时刻与
// NTFS mtime 的同源时钟差。stat 失败（缺失=与删除相符；权限等其他
// 错误=无法证伪）一律按相符处理——验真只吸收"完好且早于事件"这一种
// 可证伪形态，宁可多报不可漏报。
func (d *Defense) usnHitReal(key string, when time.Time) bool {
	spec, ok := d.canaries[key]
	if !ok {
		return false
	}
	st, err := os.Stat(spec.display)
	if err != nil {
		return true
	}
	if when.IsZero() {
		return true
	}
	return !st.ModTime().Before(when.Add(-2 * time.Second))
}

// specDisplays 把 spec key 列表转成摘要路径列表。
func (d *Defense) specDisplays(keys []string) []string {
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		if spec, ok := d.canaries[k]; ok {
			out = append(out, spec.display)
		}
	}
	return out
}

// canaryRepeatFloor/canaryRepeatCooldown 是"杀软隔离循环"的递进节流参数：
// 同一诱饵 24h 内已发射 ≥canaryRepeatFloor 次告警后，该键冷却升到
// canaryRepeatCooldown。动机（2026-11-18 实测）：本地杀软把透明诱饵当
// 可疑样本反复隔离，探针 30s 自检重建 → 再隔离 → 再告警，单键每 15min
// 一条、四个诱饵一天 25 条——每条都是"真的有人删了绊线"，但值班看到
// 第三条起就只剩噪声价值。递进到 2h 后保留告警能力（真攻击者反复
// 触碰仍可见）同时把稳态噪声压掉一个量级。
const (
	canaryRepeatFloor    = 3
	canaryRepeatCooldown = 2 * time.Hour
	canaryRecentWindow   = 24 * time.Hour
)

// canaryFinding 产出诱饵命中 Finding，冷却内返回零值（RuleID 为空）。
// Consume 在持锁状态下调用；New 的启动自检在单线程无锁状态下调用——
// 两条路径没有并发交叠（Start 之前自检已完成），共用同一把锁的调用方
// 无需重入。分级：速率 ≥ 阈值一半或速率检测器刚触发过 → critical；否则 medium。
func (d *Defense) canaryFinding(hit tamperHit) Finding {
	// 24h 滚动窗口：只统计已发射的告警（被冷却吞掉的尝试不计——
	// 否则杀软 30s 一次的隔离循环会瞬间把冷却推到 2h，第一条告警
	// 之后的信号全灭）。
	recent := d.canaryRecent[hit.key]
	cut := hit.when.Add(-canaryRecentWindow)
	kept := recent[:0]
	for _, t := range recent {
		if t.After(cut) {
			kept = append(kept, t)
		}
	}
	d.canaryRecent[hit.key] = kept
	prior := len(kept)
	// 门控与提示分两档：本次发射若是第 3 条（prior=2），它本身仍按普通
	// 冷却门控放行并携带"杀软隔离循环"提示——提示必须挂在还能被看见的
	// 那条上；从第 4 次尝试起（prior>=3）门控升到 2h。
	escalated := prior >= canaryRepeatFloor
	cooldown := d.cooldown
	if escalated {
		cooldown = canaryRepeatCooldown
	}

	if last, ok := d.lastHit[hit.key]; ok && hit.when.Sub(last) < cooldown {
		return Finding{}
	}
	d.lastHit[hit.key] = hit.when
	d.canaryRecent[hit.key] = append(d.canaryRecent[hit.key], hit.when)
	repeated := prior+1 >= canaryRepeatFloor

	sev, score := model.SeverityMedium, 45
	title := "诱饵文件被篡改"
	summary := fmt.Sprintf("诱饵文件 %s 被 %s", hit.display, kindText(hit.kind))
	if hit.note != "" {
		summary += "；" + hit.note
	}
	// 分级依据见任务口径：单独触碰大概率是人工误删，速率叠加才升级
	if d.rateActive(hit.when) {
		sev, score = model.SeverityCritical, 75
		title = "诱饵文件被篡改且删除/改名速率异常（疑似勒索软件）"
		summary += fmt.Sprintf("；当前 60s 窗口加权计数 %d（阈值 %d），符合勒索软件行为特征",
			d.weightedLocked(), d.threshold)
	} else {
		summary += "；可能是人工删除，请人工确认"
	}
	// 递进冷却的诚实提示：同键高频复发大概率是杀软隔离循环而不是
	// 攻击者（攻击者删一次就够了，反复删的唯一常见解释是"探针重建、
	// 杀软再隔离"的拉锯）。提示操作员给出路，而不是让他反复处理同一告警。
	if repeated {
		summary += fmt.Sprintf("；该诱饵 24 小时内已第 %d 次被触碰（本键告警冷却已延长到 %s）——大概率是本地安全软件把诱饵当可疑样本反复隔离，请在杀软隔离区核实，确认后将诱饵目录加入杀软排除项；若并非杀软所为，请按针对性破坏处置",
			len(d.canaryRecent[hit.key]), canaryRepeatCooldown)
	}

	notes := []string{
		fmt.Sprintf("source=%s kind=%s", hit.source, hit.kind),
		fmt.Sprintf("path=%s", hit.path),
	}
	if hit.oldPath != "" {
		notes = append(notes, fmt.Sprintf("old_path=%s", hit.oldPath))
	}
	if hit.cands != nil {
		notes = append(notes, fmt.Sprintf("候选诱饵=%d 个", len(hit.cands)))
	}
	notes = append(notes, fmt.Sprintf("when=%s", hit.when.Format(time.RFC3339)))

	return Finding{
		RuleID:   RuleCanary,
		Severity: sev,
		Score:    score,
		Verdict:  model.VerdictSuspicious,
		Title:    title,
		Summary:  summary,
		MITRE:    []string{"T1565.001"}, // Data Manipulation: Stored Data Manipulation
		Notes:    notes,
	}
}

// rateActive 判定速率侧是否处于"活跃"状态：窗口计数过半阈值，或速率
// 检测器在冷却期内触发过。锁内调用。
func (d *Defense) rateActive(when time.Time) bool {
	if !d.lastRate.IsZero() && when.Sub(d.lastRate) < d.cooldown {
		return true
	}
	half := d.threshold / 2
	if half < 1 {
		half = 1
	}
	return d.weightedLocked() >= half
}

// ---------------------------------------------------------------- 速率

// churnMarkers 是"天然高频增删"的目录特征：浏览器缓存、系统临时目录、
// 回收站、更新器暂存。这些位置的批量删除/改名是正常软件行为（实测一次
// 浏览器缓存清理 + 一次 go build 链接即可在 60s 内贡献 20+ 权重；清空
// 回收站同理——文件改名进 $Recycle.Bin 再批量删除），剔除后速率窗口
// 才保得住信噪比。USN 事件只有 leaf name 无法判目录——这类事件保留
// 计数，由"独立速率只做观察级"的定级策略兜底（见 rateFinding）。
//
// 安全软件/系统更新器自维护目录同属此类（2026-11-18 实测：火绒在
// C:\ProgramData\Huorong\Sysdiag 的引擎/特征库轮换单轮删除 59~61 个
// 文件，直接灌满速率窗口）。它们还带来第二重伤害：窗口被 AV 自清理
// 灌满后，用户手工删一个诱饵就会被"速率活跃"联动升级成 critical——
// 剔除后速率窗口才反映真实用户目录的删除形态。诱饵关联路径不受影响
// （诱饵在 Documents 等用户目录，真勒索仍会同时命中诱饵+速率）。
// USN 事件只有 leaf name，本表对它天然失效——USN 贡献由 usnCap
// 封顶兜底（见 Defense.usnWeight 注释），不再"保留计数"。
var churnMarkers = []string{
	`\appdata\local\temp\`, `\appdata\local\temp-`, `\windows\temp\`,
	// unix 风格（churnPath 会把 / 归一成 \，所以 `\tmp\` 同时覆盖
	// Linux 的 /tmp 与 Windows 的任意 \tmp\ 目录）——GitHub Actions
	// linux job 的 t.TempDir()=/tmp/... 首跑实测漏网
	`\tmp\`, `\var\tmp\`,
	`\cache\`, `\cache_data`, `\code cache`, `\gpucache`, `\inetcache\`,
	`\crashpad\`, `\go-build\`, `\npm-\`, `\pip-\`, `\.tmp`,
	`$recycle.bin`, `\recycle`,
	// 安全软件自维护：火绒（Sysdiag 引擎轮换）、360 系、Defender
	// （Definition Updates/Clean Store 的旧特征库清理）
	`\programdata\huorong\`, `\programdata\360`,
	`\programdata\microsoft\windows defender\`,
	// 系统更新器：Windows Update 下载缓存清理、浏览器自更新暂存
	// （ProgramData\Mozilla-<hash>\updates，实测单轮 20+ 删除）
	`\windows\softwaredistribution\download`, `\programdata\mozilla-`,
}

// churnPath 判断路径是否落在高频增删目录（rdcw 来源有完整路径才判得了）。
func (d *Defense) churnPath(p string) bool {
	low := strings.ToLower(strings.ReplaceAll(p, "/", `\`))
	for _, m := range d.churn {
		if strings.Contains(low, m) {
			return true
		}
	}
	return false
}

// rateWeight 返回事件在速率窗口里的权重：removed=1；renamed 新旧扩展名
// 不同=2（批量改后缀是加密器强特征）、相同或旧名未知=1；其余不计。
// 高频增删目录（缓存/临时目录）恒为 0。
func (d *Defense) rateWeight(ev Event) int {
	// 路径分隔符两种都要认：unix 路径只有 /，首版只查 \ 导致 linux 上
	// churn 过滤整体短路（GitHub Actions linux job 首跑实测抓出）
	if ev.Path != "" && (strings.ContainsRune(ev.Path, '\\') || strings.ContainsRune(ev.Path, '/')) && d.churnPath(ev.Path) {
		return 0
	}
	switch ev.Kind {
	case "removed":
		return 1
	case "renamed":
		if ev.OldPath != "" &&
			!strings.EqualFold(filepath.Ext(ev.OldPath), filepath.Ext(ev.Path)) {
			return 2
		}
		return 1
	}
	return 0
}

func (d *Defense) pushLocked(at time.Time, weight int, ev Event) {
	d.window = append(d.window, windowEvent{
		at: at, weight: weight, kind: ev.Kind, path: ev.Path, source: ev.Source,
	})
	d.weightSum += weight
	if ev.Source == "usn" {
		d.usnWeight += weight
	}
	if len(d.window) > windowCap {
		drop := len(d.window) - windowCap
		for _, e := range d.window[:drop] {
			d.weightSum -= e.weight
			if e.source == "usn" {
				d.usnWeight -= e.weight
			}
		}
		d.dropped.Add(int64(drop))
		d.window = append(d.window[:0], d.window[drop:]...)
	}
}

func (d *Defense) pruneLocked(now time.Time) {
	cut := now.Add(-windowDur)
	i := 0
	for i < len(d.window) && d.window[i].at.Before(cut) {
		d.weightSum -= d.window[i].weight
		if d.window[i].source == "usn" {
			d.usnWeight -= d.window[i].weight
		}
		i++
	}
	if i > 0 {
		d.window = append(d.window[:0], d.window[i:]...)
	}
}

func (d *Defense) weightedLocked() int {
	return d.weightSum
}

// rateFinding 产出速率 Finding（冷却内返回零值）。摘要带窗口计数与
// 涉及目录 Top3（rdcw 有完整路径）或 leaf name 样例（usn）。
//
// 目录集中升级分支（2026-11-18 可达性重排）：原判定"Top1 占比 ≥0.6 且
// 总量 ≥2×阈值"挂在首触发点——但 rateFinding 每事件评估，w 首越阈值时
// ≤ 阈值+2（单事件最大权重 2），2×阈值经此路径永不可达，2026-11-07
// 引入以来从未在生产触发过（潜伏缺陷，11-18 复盘实锤）。重排为两级：
//   - 首触发（w ≥ 阈值）按普通观察级发射（同窗口若已满足升级条件，
//     首发即 high——突发风暴在两个事件内跨过 2×阈值时仍直接升级）；
//   - 冷却期内 w 继续翻倍（≥2×阈值）且单目录集中占比 ≥0.6 → 补发一条
//     升级告警，同冷却窗口最多补发一次（escalated 置位）。语义保真：
//     "逐文件处理同一目标目录"的加密器持续工作形态，观察级首发后
//     爆发仍在继续就该升级，而不是等下一个冷却周期。
func (d *Defense) rateFinding(when time.Time) Finding {
	w := d.weightedLocked()
	if w < d.threshold {
		return Finding{}
	}
	// 冷却内复查升级：爆发仍在继续（翻倍）且形态集中 → 补发升级
	if last, ok := d.lastHit[rateCooldownKey]; ok && when.Sub(last) < d.cooldown {
		if !d.rateEscalated && w >= 2*d.threshold {
			if f, ok := d.escalateRateFinding(when, w); ok {
				d.rateEscalated = true
				return f
			}
		}
		return Finding{}
	}
	d.lastHit[rateCooldownKey] = when
	d.lastRate = when
	d.rateEscalated = false

	dirCount := map[string]int{}
	var usnSamples []string
	for _, e := range d.window {
		if e.source == "usn" {
			if len(usnSamples) < 8 {
				usnSamples = append(usnSamples, e.path)
			}
			continue
		}
		dirCount[filepath.Dir(e.path)]++
	}
	top := topDirs(dirCount, 3)

	summary := fmt.Sprintf("60 秒窗口内加权删除/改名计数 %d（阈值 %d）", w, d.threshold)
	// 目录集中度：单目录集中爆发（Top1 占比 ≥0.6 且总量 ≥2×阈值）是
	// 加密器"逐文件处理同一目标目录"的形态，首发即升级 high；分散目录
	// 多为用户整理/备份类行为，维持观察级。持续爆发的冷却期复查升级
	// 见函数头注释与 escalateRateFinding。
	escalate := len(top) > 0 && top[0].count*10 >= w*6 && w >= 2*d.threshold
	if escalate {
		summary += fmt.Sprintf("；单目录集中占比 %.0f%%，符合同目录集中加密形态",
			float64(top[0].count)/float64(w)*100)
	}
	if len(top) > 0 {
		parts := make([]string, len(top))
		for i, td := range top {
			parts[i] = fmt.Sprintf("%s(%d)", td.dir, td.count)
		}
		summary += "；涉及目录 Top：" + strings.Join(parts, " ")
	}
	if len(usnSamples) > 0 {
		summary += "；USN 样例：" + strings.Join(usnSamples, ", ") + "（仅文件名）"
	}

	notes := make([]string, 0, len(top)+2)
	for _, td := range top {
		notes = append(notes, fmt.Sprintf("dir=%s removed_or_renamed=%d", td.dir, td.count))
	}
	if d.dropped.Load() > 0 {
		notes = append(notes, fmt.Sprintf("窗口触顶丢弃事件=%d（速率超出检测容量，计数如实）", d.dropped.Load()))
	}
	if n := d.usnCapped.Load(); n > 0 {
		notes = append(notes, fmt.Sprintf("USN 封顶未计入=%d（leaf 无目录信息，单源贡献封顶防 AV 风暴灌窗）", n))
	}

	// 独立速率只做观察级（medium）：真实误报实测（2026-11-03 上线首日）
	// 是浏览器缓存清理 + 构建工具临时目录批量增删——与勒索行为同形，
	// 无进程归因无法分辨。升级路径是关联：同窗口内有诱饵命中 → critical
	//（见 canaryFinding 的 rateActive 分级），那才是"人类不太可能手工
	// 触碰诱饵"的高置信组合。
	summary += "。注意：浏览器缓存清理/编译/解压类正常批量操作也会呈现此形态，请结合目录判断；" +
		"若同时有诱饵文件被触碰会升级为 critical"
	sev, score := model.SeverityMedium, 45
	title := "批量删除/改名行为（观察级，疑似勒索加密）"
	hourly := true
	if escalate {
		sev, score = model.SeverityHigh, 60
		title = "批量删除/改名行为（同目录集中爆发，疑似勒索加密）"
		hourly = false
	}
	return Finding{
		RuleID:   RuleRansom,
		Severity: sev,
		Score:    score,
		Verdict:  model.VerdictSuspicious,
		Title:    title,
		Summary:  summary,
		MITRE:    []string{"T1486"}, // Impact: Data Encrypted for Impact
		Notes:    notes,
		HourlyFP: hourly,
	}
}

type dirCount struct {
	dir   string
	count int
}

// escalateRateFinding 构造冷却期复查的升级告警（锁内调用）。判定口径与
// 首触发点的 escalate 分支一致：Top1 占比 ≥0.6 且 w ≥2×阈值；占比
// 不达则继续等下一个事件（不置 escalated，爆发更集中时仍可补发）。
func (d *Defense) escalateRateFinding(when time.Time, w int) (Finding, bool) {
	dirCount := map[string]int{}
	for _, e := range d.window {
		if e.source == "usn" {
			continue
		}
		dirCount[filepath.Dir(e.path)]++
	}
	top := topDirs(dirCount, 3)
	if len(top) == 0 || top[0].count*10 < w*6 {
		return Finding{}, false
	}
	summary := fmt.Sprintf("60 秒窗口内加权删除/改名计数 %d（阈值 %d），仍在持续攀升；单目录集中占比 %.0f%%，符合同目录集中加密形态——这是对先前观察级告警的升级确认",
		w, d.threshold, float64(top[0].count)/float64(w)*100)
	parts := make([]string, len(top))
	for i, td := range top {
		parts[i] = fmt.Sprintf("%s(%d)", td.dir, td.count)
	}
	summary += "；涉及目录 Top：" + strings.Join(parts, " ")
	notes := make([]string, 0, len(top))
	for _, td := range top {
		notes = append(notes, fmt.Sprintf("dir=%s removed_or_renamed=%d", td.dir, td.count))
	}
	return Finding{
		RuleID:   RuleRansom,
		Severity: model.SeverityHigh,
		Score:    60,
		Verdict:  model.VerdictSuspicious,
		Title:    "批量删除/改名行为（同目录集中爆发，疑似勒索加密）",
		Summary:  summary,
		MITRE:    []string{"T1486"},
		Notes:    notes,
		// 升级级保持路径指纹（HourlyFP=false）：真实集中爆发值得按目标
		// 目录独立成行，不与观察级共用小时桶
	}, true
}

func topDirs(m map[string]int, n int) []dirCount {
	list := make([]dirCount, 0, len(m))
	for dir, c := range m {
		list = append(list, dirCount{dir: dir, count: c})
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].count != list[j].count {
			return list[i].count > list[j].count
		}
		return list[i].dir < list[j].dir // 同计数按名序，保证摘要稳定
	})
	if len(list) > n {
		list = list[:n]
	}
	return list
}

// ---------------------------------------------------------------- 工具

// emitFinding 锁外调用出口（New 期自检路径使用；Consume 在自己的锁外
// 统一调用 onFinding）。
func (d *Defense) emitFinding(f Finding) {
	if f.RuleID == "" || d.onFinding == nil {
		return
	}
	d.onFinding(f)
}

func kindText(kind string) string {
	switch kind {
	case "removed":
		return "删除"
	case "renamed":
		return "改名"
	case "renamed_old":
		return "改名（旧路径）"
	case "modified":
		return "改写"
	}
	return kind
}

// normPath 是本包内的路径规范化：统一分隔符 + 小写。与 winapi.NormalizePath
// 同口径但不引入 winapi 依赖（本包承诺纯逻辑，不碰 Win32）。
// normPath 归一化路径，用作 canaries 键与事件匹配的统一口径。Windows
// 大小写不敏感且 / 与 \ 等价，统一小写+反斜杠；Linux 大小写敏感、
// 正斜杠原生——套用同一套归一化会把 key 搅成 os.Stat 找不到的形状
// （2026-11-14 Kali 实机：OneCanaryPath 恒空串，演练 canary_touch 被
// 跳过）。键与事件路径都过本函数，匹配口径天然一致。
func normPath(p string) string {
	p = strings.TrimSpace(p)
	if runtime.GOOS == "windows" {
		return strings.ToLower(strings.ReplaceAll(p, "/", `\`))
	}
	return p
}
