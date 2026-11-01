package detect

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"hostguard/internal/agent/allow"
	"hostguard/internal/agent/baseline"
	"hostguard/internal/agent/enrich"
	"hostguard/internal/model"
	"hostguard/internal/rules"
)

// ProcessInfo 是采集层交给检测引擎的进程快照。
type ProcessInfo struct {
	PID       uint32
	PPID      uint32
	Name      string
	Path      string
	CmdLine   string
	User      string
	SessionID uint32
	Elevated  bool
	IsWow64   bool
	StartTime time.Time
}

// Input 是一次检测的完整上下文。
type Input struct {
	Proc        ProcessInfo
	Ancestry    []model.AncestorLink
	ParentAlive bool
	Connections []model.NetConn
	Modules     []model.ModuleInfo
	// LandedAt 是"该进程的镜像文件在磁盘上落地"的时间（由文件落地监控提供）。
	// 零值表示未观测到落地——可能是监控启动前就存在的文件，也可能来自
	// 未被监控的目录，两种情况都不应据此扣分或加分。
	LandedAt time.Time
}

// Result 是融合后的判定结果。
type Result struct {
	Fingerprint string
	Verdict     model.Verdict
	Severity    model.Severity
	Score       int
	Title       string
	Summary     string
	Evidence    model.Evidence
	RuleIDs     []string
	MITRE       []string

	// Alert 表示这条结果需要上报为告警。
	// 即使 Alert=false，Score/Evidence 依然有效——UI 借此展示"接近阈值"的进程，
	// 排障与误报分析都依赖这份可见性。
	Alert bool
	// Suppressed 记录被抑制的原因：whitelist / below_threshold / warmup / duplicate
	Suppressed string
}

// Config 是引擎参数。
type Config struct {
	WarmupUntil time.Time // 冷启动静默期：此前只上报恶意级告警
	MaliciousAt int       // 恶意阈值
	SuspiciousAt int      // 可疑阈值
}

// Stats 是引擎累计计数（用于本地 UI 与心跳上报）。
type Stats struct {
	Scanned     int64 `json:"scanned"`
	Fired       int64 `json:"fired"`
	Suppressed  int64 `json:"suppressed"`
	Whitelisted int64 `json:"whitelisted"`
	AvgLatencyMs int64 `json:"avg_latency_ms"`
}

// Engine 是五层检测流水线。
type Engine struct {
	enr   *enrich.Enricher
	base  *baseline.Model
	allow *allow.List
	kw    *keywordMatcher
	cfg   Config

	mu    sync.RWMutex
	rules []compiledRule
	// iocs 是服务端下发的威胁指标哈希表（hash → 备注）。
	// 与 rules 同锁保护：两者都是"服务端可热替换的检测数据"。
	iocs map[string]string

	statMu     sync.Mutex
	scanned    int64
	fired      int64
	suppressed int64
	whitelisted int64
	latSum     int64
	latN       int64

	// 本地去重：同一指纹在窗口内只上报一次
	recent map[string]time.Time
}

type compiledRule struct {
	ID       string
	Name     string
	Severity model.Severity
	Score    int
	MITRE    []string
	Def      *rules.Definition
}

// New 构造引擎。
func New(enr *enrich.Enricher, base *baseline.Model, alw *allow.List, cfg Config) *Engine {
	if cfg.MaliciousAt == 0 {
		cfg.MaliciousAt = 70
	}
	if cfg.SuspiciousAt == 0 {
		cfg.SuspiciousAt = 38
	}
	return &Engine{
		enr:    enr,
		base:   base,
		allow:  alw,
		kw:     newKeywordMatcher(),
		cfg:    cfg,
		recent: make(map[string]time.Time, 512),
	}
}

// SetIOCs 加载服务端下发的威胁指标哈希表（整包替换）。
// 传入 nil 等价于清空——服务端明确清空 IOC 库时终端应同步清空，
// 而不是保留旧表（否则删掉的指标仍在拦截，运营会困惑）。
func (e *Engine) SetIOCs(hashes map[string]string) {
	normalized := make(map[string]string, len(hashes))
	for h, note := range hashes {
		h = strings.ToLower(strings.TrimSpace(h))
		if len(h) == 64 {
			normalized[h] = note
		}
	}
	e.mu.Lock()
	e.iocs = normalized
	e.mu.Unlock()
}

// IOCCount 返回当前生效的 IOC 条数（供本地状态展示）。
func (e *Engine) IOCCount() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return len(e.iocs)
}

// lookupIOC 在服务端下发的 IOC 表中查哈希。
func (e *Engine) lookupIOC(hash string) (string, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	note, ok := e.iocs[hash]
	return note, ok
}

// SetRules 加载服务端下发的规则（编译失败的单条规则会被跳过并计数）。
// SetBuiltinRules 加载编译进二进制里的内置规则集。
//
// 作用是"兜底"：服务端不可达、或下发规则包验签失败时，行为检测层不能
// 因此变成空的——否则防护会静默降级成只剩静态指纹，而这个降级过程
// 在管理台上看不出来，是最危险的一类失效。
func (e *Engine) SetBuiltinRules() int {
	builtins := rules.Builtins()
	dtos := make([]model.RuleDTO, 0, len(builtins))
	for _, b := range builtins {
		dtos = append(dtos, model.RuleDTO{
			ID: b.ID, Name: b.Name, Severity: b.Severity, Score: b.Score,
			MITRE: b.MITRE, Enabled: true, Definition: b.JSON(), Version: 1,
		})
	}
	ok, _ := e.SetRules(dtos)
	return ok
}

func (e *Engine) SetRules(list []model.RuleDTO) (ok int, bad []string) {
	compiled := make([]compiledRule, 0, len(list))
	for _, r := range list {
		if !r.Enabled {
			continue
		}
		def, err := rules.Compile(r.Definition)
		if err != nil {
			bad = append(bad, r.ID)
			continue
		}
		compiled = append(compiled, compiledRule{
			ID: r.ID, Name: r.Name, Severity: r.Severity, Score: r.Score,
			MITRE: r.MITRE, Def: def,
		})
		ok++
	}
	e.mu.Lock()
	e.rules = compiled
	e.mu.Unlock()
	return ok, bad
}

// RuleCount 返回已加载规则数。
func (e *Engine) RuleCount() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return len(e.rules)
}

// Stats 返回累计统计。
func (e *Engine) Stats() Stats {
	e.statMu.Lock()
	defer e.statMu.Unlock()
	var avg int64
	if e.latN > 0 {
		avg = e.latSum / e.latN
	}
	return Stats{
		Scanned: e.scanned, Fired: e.fired, Suppressed: e.suppressed,
		Whitelisted: e.whitelisted, AvgLatencyMs: avg,
	}
}

// IsWarmup 判断是否仍在冷启动静默期。
func (e *Engine) IsWarmup(now time.Time) bool {
	return !e.cfg.WarmupUntil.IsZero() && now.Before(e.cfg.WarmupUntil)
}

// Analyze 执行五层检测。返回 nil 表示判定为安全（或已被白名单/去重抑制）。
func (e *Engine) Analyze(in Input) *Result {
	start := time.Now()
	defer func() {
		e.statMu.Lock()
		e.scanned++
		e.latSum += time.Since(start).Milliseconds()
		e.latN++
		e.statMu.Unlock()
	}()

	p := in.Proc

	// ---- 第 0 步：低成本白名单预判（路径 / 父子对 / 命令行）----
	if hit, kind := e.allow.Match("", p.Path, "", parentName(in), p.Name, p.CmdLine); hit {
		e.markWhitelisted()
		return &Result{
			Verdict:    model.VerdictSafe,
			Suppressed: "whitelist",
			Title:      "白名单豁免（" + kind + "）",
		}
	}

	// ---- 富化：哈希 + 签名 + 路径分类 ----
	meta := e.enr.Describe(p.Path)

	// 精确白名单：哈希 / 签名主体 / 路径
	if hit, kind := e.allow.Match(meta.Hash, p.Path, meta.Signer, parentName(in), p.Name, p.CmdLine); hit {
		e.markWhitelisted()
		return &Result{
			Verdict:    model.VerdictSafe,
			Suppressed: "whitelist",
			Title:      "白名单豁免（" + kind + "）",
			Evidence: model.Evidence{
				Process: model.ProcEvidence{
					PID: p.PID, PPID: p.PPID, Name: p.Name, Path: p.Path, CmdLine: p.CmdLine,
					User: p.User, HashSHA256: meta.Hash, Signed: meta.Signed,
					SignatureOK: meta.SignatureOK, Signer: meta.Signer,
				},
			},
		}
	}

	var signals []model.Signal
	var notes []string

	// ---- 第 1 层：静态指纹 ----
	staticScore, iocBonus := e.staticLayer(p, meta, &signals, &notes)

	// ---- 第 2 层：关键词 ----
	kwSignals := e.kw.match(p.Name, p.CmdLine)
	signals = append(signals, kwSignals...)
	keywordScore := 0
	for _, s := range kwSignals {
		keywordScore += s.Score
	}
	if keywordScore > 40 {
		keywordScore = 40
	}

	// ---- 第 3 层：行为规则 ----
	ruleScore, hits := e.ruleLayer(in, meta, &signals)

	// ---- 第 4 层：血缘图 ----
	lineageScore, lineageNotes := e.base.Score(parentName(in), p.Name, ancestorNames(in.Ancestry),
		in.ParentAlive, p.PID)
	notes = append(notes, lineageNotes...)
	if lineageScore > 0 {
		signals = append(signals, model.Signal{
			Layer: "lineage", ID: "LIN-001", Name: "进程血缘异常",
			Score: int(lineageScore), Note: strings.Join(lineageNotes, "；"),
		})
	}

	// ---- 第 4.5 层：文件落地关联 ----
	dropScore := e.dropLayer(p, meta, in, &signals, &notes)

	// ---- 第 5 层：融合定级 ----
	// iocBonus 单独入总分（见 staticLayer 注释），并计入 StaticScore 证据，
	// 保证"分量之和 = 总分"在管理台可对账。
	total := staticScore + iocBonus + keywordScore + ruleScore + int(lineageScore) + dropScore
	if total > 100 {
		total = 100
	}

	verdict := model.VerdictSafe
	switch {
	case total >= e.cfg.MaliciousAt:
		verdict = model.VerdictMalicious
	case total >= e.cfg.SuspiciousAt:
		verdict = model.VerdictSuspicious
	}

	res := &Result{
		Verdict:  verdict,
		Severity: severityFor(total, verdict, hits),
		Score:    total,
		Title:    buildTitle(p, hits, kwSignals),
		Evidence: model.Evidence{
			Process: model.ProcEvidence{
				PID: p.PID, PPID: p.PPID, Name: p.Name, Path: p.Path, CmdLine: p.CmdLine,
				User: p.User, SessionID: p.SessionID, Elevated: p.Elevated,
				StartTime: p.StartTime, HashSHA256: meta.Hash, FileSize: meta.FileSize,
				Signed: meta.Signed, SignatureOK: meta.SignatureOK, Signer: meta.Signer,
				IsWow64: p.IsWow64,
			},
			Ancestry:     in.Ancestry,
			Signals:      signals,
			RuleHits:     hits,
			Network:      in.Connections,
			Modules:      in.Modules,
			StaticScore:  float64(staticScore + iocBonus),
			KeywordScore: float64(keywordScore),
			RuleScore:    float64(ruleScore),
			LineageScore: lineageScore,
			DropScore:    float64(dropScore),
			Notes:        notes,
		},
	}
	res.Summary = buildSummary(p, res, parentName(in)) + composeUserGuidance(res)
	res.Fingerprint = fingerprint(p, res)
	for _, s := range signals {
		if s.MITRE != "" {
			res.MITRE = appendUnique(res.MITRE, s.MITRE)
		}
	}
	for _, h := range hits {
		res.RuleIDs = appendUnique(res.RuleIDs, h.RuleID)
		for _, m := range h.MITRE {
			res.MITRE = appendUnique(res.MITRE, m)
		}
	}

	// ---- 决策：是否真的产生告警 ----
	switch {
	case verdict == model.VerdictSafe:
		// 低于阈值：进引擎但不告警（"压噪"的最后一环）
		res.Suppressed = "below_threshold"
	case e.IsWarmup(time.Now()) && verdict != model.VerdictMalicious:
		// 冷启动静默期：只让恶意级漏出，可疑级先攒基线
		res.Suppressed = "warmup"
	case e.isDuplicate(res.Fingerprint):
		// 同指纹 5 分钟内不重复上报
		res.Suppressed = "duplicate"
	default:
		res.Alert = true
	}

	if res.Alert {
		e.statMu.Lock()
		e.fired++
		e.statMu.Unlock()
	} else if res.Suppressed != "below_threshold" {
		e.statMu.Lock()
		e.suppressed++
		e.statMu.Unlock()
	}
	return res
}

// ---------------------------------------------------------------- 各层实现

// iocHashBonus 是 IOC 哈希命中的融合加成。
//
// 刻意不参与 staticLayer 的 45 分封顶：帽子是给"路径信誉/签名状态"这类
// 启发式信号的，防止单层噪声主导总分；而确认的威胁情报哈希是事实而非
// 猜测，70 分意味着单凭 IOC 命中即可到达恶意阈值（MaliciousAt=70）。
const iocHashBonus = 70

// staticLayer 静态指纹层：哈希黑名单、签名状态、路径信誉。
// 返回值：(reputation 分（受帽子约束）, IOC 加成（不封顶）)。
func (e *Engine) staticLayer(p ProcessInfo, meta enrich.Meta, signals *[]model.Signal, notes *[]string) (int, int) {
	score := 0
	iocBonus := 0

	// 已知恶意哈希：内置表（EICAR 等验证用）+ 服务端下发 IOC 库
	if meta.Hash != "" {
		h := strings.ToLower(meta.Hash)
		if sig, ok := knownBadHashes[h]; ok {
			iocBonus += iocHashBonus
			*signals = append(*signals, model.Signal{
				Layer: "static", ID: "S-HASH", Name: "命中已知恶意样本哈希",
				Score: iocHashBonus, Note: sig, MITRE: "T1204",
			})
		}
		if note, ok := e.lookupIOC(h); ok {
			iocBonus += iocHashBonus
			*signals = append(*signals, model.Signal{
				Layer: "static", ID: "S-IOC", Name: "命中威胁情报 IOC 哈希",
				Score: iocHashBonus, Note: note, MITRE: "T1204",
			})
		}
	}

	// 签名状态
	switch meta.SigState {
	case "bad_digest":
		score += 35
		*signals = append(*signals, model.Signal{
			Layer: "static", ID: "S-TAMPER", Name: "数字签名存在但内容被篡改",
			Score: 35, Note: "签名校验结果 TRUST_E_BAD_DIGEST，文件在签名后被修改", MITRE: "T1553.002",
		})
		*notes = append(*notes, "签名摘要不匹配，说明文件在签名后被修改")
	case "distrusted", "untrusted":
		score += 10
		*signals = append(*signals, model.Signal{
			Layer: "static", ID: "S-UNTRUSTED", Name: "签名不受信任",
			Score: 10, Note: "证书链不受信任或已被吊销", MITRE: "T1553.002",
		})
	case "unsigned":
		// 无签名本身不构成告警，只有在"可写目录 + 非系统路径"时才加分
		if meta.DirWritable && !meta.InSystem {
			score += 8
			*signals = append(*signals, model.Signal{
				Layer: "static", ID: "S-UNSIGNED", Name: "无签名且位于用户可写目录",
				Score: 8, Note: "可执行文件未签名，且存放在普通用户可写的位置", MITRE: "T1036",
			})
		}
	}

	// 路径信誉
	lower := strings.ToLower(meta.Path)
	switch {
	case strings.HasPrefix(lower, `\\`):
		score += 12
		*signals = append(*signals, model.Signal{
			Layer: "static", ID: "S-UNC", Name: "从网络共享路径执行",
			Score: 12, Note: "镜像位于 UNC 路径，常见于横向移动", MITRE: "T1021.002",
		})
	case strings.Contains(lower, "$recycle.bin"):
		score += 10
		*signals = append(*signals, model.Signal{
			Layer: "static", ID: "S-RECYCLE", Name: "从回收站目录执行",
			Score: 10, Note: "恶意程序常把载荷藏进回收站规避人工排查", MITRE: "T1036",
		})
	case meta.Depth >= 8 && !meta.InSystem:
		// 只对"不在系统目录、且层级异常深"的路径计分。
		// 系统目录里的 DriverStore/WinSxS/WindowsApps 天然很深，不能算异常。
		score += 5
		*signals = append(*signals, model.Signal{
			Layer: "static", ID: "S-DEEP", Name: "镜像位于异常深层目录",
			Score: 5, Note: fmt.Sprintf("路径层级 %d，接近伪装目录的典型特征", meta.Depth), MITRE: "T1036",
		})
	}

	if score > 45 {
		score = 45
	}
	return score, iocBonus
}

// ruleLayer 行为规则层。
func (e *Engine) ruleLayer(in Input, meta enrich.Meta, signals *[]model.Signal) (int, []model.RuleHit) {
	e.mu.RLock()
	compiled := e.rules
	e.mu.RUnlock()

	if len(compiled) == 0 {
		return 0, nil
	}

	p := in.Proc
	target := &rules.Target{
		Name:       p.Name,
		Path:       p.Path,
		CmdLine:    p.CmdLine,
		User:       p.User,
		ParentName: parentName(in),
		ParentPath: parentPath(in),
		Ancestors:  ancestorNames(in.Ancestry),
		Signed:     meta.Signed,
		SignatureOK: meta.SignatureOK,
		Signer:     meta.Signer,
		Elevated:   p.Elevated,
		InSystem:   meta.InSystem,
		DirWritable: meta.DirWritable,
		SessionID:  p.SessionID,
		NetConnCount: len(in.Connections),
		HasPublicRemote: hasPublicRemote(in.Connections),
	}
	for _, c := range in.Connections {
		target.RemotePorts = append(target.RemotePorts, c.RemotePort)
	}
	for _, m := range in.Modules {
		_, writable, _ := enrich.DescribeFast(m.Path)
		_ = writable
		if !strings.HasPrefix(strings.ToLower(m.Path), strings.ToLower(systemRoot())) {
			target.NonSystemModules++
		}
	}
	target.UnsignedModules = e.countUnsignedModules(in)

	var hits []model.RuleHit
	score := 0
	for _, r := range compiled {
		ok, matched := r.Def.Match(target)
		if !ok {
			continue
		}
		hits = append(hits, model.RuleHit{
			RuleID: r.ID, Name: r.Name, Severity: r.Severity,
			Score: r.Score, MITRE: r.MITRE, Matched: matched,
		})
		score += r.Score
		*signals = append(*signals, model.Signal{
			Layer: "rule", ID: r.ID, Name: r.Name,
			Score: r.Score, Note: strings.Join(matched, "；"), MITRE: firstOr(r.MITRE, ""),
		})
	}
	if score > 55 {
		score = 55
	}
	sort.SliceStable(hits, func(i, j int) bool { return hits[i].Score > hits[j].Score })
	return score, hits
}

// ---------------------------------------------------------------- 辅助

func (e *Engine) markWhitelisted() {
	e.statMu.Lock()
	e.whitelisted++
	e.statMu.Unlock()
}

func (e *Engine) isDuplicate(fp string) bool {
	now := time.Now()
	e.mu.Lock()
	defer e.mu.Unlock()

	// 顺带清理过期记录，避免无界增长
	if len(e.recent) > 4096 {
		for k, t := range e.recent {
			if now.Sub(t) > 30*time.Minute {
				delete(e.recent, k)
			}
		}
	}
	if t, ok := e.recent[fp]; ok && now.Sub(t) < 5*time.Minute {
		return true
	}
	e.recent[fp] = now
	return false
}

// riskyDropDirs 是攻击者最常落地的目录。在这些目录"落地即执行"才是信号；
// 在 Program Files 落地后运行是安装程序的正常行为，不能同等对待。
var riskyDropDirs = []string{
	`\temp\`, `\tmp\`, `\downloads\`, `\users\public\`,
	`\appdata\local\`, `\appdata\roaming\`, `\programdata\`,
	`\recycle`, `\perflogs\`, `\desktop\`, `\documents\`,
}

// dropLayer 把"文件落地 → 进程执行"关联成一个可解释的分数。
//
// 这是纯进程快照做不到的一层：只看进程创建，无法区分"用户双击了装了很久的
// 程序"和"样本刚写进磁盘就被拉起"。落地监控补上了前半段证据。
func (e *Engine) dropLayer(p ProcessInfo, meta enrich.Meta, in Input, signals *[]model.Signal, notes *[]string) int {
	if in.LandedAt.IsZero() {
		return 0
	}
	age := time.Since(in.LandedAt)
	if age < 0 || age > 15*time.Minute {
		return 0
	}

	lowPath := strings.ToLower(p.Path)
	risky := false
	for _, d := range riskyDropDirs {
		if strings.Contains(lowPath, d) {
			risky = true
			break
		}
	}

	score := 0
	reason := ""
	switch {
	case !risky:
		// 正常安装位置：只作为佐证，不加权
		score = 5
		reason = "镜像文件近期落地于常规安装位置"
	case meta.Signed && meta.SignatureOK:
		// 可写目录但签名有效：多为合法软件的临时解包，适度计分
		score = 14
		reason = "镜像文件近期落地于可写目录（有有效签名）"
	default:
		score = 32
		reason = "镜像文件近期落地于可写目录且无有效签名"
	}

	// 落地后极短时间内被执行，更贴近"写盘即拉起"的行为链
	if risky && score >= 32 && age < 90*time.Second {
		score += 8
		reason += "，且落地后立即执行"
	}

	*signals = append(*signals, model.Signal{
		Layer: "behavior", ID: "DROP-001", Name: "文件落地即执行",
		Score: score,
		Note:  fmt.Sprintf("%s（落地于 %s，距今 %s）", reason, in.LandedAt.Format("15:04:05"), age.Round(time.Second)),
		MITRE: "T1105",
	})
	*notes = append(*notes, "落地关联："+reason)
	return score
}

// countUnsignedModules 统计"确实没有数字签名"的第三方模块数量。
//
// 关键：不能只看"模块是否在可写目录"就判为未签名——那是把"位置"当成"签名"，
// 会造成大规模误报（实测会把 git bash、node 这类合法签名软件的 DLL 全部误判）。
// 这里的做法是：先排除系统目录与进程自身镜像，再对留下的模块做真实验签，
// 结果由 enrich 的缓存层复用，单个新模块只付一次成本。
func (e *Engine) countUnsignedModules(in Input) int {
	root := systemRoot()
	selfPath := strings.ToLower(in.Proc.Path)
	n := 0
	for _, m := range in.Modules {
		lp := strings.ToLower(m.Path)
		if lp == "" || strings.HasPrefix(lp, root) {
			continue
		}
		if lp == selfPath {
			continue // 进程自己的主模块不算
		}
		meta := e.enr.Describe(m.Path)
		if meta.SignatureOK {
			continue
		}
		// 无签名且位于用户可写目录，才算可疑模块
		if meta.DirWritable {
			n++
		}
	}
	return n
}

func hasPublicRemote(conns []model.NetConn) bool {
	for _, c := range conns {
		if c.RemoteIP == "" || c.RemoteIP == "0.0.0.0" || c.RemoteIP == "::" {
			continue
		}
		if isPublic(c.RemoteIP) {
			return true
		}
	}
	return false
}

func parentName(in Input) string {
	if len(in.Ancestry) > 0 {
		return in.Ancestry[0].Name
	}
	return ""
}

func parentPath(in Input) string {
	if len(in.Ancestry) > 0 {
		return in.Ancestry[0].Path
	}
	return ""
}

func ancestorNames(links []model.AncestorLink) []string {
	out := make([]string, 0, len(links))
	for _, l := range links {
		if l.Name != "" {
			out = append(out, l.Name)
		}
	}
	return out
}

func severityFor(score int, v model.Verdict, hits []model.RuleHit) model.Severity {
	sev := model.SeverityMedium
	switch {
	case score >= 85:
		sev = model.SeverityCritical
	case score >= 70:
		sev = model.SeverityHigh
	case score >= 55:
		sev = model.SeverityMedium
	default:
		sev = model.SeverityLow
	}
	// 命中高危规则时抬升一级，避免"总分被摊薄"导致低估
	for _, h := range hits {
		if h.Severity.Rank() > sev.Rank() {
			sev = h.Severity
		}
	}
	if v == model.VerdictMalicious && sev.Rank() < model.SeverityHigh.Rank() {
		sev = model.SeverityHigh
	}
	return sev
}

func buildTitle(p ProcessInfo, hits []model.RuleHit, kw []model.Signal) string {
	if len(hits) > 0 {
		return hits[0].Name
	}
	if len(kw) > 0 {
		return kw[0].Name
	}
	return "可疑进程行为：" + p.Name
}

func buildSummary(p ProcessInfo, res *Result, parent string) string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("进程 %s (PID %d)", p.Name, p.PID))
	if parent != "" {
		b.WriteString(" 由 " + parent + " 拉起")
	}
	b.WriteString(fmt.Sprintf("，综合评分 %d（%s）。", res.Score,
		map[model.Verdict]string{
			model.VerdictMalicious:  "判定恶意",
			model.VerdictSuspicious: "判定可疑",
		}[res.Verdict]))

	if len(res.RuleIDs) > 0 {
		b.WriteString("命中规则：" + strings.Join(res.RuleIDs, "、") + "。")
	}
	ev := res.Evidence
	b.WriteString(fmt.Sprintf("分量：静态 %.0f / 关键词 %.0f / 规则 %.0f / 血缘 %.0f。",
		ev.StaticScore, ev.KeywordScore, ev.RuleScore, ev.LineageScore))
	return b.String()
}

func fingerprint(p ProcessInfo, res *Result) string {
	rules := append([]string(nil), res.RuleIDs...)
	sort.Strings(rules)
	key := strings.ToLower(strings.Join([]string{
		p.Name, res.Evidence.Process.HashSHA256, strings.Join(rules, ","), string(res.Severity),
	}, "|"))
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:])[:32]
}

func appendUnique(list []string, v string) []string {
	if v == "" {
		return list
	}
	for _, x := range list {
		if x == v {
			return list
		}
	}
	return append(list, v)
}

func firstOr(list []string, def string) string {
	if len(list) > 0 {
		return list[0]
	}
	return def
}

// knownBadHashes 是内置的已知恶意样本哈希表（示例数据）。
//
// 生产环境应替换为服务端下发的 IOC 库；此处保留少量公开样本特征，
// 用于验证 L1 静态层链路可用。
var knownBadHashes = map[string]string{
	// EICAR 测试文件的 SHA256（业界通用的"无害测试样本"）
	"275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f": "EICAR 测试样本（无害）",
}
