package ai

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"
)

// Config 是分析引擎的配置。
type Config struct {
	// Provider 取值 none / openai。none 表示只用确定性启发式。
	Provider string
	BaseURL  string
	APIKey   string
	Model    string
	Timeout  time.Duration

	// HourlyTokenBudget 是每小时的 token 上限。
	//
	// 主流产品按"安全计算单元"计费，账单随用量线性增长且难预测；
	// 这里做成硬上限：触顶后自动降级到启发式，成本可预测、
	// 也不会因为某个误配置的批量研判把额度烧光。
	HourlyTokenBudget int

	// CacheTTL 是研判结果缓存时长。同一条告警短时间内被反复查看时，
	// 没必要每次都调模型（既慢又费钱）。
	CacheTTL time.Duration
}

// Stats 是引擎运行统计（暴露给管理台）。
type Stats struct {
	Triaged      int64 `json:"triaged"`
	LLMCalls     int64 `json:"llm_calls"`
	Degraded     int64 `json:"degraded"`
	CacheHits    int64 `json:"cache_hits"`
	TokensUsed   int64 `json:"tokens_used"`
	BudgetCap    int   `json:"budget_cap"`
	BudgetUsed   int   `json:"budget_used"`
	AvgLatencyMs int64 `json:"avg_latency_ms"`
	// GroundedRate 是"结论全部带有效证据引用"的比例，
	// 这是衡量 AI 输出可核查性的核心指标。
	GroundedRate float64 `json:"grounded_rate"`
	// ConflictCount 是模型结论与硬证据冲突、被护栏拦下的次数。
	ConflictCount int64 `json:"conflict_count"`
	Engine        string `json:"engine"`
	Model         string `json:"model"`
}

type cacheEntry struct {
	res *TriageResult
	at  time.Time
}

// Engine 是 AI 能力门面：统一调度推理后端、预算、缓存与护栏。
type Engine struct {
	log   *slog.Logger
	cfg   Config
	llm   Backend
	heur  Backend
	start time.Time

	mu         sync.Mutex
	windowFrom time.Time
	tokens     int
	cache      map[string]cacheEntry

	stTriaged   int64
	stLLM       int64
	stDegraded  int64
	stCacheHit  int64
	stTokens    int64
	stLatSum    int64
	stGrounded  int64
	stConflicts int64
}

// NewEngine 按配置构造引擎。
func NewEngine(cfg Config, log *slog.Logger) *Engine {
	if cfg.Provider == "" {
		cfg.Provider = "none"
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 45 * time.Second
	}
	if cfg.HourlyTokenBudget <= 0 {
		cfg.HourlyTokenBudget = 200_000
	}
	if cfg.CacheTTL <= 0 {
		cfg.CacheTTL = 5 * time.Minute
	}

	e := &Engine{
		log:        log,
		cfg:        cfg,
		heur:       NewHeuristic(),
		start:      time.Now(),
		windowFrom: time.Now(),
		cache:      make(map[string]cacheEntry, 256),
	}

	if cfg.Provider == "openai" && cfg.BaseURL != "" && cfg.Model != "" {
		e.llm = NewOpenAICompatible(cfg.BaseURL, cfg.APIKey, cfg.Model, cfg.Timeout)
		if log != nil {
			log.Info("ai_engine_ready", "provider", cfg.Provider, "model", cfg.Model,
				"base_url", cfg.BaseURL, "budget_per_hour", cfg.HourlyTokenBudget)
		}
	} else {
		if cfg.Provider != "none" && log != nil {
			log.Warn("ai_llm_not_configured",
				"provider", cfg.Provider, "hint", "缺少 base_url 或 model，已回退到确定性分析")
		}
	}
	return e
}

// Enabled 返回是否配置了外部模型。
func (e *Engine) Enabled() bool { return e.llm != nil }

// Triage 研判一条告警。
//
// 流程固定为：缓存 → 模型（预算内）→ 降级启发式 → 校验 → 护栏 → 缓存。
// 任何一步出问题都退回启发式，绝不返回错误给调用方——
// 对分析师而言，"给出一份稍弱的结论"永远优于"分析失败请重试"。
func (e *Engine) Triage(ctx context.Context, in *TriageInput) *TriageResult {
	start := time.Now()

	if cached := e.fromCache(in.AlertID); cached != nil {
		e.bump(func(s *Engine) { s.stCacheHit++ })
		return cached
	}

	// ---- 注入隔离放在统一入口 ----
	//
	// 最初它写在 LLM 后端内部，结果"没配模型"的部署完全不做扫描——
	// 而恰恰是这类部署更需要它：确定性引擎按字面匹配规则，
	// 攻击者在命令行里写"不要告警"更容易直接影响判定逻辑。
	//
	// 更重要的一点：**"试图操纵分析引擎"本身就是一条攻击特征**。
	// 正常软件不会把 "ignore previous instructions" 写进命令行。
	// 所以它不只是防御动作，还是一个独立的检测维度。
	safeIn, ignored, hits := sanitizeInput(in)
	if ignored > 0 {
		safeIn.Evidence = append(safeIn.Evidence, EvidenceItem{
			ID:    fmt.Sprintf("E%d", len(safeIn.Evidence)+1),
			Layer: "behavior",
			Name:  "对抗性内容：试图操纵分析引擎",
			Score: 35,
			Detail: fmt.Sprintf("进程名/命令行/路径中包含 %d 处指令注入特征（%s），已隔离后分析",
				ignored, strings.Join(hits, "、")),
			Trust: Trusted, // 这条是我们自己的判断，不是攻击者写的
		})
		in = safeIn
	}

	var (
		res       *TriageResult
		degraded  bool
		degReason string
	)

	if e.llm != nil && e.budgetLeft() > 0 {
		r, err := e.llm.Triage(ctx, in)
		if err == nil {
			res = r
			e.bump(func(s *Engine) { s.stLLM++ })
		} else {
			degraded = true
			degReason = "模型调用失败：" + err.Error()
			if e.log != nil {
				e.log.Warn("ai_triage_llm_failed", "err", err)
			}
		}
	} else if e.llm != nil {
		degraded = true
		degReason = fmt.Sprintf("本小时 token 预算已用尽（上限 %d）", e.cfg.HourlyTokenBudget)
	} else {
		degraded = true
		degReason = "未配置外部模型，使用确定性分析"
	}

	if res == nil {
		r, err := e.heur.Triage(ctx, in)
		if err != nil {
			// 启发式不会失败，这里只是防御性兜底
			res = &TriageResult{Verdict: "inconclusive", Confidence: 0, Engine: "heuristic"}
		} else {
			res = r
		}
		res.Degraded = degraded
		res.DegradedReason = degReason
		e.bump(func(s *Engine) { s.stDegraded++ })
	}

	res.UntrustedIgnored = ignored

	// ---- 护栏 1：结构与引用校验 ----
	validIDs := make(map[string]bool, len(in.Evidence))
	for _, ev := range in.Evidence {
		validIDs[ev.ID] = true
	}
	res = Validate(res, validIDs)

	// ---- 护栏 2：与确定性证据的冲突裁决 ----
	if msg := Conflict(res, in); msg != "" {
		res.Reasoning = append(res.Reasoning, Reason{
			Text: "【护栏】" + msg,
		})
		res.Verdict = "malicious"
		if res.Confidence < 0.85 {
			res.Confidence = 0.85
		}
		e.bump(func(s *Engine) { s.stConflicts++ })
	}

	// ---- 护栏 3：处置建议一律需要审批 ----
	//
	// 推理结论可以自动化，"执行动作"不行。历史上所有 AI 驱动的
	// 自动处置事故，根因都是把建议当成了授权。
	for i := range res.Actions {
		res.Actions[i].RequiresApproval = true
	}

	res.LatencyMs = time.Since(start).Milliseconds()
	e.record(res)
	e.toCache(in.AlertID, res)
	return res
}

// Translate 把自然语言转成受控查询。
func (e *Engine) Translate(ctx context.Context, nl string) (*Query, error) {
	if strings.TrimSpace(nl) == "" {
		return nil, fmt.Errorf("查询语句为空")
	}
	schema := AlertQuerySchema()

	if e.llm != nil && e.budgetLeft() > 0 {
		q, err := e.llm.Translate(ctx, nl, schema)
		if err == nil {
			e.bump(func(s *Engine) { s.stLLM++ })
			return q, nil
		}
		if e.log != nil {
			e.log.Warn("ai_translate_llm_failed", "err", err)
		}
	}

	// 降级：关键词规则解析。表达能力有限，但覆盖了绝大多数日常检索。
	q := heuristicTranslate(nl)
	return schema.Normalize(q)
}

// Stats 返回运行统计。
func (e *Engine) Stats() Stats {
	e.mu.Lock()
	defer e.mu.Unlock()

	st := Stats{
		Triaged:       e.stTriaged,
		LLMCalls:      e.stLLM,
		Degraded:      e.stDegraded,
		CacheHits:     e.stCacheHit,
		TokensUsed:    e.stTokens,
		BudgetCap:     e.cfg.HourlyTokenBudget,
		BudgetUsed:    e.tokens,
		ConflictCount: e.stConflicts,
		Engine:        "heuristic",
	}
	if e.stTriaged > 0 {
		st.AvgLatencyMs = e.stLatSum / e.stTriaged
		st.GroundedRate = round2(float64(e.stGrounded) / float64(e.stTriaged))
	}
	if e.llm != nil {
		st.Engine = "llm"
		st.Model = e.cfg.Model
	}
	return st
}

func (e *Engine) record(res *TriageResult) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.stTriaged++
	e.stLatSum += res.LatencyMs
	if res.Grounded {
		e.stGrounded++
	}
}

func (e *Engine) bump(f func(*Engine)) {
	e.mu.Lock()
	defer e.mu.Unlock()
	f(e)
}

// budgetLeft 返回本小时剩余可用 token 预算。
func (e *Engine) budgetLeft() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.rollWindowLocked()
	return e.cfg.HourlyTokenBudget - e.tokens
}

func (e *Engine) rollWindowLocked() {
	if time.Since(e.windowFrom) >= time.Hour {
		e.windowFrom = time.Now()
		e.tokens = 0
	}
}

func (e *Engine) fromCache(id string) *TriageResult {
	if id == "" {
		return nil
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if ent, ok := e.cache[id]; ok && time.Since(ent.at) < e.cfg.CacheTTL {
		return ent.res
	}
	return nil
}

func (e *Engine) toCache(id string, res *TriageResult) {
	if id == "" || res == nil {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	// 简单容量控制：超过 1024 条时清空重来，避免无界增长
	if len(e.cache) >= 1024 {
		e.cache = make(map[string]cacheEntry, 256)
	}
	e.cache[id] = cacheEntry{res: res, at: time.Now()}
}

// AddTokens 由后端回填实际 token 消耗（成本可观测）。
func (e *Engine) AddTokens(n int) {
	if n <= 0 {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.rollWindowLocked()
	e.tokens += n
	e.stTokens += int64(n)
}

// heuristicTranslate 是自然语言查询的确定性解析。
//
// 覆盖不了复杂组合，但能覆盖"未签名、临时目录、最近24小时、恶意"这类
// 日常高频检索。它的价值在于：没有模型的机器上，狩猎功能依然可用。
func heuristicTranslate(nl string) *Query {
	low := strings.ToLower(nl)
	q := &Query{Target: "alerts", SinceSec: 86400, OrderBy: "created_at", Desc: true, Limit: 50}
	q.Explain = "按关键词规则解析：" + nl

	add := func(f Filter) { q.Filters = append(q.Filters, f) }

	// 时间窗口
	switch {
	case strings.Contains(low, "1小时") || strings.Contains(low, "一小时") || strings.Contains(low, "last hour"):
		q.SinceSec = 3600
	case strings.Contains(low, "7天") || strings.Contains(low, "一周") || strings.Contains(low, "last week"):
		q.SinceSec = 7 * 86400
	case strings.Contains(low, "30天") || strings.Contains(low, "一个月"):
		q.SinceSec = 30 * 86400
	case strings.Contains(low, "24小时") || strings.Contains(low, "今天") || strings.Contains(low, "today"):
		q.SinceSec = 86400
	}

	// 结论
	switch {
	case strings.Contains(low, "恶意") || strings.Contains(low, "malicious"):
		add(Filter{Field: "verdict", Op: "eq", Value: "malicious"})
	case strings.Contains(low, "可疑") || strings.Contains(low, "suspicious"):
		add(Filter{Field: "verdict", Op: "eq", Value: "suspicious"})
	case strings.Contains(low, "误报") || strings.Contains(low, "false positive"):
		add(Filter{Field: "status", Op: "eq", Value: "false_positive"})
	}

	// 签名
	if strings.Contains(low, "未签名") || strings.Contains(low, "unsigned") || strings.Contains(low, "无签名") {
		add(Filter{Field: "signed", Op: "eq", Value: "false"})
	}

	// 常见落点（中英文都要认，否则中文查询会静默丢条件）
	dropDirs := []struct{ kw, val string }{
		{"temp", "temp"}, {"临时", "temp"},
		{"download", "downloads"}, {"下载", "downloads"},
		{"programdata", "programdata"},
		{"appdata", "appdata"},
		{"public", "public"}, {"公共", "public"},
		{"desktop", "desktop"}, {"桌面", "desktop"},
	}
	for _, d := range dropDirs {
		if strings.Contains(low, d.kw) {
			add(Filter{Field: "image_path", Op: "contains", Value: d.val})
			break
		}
	}

	// 进程名（能识别出常见的解释器/工具名）
	for _, kw := range []string{"powershell", "cmd", "wscript", "mshta", "rundll32", "regsvr32",
		"certutil", "bitsadmin", "msiexec", "svchost", "lsass", "python", "curl"} {
		if strings.Contains(low, kw) {
			add(Filter{Field: "process_name", Op: "contains", Value: kw})
			break
		}
	}

	// 分值
	if strings.Contains(low, "高分") || strings.Contains(low, "严重") || strings.Contains(low, "high score") {
		add(Filter{Field: "score", Op: "gte", Value: "70"})
	}

	return q
}
