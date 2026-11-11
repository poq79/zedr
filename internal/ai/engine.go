package ai

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"
)


// 任务槽：一次 AI 能力调用走哪个槽位的模型。
// 研判要快、狩猎要稳、调查与叙事要强——不同任务的成本/质量取舍不同，
// 分槽配置是成本精细化的前提。investigate/narrative v1 预留，
// 未单独配置时自动回落 triage 槽。
const (
	SlotTriage      = "triage"
	SlotHunt        = "hunt"
	SlotInvestigate = "investigate"
	SlotNarrative   = "narrative"
)

// SlotConfig 是一个任务槽的模型接入配置。
type SlotConfig struct {
	// Provider 当前仅 openai（OpenAI 兼容协议，覆盖 OpenAI/DeepSeek/通义/
	// Kimi/vLLM/Ollama 等）。Anthropic 的 /v1/messages 协议列入 TODO。
	Provider    string
	BaseURL     string
	APIKey      string
	Model       string
	// Effort 是思考强度：off/low/medium/high。off 不发送 reasoning_effort
	// 参数；其余原样透传，服务端不认时调用失败 → 自动降级启发式，
	// 失败原因在研判面板与测试按钮里可见（诚实暴露，不做静默兼容）。
	Effort      string
	Temperature float64
	MaxTokens   int
	Timeout     time.Duration
	Enabled     bool
}

// Config 是分析引擎的配置。
type Config struct {
	// Provider/BaseURL/APIKey/Model/Timeout 是环境变量引导配置（单模型）。
	// 后台配置中心（Slots）存在时以它为准；两者都空 = 纯启发式。
	Provider string
	BaseURL  string
	APIKey   string
	Model    string
	Timeout  time.Duration

	// Slots 是任务槽配置（键见 Slot* 常量），优先于上面的单模型配置。
	Slots map[string]SlotConfig

	// HourlyTokenBudget 是每小时的 token 上限。
	//
	// 主流产品按"安全计算单元"计费，账单随用量线性增长且难预测；
	// 这里做成硬上限：触顶后自动降级到启发式，成本可预测、
	// 也不会因为某个误配置的批量研判把额度烧光。
	HourlyTokenBudget int

	// CacheTTL 是研判结果缓存时长。同一条告警短时间内被反复查看时，
	// 没必要每次都调模型（既慢又费钱）。
	CacheTTL time.Duration

	// Agent 循环预算（零值 = 内置默认）。1M 上下文模型普及后，固定
	// 6 步/8 次调用对复杂调查偏紧；放开成可配置，按部署的模型与预算
	// 承受力调整。ApplyConfig 会做默认回填与范围钳制（防误配打爆预算）。
	AgentMaxSteps     int
	AgentMaxToolCalls int
	AgentToolTimeout  time.Duration
}

// Incidents 是事件叙事统计（与 Triage 分列）。
type Incidents struct {
	Narrated int64
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
	// Narrated 是事件叙事调用次数（事件级检测的用量）。
	Narrated int64 `json:"narrated"`
	// Slots 是按任务槽的调用分布（判断"钱花在哪个能力上"）。
	Slots map[string]SlotStat `json:"slots,omitempty"`
	// GroundedRate 是"结论全部带有效证据引用"的比例，
	// 这是衡量 AI 输出可核查性的核心指标。
	GroundedRate float64 `json:"grounded_rate"`
	// ConflictCount 是模型结论与硬证据冲突、被护栏拦下的次数。
	ConflictCount int64 `json:"conflict_count"`
	Engine        string `json:"engine"`
	Model         string `json:"model"`
}

// SlotStat 是单个任务槽的用量。
type SlotStat struct {
	Calls int64 `json:"calls"`
	AvgMs int64 `json:"avg_ms"`
}

// slotCounter 是槽位统计的内部累加器。
type slotCounter struct {
	calls int64
	msSum int64
}

type cacheEntry struct {
	res *TriageResult
	at  time.Time
}

// narrativeEntry 是事件叙事缓存项。
type narrativeEntry struct {
	narrative *IncidentNarrative
	at        time.Time
}

// Engine 是 AI 能力门面：统一调度推理后端、预算、缓存与护栏。
type Engine struct {
	log   *slog.Logger
	heur  Backend
	start time.Time

	// cfg/llms/prompts/skills 全部受 mu 保护：配置中心要求运行中热更新，
	// 而它们又同时被请求路径读取。锁粒度是可接受的——这些读都是
	// O(1) 的 map/字段访问，不会与模型调用的长耗时区间重叠。
	mu      sync.Mutex
	cfg     Config
	llms    map[string]Backend // 槽位 → 后端（nil 缺席 = 该槽未配置）
	prompts map[string]string  // 任务 → 系统提示覆盖（空 = 内置）
	skills  map[string][]string

	windowFrom time.Time
	tokens     int
	cache      map[string]cacheEntry
	// narrativeCache 是事件叙事的短时缓存（key: incidentID#ver）。
	narrativeCache map[string]narrativeEntry
	// ver 是配置版本：ApplyConfig 每次递增，缓存键携带版本号——
	// 改模型/提示词/技能包后旧结论立即失效（此前要等 5 分钟 TTL）。
	ver uint64
	slots map[string]*slotCounter

	stTriaged   int64
	stLLM       int64
	stDegraded  int64
	stCacheHit  int64
	stTokens    int64
	stLatSum    int64
	stGrounded  int64
	stConflicts int64
	stNarrated  int64
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
		log:            log,
		heur:           NewHeuristic(),
		start:          time.Now(),
		windowFrom:     time.Now(),
		cache:          make(map[string]cacheEntry, 256),
		narrativeCache: make(map[string]narrativeEntry, 64),
		slots:          make(map[string]*slotCounter, 4),
		prompts:        map[string]string{},
		skills:         map[string][]string{},
		ver:            1,
	}
	e.llms = buildBackends(cfg, log)
	e.cfg = cfg

	if len(e.llms) == 0 && cfg.Provider != "none" && log != nil {
		log.Warn("ai_llm_not_configured",
			"provider", cfg.Provider, "hint", "缺少 base_url 或 model，已回退到确定性分析")
	}
	return e
}

// buildBackends 按配置构造槽位后端表。
// Slots 非空时以槽位为准；否则把环境变量单模型配置镜像到
// triage/hunt 两个槽（保持既有部署行为完全不变）。
func buildBackends(cfg Config, log *slog.Logger) map[string]Backend {
	configure := func(sc SlotConfig) Backend {
		if sc.Provider != "openai" || sc.BaseURL == "" || sc.Model == "" {
			return nil
		}
		if sc.Timeout <= 0 {
			sc.Timeout = 45 * time.Second
		}
		if sc.Temperature <= 0 {
			sc.Temperature = 0.1 // 安全研判要稳定，不要创造性
		}
		if sc.MaxTokens <= 0 {
			sc.MaxTokens = 1400
		}
		b := NewOpenAICompatible(sc.BaseURL, sc.APIKey, sc.Model, sc.Timeout)
		b.temperature = sc.Temperature
		b.effort = sc.Effort
		b.maxTokens = sc.MaxTokens
		return b
	}

	llms := make(map[string]Backend, 4)
	if len(cfg.Slots) > 0 {
		for slot, sc := range cfg.Slots {
			if !sc.Enabled {
				continue
			}
			if b := configure(sc); b != nil {
				llms[slot] = b
			}
		}
		return llms
	}
	if cfg.Provider == "openai" && cfg.BaseURL != "" && cfg.Model != "" {
		b := configure(SlotConfig{
			Provider: cfg.Provider, BaseURL: cfg.BaseURL, APIKey: cfg.APIKey,
			Model: cfg.Model, Timeout: cfg.Timeout, Enabled: true,
		})
		if b != nil {
			llms[SlotTriage] = b
			llms[SlotHunt] = b
		}
		if log != nil {
			log.Info("ai_engine_ready", "provider", cfg.Provider, "model", cfg.Model,
				"base_url", cfg.BaseURL, "budget_per_hour", cfg.HourlyTokenBudget)
		}
	}
	return llms
}

// backend 取槽位后端；investigate/narrative 未单独配置时回落 triage
// （这两个槽 v1 由研判链路代跑，独立配置的入口已在配置模型里预留）。
func (e *Engine) backend(slot string) Backend {
	e.mu.Lock()
	defer e.mu.Unlock()
	if b, ok := e.llms[slot]; ok {
		return b
	}
	if slot == SlotInvestigate || slot == SlotNarrative {
		return e.llms[SlotTriage]
	}
	return nil
}

// promptFor 返回某任务的系统提示覆盖与启用的技能包文本。
func (e *Engine) promptFor(task string) (string, []string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.prompts[task], e.skills[task]
}

// ApplyConfig 热更新引擎配置（配置中心保存后调用，无需重启）。
//
// prompts 的键是任务名（triage/hunt/investigate），值为空串表示用内置；
// skills 的键同为任务名，值是该任务启用的技能包文本列表（服务层已把
// task=all 的技能包展开合并）。换后端时旧后端直接丢弃——Backend 无状态，
// 在途请求持有旧引用自然完成，不需要优雅停机协议。
func (e *Engine) ApplyConfig(cfg Config, prompts map[string]string, skills map[string][]string) {
	if cfg.Provider == "" && len(cfg.Slots) == 0 {
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
	// Agent 循环预算：零值回填内置默认，越界钳制（防误配打爆预算或
	// 把单次调查饿死）。默认与历史硬编码一致（6 步/8 次/10s）——
	// 未显式配置时行为零变化。
	switch {
	case cfg.AgentMaxSteps <= 0:
		cfg.AgentMaxSteps = 6
	case cfg.AgentMaxSteps > 12:
		cfg.AgentMaxSteps = 12
	}
	switch {
	case cfg.AgentMaxToolCalls <= 0:
		cfg.AgentMaxToolCalls = 8
	case cfg.AgentMaxToolCalls > 24:
		cfg.AgentMaxToolCalls = 24
	}
	switch {
	case cfg.AgentToolTimeout <= 0:
		cfg.AgentToolTimeout = 10 * time.Second
	case cfg.AgentToolTimeout > 60*time.Second:
		cfg.AgentToolTimeout = 60 * time.Second
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	// 重算预算窗口：预算值变更后，旧窗口的已用量按旧口径保留可能
	// 立刻触顶或远未触顶；重置窗口是唯一口径一致的选择。
	e.cfg = cfg
	e.windowFrom = time.Now()
	e.tokens = 0
	e.ver++
	e.cache = make(map[string]cacheEntry, 256)
	e.narrativeCache = make(map[string]narrativeEntry, 64)
	e.llms = buildBackends(cfg, e.log)

	e.prompts = map[string]string{}
	for task, p := range prompts {
		if p != "" {
			e.prompts[task] = p
		}
	}
	e.skills = map[string][]string{}
	for task, list := range skills {
		if len(list) > 0 {
			e.skills[task] = list
		}
	}
	// 把提示词查找回调挂到每个新后端上：后端保持"哑"，
	// 不持有引擎引用，测试里单构造的后端不受影响。
	for _, b := range e.llms {
		if ob, ok := b.(*OpenAICompatible); ok {
			ob.SetPromptSource(e.promptFor)
		}
	}
	if e.log != nil {
		slots := make([]string, 0, len(e.llms))
		for slot := range e.llms {
			slots = append(slots, slot)
		}
		e.log.Info("ai_config_applied", "active_slots", strings.Join(slots, ","),
			"prompt_overrides", len(e.prompts), "skill_tasks", len(e.skills))
	}
}

// Enabled 返回是否配置了外部模型。
func (e *Engine) Enabled() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.llms) > 0
}

// Triage 研判一条告警。
//
// 流程固定为：缓存 → 模型（预算内）→ 降级启发式 → 校验 → 护栏 → 缓存。
// 任何一步出问题都退回启发式，绝不返回错误给调用方——
// 对分析师而言，"给出一份稍弱的结论"永远优于"分析失败请重试"。
func (e *Engine) Triage(ctx context.Context, in *TriageInput) *TriageResult {
	start := time.Now()

	cacheKey := e.cacheKey(in.AlertID)
	if cached := e.fromCache(cacheKey); cached != nil {
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

	be := e.backend(SlotTriage)
	if be != nil && e.budgetLeft() > 0 {
		r, err := be.Triage(ctx, in)
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
	} else if be != nil {
		degraded = true
		degReason = fmt.Sprintf("本小时 token 预算已用尽（上限 %d）", e.budgetCap())
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
	e.toCache(cacheKey, res)
	e.slotBump(SlotTriage, res.LatencyMs)
	return res
}

// cacheKey 给缓存键附加配置版本：配置中心每次保存都会 bump ver，
// 旧的研判缓存立刻失效——"改了提示词/模型却还要等 5 分钟"不再是问题。
func (e *Engine) cacheKey(id string) string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return fmt.Sprintf("%s#%d", id, e.ver)
}

// slotBump 记录某任务槽的一次调用（用量分布，帮助判断成本花在哪）。
func (e *Engine) slotBump(slot string, ms int64) {
	e.mu.Lock()
	defer e.mu.Unlock()
	c, ok := e.slots[slot]
	if !ok {
		c = &slotCounter{}
		e.slots[slot] = c
	}
	c.calls++
	c.msSum += ms
}

// Translate 把自然语言转成受控查询。
func (e *Engine) Translate(ctx context.Context, nl string) (*Query, error) {
	if strings.TrimSpace(nl) == "" {
		return nil, fmt.Errorf("查询语句为空")
	}
	start := time.Now()
	defer func() { e.slotBump(SlotHunt, time.Since(start).Milliseconds()) }()
	schema := AlertQuerySchema()

	if hb := e.backend(SlotHunt); hb != nil && e.budgetLeft() > 0 {
		q, err := hb.Translate(ctx, nl, schema)
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

// NarrateIncident 把一组告警重建为攻击链叙事（事件级检测 L6）。
//
// 与 Triage 同一条流水线形态：缓存 → 注入隔离 → 模型（预算内）→
// 降级确定性重建 → 引用校验 → 审批强制 → 缓存。
// 任何一步失败都退回确定性叙事，绝不把错误抛给调用方——
// "稍弱的结论"永远优于"分析失败"。
func (e *Engine) NarrateIncident(ctx context.Context, in *IncidentInput) *IncidentNarrative {
	start := time.Now()

	key := e.cacheKey("inc:" + in.IncidentID)
	if cached := e.fromNarrativeCache(key); cached != nil {
		e.bump(func(s *Engine) { s.stCacheHit++ })
		return cached
	}

	// ---- 注入隔离：告警字段同样是攻击者可控内容 ----
	safeIn, ignored := sanitizeIncidentInput(in)
	in = safeIn

	var (
		res       *IncidentNarrative
		degraded  bool
		degReason string
	)

	be := e.backend(SlotNarrative)
	if be != nil && e.budgetLeft() > 0 {
		n, err := be.Narrate(ctx, in)
		if err == nil {
			res = n
			e.bump(func(s *Engine) { s.stLLM++ })
		} else {
			degraded = true
			degReason = "模型调用失败：" + err.Error()
			if e.log != nil {
				e.log.Warn("ai_narrate_llm_failed", "err", err)
			}
		}
	} else if be != nil {
		degraded = true
		degReason = fmt.Sprintf("本小时 token 预算已用尽（上限 %d）", e.budgetCap())
	} else {
		degraded = true
		degReason = "未配置外部模型，使用确定性事件重建"
	}

	if res == nil {
		r, err := e.heur.Narrate(ctx, in)
		if err != nil || r == nil {
			res = &IncidentNarrative{Engine: "heuristic", RiskScore: 0,
				Summary: "事件重建失败，请人工复核时间线。"}
		} else {
			res = r
		}
		res.Degraded = degraded
		res.DegradedReason = degReason
		e.bump(func(s *Engine) { s.stDegraded++ })
	}

	res.UntrustedIgnored = ignored
	// ---- 护栏：引用校验（编造引用剔除）+ 风险钳制 + 审批强制 ----
	res = ValidateNarrative(res, in)

	res.LatencyMs = time.Since(start).Milliseconds()
	e.bump(func(s *Engine) { s.stNarrated++ })
	e.slotBump(SlotNarrative, res.LatencyMs)
	e.toNarrativeCache(key, res)
	return res
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
		Narrated:      e.stNarrated,
		ConflictCount: e.stConflicts,
		Engine:        "heuristic",
	}
	if len(e.slots) > 0 {
		st.Slots = make(map[string]SlotStat, len(e.slots))
		for name, c := range e.slots {
			avg := int64(0)
			if c.calls > 0 {
				avg = c.msSum / c.calls
			}
			st.Slots[name] = SlotStat{Calls: c.calls, AvgMs: avg}
		}
	}
	if e.stTriaged > 0 {
		st.AvgLatencyMs = e.stLatSum / e.stTriaged
		st.GroundedRate = round2(float64(e.stGrounded) / float64(e.stTriaged))
	}
	if tb, ok := e.llms[SlotTriage]; ok {
		st.Engine = "llm"
		st.Model = tb.Name()
	} else if hb, ok := e.llms[SlotHunt]; ok {
		// 只有狩猎槽时如实标注：引擎可用，但研判模型未配置
		st.Engine = "llm"
		st.Model = hb.Name()
	}
	return st
}

// budgetCap 返回当前配置的小时 token 上限。
func (e *Engine) budgetCap() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.cfg.HourlyTokenBudget
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

func (e *Engine) toCache(key string, res *TriageResult) {
	if key == "" || res == nil {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	// 简单容量控制：超过 1024 条时清空重来，避免无界增长
	if len(e.cache) >= 1024 {
		e.cache = make(map[string]cacheEntry, 256)
	}
	e.cache[key] = cacheEntry{res: res, at: time.Now()}
}

// fromNarrativeCache / toNarrativeCache 是事件叙事的独立缓存
// （结构与研判缓存相同，但结果类型不同，不能共用 map）。
func (e *Engine) fromNarrativeCache(key string) *IncidentNarrative {
	e.mu.Lock()
	defer e.mu.Unlock()
	if ent, ok := e.narrativeCache[key]; ok && time.Since(ent.at) < e.cfg.CacheTTL {
		return ent.narrative
	}
	return nil
}

func (e *Engine) toNarrativeCache(key string, res *IncidentNarrative) {
	if key == "" || res == nil {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.narrativeCache) >= 256 {
		e.narrativeCache = make(map[string]narrativeEntry, 64)
	}
	e.narrativeCache[key] = narrativeEntry{narrative: res, at: time.Now()}
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
