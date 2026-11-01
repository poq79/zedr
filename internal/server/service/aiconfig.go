package service

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"hostguard/internal/ai"
	"hostguard/internal/platform/apperr"
	"hostguard/internal/platform/idgen"
	"hostguard/internal/platform/settingseal"
	"hostguard/internal/server/domain"
)

// settings 表中的 AI 配置键。
const aiConfigSettingKey = "ai_config"

// AIService 的 AI 配置中心扩展：模型槽位、提示词模板、技能包。
//
// 与告警研判（AIService.Triage）同住一个服务是有意的——配置热更新
// 直接作用在本服务持有的引擎引用上，不存在"两处各持一份引擎"的漂移。
//
// 敏感字段策略：API Key 以 enc:v1 密文存 settings 表（settingseal），
// API 出口永远打码；明文只在两个瞬间存在——管理员提交时、引擎构造
// OpenAICompatible 后端时。其余环节（日志、审计、读接口）只见密文或掩码。

// storedAIConfig 是 settings.ai_config 里的 JSON 结构。
type storedAIConfig struct {
	Slots        map[string]storedSlot `json:"slots"`
	HourlyTokens int                   `json:"hourly_tokens,omitempty"`
	CacheTTLSec  int                   `json:"cache_ttl_sec,omitempty"`
}

type storedSlot struct {
	Provider    string  `json:"provider"`
	BaseURL     string  `json:"base_url"`
	APIKey      string  `json:"api_key"` // enc:v1:... 密文；空 = 无密钥
	Model       string  `json:"model"`
	Effort      string  `json:"effort,omitempty"`
	Temperature float64 `json:"temperature,omitempty"`
	MaxTokens   int     `json:"max_tokens,omitempty"`
	TimeoutSec  int     `json:"timeout_sec,omitempty"`
	Enabled     bool    `json:"enabled"`
}

// SlotView 是配置读接口里单个槽位的展示结构（Key 已打码）。
type SlotView struct {
	Provider    string  `json:"provider"`
	BaseURL     string  `json:"base_url"`
	Model       string  `json:"model"`
	Effort      string  `json:"effort"`
	Temperature float64 `json:"temperature"`
	MaxTokens   int     `json:"max_tokens"`
	TimeoutSec  int     `json:"timeout_sec"`
	Enabled     bool    `json:"enabled"`
	HasKey      bool    `json:"has_key"`
	KeyHint     string  `json:"key_hint,omitempty"` // 尾 4 位，帮助识别用的是哪把钥匙
	// Source 标注该槽位配置来自哪里：db（配置中心）/ env（环境变量引导）。
	// 展示口径问题：管理员需要知道改了 env 但后台没保存时，生效的到底是哪份。
	Source string `json:"source"`
}

// AIConfigView 是 GET /ai/config 的响应体。
type AIConfigView struct {
	Slots        map[string]SlotView `json:"slots"`
	HourlyTokens int                 `json:"hourly_tokens"`
	CacheTTLSec  int                 `json:"cache_ttl_sec"`
	Engine       string              `json:"engine"`  // 当前生效引擎（llm/heuristic）
	EngineModel  string              `json:"engine_model"`
	// PromptOverridden 标注哪些任务存在提示词覆盖。
	PromptOverridden map[string]bool `json:"prompt_overridden"`
	SkillCount       int             `json:"skill_count"`
}

// SaveSlotInput 是保存/测试请求里的单个槽位（部分更新语义）。
// Task 仅测试请求使用：api_key 为空时按该槽位回退到已存密钥。
type SaveSlotInput struct {
	Task        string  `json:"task,omitempty"`
	Provider    string  `json:"provider"`
	BaseURL     string  `json:"base_url"`
	APIKey      string  `json:"api_key"` // 空 = 保留旧值
	Model       string  `json:"model"`
	Effort      string  `json:"effort"`
	Temperature float64 `json:"temperature"`
	MaxTokens   int     `json:"max_tokens"`
	TimeoutSec  int     `json:"timeout_sec"`
	Enabled     *bool   `json:"enabled"` // 指针：区分"没传"与"显式 false"
	ClearKey    bool    `json:"clear_key"`
}

// SaveAIConfigInput 是 PUT /ai/config 的请求体。
// 所有字段都是可选的：只更新出现的部分（nil 槽位不动）。
type SaveAIConfigInput struct {
	Slots        map[string]*SaveSlotInput `json:"slots"`
	HourlyTokens *int                      `json:"hourly_tokens"`
	CacheTTLSec  *int                      `json:"cache_ttl_sec"`
}

// aiSlotTasks 是配置中心管理的槽位清单（narrative 预留、暂不开放编辑）。
var aiSlotTasks = []string{ai.SlotTriage, ai.SlotHunt, ai.SlotInvestigate}

// GetConfig 读当前配置并打码。
func (s *AIService) GetConfig(ctx context.Context) (*AIConfigView, error) {
	stored := s.loadStored(ctx)
	if stored == nil {
		// 首次部署/从未在后台保存过：按空配置展示（各槽位回落 env 引导值）
		stored = &storedAIConfig{Slots: map[string]storedSlot{}}
	}

	view := &AIConfigView{
		Slots:            map[string]SlotView{},
		HourlyTokens:     s.bootstrap.HourlyTokenBudget,
		CacheTTLSec:      int(s.bootstrap.CacheTTL.Seconds()),
		PromptOverridden: map[string]bool{},
	}
	if view.CacheTTLSec <= 0 {
		// env 引导配置不携带 CacheTTL（引擎内部默认 5 分钟），展示层对齐同一默认
		view.CacheTTLSec = 300
	}
	if stored != nil {
		if stored.HourlyTokens > 0 {
			view.HourlyTokens = stored.HourlyTokens
		}
		if stored.CacheTTLSec > 0 {
			view.CacheTTLSec = stored.CacheTTLSec
		}
	}

	for _, task := range aiSlotTasks {
		var sv SlotView
		if sc, ok := stored.Slots[task]; ok {
			sv = slotViewFromStored(sc, "db")
		} else if task == ai.SlotTriage || task == ai.SlotHunt {
			// 环境变量引导的单模型配置在这两个槽位生效（engine.buildBackends 同口径）
			sv = slotViewFromBootstrap(s.bootstrap, "env")
		} else {
			// investigate 未单独配置时回落 triage（引擎侧逻辑），展示 triage 的生效值
			if sc, ok := stored.Slots[ai.SlotTriage]; ok {
				sv = slotViewFromStored(sc, "db")
			} else {
				sv = slotViewFromBootstrap(s.bootstrap, "env")
			}
		}
		view.Slots[task] = sv
	}

	st := s.eng.Stats()
	view.Engine = st.Engine
	view.EngineModel = st.Model

	for _, task := range aiSlotTasks {
		if p, err := s.repos.AIConfig.Prompt(ctx, task); err == nil && p != nil {
			view.PromptOverridden[task] = p.Content != ""
		}
	}
	if skills, err := s.repos.AIConfig.Skills(ctx); err == nil {
		view.SkillCount = len(skills)
	}
	return view, nil
}

func slotViewFromStored(sc storedSlot, source string) SlotView {
	sv := SlotView{
		Provider: sc.Provider, BaseURL: sc.BaseURL, Model: sc.Model,
		Effort: sc.Effort, Temperature: sc.Temperature,
		MaxTokens: sc.MaxTokens, TimeoutSec: sc.TimeoutSec,
		Enabled: sc.Enabled, Source: source,
		HasKey: sc.APIKey != "",
	}
	sv.Effort = normalizeEffort(sv.Effort)
	if sv.Temperature <= 0 {
		sv.Temperature = 0.1
	}
	if sv.MaxTokens <= 0 {
		sv.MaxTokens = 1400
	}
	if sv.TimeoutSec <= 0 {
		sv.TimeoutSec = 45
	}
	if sc.APIKey != "" {
		sv.KeyHint = keyHint(sc.APIKey)
	}
	return sv
}

func slotViewFromBootstrap(cfg ai.Config, source string) SlotView {
	sv := SlotView{
		Provider: cfg.Provider, BaseURL: cfg.BaseURL, Model: cfg.Model,
		Effort: "off", Temperature: 0.1, MaxTokens: 1400,
		TimeoutSec: int(cfg.Timeout.Seconds()), Source: source,
		HasKey: cfg.APIKey != "", Enabled: cfg.Provider == "openai",
	}
	if sv.TimeoutSec <= 0 {
		sv.TimeoutSec = 45
	}
	if cfg.APIKey != "" {
		sv.KeyHint = keyHint(cfg.APIKey)
	}
	return sv
}

func normalizeEffort(e string) string {
	switch e {
	case "low", "medium", "high":
		return e
	default:
		return "off"
	}
}

// keyHint 提取密钥尾 4 位。密文本身不可逆出明文（AES-GCM），
// 所以这里的提示只能基于密文尾部——同值同密文（不同 nonce 会不同），
// 实际做法：解密后取尾。为了读接口不引入解密依赖，直接取密文尾部
// 也能满足"区分换了没有"的目的（换 key 必换密文）。
func keyHint(sealed string) string {
	if len(sealed) <= 4 {
		return "****"
	}
	return "…" + sealed[len(sealed)-4:]
}

// loadStored 读并反序列化 settings 里的 AI 配置；不存在时返回 nil。
func (s *AIService) loadStored(ctx context.Context) *storedAIConfig {
	raw, ok, err := s.repos.AIConfig.GetSetting(ctx, aiConfigSettingKey)
	if err != nil || !ok || raw == "" {
		return nil
	}
	var c storedAIConfig
	if json.Unmarshal([]byte(raw), &c) != nil {
		// 配置损坏不阻断读取：按"未配置"处理，管理员保存时会整体覆盖
		if s.log != nil {
			s.log.Warn("ai_config_corrupted", "hint", "settings.ai_config 解析失败，按未配置处理")
		}
		return nil
	}
	return &c
}

// SaveConfig 保存配置并热更新引擎（无需重启）。
func (s *AIService) SaveConfig(ctx context.Context, in *SaveAIConfigInput) (*AIConfigView, error) {
	if in == nil {
		return nil, apperr.Invalid("空的配置请求")
	}
	if len(in.Slots) > len(aiSlotTasks)+1 {
		return nil, apperr.Invalid("槽位数量超限")
	}
	if s.encKey == nil {
		return nil, apperr.Unavailable("未配置加密密钥（HG_SERVER_SETTING_ENC_KEY），无法在后台保存 API Key；仍可用环境变量引导配置")
	}

	stored := s.loadStored(ctx)
	if stored == nil {
		stored = &storedAIConfig{Slots: map[string]storedSlot{}}
	}

	for task, req := range in.Slots {
		valid := false
		for _, t := range aiSlotTasks {
			if task == t {
				valid = true
				break
			}
		}
		if !valid {
			return nil, apperr.Invalid("未知的模型槽位: %s", task)
		}
		if err := s.validateSlotInput(task, req); err != nil {
			return nil, err
		}

		// 合并语义：请求里没出现的字段沿用旧值（或 env 引导值）
		base := storedSlot{}
		if old, ok := stored.Slots[task]; ok {
			base = old
		} else if task == ai.SlotTriage || task == ai.SlotHunt {
			base = bootstrapSlot(s.bootstrap)
		}

		if req.Provider != "" {
			base.Provider = req.Provider
		}
		if req.BaseURL != "" {
			base.BaseURL = strings.TrimRight(req.BaseURL, "/")
		}
		if req.Model != "" {
			base.Model = req.Model
		}
		if req.Effort != "" {
			base.Effort = req.Effort
		}
		if req.Temperature > 0 {
			base.Temperature = req.Temperature
		}
		if req.MaxTokens > 0 {
			base.MaxTokens = req.MaxTokens
		}
		if req.TimeoutSec > 0 {
			base.TimeoutSec = req.TimeoutSec
		}
		if req.Enabled != nil {
			base.Enabled = *req.Enabled
		}
		switch {
		case req.ClearKey:
			base.APIKey = ""
		case req.APIKey != "":
			sealed, err := settingseal.Seal(s.encKey, req.APIKey)
			if err != nil {
				return nil, apperr.Internal(fmt.Errorf("加密 API Key 失败: %w", err))
			}
			base.APIKey = sealed
		default:
			// 空串 = 保留旧密钥
		}
		stored.Slots[task] = base
	}

	if in.HourlyTokens != nil {
		if *in.HourlyTokens < 1000 {
			return nil, apperr.Invalid("hourly_tokens 至少 1000")
		}
		stored.HourlyTokens = *in.HourlyTokens
	}
	if in.CacheTTLSec != nil {
		if *in.CacheTTLSec < 0 || *in.CacheTTLSec > 3600 {
			return nil, apperr.Invalid("cache_ttl_sec 需在 0-3600 之间")
		}
		stored.CacheTTLSec = *in.CacheTTLSec
	}

	raw, err := json.Marshal(stored)
	if err != nil {
		return nil, apperr.Internal(err)
	}
	if err := s.repos.AIConfig.SetSetting(ctx, aiConfigSettingKey, string(raw)); err != nil {
		return nil, err
	}

	if err := s.applyEngineConfig(ctx); err != nil {
		return nil, err
	}
	return s.GetConfig(ctx)
}

// bootstrapSlot 把 env 引导配置转成槽位存储结构（合并基线）。
func bootstrapSlot(cfg ai.Config) storedSlot {
	return storedSlot{
		Provider: cfg.Provider, BaseURL: cfg.BaseURL, Model: cfg.Model,
		TimeoutSec: int(cfg.Timeout.Seconds()), Enabled: cfg.Provider == "openai",
	}
}

func (s *AIService) validateSlotInput(task string, in *SaveSlotInput) error {
	if in.Provider != "" && in.Provider != "openai" && in.Provider != "none" {
		return apperr.Invalid("槽位 %s 的 provider 只支持 openai/none", task)
	}
	if in.BaseURL != "" && !strings.HasPrefix(in.BaseURL, "http://") && !strings.HasPrefix(in.BaseURL, "https://") {
		return apperr.Invalid("槽位 %s 的 base_url 必须以 http:// 或 https:// 开头", task)
	}
	if in.Effort != "" && in.Effort != "off" && in.Effort != "low" && in.Effort != "medium" && in.Effort != "high" {
		return apperr.Invalid("槽位 %s 的 effort 只能是 off/low/medium/high", task)
	}
	if in.Temperature < 0 || in.Temperature > 2 {
		return apperr.Invalid("槽位 %s 的 temperature 需在 0-2 之间", task)
	}
	if in.MaxTokens != 0 && (in.MaxTokens < 100 || in.MaxTokens > 32000) {
		return apperr.Invalid("槽位 %s 的 max_tokens 需在 100-32000 之间", task)
	}
	if in.TimeoutSec != 0 && (in.TimeoutSec < 3 || in.TimeoutSec > 300) {
		return apperr.Invalid("槽位 %s 的 timeout_sec 需在 3-300 之间", task)
	}
	return nil
}

// TestConfig 对一套"尚未保存"的接入配置做真实拨测。
// api_key 为空且给了 task 时，回退到该槽位已存的密钥（或 env 引导密钥）——
// 管理员验证"换 base_url/模型后还通不通"时不应被迫重输钥匙。
func (s *AIService) TestConfig(ctx context.Context, in *SaveSlotInput) (*ai.ProbeResult, error) {
	if in == nil || in.BaseURL == "" {
		return nil, apperr.Invalid("base_url 不能为空")
	}
	if !strings.HasPrefix(in.BaseURL, "http://") && !strings.HasPrefix(in.BaseURL, "https://") {
		return nil, apperr.Invalid("base_url 必须以 http:// 或 https:// 开头")
	}
	apiKey := in.APIKey
	if apiKey == "" && in.Task != "" {
		apiKey = s.storedSlotKey(ctx, in.Task)
	}
	timeout := time.Duration(in.TimeoutSec) * time.Second
	if timeout <= 0 {
		timeout = 45 * time.Second
	}
	res := ai.ProbeOpenAI(in.BaseURL, apiKey, in.Model, timeout)
	return res, nil
}

// storedSlotKey 解出某槽位当前生效的密钥（DB 优先，回退 env 引导）。
func (s *AIService) storedSlotKey(ctx context.Context, task string) string {
	if stored := s.loadStored(ctx); stored != nil {
		if sc, ok := stored.Slots[task]; ok && sc.APIKey != "" && s.encKey != nil {
			if pt, err := settingseal.Open(s.encKey, sc.APIKey); err == nil {
				return pt
			}
		}
	}
	if task == ai.SlotTriage || task == ai.SlotHunt {
		return s.bootstrap.APIKey
	}
	return ""
}

// ---------------------------------------------------------------- 提示词模板

// PromptTasks 是开放覆盖的提示词任务清单。
var PromptTasks = []string{ai.SlotTriage, ai.SlotHunt, ai.SlotInvestigate}

// GetPrompt 读某任务的提示词模板（含历史版本）。
func (s *AIService) GetPrompt(ctx context.Context, task string) (*domain.AIPrompt, error) {
	if !validPromptTask(task) {
		return nil, apperr.Invalid("未知的提示词任务: %s", task)
	}
	return s.repos.AIConfig.Prompt(ctx, task)
}

// SavePrompt 保存提示词覆盖（护栏校验不过拒绝保存）。
func (s *AIService) SavePrompt(ctx context.Context, task, content, by string) (int, error) {
	if !validPromptTask(task) {
		return 0, apperr.Invalid("未知的提示词任务: %s", task)
	}
	if err := ai.ValidatePromptOverride(task, content); err != nil {
		return 0, apperr.Invalid("%s", err.Error())
	}
	ver, err := s.repos.AIConfig.SavePrompt(ctx, task, content, by, time.Now())
	if err != nil {
		return 0, err
	}
	if err := s.applyEngineConfig(ctx); err != nil {
		return ver, err
	}
	return ver, nil
}

// RollbackPrompt 回滚到指定历史版本（追加式：旧版本复制为新版本）。
func (s *AIService) RollbackPrompt(ctx context.Context, task string, version int, by string) (int, error) {
	if !validPromptTask(task) {
		return 0, apperr.Invalid("未知的提示词任务: %s", task)
	}
	ver, err := s.repos.AIConfig.RollbackPrompt(ctx, task, version, by, time.Now())
	if err != nil {
		return 0, apperr.Invalid("%s", err.Error())
	}
	if err := s.applyEngineConfig(ctx); err != nil {
		return ver, err
	}
	return ver, nil
}

func validPromptTask(task string) bool {
	for _, t := range PromptTasks {
		if t == task {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------- 技能包

// skillContentCap 单个技能包内容上限。技能包是追加进每次模型调用的
// 固定成本：4KB 约一千汉字，足够写清一个环境事实，再多就该拆包了。
const skillContentCap = 4096

// ListSkills 技能包清单。空时返回 [] 而非 null（前端契约：列表永远可迭代）。
func (s *AIService) ListSkills(ctx context.Context) ([]domain.AISkill, error) {
	list, err := s.repos.AIConfig.Skills(ctx)
	if err != nil {
		return nil, err
	}
	if list == nil {
		list = []domain.AISkill{}
	}
	return list, nil
}

// UpsertSkill 新建或更新技能包。id 为空表示新建。
func (s *AIService) UpsertSkill(ctx context.Context, in *domain.AISkill, by string) (*domain.AISkill, error) {
	if strings.TrimSpace(in.Name) == "" {
		return nil, apperr.Invalid("技能包名称不能为空")
	}
	if len(in.Name) > 100 {
		return nil, apperr.Invalid("技能包名称过长（上限 100 字）")
	}
	if strings.TrimSpace(in.Content) == "" {
		return nil, apperr.Invalid("技能包内容不能为空")
	}
	if len(in.Content) > skillContentCap {
		return nil, apperr.Invalid("技能包内容过长（%d 字节，上限 %d）", len(in.Content), skillContentCap)
	}
	if !in.Task.Valid() {
		return nil, apperr.Invalid("task 只能是 triage/hunt/investigate/all")
	}
	if in.Sort < 0 || in.Sort > 10000 {
		return nil, apperr.Invalid("sort 需在 0-10000 之间")
	}

	now := time.Now()
	if in.ID == "" {
		in.ID = idgen.URLSafe(12)
		in.CreatedBy = by
		in.CreatedAt = now
	} else if old, err := s.repos.AIConfig.Skill(ctx, in.ID); err != nil {
		return nil, err
	} else if old == nil {
		return nil, apperr.NotFound("技能包不存在")
	} else {
		in.CreatedBy = old.CreatedBy
		in.CreatedAt = old.CreatedAt
	}
	in.UpdatedAt = now

	if err := s.repos.AIConfig.UpsertSkill(ctx, in); err != nil {
		return nil, err
	}
	if err := s.applyEngineConfig(ctx); err != nil {
		return in, err
	}
	return in, nil
}

// DeleteSkill 删除技能包。
func (s *AIService) DeleteSkill(ctx context.Context, id string) error {
	if err := s.repos.AIConfig.DeleteSkill(ctx, id); err != nil {
		return apperr.NotFound("技能包不存在")
	}
	return s.applyEngineConfig(ctx)
}

// ---------------------------------------------------------------- 引擎热更新

// applyEngineConfig 把 DB 里的配置 + 提示词 + 技能包组装成引擎配置并热更新。
//
// 这是配置中心的"最后一公里"：所有写路径（改配置/改提示词/改技能）
// 汇合到这里，保证引擎状态永远等于 DB 状态，不存在第二份真值。
// 启动时也会调用一次（LoadStoredConfig）。
func (s *AIService) applyEngineConfig(ctx context.Context) error {
	stored := s.loadStored(ctx)

	cfg := ai.Config{
		Provider:          s.bootstrap.Provider,
		BaseURL:           s.bootstrap.BaseURL,
		APIKey:            s.bootstrap.APIKey,
		Model:             s.bootstrap.Model,
		Timeout:           s.bootstrap.Timeout,
		HourlyTokenBudget: s.bootstrap.HourlyTokenBudget,
		CacheTTL:          s.bootstrap.CacheTTL,
	}
	if stored != nil {
		slots := map[string]ai.SlotConfig{}
		for task, sc := range stored.Slots {
			key := sc.APIKey
			if key != "" && s.encKey != nil {
				if pt, err := settingseal.Open(s.encKey, sc.APIKey); err == nil {
					key = pt
				} else if s.log != nil {
					// 解密失败（换了加密主密钥）时保留密文形态：
					// 后端会因认证失败降级并在日志里可见，而不是静默丢配置
					s.log.Warn("ai_config_key_decrypt_failed", "slot", task, "err", err.Error())
				}
			}
			slots[task] = ai.SlotConfig{
				Provider: sc.Provider, BaseURL: sc.BaseURL, APIKey: key, Model: sc.Model,
				Effort: sc.Effort, Temperature: sc.Temperature, MaxTokens: sc.MaxTokens,
				Timeout: time.Duration(sc.TimeoutSec) * time.Second, Enabled: sc.Enabled,
			}
		}
		if len(slots) > 0 {
			cfg.Slots = slots
		}
		if stored.HourlyTokens > 0 {
			cfg.HourlyTokenBudget = stored.HourlyTokens
		}
		if stored.CacheTTLSec > 0 {
			cfg.CacheTTL = time.Duration(stored.CacheTTLSec) * time.Second
		}
	}

	prompts := map[string]string{}
	for _, task := range PromptTasks {
		if p, err := s.repos.AIConfig.Prompt(ctx, task); err == nil && p != nil {
			prompts[task] = p.Content
		}
	}
	skills, err := s.skillTexts(ctx)
	if err != nil {
		return err
	}

	s.eng.ApplyConfig(cfg, prompts, skills)
	return nil
}

// skillTexts 把技能包清单展开成 task → 文本列表（task=all 摊入所有任务）。
func (s *AIService) skillTexts(ctx context.Context) (map[string][]string, error) {
	list, err := s.repos.AIConfig.Skills(ctx)
	if err != nil {
		return nil, err
	}
	out := map[string][]string{}
	for _, sk := range list {
		if !sk.Enabled {
			continue
		}
		tasks := []string{string(sk.Task)}
		if sk.Task == domain.SkillTaskAll {
			tasks = PromptTasks
		}
		for _, t := range tasks {
			out[t] = append(out[t], sk.Content)
		}
	}
	return out, nil
}

// LoadStoredConfig 启动时加载 DB 配置并应用到引擎。
// 失败只记日志不阻断启动：AI 能力降级到 env 引导配置或启发式，
// 绝不能因为配置问题让整个服务起不来。
func (s *AIService) LoadStoredConfig(ctx context.Context) {
	if err := s.applyEngineConfig(ctx); err != nil && s.log != nil {
		s.log.Warn("ai_config_load_failed", "err", err.Error(),
			"hint", "后台 AI 配置未生效，使用环境变量引导配置")
	}
}
