package service

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"zedr/internal/ai"
	"zedr/internal/platform/apperr"
	"zedr/internal/platform/idgen"
	"zedr/internal/platform/settingseal"
	"zedr/internal/server/domain"
)

// settings 表中的 AI 配置键。
const aiConfigSettingKey = "ai_config"

// AIService 的 AI 配置中心扩展：统一 Provider、任务槽位、提示词模板、技能包。
//
// 与告警研判（AIService.Triage）同住一个服务是有意的——配置热更新
// 直接作用在本服务持有的引擎引用上，不存在"两处各持一份引擎"的漂移。
//
// 配置模型（人性化口径）：同一个模型服务只配一次——
//   Provider（base_url / api_key / 默认模型 / effort / 温度 / 超时）是全局唯一
//   的"服务商接入"；任务槽位只声明差异（换模型 / 换思考强度 / 开关），
//   留空一律跟随 Provider 默认。少数"调查走另一家"的场景通过槽位级
//   高级覆盖表达，UI 默认折叠。
//   兼容：v1 期间曾按槽位存 base_url/api_key，storedSlot 保留这两个字段
//   作为覆盖项读旧数据，无需迁移。
//
// 敏感字段策略：API Key 以 enc:v1 密文存 settings 表（settingseal），
// API 出口永远打码；明文只在两个瞬间存在——管理员提交时、引擎构造
// OpenAICompatible 后端时。其余环节（日志、审计、读接口）只见密文或掩码。

// storedProvider 是统一服务商接入（存密文 Key）。
type storedProvider struct {
	BaseURL     string  `json:"base_url,omitempty"`
	APIKey      string  `json:"api_key,omitempty"` // enc:v1:... 密文；空 = 无密钥
	Model       string  `json:"model,omitempty"`   // 默认模型：槽位留空时使用
	Effort      string  `json:"effort,omitempty"`
	Temperature float64 `json:"temperature,omitempty"`
	MaxTokens   int     `json:"max_tokens,omitempty"`
	TimeoutSec  int     `json:"timeout_sec,omitempty"`
}

// storedAIConfig 是 settings.ai_config 里的 JSON 结构。
type storedAIConfig struct {
	Provider     *storedProvider       `json:"provider,omitempty"`
	Slots        map[string]storedSlot `json:"slots"`
	HourlyTokens int                   `json:"hourly_tokens,omitempty"`
	CacheTTLSec  int                   `json:"cache_ttl_sec,omitempty"`
}

// storedSlot 是任务槽位的差异声明：所有字段留空/零值 = 跟随 Provider 默认。
// BaseURL/APIKey 是高级覆盖（"调查走另一家服务商"），常规配置不碰。
type storedSlot struct {
	BaseURL     string  `json:"base_url,omitempty"` // 覆盖 Provider
	APIKey      string  `json:"api_key,omitempty"`  // 覆盖 Provider（enc:v1 密文）
	Model       string  `json:"model,omitempty"`    // 覆盖默认模型
	Effort      string  `json:"effort,omitempty"`
	Temperature float64 `json:"temperature,omitempty"`
	MaxTokens   int     `json:"max_tokens,omitempty"`
	TimeoutSec  int     `json:"timeout_sec,omitempty"`
	Enabled     bool    `json:"enabled"`
}

// ProviderView 是 GET /ai/config 里的统一服务商展示（Key 已打码）。
type ProviderView struct {
	BaseURL     string  `json:"base_url"`
	Model       string  `json:"model"` // 默认模型（槽位留空时跟随）
	Effort      string  `json:"effort"`
	Temperature float64 `json:"temperature"`
	MaxTokens   int     `json:"max_tokens"`
	TimeoutSec  int     `json:"timeout_sec"`
	HasKey      bool    `json:"has_key"`
	KeyHint     string  `json:"key_hint,omitempty"`
	// Source：db（后台已保存）/ env（环境变量引导）/ none（未配置任何模型服务）
	Source string `json:"source"`
}

// SlotView 是单个任务槽位的展示结构：覆盖值 + 实际生效值。
type SlotView struct {
	Enabled bool `json:"enabled"`
	// 覆盖值（空 = 跟随 Provider 默认，前端展示"跟随默认"）
	Model  string `json:"model"`
	Effort string `json:"effort"`
	// 实际生效值（解析 Provider 默认与覆盖后的结果），供界面直接展示
	EffectiveModel  string `json:"effective_model"`
	EffectiveEffort string `json:"effective_effort"`
	// 高级覆盖：仅在设置过时返回（零值字段前端不渲染）
	OverrideBaseURL     string  `json:"override_base_url,omitempty"`
	OverrideKeyHint     string  `json:"override_key_hint,omitempty"`
	OverrideTemperature float64 `json:"override_temperature,omitempty"`
	OverrideMaxTokens   int     `json:"override_max_tokens,omitempty"`
	OverrideTimeoutSec  int     `json:"override_timeout_sec,omitempty"`
	OverrideHasKey      bool    `json:"override_has_key,omitempty"`
}

// AIConfigView 是 GET /ai/config 的响应体。
type AIConfigView struct {
	Provider      ProviderView        `json:"provider"`
	Slots         map[string]SlotView `json:"slots"`
	HourlyTokens  int                 `json:"hourly_tokens"`
	CacheTTLSec   int                 `json:"cache_ttl_sec"`
	Engine        string              `json:"engine"` // 当前生效引擎（llm/heuristic）
	EngineModel   string              `json:"engine_model"`
	// PromptOverridden 标注哪些任务存在提示词覆盖。
	PromptOverridden map[string]bool `json:"prompt_overridden"`
	SkillCount       int             `json:"skill_count"`
}

// SaveProviderInput 是统一服务商接入的保存请求（部分更新语义；
// api_key 空 = 保留旧值，clear_key = 显式清除）。
type SaveProviderInput struct {
	BaseURL     string  `json:"base_url"`
	APIKey      string  `json:"api_key"`
	Model       string  `json:"model"`
	Effort      string  `json:"effort"`
	Temperature float64 `json:"temperature"`
	MaxTokens   int     `json:"max_tokens"`
	TimeoutSec  int     `json:"timeout_sec"`
	ClearKey    bool    `json:"clear_key"`
}

// SaveSlotInput 是保存请求里的单个槽位差异。
// 语义约定：非敏感字段（model/effort/base_url…）传空 = 清除覆盖（跟随默认）；
// api_key 是唯一例外——空 = 保留旧值（密钥从不回显，无法"传空清除"，
// 清除走 clear_key）。
type SaveSlotInput struct {
	Task        string  `json:"task,omitempty"` // 仅拨测请求使用
	BaseURL     string  `json:"base_url"`
	APIKey      string  `json:"api_key"`
	Model       string  `json:"model"`
	Effort      string  `json:"effort"`
	Temperature float64 `json:"temperature"`
	MaxTokens   int     `json:"max_tokens"`
	TimeoutSec  int     `json:"timeout_sec"`
	Enabled     *bool   `json:"enabled"` // 指针：区分"没传"与"显式 false"
	ClearKey    bool    `json:"clear_key"`
}

// SaveAIConfigInput 是 PUT /ai/config 的请求体。
// 所有字段都是可选的：只更新出现的部分（nil 段不动）。
type SaveAIConfigInput struct {
	Provider     *SaveProviderInput        `json:"provider"`
	Slots        map[string]*SaveSlotInput `json:"slots"`
	HourlyTokens *int                      `json:"hourly_tokens"`
	CacheTTLSec  *int                      `json:"cache_ttl_sec"`
}

// aiSlotTasks 是配置中心管理的槽位清单（narrative 预留、暂不开放编辑）。
var aiSlotTasks = []string{ai.SlotTriage, ai.SlotHunt, ai.SlotInvestigate}

// ---------------------------------------------------------------- 解析（纯函数，可单测）

// resolveProvider 计算"实际生效"的 Provider 配置：
// env 引导基线 → DB Provider 覆盖 → 默认值兜底。
func resolveProvider(bootstrap ai.Config, stored *storedAIConfig) storedProvider {
	p := storedProvider{
		Model:       bootstrap.Model,
		Temperature: 0.1, // 安全研判要稳定，不要创造性
		MaxTokens:   1400,
		TimeoutSec:  int(bootstrap.Timeout.Seconds()),
	}
	if bootstrap.Provider == "openai" {
		p.BaseURL = bootstrap.BaseURL
		p.APIKey = bootstrap.APIKey
	}
	if p.TimeoutSec <= 0 {
		p.TimeoutSec = 45
	}
	if stored != nil && stored.Provider != nil {
		sp := stored.Provider
		if sp.BaseURL != "" {
			p.BaseURL = sp.BaseURL
		}
		if sp.APIKey != "" {
			p.APIKey = sp.APIKey
		}
		if sp.Model != "" {
			p.Model = sp.Model
		}
		if sp.Effort != "" {
			p.Effort = sp.Effort
		}
		if sp.Temperature > 0 {
			p.Temperature = sp.Temperature
		}
		if sp.MaxTokens > 0 {
			p.MaxTokens = sp.MaxTokens
		}
		if sp.TimeoutSec > 0 {
			p.TimeoutSec = sp.TimeoutSec
		}
	}
	p.Effort = normalizeEffort(p.Effort)
	return p
}

// resolveSlot 计算某任务槽位实际生效的引擎配置。
// 返回值 ready 表示" enabled 且服务商接入完整（base_url+model 齐备）"。
func resolveSlot(task string, bootstrap ai.Config, stored *storedAIConfig) (ai.SlotConfig, bool) {
	p := resolveProvider(bootstrap, stored)

	var sl storedSlot
	haveSlot := false
	if stored != nil {
		sl, haveSlot = stored.Slots[task]
	}

	eff := p // 起点是 Provider 默认
	if sl.BaseURL != "" {
		eff.BaseURL = sl.BaseURL
	}
	if sl.APIKey != "" {
		eff.APIKey = sl.APIKey
	}
	if sl.Model != "" {
		eff.Model = sl.Model
	}
	if sl.Effort != "" {
		eff.Effort = sl.Effort
	}
	if sl.Temperature > 0 {
		eff.Temperature = sl.Temperature
	}
	if sl.MaxTokens > 0 {
		eff.MaxTokens = sl.MaxTokens
	}
	if sl.TimeoutSec > 0 {
		eff.TimeoutSec = sl.TimeoutSec
	}
	eff.Effort = normalizeEffort(eff.Effort)

	// 未显式声明过的槽位默认启用（Provider 就绪即生效）——
	// "填一次 Provider，三个开关全亮"是管理员对这套配置的自然预期。
	enabled := sl.Enabled
	if !haveSlot {
		enabled = eff.BaseURL != "" && eff.Model != ""
	}
	ready := enabled && eff.BaseURL != "" && eff.Model != ""
	return ai.SlotConfig{
		Provider:    "openai",
		BaseURL:     eff.BaseURL,
		APIKey:      eff.APIKey,
		Model:       eff.Model,
		Effort:      eff.Effort,
		Temperature: eff.Temperature,
		MaxTokens:   eff.MaxTokens,
		Timeout:     time.Duration(eff.TimeoutSec) * time.Second,
		Enabled:     enabled,
	}, ready
}

// providerSource 判断统一接入的配置来源。
func providerSource(bootstrap ai.Config, stored *storedAIConfig) string {
	if stored != nil && stored.Provider != nil {
		return "db"
	}
	if bootstrap.Provider == "openai" {
		return "env"
	}
	return "none"
}

// ---------------------------------------------------------------- 读接口

// GetConfig 读当前配置并打码（Provider 统一展示 + 槽位覆盖/生效值）。
func (s *AIService) GetConfig(ctx context.Context) (*AIConfigView, error) {
	stored := s.loadStored(ctx)

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

	p := resolveProvider(s.bootstrap, stored)
	view.Provider = ProviderView{
		BaseURL: p.BaseURL, Model: p.Model, Effort: p.Effort,
		Temperature: p.Temperature, MaxTokens: p.MaxTokens, TimeoutSec: p.TimeoutSec,
		HasKey: p.APIKey != "", KeyHint: keyHint(p.APIKey),
		Source: providerSource(s.bootstrap, stored),
	}

	for _, task := range aiSlotTasks {
		sc, _ := resolveSlot(task, s.bootstrap, stored)
		var sl storedSlot
		if stored != nil {
			sl = stored.Slots[task]
		}
		sv := SlotView{
			Enabled:         sc.Enabled,
			Model:           sl.Model,
			Effort:          normalizeEffort(sl.Effort),
			EffectiveModel:  sc.Model,
			EffectiveEffort: sc.Effort,
		}
		if sl.BaseURL != "" {
			sv.OverrideBaseURL = sl.BaseURL
		}
		if sl.APIKey != "" {
			sv.OverrideHasKey = true
			sv.OverrideKeyHint = keyHint(sl.APIKey)
		}
		if sl.Temperature > 0 {
			sv.OverrideTemperature = sl.Temperature
		}
		if sl.MaxTokens > 0 {
			sv.OverrideMaxTokens = sl.MaxTokens
		}
		if sl.TimeoutSec > 0 {
			sv.OverrideTimeoutSec = sl.TimeoutSec
		}
		view.Slots[task] = sv
	}

	st := s.eng.Stats()
	view.Engine = st.Engine
	view.EngineModel = st.Model

	for _, task := range aiSlotTasks {
		if pr, err := s.repos.AIConfig.Prompt(ctx, task); err == nil && pr != nil {
			view.PromptOverridden[task] = pr.Content != ""
		}
	}
	if skills, err := s.repos.AIConfig.Skills(ctx); err == nil {
		view.SkillCount = len(skills)
	}
	return view, nil
}

func normalizeEffort(e string) string {
	switch e {
	case "low", "medium", "high":
		return e
	default:
		return "off"
	}
}

// keyHint 提取密文尾 4 位。密文不可逆（AES-GCM），但"换 key 必换密文"，
// 尾部对比足以让管理员识别钥匙有没有换过。
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

// ---------------------------------------------------------------- 保存

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

	// ---- Provider 统一接入 ----
	if in.Provider != nil {
		req := in.Provider
		if err := validateProviderInput(req); err != nil {
			return nil, err
		}
		base := stored.Provider
		if base == nil {
			base = &storedProvider{}
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
		stored.Provider = base
	}

	// ---- 槽位差异 ----
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
		if err := validateSlotInput(task, req); err != nil {
			return nil, err
		}

		base := stored.Slots[task]
		// 非敏感覆盖：空串 = 清除覆盖（跟随 Provider 默认）
		base.BaseURL = strings.TrimRight(req.BaseURL, "/")
		base.Model = req.Model
		base.Effort = req.Effort
		base.Temperature = req.Temperature
		base.MaxTokens = req.MaxTokens
		base.TimeoutSec = req.TimeoutSec
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
			// 密钥不回显：空 = 保留旧值
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

func validateProviderInput(in *SaveProviderInput) error {
	if in.BaseURL != "" && !strings.HasPrefix(in.BaseURL, "http://") && !strings.HasPrefix(in.BaseURL, "https://") {
		return apperr.Invalid("base_url 必须以 http:// 或 https:// 开头")
	}
	if in.Effort != "" && in.Effort != "off" && in.Effort != "low" && in.Effort != "medium" && in.Effort != "high" {
		return apperr.Invalid("effort 只能是 off/low/medium/high")
	}
	if in.Temperature < 0 || in.Temperature > 2 {
		return apperr.Invalid("temperature 需在 0-2 之间")
	}
	if in.MaxTokens != 0 && (in.MaxTokens < 100 || in.MaxTokens > 32000) {
		return apperr.Invalid("max_tokens 需在 100-32000 之间")
	}
	if in.TimeoutSec != 0 && (in.TimeoutSec < 3 || in.TimeoutSec > 300) {
		return apperr.Invalid("timeout_sec 需在 3-300 之间")
	}
	return nil
}

func validateSlotInput(task string, in *SaveSlotInput) error {
	if in.BaseURL != "" && !strings.HasPrefix(in.BaseURL, "http://") && !strings.HasPrefix(in.BaseURL, "https://") {
		return apperr.Invalid("槽位 %s 的覆盖 base_url 必须以 http:// 或 https:// 开头", task)
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
// api_key 为空时回退到当前生效密钥（DB Provider → env 引导）——
// 管理员验证"换 base_url/模型后还通不通"时不应被迫重输钥匙。
func (s *AIService) TestConfig(ctx context.Context, in *SaveSlotInput) (*ai.ProbeResult, error) {
	if in == nil || in.BaseURL == "" {
		return nil, apperr.Invalid("base_url 不能为空")
	}
	if !strings.HasPrefix(in.BaseURL, "http://") && !strings.HasPrefix(in.BaseURL, "https://") {
		return nil, apperr.Invalid("base_url 必须以 http:// 或 https:// 开头")
	}
	apiKey := in.APIKey
	if apiKey == "" {
		apiKey = s.effectiveKey(ctx)
	}
	timeout := time.Duration(in.TimeoutSec) * time.Second
	if timeout <= 0 {
		timeout = 45 * time.Second
	}
	res := ai.ProbeOpenAI(in.BaseURL, apiKey, in.Model, timeout)
	return res, nil
}

// effectiveKey 解出当前生效的 API Key（DB Provider 优先，回退 env 引导）。
func (s *AIService) effectiveKey(ctx context.Context) string {
	stored := s.loadStored(ctx)
	if stored != nil && stored.Provider != nil && stored.Provider.APIKey != "" && s.encKey != nil {
		if pt, err := settingseal.Open(s.encKey, stored.Provider.APIKey); err == nil {
			return pt
		}
	}
	return s.bootstrap.APIKey
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

// assembleEngineConfig 把 DB 里的配置 + 提示词 + 技能包组装成引擎配置。
//
// 生产热更新与评测引擎共用这一处组装逻辑：评测必须测"当前生效的生产配置"
// （同提示词/同技能包/同槽位），否则评测结果没有代表性。
func (s *AIService) assembleEngineConfig(ctx context.Context) (ai.Config, map[string]string, map[string][]string, error) {
	stored := s.loadStored(ctx)
	if stored == nil {
		stored = &storedAIConfig{Slots: map[string]storedSlot{}}
	}

	slots := map[string]ai.SlotConfig{}
	for _, task := range aiSlotTasks {
		sc, ready := resolveSlot(task, s.bootstrap, stored)
		if !ready {
			continue // 未启用或服务商接入不完整 → 引擎侧该槽位走启发式
		}
		sc.APIKey = s.decryptKey(sc.APIKey, task)
		slots[task] = sc
	}

	cfg := ai.Config{
		Slots:             slots,
		HourlyTokenBudget: s.bootstrap.HourlyTokenBudget,
		CacheTTL:          s.bootstrap.CacheTTL,
	}
	if stored.HourlyTokens > 0 {
		cfg.HourlyTokenBudget = stored.HourlyTokens
	}
	if stored.CacheTTLSec > 0 {
		cfg.CacheTTL = time.Duration(stored.CacheTTLSec) * time.Second
	}

	prompts := map[string]string{}
	for _, task := range PromptTasks {
		if p, err := s.repos.AIConfig.Prompt(ctx, task); err == nil && p != nil {
			prompts[task] = p.Content
		}
	}
	skills, err := s.skillTexts(ctx)
	if err != nil {
		return cfg, nil, nil, err
	}
	return cfg, prompts, skills, nil
}

// applyEngineConfig 把配置热更新到生产引擎。
//
// 这是配置中心的"最后一公里"：所有写路径（改配置/改提示词/改技能）
// 汇合到这里，保证引擎状态永远等于 DB 状态，不存在第二份真值。
// 启动时也会调用一次（LoadStoredConfig）。
func (s *AIService) applyEngineConfig(ctx context.Context) error {
	cfg, prompts, skills, err := s.assembleEngineConfig(ctx)
	if err != nil {
		return err
	}
	s.eng.ApplyConfig(cfg, prompts, skills)
	return nil
}

// decryptKey 解密 API Key；解密失败（如更换了加密主密钥）时保留密文形态：
// 后端会因认证失败降级并在日志里可见，而不是静默丢配置。
func (s *AIService) decryptKey(sealed, task string) string {
	if sealed == "" || s.encKey == nil {
		return sealed
	}
	pt, err := settingseal.Open(s.encKey, sealed)
	if err != nil {
		if s.log != nil {
			s.log.Warn("ai_config_key_decrypt_failed", "slot", task, "err", err.Error())
		}
		return sealed
	}
	return pt
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
