package service

import (
	"testing"
	"time"

	"zedr/internal/ai"
	"zedr/internal/platform/settingseal"
)

func testBootstrap() ai.Config {
	return ai.Config{
		Provider: "openai", BaseURL: "https://env.example.com", APIKey: "env-key",
		Model: "env-model", Timeout: 30 * time.Second, HourlyTokenBudget: 100000,
	}
}

// 密钥尾号提示必须来自明文：密文尾部的 base64 噪声会随每次保存变化。
func TestKeyHintUsesPlaintextTail(t *testing.T) {
	key, err := settingseal.Key("", "master-secret-at-least-32-bytes-long!!")
	if err != nil {
		t.Fatalf("派生密钥失败: %v", err)
	}
	sealed, err := settingseal.Seal(key, "sk-abc1234")
	if err != nil {
		t.Fatalf("加密失败: %v", err)
	}
	s := &AIService{encKey: key}
	if got := s.keyHint(sealed, "provider"); got != "…1234" {
		t.Fatalf("应显示明文尾号 …1234，得到 %q", got)
	}
	// env 引导的明文 Key 同样显示尾号（不是 enc:v1 密文）。
	if got := s.keyHint("sk-xyz9876", "provider"); got != "…9876" {
		t.Fatalf("明文 Key 应显示 …9876，得到 %q", got)
	}
	// 换主密钥后解不开：只能显示 ****，绝不能暴露密文片段。
	other, _ := settingseal.Key("", "another-master-secret-at-least-32-bytes!!")
	s2 := &AIService{encKey: other}
	if got := s2.keyHint(sealed, "provider"); got != "****" {
		t.Fatalf("解密失败应显示 ****，得到 %q", got)
	}
}

// Provider 统一配置覆盖 env 引导；默认值（温度/超时/max_tokens）有兜底。
func TestResolveProviderDBOverridesEnv(t *testing.T) {
	stored := &storedAIConfig{Provider: &storedProvider{
		BaseURL: "https://db.example.com", APIKey: "enc:dbkey", Model: "db-model",
	}}
	p := resolveProvider(testBootstrap(), stored)
	if p.BaseURL != "https://db.example.com" || p.Model != "db-model" || p.APIKey != "enc:dbkey" {
		t.Fatalf("DB Provider 应覆盖 env 引导: %+v", p)
	}
	if p.Temperature != 0.1 || p.MaxTokens != 1400 || p.TimeoutSec != 30 {
		t.Fatalf("默认值兜底不对: %+v", p)
	}
}

func TestResolveProviderEnvFallback(t *testing.T) {
	p := resolveProvider(testBootstrap(), nil)
	if p.BaseURL != "https://env.example.com" || p.Model != "env-model" || p.APIKey != "env-key" {
		t.Fatalf("无 DB 配置时应回落 env 引导: %+v", p)
	}
	if p.Effort != "off" {
		t.Fatalf("effort 应归一化为 off: %q", p.Effort)
	}
}

// 槽位留空 = 全部跟随 Provider 默认（"同一模型只配一次"的核心语义）。
func TestResolveSlotFollowsProvider(t *testing.T) {
	stored := &storedAIConfig{
		Provider: &storedProvider{BaseURL: "https://db.example.com", APIKey: "enc:k", Model: "main-model", Effort: "high"},
		Slots:    map[string]storedSlot{},
	}
	for _, task := range []string{ai.SlotTriage, ai.SlotHunt, ai.SlotInvestigate} {
		sc, ready := resolveSlot(task, testBootstrap(), stored)
		if !ready {
			t.Fatalf("%s 应 ready（Provider 就绪即默认启用）", task)
		}
		if sc.Model != "main-model" || sc.Effort != "high" || sc.BaseURL != "https://db.example.com" {
			t.Fatalf("%s 应跟随 Provider 默认: %+v", task, sc)
		}
	}
}

// 槽位只覆盖声明的差异：换了模型，其余仍跟随默认。
func TestResolveSlotPartialOverride(t *testing.T) {
	stored := &storedAIConfig{
		Provider: &storedProvider{BaseURL: "https://db.example.com", APIKey: "enc:k", Model: "main-model", Effort: "high", Temperature: 0.2},
		Slots: map[string]storedSlot{
			ai.SlotHunt: {Model: "fast-model", Effort: "off", Enabled: true},
		},
	}
	sc, ready := resolveSlot(ai.SlotHunt, testBootstrap(), stored)
	if !ready || sc.Model != "fast-model" || sc.Effort != "off" {
		t.Fatalf("覆盖字段应生效: %+v", sc)
	}
	if sc.BaseURL != "https://db.example.com" || sc.Temperature != 0.2 || sc.APIKey != "enc:k" {
		t.Fatalf("未覆盖字段应跟随 Provider: %+v", sc)
	}
}

// v1 兼容：旧数据按槽位存 base_url/api_key，无 Provider 块——照样解析。
func TestResolveSlotV1LegacyData(t *testing.T) {
	stored := &storedAIConfig{
		Slots: map[string]storedSlot{
			ai.SlotTriage: {BaseURL: "https://legacy.example.com", APIKey: "enc:legacy", Model: "legacy-model", Enabled: true, TimeoutSec: 60},
		},
	}
	sc, ready := resolveSlot(ai.SlotTriage, ai.Config{Provider: "none"}, stored)
	if !ready || sc.BaseURL != "https://legacy.example.com" || sc.Model != "legacy-model" {
		t.Fatalf("v1 旧数据应原样解析: %+v", sc)
	}
	if sc.Timeout != 60*time.Second {
		t.Fatalf("槽位超时覆盖应生效: %v", sc.Timeout)
	}
	// 狩猎槽没有旧数据且 Provider 缺失 → 不 ready（引擎走启发式）
	if _, ready := resolveSlot(ai.SlotHunt, ai.Config{Provider: "none"}, stored); ready {
		t.Fatal("无 Provider 且槽位无覆盖时不应 ready")
	}
}

// 显式停用优先于"Provider 就绪即默认启用"。
func TestResolveSlotExplicitDisable(t *testing.T) {
	stored := &storedAIConfig{
		Provider: &storedProvider{BaseURL: "https://db.example.com", Model: "m"},
		Slots:    map[string]storedSlot{ai.SlotTriage: {Enabled: false}},
	}
	if _, ready := resolveSlot(ai.SlotTriage, testBootstrap(), stored); ready {
		t.Fatal("显式停用的槽位不应 ready")
	}
}

func TestProviderSource(t *testing.T) {
	if got := providerSource(ai.Config{Provider: "none"}, nil); got != "none" {
		t.Fatalf("空配置 source 应为 none: %s", got)
	}
	if got := providerSource(testBootstrap(), nil); got != "env" {
		t.Fatalf("仅 env 时 source 应为 env: %s", got)
	}
	if got := providerSource(testBootstrap(), &storedAIConfig{Provider: &storedProvider{}}); got != "db" {
		t.Fatalf("有 DB Provider 时 source 应为 db: %s", got)
	}
}
