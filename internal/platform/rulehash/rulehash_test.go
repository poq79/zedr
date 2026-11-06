package rulehash

import (
	"encoding/json"
	"testing"
	"time"

	"zedr/internal/model"
)

func testIOCBundle() *model.IOCBundle {
	return &model.IOCBundle{
		Version:     3,
		GeneratedAt: time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC),
		IOCs: []model.IOCDTO{
			{Hash: "aa01010101010101010101010101010101010101010101010101010101010101", Note: "演练样本"},
			{Hash: "bb02020202020202020202020202020202020202020202020202020202020202"},
		},
	}
}

// TestIOCBundleSignVerify 签名→验签闭环。
func TestIOCBundleSignVerify(t *testing.T) {
	key := []byte("unit-test-key-0123456789abcdef")
	b := testIOCBundle()
	if err := SignIOCBundle(b, key); err != nil {
		t.Fatalf("签名失败: %v", err)
	}
	if b.Signature == "" {
		t.Fatal("签名不应为空")
	}
	if err := VerifyIOCBundle(b, key); err != nil {
		t.Fatalf("验签失败: %v", err)
	}
}

// TestIOCBundleTamperDetected 任何内容改动（包括删除条目）都必须验签失败。
func TestIOCBundleTamperDetected(t *testing.T) {
	key := []byte("unit-test-key-0123456789abcdef")
	cases := []string{
		"删条目", "改版本", "改时间戳", "改备注",
	}
	for _, c := range cases {
		b := testIOCBundle()
		if err := SignIOCBundle(b, key); err != nil {
			t.Fatalf("%s: 签名失败: %v", c, err)
		}
		switch c {
		case "删条目":
			b.IOCs = b.IOCs[:1]
		case "改版本":
			b.Version = 4
		case "改时间戳":
			b.GeneratedAt = b.GeneratedAt.Add(time.Second)
		case "改备注":
			b.IOCs[1].Note = "被篡改的备注"
		}
		if err := VerifyIOCBundle(b, key); err == nil {
			t.Fatalf("%s: 篡改不应通过验签", c)
		}
	}
}

// TestIOCBundleWrongKey 换密钥必须验签失败。
func TestIOCBundleWrongKey(t *testing.T) {
	b := testIOCBundle()
	if err := SignIOCBundle(b, []byte("key-one-0123456789abcdef01234567")); err != nil {
		t.Fatalf("签名失败: %v", err)
	}
	if err := VerifyIOCBundle(b, []byte("key-two-0123456789abcdef01234567")); err == nil {
		t.Fatal("错误密钥不应通过验签")
	}
}

// TestIOCAndRulePayloadDomains 两条签名链域隔离：
// 同一把密钥下，IOC 包签名与规则包签名互不通用。
func TestIOCAndRulePayloadDomains(t *testing.T) {
	key := DeriveKey([]byte("master-secret"), "rule-signing")
	iocB := testIOCBundle()
	if err := SignIOCBundle(iocB, key); err != nil {
		t.Fatalf("IOC 签名失败: %v", err)
	}
	// 把 IOC 签名塞进一个空规则包：校验必须失败（payload 域隔离生效）
	rb := &model.RuleBundle{Version: 1, GeneratedAt: time.Now().UTC()}
	if err := Sign(rb, key); err != nil {
		t.Fatalf("规则包签名失败: %v", err)
	}
	if iocB.Signature == rb.Signature {
		t.Fatal("IOC 与规则包的签名不应相同")
	}
}

// testRuleBundle 构造带观察模式规则的规则包（mode 字段参与 v2 签名）。
func testRuleBundle() *model.RuleBundle {
	return &model.RuleBundle{
		Version:     7,
		GeneratedAt: time.Date(2026, 11, 7, 9, 0, 0, 0, time.UTC),
		Rules: []model.RuleDTO{
			{ID: "HG-001", Name: "内置规则", Severity: model.SeverityHigh, Score: 45,
				Enabled: true, Definition: `{"all":[]}`, Version: 3},
			{ID: "HG-C-abc1", Name: "观察中的自定义规则", Severity: model.SeverityMedium, Score: 30,
				Enabled: true, Mode: "observe", Definition: `{"all":[]}`, Version: 4},
		},
	}
}

// roundTrip 模拟"网络传输 + 探针反序列化"。老探针结构体没有 Mode/
// SignatureV2 字段，反序列化即丢弃（dropMode/dropV2 模拟）；新探针全保留。
func roundTrip(t *testing.T, b *model.RuleBundle, dropMode, dropV2 bool) *model.RuleBundle {
	t.Helper()
	raw, err := json.Marshal(b)
	if err != nil {
		t.Fatalf("序列化失败: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	rules, _ := m["rules"].([]any)
	for i := range rules {
		r, _ := rules[i].(map[string]any)
		if dropMode {
			delete(r, "mode") // 老探针结构体没有 Mode 字段，反序列化即丢弃
		}
	}
	if dropV2 {
		delete(m, "signature_v2")
	}
	clean, _ := json.Marshal(m)
	var out model.RuleBundle
	if err := json.Unmarshal(clean, &out); err != nil {
		t.Fatalf("重解析失败: %v", err)
	}
	return &out
}

// TestRuleBundleDualSignatureInterop 双签名混合舰队兼容性：
// 新服务端（双签名）→ 老探针（只有 v1 口径）必须验签通过；
// 新探针（双口径）必须两个签名都验过。
func TestRuleBundleDualSignatureInterop(t *testing.T) {
	key := []byte("unit-test-key-0123456789abcdef")
	b := testRuleBundle()
	if err := Sign(b, key); err != nil {
		t.Fatalf("签名失败: %v", err)
	}
	if b.Signature == "" || b.SignatureV2 == "" {
		t.Fatal("双签名都应写入")
	}

	// 老探针路径：mode/signature_v2 在反序列化时被丢弃，v1 验签必须通过
	oldAgent := roundTrip(t, b, true, true)
	if oldAgent.Rules[1].Mode != "" {
		t.Fatal("老探针模拟不应保留 mode")
	}
	if err := Verify(oldAgent, key); err != nil {
		t.Fatalf("老探针验签失败（混合舰队兼容性被破坏）: %v", err)
	}

	// 新探针路径：mode 与双签名都保留，两个口径都必须验过
	if err := Verify(roundTrip(t, b, false, false), key); err != nil {
		t.Fatalf("新探针验签失败: %v", err)
	}
}

// TestRuleBundleModeTamperDetected mode 被篡改（把规则悄悄切到观察=致盲
// 单条规则）必须被新探针发现。老探针不认识 mode 字段，攻击面对它们
// 不存在——mode 在反序列化时即被丢弃，规则仍按正常模式运行。
func TestRuleBundleModeTamperDetected(t *testing.T) {
	key := []byte("unit-test-key-0123456789abcdef")
	b := testRuleBundle()
	if err := Sign(b, key); err != nil {
		t.Fatalf("签名失败: %v", err)
	}

	// 篡改方向一：观察规则被切回正常（绕过试运行）
	flip := testRuleBundle()
	if err := Sign(flip, key); err != nil {
		t.Fatalf("签名失败: %v", err)
	}
	flip.Rules[1].Mode = ""
	if err := Verify(flip, key); err == nil {
		t.Fatal("mode 被清除不应通过验签")
	}

	// 篡改方向二：正常规则被切到观察（致盲）
	blind := testRuleBundle()
	if err := Sign(blind, key); err != nil {
		t.Fatalf("签名失败: %v", err)
	}
	blind.Rules[0].Mode = "observe"
	if err := Verify(blind, key); err == nil {
		t.Fatal("正常规则被切观察不应通过验签")
	}
}
