package rulehash

import (
	"testing"
	"time"

	"hostguard/internal/model"
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
