package settingseal

import (
	"strings"
	"testing"

	"zedr/internal/platform/rulehash"
)

func TestSealOpenRoundtrip(t *testing.T) {
	key, err := Key("", "master-secret-at-least-32-bytes-long!!")
	if err != nil {
		t.Fatalf("派生密钥失败: %v", err)
	}
	sealed, err := Seal(key, "sk-test-1234567890")
	if err != nil {
		t.Fatalf("加密失败: %v", err)
	}
	if !strings.HasPrefix(sealed, prefixV1) {
		t.Fatalf("密文应带 enc:v1 前缀: %q", sealed)
	}
	pt, err := Open(key, sealed)
	if err != nil {
		t.Fatalf("解密失败: %v", err)
	}
	if pt != "sk-test-1234567890" {
		t.Fatalf("往返不一致: %q", pt)
	}
}

func TestOpenWrongKeyFails(t *testing.T) {
	k1, _ := Key("", "master-one-32-bytes-aaaaaaaaaaaaaaa")
	k2, _ := Key("", "master-two-32-bytes-bbbbbbbbbbbbbbb")
	sealed, _ := Seal(k1, "secret")
	if _, err := Open(k2, sealed); err == nil {
		t.Fatal("用错误密钥解密应当失败")
	}
}

func TestOpenNotSealed(t *testing.T) {
	k, _ := Key("", "master-32-bytes-cccccccccccccccccc")
	if _, err := Open(k, "sk-plaintext"); err != ErrNotSealed {
		t.Fatalf("明文输入应返回 ErrNotSealed，得到: %v", err)
	}
}

func TestSealNonDeterministic(t *testing.T) {
	k, _ := Key("", "master-32-bytes-dddddddddddddddddd")
	a, _ := Seal(k, "same-input")
	b, _ := Seal(k, "same-input")
	if a == b {
		t.Fatal("AES-GCM 随机 nonce 下两次密文不应相同")
	}
}

func TestKeyExplicitHex(t *testing.T) {
	hex32 := strings.Repeat("ab", 32)
	k, err := Key(hex32, "ignored-master")
	if err != nil {
		t.Fatalf("显式密钥解析失败: %v", err)
	}
	if len(k) != 32 {
		t.Fatalf("密钥长度应为 32，得到 %d", len(k))
	}
	if _, err := Key("zz", "m"); err == nil {
		t.Fatal("非法 hex 应报错")
	}
	if _, err := Key(strings.Repeat("ab", 10), "m"); err == nil {
		t.Fatal("长度不是 32 字节应报错")
	}
}

// 派生密钥必须与规则签名用途隔离：同一主密钥的不同 purpose 派生值不同。
func TestDerivedKeyDomainSeparated(t *testing.T) {
	k1, _ := Key("", "shared-master")
	k2 := rulehash.DeriveKey([]byte("shared-master"), "rule-signing")
	if string(k1) == string(k2) {
		t.Fatal("setting-encryption 与 rule-signing 的派生密钥不应相同")
	}
}
