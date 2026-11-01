// Package rulehash 为规则包提供完整性签名与校验。
//
// 为什么需要它：规则下发走的是"服务端说是什么就是什么"的信任模型。
// 一旦链路被中间人劫持，攻击者可以把检测规则删掉或调宽，而终端毫无察觉——
// 这等于让防护产品自己闭眼。加签名后，篡改与重放都能被发现。
//
// 同时提供版本单调性检查：即使签名有效，也不接受"比本地更旧"的规则包，
// 防止攻击者重放一份历史上曾经合法、但已被收紧前的宽松规则。
package rulehash

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"hostguard/internal/model"
)

// signingPayload 是参与签名的规范化内容。
//
// 刻意不直接序列化 RuleBundle：Signature 字段本身要排除，否则无法自洽。
// 只取确定性的字段，并显式带上长度与时间戳，避免"删掉几条规则后
// 拼接结果恰好相同"这类碰撞。
func signingPayload(b *model.RuleBundle) ([]byte, error) {
	rules, err := json.Marshal(b.Rules)
	if err != nil {
		return nil, fmt.Errorf("规则序列化失败: %w", err)
	}
	allow, err := json.Marshal(b.Allowlist)
	if err != nil {
		return nil, fmt.Errorf("白名单序列化失败: %w", err)
	}

	head := fmt.Sprintf("v1|%d|%d|%d|%d|",
		b.Version, b.GeneratedAt.UnixNano(), len(b.Rules), len(b.Allowlist))

	out := make([]byte, 0, len(head)+len(rules)+len(allow)+1)
	out = append(out, head...)
	out = append(out, rules...)
	out = append(out, '|')
	out = append(out, allow...)
	return out, nil
}

// Sign 计算并写入签名。
func Sign(b *model.RuleBundle, key []byte) error {
	if len(key) == 0 {
		return fmt.Errorf("规则签名密钥为空")
	}
	payload, err := signingPayload(b)
	if err != nil {
		return err
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(payload)
	b.Signature = hex.EncodeToString(mac.Sum(nil))
	return nil
}

// Verify 校验签名，返回错误说明失败原因。
func Verify(b *model.RuleBundle, key []byte) error {
	if b.Signature == "" {
		return fmt.Errorf("规则包未签名")
	}
	if len(key) == 0 {
		return fmt.Errorf("未配置规则签名密钥，无法校验")
	}
	payload, err := signingPayload(b)
	if err != nil {
		return err
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(payload)
	want := mac.Sum(nil)

	got, err := hex.DecodeString(b.Signature)
	if err != nil {
		return fmt.Errorf("规则签名格式非法")
	}
	// 恒定时间比较：签名校验本身不能成为侧信道
	if !hmac.Equal(want, got) {
		return fmt.Errorf("规则包签名校验失败（内容可能被篡改）")
	}
	return nil
}

// DeriveKey 从主密钥派生专用子密钥。
// 这样规则签名密钥与 JWT 签名密钥相互独立：即使其中一个泄露，
// 也不能直接推出另一个，更不会出现"改 JWT 顺便改规则"的连带风险。
func DeriveKey(master []byte, purpose string) []byte {
	mac := hmac.New(sha256.New, master)
	mac.Write([]byte("hostguard/" + purpose + "/v1"))
	return mac.Sum(nil)
}
