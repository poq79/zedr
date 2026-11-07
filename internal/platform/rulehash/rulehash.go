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

	"zedr/internal/model"
)

// signingPayload 构造 v1 口径的规范化签名内容：不含 RuleDTO.Mode 与
// RuleBundle.Intel。
//
// 双签名兼容说明（规则观察模式引入 Mode 字段时的混合舰队问题）：
// 验签是对"解码后结构体重序列化"的字节算 HMAC，老探针的 RuleDTO
// 结构体没有 Mode 字段，收到新包时会把 mode 反序列化丢弃，再重序列化
// 得到的是不含 mode 的字节——如果 v1 直接对含 mode 的字节签名，
// 老探针必然验签失败、整包拒绝应用、回退内置规则。因此 v1 口径
// 显式清零 Mode 后序列化：老探针（天然丢字段）与新探针（清零后序列化）
// 得到的字节完全一致，签名互通。mode 的防篡改由 v2 口径承接。
// Intel 同理（v0.9.11 扩维）：老探针不认识该字段，反序列化即丢弃。
func signingPayload(b *model.RuleBundle) ([]byte, error) {
	rules, err := json.Marshal(stripRuleModes(b.Rules))
	if err != nil {
		return nil, fmt.Errorf("规则序列化失败: %w", err)
	}
	allow, err := json.Marshal(b.Allowlist)
	if err != nil {
		return nil, fmt.Errorf("白名单序列化失败: %w", err)
	}
	head := fmt.Sprintf("v1|%d|%d|%d|%d|",
		b.Version, b.GeneratedAt.UnixNano(), len(b.Rules), len(b.Allowlist))
	return joinPayload(head, rules, allow), nil
}

// signingPayloadV2 构造 v2 口径：包含 Mode 与 Intel。这两者都直接影响
// 检测是否告警（mode=致盲单条规则；intel=下发黑名单），属于"能让人
// 闭眼"的字段，必须纳入签名——老探针验不了 v2，但老探针本来就不认识
// 这些字段（反序列化即丢弃），它们对老探针不存在，攻击面为零。
func signingPayloadV2(b *model.RuleBundle) ([]byte, error) {
	rules, err := json.Marshal(b.Rules)
	if err != nil {
		return nil, fmt.Errorf("规则序列化失败: %w", err)
	}
	allow, err := json.Marshal(b.Allowlist)
	if err != nil {
		return nil, fmt.Errorf("白名单序列化失败: %w", err)
	}
	// Intel 归一：nil 与空切片序列化结果不同（"null" vs "[]"），而
	// omitempty 会让空切片在 wire 上消失、探针解码得到 nil——两端
	// 口径必须钉死为"空=nil"。
	intelSrc := b.Intel
	if len(intelSrc) == 0 {
		intelSrc = nil
	}
	intel, err := json.Marshal(intelSrc)
	if err != nil {
		return nil, fmt.Errorf("情报序列化失败: %w", err)
	}
	head := fmt.Sprintf("v2|%d|%d|%d|%d|%d|",
		b.Version, b.GeneratedAt.UnixNano(), len(b.Rules), len(b.Allowlist), len(intelSrc))
	return joinPayload(head, rules, allow, intel), nil
}

// stripRuleModes 返回清零 Mode 的规则切片副本（不改动调用方的切片）。
func stripRuleModes(list []model.RuleDTO) []model.RuleDTO {
	out := make([]model.RuleDTO, len(list))
	copy(out, list)
	for i := range out {
		out[i].Mode = ""
	}
	return out
}

func joinPayload(head string, parts ...[]byte) []byte {
	out := make([]byte, 0, len(head)+64)
	out = append(out, head...)
	for i, p := range parts {
		if i > 0 {
			out = append(out, '|')
		}
		out = append(out, p...)
	}
	return out
}

// Sign 计算并写入双口径签名：Signature（v1，老探针唯一依据）+
// SignatureV2（v2，含 mode，新探针优先）。
func Sign(b *model.RuleBundle, key []byte) error {
	if len(key) == 0 {
		return fmt.Errorf("规则签名密钥为空")
	}
	v1, err := signingPayload(b)
	if err != nil {
		return err
	}
	v2, err := signingPayloadV2(b)
	if err != nil {
		return err
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(v1)
	b.Signature = hex.EncodeToString(mac.Sum(nil))
	mac.Reset()
	mac.Write(v2)
	b.SignatureV2 = hex.EncodeToString(mac.Sum(nil))
	return nil
}

// Verify 校验签名，返回错误说明失败原因。
//
// 包里同时有 v2 时优先验 v2、再验 v1（新探针两口径都必须过，篡改任意
// 一个覆盖面都会被发现）；只有 v1 的包（老服务端下发）按 v1 校验。
func Verify(b *model.RuleBundle, key []byte) error {
	if b.Signature == "" {
		return fmt.Errorf("规则包未签名")
	}
	if len(key) == 0 {
		return fmt.Errorf("未配置规则签名密钥，无法校验")
	}
	if err := verifyPayload(b, key, b.Signature, signingPayload); err != nil {
		return err
	}
	if b.SignatureV2 != "" {
		if err := verifyPayload(b, key, b.SignatureV2, signingPayloadV2); err != nil {
			return err
		}
	}
	return nil
}

func verifyPayload(b *model.RuleBundle, key []byte, sigHex string, payloadFn func(*model.RuleBundle) ([]byte, error)) error {
	payload, err := payloadFn(b)
	if err != nil {
		return err
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(payload)
	want := mac.Sum(nil)

	got, err := hex.DecodeString(sigHex)
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
	mac.Write([]byte("zedr/" + purpose + "/v1"))
	return mac.Sum(nil)
}

// iocPayload 构造 IOC 包的规范化签名内容。
// 与规则包（signingPayload）格式完全独立，靠 "iocv1" 前缀做域隔离：
// 两种包复用同一把派生密钥，但一条消息永远只会被当成一种格式校验。
func iocPayload(b *model.IOCBundle) ([]byte, error) {
	iocs, err := json.Marshal(b.IOCs)
	if err != nil {
		return nil, fmt.Errorf("IOC 序列化失败: %w", err)
	}
	head := fmt.Sprintf("iocv1|%d|%d|%d|", b.Version, b.GeneratedAt.UnixNano(), len(b.IOCs))
	out := make([]byte, 0, len(head)+len(iocs))
	out = append(out, head...)
	out = append(out, iocs...)
	return out, nil
}

// upgradePayload 构造升级清单的规范化签名内容。
// 与 IOC 包同一套域隔离思路（"upgv1" 前缀）；payload 公式必须与
// 探针侧验签实现逐字节一致：upgv1|<version>|<sha256hex>|<size>
func upgradePayload(m *model.UpgradeManifest) []byte {
	head := fmt.Sprintf("upgv1|%s|%s|%d|", m.Version, m.SHA256, m.Size)
	return []byte(head)
}

// SignUpgradeManifest 计算并写入升级清单签名。
func SignUpgradeManifest(m *model.UpgradeManifest, key []byte) error {
	if len(key) == 0 {
		return fmt.Errorf("规则签名密钥为空")
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(upgradePayload(m))
	m.Signature = hex.EncodeToString(mac.Sum(nil))
	return nil
}

// VerifyUpgradeManifest 校验升级清单签名。
func VerifyUpgradeManifest(m *model.UpgradeManifest, key []byte) error {
	if m.Signature == "" {
		return fmt.Errorf("升级清单未签名")
	}
	if len(key) == 0 {
		return fmt.Errorf("未配置签名密钥，无法校验升级清单")
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(upgradePayload(m))
	want := mac.Sum(nil)
	got, err := hex.DecodeString(m.Signature)
	if err != nil {
		return fmt.Errorf("升级清单签名格式非法")
	}
	if !hmac.Equal(want, got) {
		return fmt.Errorf("升级清单签名校验失败（内容可能被篡改）")
	}
	return nil
}

// SignIOCBundle 计算并写入 IOC 包签名。
func SignIOCBundle(b *model.IOCBundle, key []byte) error {
	if len(key) == 0 {
		return fmt.Errorf("规则签名密钥为空")
	}
	payload, err := iocPayload(b)
	if err != nil {
		return err
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(payload)
	b.Signature = hex.EncodeToString(mac.Sum(nil))
	return nil
}

// VerifyIOCBundle 校验 IOC 包签名。
func VerifyIOCBundle(b *model.IOCBundle, key []byte) error {
	if b.Signature == "" {
		return fmt.Errorf("IOC 包未签名")
	}
	if len(key) == 0 {
		return fmt.Errorf("未配置签名密钥，无法校验 IOC 包")
	}
	payload, err := iocPayload(b)
	if err != nil {
		return err
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(payload)
	want := mac.Sum(nil)
	got, err := hex.DecodeString(b.Signature)
	if err != nil {
		return fmt.Errorf("IOC 签名格式非法")
	}
	if !hmac.Equal(want, got) {
		return fmt.Errorf("IOC 包签名校验失败（内容可能被篡改）")
	}
	return nil
}
