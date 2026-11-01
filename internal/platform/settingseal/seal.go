// Package settingseal 提供后台配置中敏感字段（如模型 API Key）的静态加密。
//
// 为什么不用明文入库：AGENTS.md 的纪律是"密钥只在 .env，永不入库"，
// 但 AI 配置中心的产品要求恰恰是 Key 可在后台配置。折中方案是把
// "可配置"与"静态加密"组合：库文件单独泄露时拿不到可用密钥——
// 解密主密钥来自 .env（显式配置或从 JWTSecret 派生），不进数据库。
// 这与规则包签名密钥的派生策略（rulehash.DeriveKey）同构。
package settingseal

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"zedr/internal/platform/rulehash"
)

// 前缀用于自描述密文版本：算法轮换时老数据仍可识别。
const prefixV1 = "enc:v1:"

// ErrNotSealed 表示输入不是本包产生的密文（调用方应按明文处理）。
var ErrNotSealed = errors.New("settingseal: 不是 enc:v1 密文")

// Key 从显式配置或主密钥派生 32 字节 AES 密钥。
// explicit 是 hex 编码的 32 字节（64 个字符）；为空时从 master 派生子密钥。
func Key(explicit, master string) ([]byte, error) {
	if strings.TrimSpace(explicit) != "" {
		k, err := hex.DecodeString(strings.TrimSpace(explicit))
		if err != nil || len(k) != 32 {
			return nil, fmt.Errorf("加密密钥必须是 64 个 hex 字符（32 字节）: %w", err)
		}
		return k, nil
	}
	if master == "" {
		return nil, errors.New("settingseal: 缺少主密钥")
	}
	// 与规则包签名同构的派生策略：主密钥不直接参与加密，
	// purpose 隔离保证同一主密钥的不同用途互不干扰。
	return rulehash.DeriveKey([]byte(master), "setting-encryption"), nil
}

// Seal 加密明文，输出 enc:v1:<b64>。短输入（API Key 通常 <200B）无性能顾虑。
func Seal(key []byte, plaintext string) (string, error) {
	if plaintext == "" {
		return "", nil
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	out := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return prefixV1 + base64.StdEncoding.EncodeToString(out), nil
}

// Open 解密 enc:v1 密文；输入不是密文时返回 ErrNotSealed，调用方可按明文回退。
func Open(key []byte, sealed string) (string, error) {
	if !strings.HasPrefix(sealed, prefixV1) {
		return "", ErrNotSealed
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(sealed, prefixV1))
	if err != nil {
		return "", fmt.Errorf("settingseal: base64 解码失败: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	if len(raw) < gcm.NonceSize() {
		return "", errors.New("settingseal: 密文过短")
	}
	pt, err := gcm.Open(nil, raw[:gcm.NonceSize()], raw[gcm.NonceSize():], nil)
	if err != nil {
		return "", fmt.Errorf("settingseal: 解密失败（密钥不匹配或数据损坏）: %w", err)
	}
	return string(pt), nil
}
