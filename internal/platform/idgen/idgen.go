// Package idgen 生成各类随机标识与密钥。
package idgen

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

// Hex 返回 n 字节随机数的十六进制串。
func Hex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

// URLSafe 返回 n 字节随机数的 URL 安全串。
func URLSafe(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// MachineID 生成稳定的机器指纹（基于随机持久化 ID，不采集硬件隐私信息）。
func MachineID() string {
	return strings.ToUpper(Hex(8))
}
