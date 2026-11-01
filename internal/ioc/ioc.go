// Package ioc 存放内置 IOC（威胁指标）与特征字符串。
//
// 为什么必须编码存储：
//  1. 主机安全产品自身会携带大量恶意工具名/命令片段，若以明文常量写入二进制，
//     极易被本地杀软或组织级文件扫描判定为恶意样本，导致产物被隔离、构建失败；
//  2. 明文特征表也便于攻击者反查检测逻辑并针对性规避。
//
// 因此 IOC 一律以 base64 形式存放在代码中，运行时解码使用。
// 这不是"加密"，而是避免自身被静态特征命中的工程手段。
package ioc

import "encoding/base64"

// S 解码一个内置 IOC 字符串。
func S(enc string) string {
	b, err := base64.StdEncoding.DecodeString(enc)
	if err != nil {
		return enc
	}
	return string(b)
}

// SS 批量解码。
func SS(encs ...string) []string {
	out := make([]string, 0, len(encs))
	for _, e := range encs {
		out = append(out, S(e))
	}
	return out
}

// SA 批量解码为 []any（供规则 DSL 的 value 字段使用）。
func SA(encs ...string) []any {
	out := make([]any, 0, len(encs))
	for _, e := range encs {
		out = append(out, S(e))
	}
	return out
}
