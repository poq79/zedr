//go:build windows

package enrich

import "zedr/internal/agent/winapi"

// verifySignature 委托 winapi 的 WinVerifyTrust 实现，逐字段转换成
// 本包形状（不直接用类型别名：winapi↔enrich 会成环）。
func verifySignature(path string) SignatureResult {
	r := winapi.VerifySignature(path)
	return SignatureResult{Valid: r.Valid, Signed: r.Signed, Signer: r.Signer, State: r.State, RawCode: r.RawCode}
}
