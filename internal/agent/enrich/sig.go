// 签名结果的跨平台形状。Windows 实现走 WinVerifyTrust（sig_windows.go）；
// Linux 无 Authenticode 等价物（发行版签名以包管理器元数据为准），v1
// 返回"未签名"诚实降级（sig_linux.go）——调用方（检测引擎）对
// Signed=false 的处理是"少一个可信信号"，不会硬错。
package enrich

// SignatureResult 是文件签名验证结果。
type SignatureResult struct {
	Valid   bool   // 签名链是否可信通过
	Signed  bool   // 文件是否带有签名（即便不受信）
	Signer  string // 签名主体
	State   string // valid | unsigned | untrusted | expired | bad_digest | ...
	RawCode uint32 // Windows: WinVerifyTrust 原始返回码；Linux 恒 0
}
