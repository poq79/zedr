//go:build linux

package enrich

// verifySignature 是 Linux 侧的诚实降级：没有 Authenticode 等价物，
// 签名信任以发行版包管理器元数据为准（dpkg/rpm 校验属 hygiene 面，
// 不在逐进程热路径做）。State=unsigned 与"未签名文件"同一语义——
// 检测引擎把它当"少一个可信信号"处理，不会硬错。未在 Linux 实机
// 验证（本文件无任何系统调用，语义上无平台风险）。
func verifySignature(path string) SignatureResult {
	return SignatureResult{State: "unsigned"}
}
