//go:build !windows

package isolate

import "net/netip"

// noopFW 是非 Windows 平台的占位执行面：Linux 隔离走 iptables owner-match
// 是独立方向（RESEARCH §5 不做清单），在此之前诚实拒绝而不是假装成功。
type noopFW struct{}

func (noopFW) AddBlock(string, string, string) error {
	return errNotSupported
}
func (noopFW) DeleteByPrefix(string) (int, error) { return 0, errNotSupported }
func (noopFW) ListByPrefix(string) ([]string, error) {
	return nil, nil
}
func (noopFW) ProfileStates() (map[string]bool, error) {
	return map[string]bool{}, errNotSupported
}
func (noopFW) SetProfileEnabled(string, bool) error { return errNotSupported }

var errNotSupported = &notSupportedError{}

type notSupportedError struct{}

func (*notSupportedError) Error() string {
	return "本平台没有网络隔离执行面（Windows 走 netsh；Linux 规划中）"
}

// NewPlatformFW 返回当前平台的防火墙执行面。
func NewPlatformFW() Firewall { return noopFW{} }

// PlatformDNS 非 Windows 平台暂无采集实现。
func PlatformDNS() []netip.Addr { return nil }
