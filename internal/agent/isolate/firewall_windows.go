//go:build windows

package isolate

import (
	"net/netip"
	"strings"

	"zedr/internal/agent/winapi"
)

// NewPlatformFW 返回当前平台的防火墙执行面（Windows=netsh）。
// app.go 是跨平台编译的（CI linux job 也要 vet 过），平台差异必须
// 收在本文件，不能让 app 直接引用 netsh 实现。
func NewPlatformFW() Firewall { return netshFW{} }

// PlatformDNS 返回当前系统解析器地址（GetAdaptersAddresses），供
// keep 集合掏空。采集失败返回空——诚实降级（按主机名重连的场景
// 会受影响，IP 直连部署不受影响），不阻断隔离。
func PlatformDNS() []netip.Addr {
	adps, err := winapi.Adapters()
	if err != nil {
		return nil
	}
	seen := map[string]bool{}
	var out []netip.Addr
	for _, a := range adps {
		for _, d := range a.DNS {
			d = strings.TrimSpace(d)
			if d == "" || seen[d] {
				continue
			}
			if ip, perr := netip.ParseAddr(d); perr == nil {
				seen[d] = true
				out = append(out, ip.Unmap())
			}
		}
	}
	return out
}
