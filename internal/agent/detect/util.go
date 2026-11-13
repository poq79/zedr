package detect

import (
	"net"
	"sync"
)

// isPublic 判断远端地址是否为公网。原实现调 winapi.IsPublicRemote——
// 那是纯 net 逻辑，为解掉 detect→winapi 的 Linux 构建耦合移入本包
// （语义与 winapi 版本保持逐行一致）。
func isPublic(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	if ip.IsLoopback() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return false
	}
	privateOnce.Do(func() {
		for _, cidr := range []string{
			"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16",
			"127.0.0.0/8", "fc00::/7", "fe80::/10",
		} {
			_, ipNet, err := net.ParseCIDR(cidr)
			if err == nil {
				privateNets = append(privateNets, ipNet)
			}
		}
	})
	for _, ipNet := range privateNets {
		if ipNet.Contains(ip) {
			return false
		}
	}
	return true
}

var (
	privateOnce sync.Once
	privateNets []*net.IPNet
)
