//go:build windows
// +build windows

package winapi

// netinfo_test.go：ARP/路由/DNS 缓存真机冒烟。
// 口径：表空是合法状态（返回空切片 nil error），只拦解析错误与 panic。

import (
	"encoding/json"
	"net"
	"testing"
	"time"
)

func TestArpTable(t *testing.T) {
	start := time.Now()
	entries, err := ArpTable()
	if err != nil {
		t.Fatalf("ArpTable 失败: %v", err)
	}
	t.Logf("ArpTable 耗时 %s，%d 条", time.Since(start), len(entries))
	for _, e := range entries {
		if e.IP != "" && net.ParseIP(e.IP) == nil {
			t.Errorf("ARP IP 不可解析: %q (MAC=%s state=%s)", e.IP, e.MAC, e.State)
		}
		if e.MAC != "" && len(e.MAC) != 17 { // xx:xx:xx:xx:xx:xx
			t.Errorf("MAC 形态异常: %q", e.MAC)
		}
		if e.State == "" {
			t.Errorf("ARP 条目 State 为空: %+v", e)
		}
	}
	raw, _ := json.Marshal(entries)
	if len(raw) > 2048 {
		raw = raw[:2048]
	}
	t.Logf("arp=%s", raw)
}

func TestRouteTable(t *testing.T) {
	start := time.Now()
	routes, err := RouteTable()
	if err != nil {
		t.Fatalf("RouteTable 失败: %v", err)
	}
	t.Logf("RouteTable 耗时 %s，%d 条", time.Since(start), len(routes))
	if len(routes) == 0 {
		t.Fatal("运行中的系统至少应有 1 条路由（回环/默认路由恒在）")
	}
	for _, r := range routes {
		for _, ipStr := range []string{r.Dest, r.Mask, r.Gateway} {
			if ipStr != "" && net.ParseIP(ipStr) == nil {
				t.Errorf("路由地址不可解析: %q (dest=%s mask=%s gw=%s)", ipStr, r.Dest, r.Mask, r.Gateway)
			}
		}
	}
}

func TestDnsCache(t *testing.T) {
	start := time.Now()
	entries, err := DnsCache()
	if err != nil {
		t.Fatalf("DnsCache 失败: %v", err)
	}
	// 缓存可能为空（新启动机器/刚清过缓存），只测不 panic 与字段自洽
	t.Logf("DnsCache 耗时 %s，%d 条", time.Since(start), len(entries))
	for _, e := range entries {
		if e.Name == "" {
			t.Error("DNS 缓存条目 Name 为空")
		}
		if e.Type == "" {
			t.Errorf("DNS 缓存条目 Type 为空: %q", e.Name)
		}
	}
	if len(entries) > 0 {
		raw, _ := json.Marshal(entries)
		if len(raw) > 4096 {
			raw = raw[:4096]
		}
		t.Logf("dns=%s", raw)
	}
}
