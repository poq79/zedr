//go:build linux
// +build linux

package lapp

import (
	"testing"

	"zedr/internal/agent/inventory"
)

// benignInventoryChangeLinux：与 Windows 版 TestBenignListenersRemoved
// 同语义的判定表（lapp 侧）。linux 标签：Windows 宿主只做交叉编译验证，
// 执行留给 Linux 实机/CI（仓库既有纪律，见 doc.go）。
func TestBenignListenersRemovedLinux(t *testing.T) {
	alive := map[uint32]struct{}{333: {}}
	mk := func(kind string, key string, pid float64) inventory.ChangeEvent {
		ev := inventory.ChangeEvent{Section: "listeners", Kind: kind, Key: key}
		if pid >= 0 {
			ev.Before = map[string]any{"proto": "udp", "port": 5657.0, "pid": pid}
		}
		return ev
	}

	cases := []struct {
		name string
		ev   inventory.ChangeEvent
		want bool
	}{
		{"死进程带走端口", mk(inventory.DiffRemoved, "udp|5657", 10764), true},
		{"动态端口段移除", mk(inventory.DiffRemoved, "tcp|52341", 333), true},
		{"存活进程关监听仍告警", mk(inventory.DiffRemoved, "tcp|8080", 333), false},
		{"pid 未知不抑制", mk(inventory.DiffRemoved, "udp|5657", 0), false},
		{"新增动态端口过滤", mk(inventory.DiffAdded, "tcp|52341", 1), true},
		{"新增低端口仍告警", mk(inventory.DiffAdded, "tcp|8080", 1), false},
		{"services 节不受影响", inventory.ChangeEvent{Section: "services", Kind: inventory.DiffAdded, Key: "nginx"}, false},
	}
	for _, c := range cases {
		if got := benignInventoryChangeLinux(c.ev, alive); got != c.want {
			t.Errorf("%s: benignInventoryChangeLinux = %v, want %v", c.name, got, c.want)
		}
	}
}
