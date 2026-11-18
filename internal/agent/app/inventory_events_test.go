//go:build windows
// +build windows

package agentapp

import (
	"testing"

	"zedr/internal/agent/inventory"
)

// listeners removed 的稳态噪声过滤（2026-11-18 误报治理）：
//   - 属主 pid 已退出 → 进程生命周期事件，不是服务监听面变更；
//   - 动态端口段（≥49152）→ 与 added 对称过滤；
//   - 存活进程主动关闭监听 / pid 未知 → 不抑制（真服务面变化保持可见）。
func TestBenignListenersRemoved(t *testing.T) {
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
		{"无 before 条目不抑制", mk(inventory.DiffRemoved, "udp|5657", -1), false},
		{"新增动态端口仍过滤", mk(inventory.DiffAdded, "tcp|52341", 1), true},
		{"新增低端口仍告警", mk(inventory.DiffAdded, "tcp|8080", 1), false},
		{"pid 漂移仍过滤", mk(inventory.DiffChanged, "tcp|8080", 333), true},
	}
	for _, c := range cases {
		if got := benignInventoryChange(c.ev, alive); got != c.want {
			t.Errorf("%s: benignInventoryChange = %v, want %v", c.name, got, c.want)
		}
	}
}
