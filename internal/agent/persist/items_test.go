package persist

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeTestBaseline(t *testing.T, path string, items map[string]record) {
	t.Helper()
	f := baselineFile{Version: 1, Schema: baselineSchema, UpdatedAt: time.Now(), Items: items}
	raw, err := json.Marshal(&f)
	if err != nil {
		t.Fatalf("marshal baseline: %v", err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("write baseline: %v", err)
	}
}

// Items 应返回基线全部条目：新基线带 type/location 两列；
// 老基线缺列时 kind 从 key 首段兜底解析，location 留空。
func TestItemsReturnsBaselineEntries(t *testing.T) {
	path := filepath.Join(t.TempDir(), "persist-baseline.json")
	now := time.Now()
	writeTestBaseline(t, path, map[string]record{
		"service|spooler": {
			Command: `C:\Windows\System32\spoolsv.exe`, Type: "service", Location: "SCM",
			FirstSeen: now, LastSeen: now,
		},
		// 老版本基线条目：没有 type/location 列
		`scheduled_task|\zedr\worker`: {
			Command:   "cmd /c worker.exe",
			FirstSeen: now, LastSeen: now,
		},
	})

	m := New(path, nil)
	if err := m.Load(); err != nil {
		t.Fatalf("load: %v", err)
	}

	items := m.Items()
	if len(items) != 2 {
		t.Fatalf("应返回 2 条, got %d: %+v", len(items), items)
	}
	byKey := make(map[string]Item, len(items))
	for _, it := range items {
		byKey[it.Key] = it
	}

	svc, ok := byKey["service|spooler"]
	if !ok {
		t.Fatalf("缺 service|spooler: %+v", items)
	}
	if svc.Kind != "service" || svc.Location != "SCM" || svc.Value != `C:\Windows\System32\spoolsv.exe` {
		t.Fatalf("service 条目字段不符: %+v", svc)
	}

	task, ok := byKey[`scheduled_task|\zedr\worker`]
	if !ok {
		t.Fatalf("缺 scheduled_task 条目: %+v", items)
	}
	if task.Kind != "scheduled_task" {
		t.Fatalf("老基线条目 kind 应从 key 前缀兜底解析, got %q", task.Kind)
	}
	if task.Location != "" {
		t.Fatalf("老基线条目 location 应为空, got %q", task.Location)
	}
	if task.Value != "cmd /c worker.exe" {
		t.Fatalf("task 条目 value 不符: %+v", task)
	}
}

// Items 返回的是值拷贝：修改返回切片不得污染监控器内部状态。
func TestItemsReturnsCopies(t *testing.T) {
	path := filepath.Join(t.TempDir(), "persist-baseline.json")
	now := time.Now()
	writeTestBaseline(t, path, map[string]record{
		"service|x": {Command: `C:\a.exe`, Type: "service", Location: "SCM", FirstSeen: now, LastSeen: now},
	})
	m := New(path, nil)
	if err := m.Load(); err != nil {
		t.Fatalf("load: %v", err)
	}

	items := m.Items()
	items[0].Value = "tampered"
	items[0].Kind = "tampered"

	again := m.Items()
	if again[0].Value != `C:\a.exe` || again[0].Kind != "service" {
		t.Fatalf("Items 应返回值拷贝, 内部状态被污染: %+v", again[0])
	}
	if m.Size() != 1 {
		t.Fatalf("内部基线不应被外部修改影响, size=%d", m.Size())
	}
}

// 空基线（干净机器 / 首轮扫描前）返回空切片，不是错误。
func TestItemsEmptyBaseline(t *testing.T) {
	m := New(filepath.Join(t.TempDir(), "missing.json"), nil)
	if err := m.Load(); err != nil {
		t.Fatalf("load missing file 应按空基线处理: %v", err)
	}
	if items := m.Items(); len(items) != 0 {
		t.Fatalf("空基线应返回 0 条, got %d", len(items))
	}
}
