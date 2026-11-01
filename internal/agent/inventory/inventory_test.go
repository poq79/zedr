package inventory

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"zedr/internal/model"
)

// newTestManager 返回免抖动的 Manager（生产默认 0~10s 启动抖动，
// 测试等不起也不需要随机性）。
func newTestManager() *Manager {
	m := New(nil)
	m.jitterMax = 0
	return m
}

func namesOf(sections []model.InventorySection) []string {
	out := make([]string, 0, len(sections))
	for _, s := range sections {
		out = append(out, s.Name)
	}
	return out
}

func contains(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}

// 首次 Snapshot：last 表为空，所有注册节都应返回。
func TestSnapshotFirstRoundReturnsAll(t *testing.T) {
	m := newTestManager()
	m.Register("system", func() (any, error) { return map[string]any{"a": 1}, nil })
	m.Register("agent", func() (any, error) { return map[string]any{"b": "x"}, nil })
	m.Register("tasks", func() (any, error) { return []map[string]any{{"n": 1}}, nil })

	got := m.Snapshot()
	if len(got) != 3 {
		t.Fatalf("首轮应返回全部 3 节, got %d: %v", len(got), namesOf(got))
	}
	for _, name := range []string{"system", "agent", "tasks"} {
		if !contains(namesOf(got), name) {
			t.Fatalf("首轮缺少节 %q: %v", name, namesOf(got))
		}
	}
}

// 不变的节第二次 Snapshot 不返回；变化后重新出现。
func TestSnapshotSuppressesUnchanged(t *testing.T) {
	m := newTestManager()
	val := "v1"
	m.Register("s", func() (any, error) { return map[string]any{"k": val}, nil })

	if got := m.Snapshot(); len(got) != 1 {
		t.Fatalf("首轮应返回 1 节, got %d", len(got))
	}
	if got := m.Snapshot(); len(got) != 0 {
		t.Fatalf("数据未变时第二轮应返回 0 节, got %d: %v", len(got), namesOf(got))
	}

	val = "v2" // 数据源变化
	got := m.Snapshot()
	if len(got) != 1 || got[0].Name != "s" {
		t.Fatalf("变化后应重新出现节 s, got %v", namesOf(got))
	}
	if got := m.Snapshot(); len(got) != 0 {
		t.Fatalf("变化被消费后应回到 0 节, got %v", namesOf(got))
	}
}

// fn 出错的节被跳过且不崩；恢复后作为"变化"重新出现（错误不污染 hash 表）。
func TestSnapshotSectionErrorSkipped(t *testing.T) {
	m := newTestManager()
	fail := true
	m.Register("ok", func() (any, error) { return map[string]any{"k": "stable"}, nil })
	m.Register("bad", func() (any, error) {
		if fail {
			return nil, errors.New("boom")
		}
		return map[string]any{"k": "recovered"}, nil
	})

	got := m.Snapshot()
	if len(got) != 1 || got[0].Name != "ok" {
		t.Fatalf("出错的节应被跳过, got %v", namesOf(got))
	}

	fail = false
	got = m.Snapshot()
	if len(got) != 1 || got[0].Name != "bad" {
		t.Fatalf("恢复后出错节应重新出现（ok 未变不应出现）, got %v", namesOf(got))
	}
}

// Snapshot 产出的 hash 必须与 payload 重算一致，payload 必须是合法 JSON。
func TestSnapshotHashMatchesPayload(t *testing.T) {
	m := newTestManager()
	m.Register("system", func() (any, error) {
		return map[string]any{
			"uptime_sec": 123, "disks": []map[string]any{{"drive": "C:", "total_mb": 100}},
		}, nil
	})
	m.Register("listeners", func() (any, error) {
		return map[string]any{"tcp": []map[string]any{{"port": 8080, "pid": 4}}, "udp": []any{}}, nil
	})

	got := m.Snapshot()
	if len(got) != 2 {
		t.Fatalf("应有 2 节, got %v", namesOf(got))
	}
	for _, s := range got {
		sum := sha256.Sum256([]byte(s.Payload))
		if hex.EncodeToString(sum[:]) != s.Hash {
			t.Errorf("节 %s 的 hash 与 payload 重算不一致: hash=%s", s.Name, s.Hash)
		}
		var probe map[string]any
		if err := json.Unmarshal([]byte(s.Payload), &probe); err != nil {
			t.Errorf("节 %s 的 payload 不是合法 JSON: %v", s.Name, err)
		}
	}
}

// Run：有差量才 post（静态节只出现在首轮批次），ctx cancel 后退出。
func TestRunPostsDiffAndExits(t *testing.T) {
	m := newTestManager()

	var mu sync.Mutex
	round := 0
	var batches [][]string

	m.Register("dynamic", func() (any, error) {
		mu.Lock()
		defer mu.Unlock()
		return map[string]any{"round": round}, nil
	})
	m.Register("static", func() (any, error) {
		return map[string]any{"k": "never-changes"}, nil
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		m.Run(ctx, 50*time.Millisecond, func(sections []model.InventorySection) ([]string, error) {
			mu.Lock()
			defer mu.Unlock()
			batches = append(batches, namesOf(sections))
			round++ // 每次上报后推进数据源 → 下一轮 dynamic 必然产生差量
			return []string{"dynamic", "static"}, nil
		})
	}()

	// 等到至少 3 轮上报
	deadline := time.After(5 * time.Second)
	for {
		mu.Lock()
		n := len(batches)
		mu.Unlock()
		if n >= 3 {
			break
		}
		select {
		case <-deadline:
			t.Fatalf("Run 迟迟没有产生差量上报, batches=%v", batches)
		case <-time.After(10 * time.Millisecond):
		}
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("ctx cancel 后 Run 未退出")
	}

	mu.Lock()
	defer mu.Unlock()
	if !contains(batches[0], "static") || !contains(batches[0], "dynamic") {
		t.Fatalf("首轮应同时上报两个节, got %v", batches[0])
	}
	for i, b := range batches[1:] {
		if contains(b, "static") {
			t.Errorf("static 未变化却出现在第 %d 批: %v", i+2, b)
		}
		if !contains(b, "dynamic") {
			t.Errorf("dynamic 已变化却未出现在第 %d 批: %v", i+2, b)
		}
	}
}

// post 失败：不退出、hash 回滚、下一轮重试同一节（差量不被吞掉）。
func TestRunRetriesAfterPostFailure(t *testing.T) {
	m := newTestManager()

	m.Register("s", func() (any, error) { return map[string]any{"k": "v"}, nil })

	var mu sync.Mutex
	attempts := 0
	posted := 0
	failUntil := 2 // 前两次失败，第三次成功

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		m.Run(ctx, 50*time.Millisecond, func(sections []model.InventorySection) ([]string, error) {
			mu.Lock()
			defer mu.Unlock()
			attempts++
			if attempts <= failUntil {
				return nil, fmt.Errorf("server down (attempt %d)", attempts)
			}
			if len(sections) != 1 || sections[0].Name != "s" {
				t.Errorf("重试批次应包含节 s, got %v", namesOf(sections))
			}
			posted++
			return nil, nil // 空 applied，足够走成功路径
		})
	}()

	deadline := time.After(5 * time.Second)
	for {
		mu.Lock()
		ok := posted > 0
		mu.Unlock()
		if ok {
			break
		}
		select {
		case <-deadline:
			t.Fatalf("post 失败后未重试成功, attempts=%d", attempts)
		case <-time.After(10 * time.Millisecond):
		}
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("ctx cancel 后 Run 未退出")
	}

	mu.Lock()
	if attempts < 3 {
		t.Fatalf("应至少尝试 3 次（2 次失败 + 1 次成功）, got %d", attempts)
	}
	if posted != 1 {
		t.Fatalf("成功 post 应恰好 1 次, got %d", posted)
	}
	mu.Unlock()

	// 成功后再无差量：短暂观察窗口内不应再有 post。
	// 注意 sleep 必须在锁外——测试锁不可重入，持锁再 Lock 是自死锁。
	time.Sleep(120 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	if posted != 1 {
		t.Fatalf("稳定态不应继续上报, posted=%d", posted)
	}
}

// post 报错路径不能把 Manager 的状态打坏：失败后手动 Snapshot 仍能看到该节。
func TestSnapshotAfterFailedPostStillReportsSection(t *testing.T) {
	m := newTestManager()
	m.Register("s", func() (any, error) { return map[string]any{"k": 1}, nil })

	sections, prev := m.collect()
	if len(sections) != 1 {
		t.Fatalf("collect 应产出 1 节, got %d", len(sections))
	}
	m.restore(prev) // 模拟 post 失败后的回滚

	again := m.Snapshot()
	if len(again) != 1 || again[0].Name != "s" {
		t.Fatalf("回滚后 Snapshot 应重新产出该节, got %v", namesOf(again))
	}
}
