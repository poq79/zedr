// Package inventory 实现探针侧资产清单（inventory）快照与差量上报。
//
// 工作方式：各节的数据源以 SnapshotFn 闭包注入（依赖倒置——真正的采集
// 函数在 winapi 包，本包不做任何系统调用），Manager 对每节 payload 计算
// SHA-256 并与上次比对，只把发生变化的节交给 post 回调。
//
// 服务端按 (agent_id, name, hash) 做节级幂等：稳定态下几乎零流量；
// 某节变化时又能拿到完整 JSON 快照，不需要服务端理解节内 schema。
//
// 并发约定：锁只保护注册表与 hash 表，不跨过 SnapshotFn 执行——
// 快照函数可能做系统调用（毫秒到几十毫秒），持锁执行会卡住 Register。
package inventory

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"math/rand"
	"sort"
	"sync"
	"time"

	"hostguard/internal/model"
)

// SnapshotFn 是一个节的快照函数：返回值会被 json.Marshal 成 payload。
// 返回的对象字段名应使用 json tag 声明为 snake_case；
// 返回 error 表示本节本轮采集失败，会被跳过（不影响其他节）。
type SnapshotFn func() (any, error)

// PostFn 是差量上报回调；返回服务端确认应用的节名。
type PostFn func(sections []model.InventorySection) (applied []string, err error)

// Manager 维护各节上一次上报的 payload 哈希，产出差量。
type Manager struct {
	log *slog.Logger

	mu   sync.Mutex
	fns  map[string]SnapshotFn
	last map[string]string // 节名 → 上次成功快照的 sha256 hex

	// jitterMax 是 Run 启动抖动上限（错峰用）；测试置 0 跳过等待。
	jitterMax time.Duration
}

// New 创建清单管理器。log 可为 nil（使用 slog.Default）。
func New(log *slog.Logger) *Manager {
	if log == nil {
		log = slog.Default()
	}
	return &Manager{
		log:       log,
		fns:       make(map[string]SnapshotFn, 8),
		last:      make(map[string]string, 8),
		jitterMax: 10 * time.Second,
	}
}

// Register 注册（或替换）一个节的快照函数。必须在 Run 之前或并发调用均可。
func (m *Manager) Register(name string, fn SnapshotFn) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.fns[name] = fn
}

// Snapshot 执行全部注册节并返回与上次相比发生变化的节（首次全部返回）。
// fn 出错或 marshal 失败的节被跳过且不更新其 hash——下一轮成功时仍算变化，
// 不会因为一次采集抖动而永久丢节。
func (m *Manager) Snapshot() []model.InventorySection {
	sections, _ := m.collect()
	return sections
}

// Run 驱动清单循环：先随机抖动 0~10s 错峰（成批部署的终端若同时打首轮
// 全量，服务端会看到写入尖峰），之后每 interval 采集一轮，有差量就 post。
//
// post 失败回滚对应节的 hash 并在下轮重试：不回滚的话，这次差量会被
// last 表"吞掉"，服务端要等到该节下一次真实变化才能再见到数据——
// 对一次网络抖动来说，丢失窗口是无限长的，不可接受。
// post 失败只记 warn，循环绝不退出；ctx.Done 时返回。
func (m *Manager) Run(ctx context.Context, interval time.Duration, post PostFn) {
	if post == nil {
		m.log.Error("inventory_post_nil", "hint", "未提供上报回调，清单循环不启动")
		return
	}
	if m.jitterMax > 0 {
		jitter := time.Duration(rand.Int63n(int64(m.jitterMax)))
		select {
		case <-ctx.Done():
			return
		case <-time.After(jitter):
		}
	}

	for {
		sections, prev := m.collect()
		if len(sections) > 0 {
			if _, err := post(sections); err != nil {
				m.log.Warn("inventory_post_failed", "sections", len(sections), "err", err)
				m.restore(prev)
			} else {
				m.log.Debug("inventory_posted", "sections", len(sections))
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(interval):
		}
	}
}

// collect 执行全部节：锁外跑快照函数，锁内做 hash 比对与更新。
// 返回差量节与各节的旧 hash（供 post 失败时回滚）。
func (m *Manager) collect() ([]model.InventorySection, map[string]string) {
	m.mu.Lock()
	names := make([]string, 0, len(m.fns))
	for name := range m.fns {
		names = append(names, name)
	}
	m.mu.Unlock()
	// 固定顺序：输出稳定，也便于测试与日志比对（hash 是按节算的，
	// 顺序本不影响正确性，但随机的输出顺序会让排查多绕一圈）。
	sort.Strings(names)

	sections := make([]model.InventorySection, 0, len(names))
	prev := make(map[string]string, len(names))
	for _, name := range names {
		m.mu.Lock()
		fn := m.fns[name]
		m.mu.Unlock()

		v, err := fn()
		if err != nil {
			m.log.Debug("inventory_section_failed", "section", name, "err", err)
			continue
		}
		raw, err := json.Marshal(v)
		if err != nil {
			// json.Marshal 对 map/slice/struct 基本不会失败，走到这里
			// 说明 builder 返回了带 channel/func 的对象，是代码 bug 而非数据问题
			m.log.Debug("inventory_section_marshal_failed", "section", name, "err", err)
			continue
		}

		sum := sha256.Sum256(raw)
		hash := hex.EncodeToString(sum[:])

		m.mu.Lock()
		if old, ok := m.last[name]; !ok || old != hash {
			prev[name] = m.last[name]
			m.last[name] = hash
			sections = append(sections, model.InventorySection{
				Name: name, Hash: hash, Payload: string(raw),
			})
		}
		m.mu.Unlock()
	}
	return sections, prev
}

// restore 把节的 hash 回滚到快照前（post 失败重试语义的一部分）。
// 若期间有并发 Snapshot 已写入更新的 hash，回滚会造成下一轮重复上报
// 该节——清单是幂等的（服务端按 hash 去重），多报一次无害。
func (m *Manager) restore(prev map[string]string) {
	if len(prev) == 0 {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for name, old := range prev {
		if old == "" {
			delete(m.last, name)
		} else {
			m.last[name] = old
		}
	}
}
