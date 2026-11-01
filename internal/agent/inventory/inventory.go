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
	"errors"
	"fmt"
	"log/slog"
	"math/rand"
	"reflect"
	"sort"
	"strings"
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
// 同时保留每节最近一次"变化前"的 payload，供上层做条目级 diff（见 Diff/LastPayload）。
type Manager struct {
	log *slog.Logger

	mu   sync.Mutex
	fns  map[string]SnapshotFn
	last map[string]string // 节名 → 上次成功快照的 sha256 hex

	// payload 状态（条目级 diff 支持）：
	// payloads    节名 → 最近一次成功快照的 payload（当前态）
	// prevPayload 节名 → 最近一次"变化前"的 payload。只在变化的轮次存在，
	//             未变化的轮次会被清掉，保证 LastPayload 的语义精确
	// rb          本轮变化节的 payload 回滚快照（post 失败时 restore 用）
	payloads    map[string]string
	prevPayload map[string]string
	rb          map[string]payloadRollback

	// jitterMax 是 Run 启动抖动上限（错峰用）；测试置 0 跳过等待。
	jitterMax time.Duration
}

// payloadRollback 记录一节在本次 collect 之前的 payload 状态，
// post 失败回滚时把 payloads/prevPayload 一起还原。
type payloadRollback struct {
	hadPayload  bool
	payload     string
	hadPrev     bool
	prevPayload string
}

// New 创建清单管理器。log 可为 nil（使用 slog.Default）。
func New(log *slog.Logger) *Manager {
	if log == nil {
		log = slog.Default()
	}
	return &Manager{
		log:         log,
		fns:         make(map[string]SnapshotFn, 8),
		last:        make(map[string]string, 8),
		payloads:    make(map[string]string, 8),
		prevPayload: make(map[string]string, 8),
		rb:          make(map[string]payloadRollback, 8),
		jitterMax:   10 * time.Second,
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
// 同时维护 payloads/prevPayload（条目级 diff 支持）与 rb（回滚快照）。
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
	rb := make(map[string]payloadRollback, len(names))
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

			// 保留"变化前"payload 供条目级 diff。首轮（此前从未成功采集）
			// 不留 prev：上层据此把首轮当建基线，而不是喷出一堆"新增"。
			oldPayload, hadPayload := m.payloads[name]
			oldPrev, hadPrev := m.prevPayload[name]
			if hadPayload && oldPayload != "" {
				m.prevPayload[name] = oldPayload
			} else {
				delete(m.prevPayload, name)
			}
			m.payloads[name] = string(raw)
			rb[name] = payloadRollback{
				hadPayload: hadPayload, payload: oldPayload,
				hadPrev: hadPrev, prevPayload: oldPrev,
			}

			sections = append(sections, model.InventorySection{
				Name: name, Hash: hash, Payload: string(raw),
			})
		} else {
			// 本轮未变化：清掉上一轮遗留的 prev，保证 LastPayload 的
			// 语义是"最近一次变化前"，而不是任意历史值。
			delete(m.prevPayload, name)
		}
		m.mu.Unlock()
	}
	m.mu.Lock()
	m.rb = rb
	m.mu.Unlock()
	return sections, prev
}

// restore 把节的 hash 回滚到快照前（post 失败重试语义的一部分）。
// 若期间有并发 Snapshot 已写入更新的 hash，回滚会造成下一轮重复上报
// 该节——清单是幂等的（服务端按 hash 去重），多报一次无害。
//
// payload/prevPayload 必须一并回滚：下一轮重试同一节时，"变化前"状态必须
// 仍是这次失败前的那份。只回滚 hash 的话，重试轮会算出 prev==cur，
// diff 为空——这次变更的事件被吞掉，直到该节下一次真实变化才恢复，
// 丢事件窗口不可接受。
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
		if r, ok := m.rb[name]; ok {
			if r.hadPayload {
				m.payloads[name] = r.payload
			} else {
				delete(m.payloads, name)
			}
			if r.hadPrev {
				m.prevPayload[name] = r.prevPayload
			} else {
				delete(m.prevPayload, name)
			}
		}
	}
}

// Count 返回已注册的节数。
func (m *Manager) Count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.fns)
}

// LastPayload 返回该节"最近一次变化前"的 payload，供条目级 diff 使用。
//
// 时序语义：Snapshot/Run 每轮 collect 时会把变化节的旧 payload 存入
// prevPayload，因此调用方必须在本轮快照（或 Run 的 post 回调）之后、
// 下一轮快照之前读取——拿到的才是产生本轮差量的那个"变化前"版本。
// ok=false 表示本轮没有可 diff 的前一版本：首轮建基线、本轮该节未变化、
// 或 post 失败回滚后等待重试。
func (m *Manager) LastPayload(name string) (string, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	p, ok := m.prevPayload[name]
	return p, ok
}

// ---------------------------------------------------------------- 条目级 diff

// 事件类型取值（ChangeEvent.Kind）。
const (
	DiffAdded   = "added"
	DiffRemoved = "removed"
	DiffChanged = "changed"
)

// maxDiffEntries 是 Diff 单侧 payload 的条目数上限。正常机器任何一节的
// 条目都在千条以内（服务约几百、计划任务约两百），超限更像是异常或
// 恶意构造的 payload——拒绝 diff，而不是做无上限的内存分配。
const maxDiffEntries = 2000

// ChangeEvent 是一节 payload 内部、按条目主键 diff 出的一个变更。
type ChangeEvent struct {
	// Section 由调用方回填（Diff 是纯函数，不知道节名）。
	Section string `json:"section"`
	// Kind 取值 DiffAdded / DiffRemoved / DiffChanged。
	Kind string `json:"kind"`
	// Key 是 keyFn 从条目提取的主键。
	Key string `json:"key"`
	// Detail 是人类可读摘要；changed 事件含"字段: 旧值 → 新值"列表。
	Detail string `json:"detail,omitempty"`
	// 以下三项只在 changed 事件有值：字段级差异分类。
	Added         []string `json:"added,omitempty"`   // after 有、before 没有的字段名
	Removed       []string `json:"removed,omitempty"` // before 有、after 没有的字段名
	ChangedFields []string `json:"changed_fields,omitempty"`

	// Before/After 是原始条目（removed 只有 Before，added 只有 After，
	// changed 两者都有），供策略层直接提取路径/进程名等做富化，
	// 不必再回头解析 payload。
	Before map[string]any `json:"before,omitempty"`
	After  map[string]any `json:"after,omitempty"`
}

// Diff 对比两份同构 payload（上一轮 / 这一轮），按 keyFn 主键产出
// added/removed/changed 三类事件。纯函数：不访问 Manager 状态、不做 IO。
//
// payload 形态兼容三种：
//   - 裸数组  [{"name":...}, ...]
//   - 单列表包装  {"items":[...]}
//   - 多列表包装（listeners 节）{"tcp":[...],"udp":[...]}：按列表名排序合并，
//     并给每个条目注入列表名作为 proto 字段（条目已带该字段时不覆盖），
//     keyFn 据此可以拼出 "tcp|8080" 这类带协议前缀的主键。
//
// keyFn 返回空串的条目无法跨轮追踪，跳过；同一 payload 内主键冲突时
// 先到先得（各节 builder 已按主键排序，冲突只可能是采集侧数据 bug，
// 固定取首条保证输出确定）。
//
// 返回顺序固定：added → removed → changed，各自按 key 升序，
// 测试与告警折叠逻辑都可依赖这个顺序。
func Diff(prevJSON, curJSON string, keyFn func(map[string]any) string) ([]ChangeEvent, error) {
	if keyFn == nil {
		return nil, errors.New("inventory: keyFn 不能为空")
	}
	prev, err := parseEntries(prevJSON)
	if err != nil {
		return nil, fmt.Errorf("解析 prev payload: %w", err)
	}
	cur, err := parseEntries(curJSON)
	if err != nil {
		return nil, fmt.Errorf("解析 cur payload: %w", err)
	}
	if len(prev) > maxDiffEntries {
		return nil, fmt.Errorf("prev 条目数 %d 超过上限 %d", len(prev), maxDiffEntries)
	}
	if len(cur) > maxDiffEntries {
		return nil, fmt.Errorf("cur 条目数 %d 超过上限 %d", len(cur), maxDiffEntries)
	}

	prevByKey := indexEntries(prev, keyFn)
	curByKey := indexEntries(cur, keyFn)

	out := make([]ChangeEvent, 0, 8)

	for _, k := range sortedKeysIn(curByKey, prevByKey) {
		out = append(out, ChangeEvent{Kind: DiffAdded, Key: k, After: curByKey[k]})
	}
	for _, k := range sortedKeysIn(prevByKey, curByKey) {
		out = append(out, ChangeEvent{Kind: DiffRemoved, Key: k, Before: prevByKey[k]})
	}
	for _, k := range sortedKeysIn(prevByKey, nil) {
		after, inCur := curByKey[k]
		if !inCur {
			continue // removed 已在上面产出
		}
		before := prevByKey[k]
		if reflect.DeepEqual(before, after) {
			continue
		}
		ev := ChangeEvent{Kind: DiffChanged, Key: k, Before: before, After: after}
		for f, v := range after {
			bv, ok := before[f]
			switch {
			case !ok:
				ev.Added = append(ev.Added, f)
			case !reflect.DeepEqual(bv, v):
				ev.ChangedFields = append(ev.ChangedFields, f)
			}
		}
		for f := range before {
			if _, ok := after[f]; !ok {
				ev.Removed = append(ev.Removed, f)
			}
		}
		sort.Strings(ev.Added)
		sort.Strings(ev.Removed)
		sort.Strings(ev.ChangedFields)
		ev.Detail = diffDetail(before, after, ev)
		out = append(out, ev)
	}
	return out, nil
}

// diffDetail 生成 changed 事件的字段级摘要，例如
// "state: stopped → running；start_mode: auto → manual"。
// 覆盖三类字段差异（值变化/新增/消失），长值截断。
func diffDetail(before, after map[string]any, ev ChangeEvent) string {
	parts := make([]string, 0, len(ev.ChangedFields)+len(ev.Added)+len(ev.Removed))
	for _, f := range ev.ChangedFields {
		parts = append(parts, fmt.Sprintf("%s: %s → %s", f, fmtDiffVal(before[f]), fmtDiffVal(after[f])))
	}
	for _, f := range ev.Added {
		parts = append(parts, fmt.Sprintf("%s: 新增 %s", f, fmtDiffVal(after[f])))
	}
	for _, f := range ev.Removed {
		parts = append(parts, fmt.Sprintf("%s: 移除（原 %s）", f, fmtDiffVal(before[f])))
	}
	return truncateRunes(strings.Join(parts, "；"), 512)
}

// fmtDiffVal 格式化单个字段值用于摘要（截断，避免超长命令行刷屏）。
func fmtDiffVal(v any) string {
	return truncateRunes(fmt.Sprintf("%v", v), 64)
}

// truncateRunes 按 rune 截断（服务显示名可能是中文，按字节截会切开 UTF-8）。
func truncateRunes(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}

// indexEntries 把条目列表按 keyFn 主键索引。空主键跳过，键冲突先到先得。
func indexEntries(entries []map[string]any, keyFn func(map[string]any) string) map[string]map[string]any {
	out := make(map[string]map[string]any, len(entries))
	for _, e := range entries {
		k := keyFn(e)
		if k == "" {
			continue
		}
		if _, dup := out[k]; !dup {
			out[k] = e
		}
	}
	return out
}

// sortedKeysIn 返回 m 中有、exclude 中没有的 key，升序。
// exclude 传 nil 表示取 m 的全部 key。
func sortedKeysIn(m, exclude map[string]map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		if exclude == nil {
			keys = append(keys, k)
			continue
		}
		if _, in := exclude[k]; !in {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	return keys
}

// parseEntries 把 payload 解析成条目列表，兼容裸数组、{"items":[...]} 包装
// 与多列表包装（合并 + 注入列表名为 proto 字段）。空/null payload 返回空列表。
func parseEntries(raw string) ([]map[string]any, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return nil, nil
	}
	if strings.HasPrefix(s, "[") {
		var arr []any
		if err := json.Unmarshal([]byte(s), &arr); err != nil {
			return nil, err
		}
		return anyMaps(arr), nil
	}
	var obj map[string]any
	if err := json.Unmarshal([]byte(s), &obj); err != nil {
		return nil, err
	}
	if obj == nil { // "null"
		return nil, nil
	}
	if items, ok := obj["items"]; ok {
		arr, ok := items.([]any)
		if !ok {
			return nil, errors.New("items 字段不是数组")
		}
		return anyMaps(arr), nil
	}
	// 多列表包装（listeners 节的 {"tcp":[...],"udp":[...]}）：所有值都是
	// 数组时按列表名排序合并；每个条目注入列表名作为 proto 字段——
	// 原始条目没有这个字段，注入后 keyFn 才能拼出带协议前缀的主键。
	// 两轮 payload 做同样的注入，因此注入字段永远不会出现在差异里。
	if len(obj) > 0 {
		keys := make([]string, 0, len(obj))
		allArrays := true
		for k, v := range obj {
			keys = append(keys, k)
			if _, isArr := v.([]any); !isArr {
				allArrays = false
			}
		}
		if allArrays {
			sort.Strings(keys)
			out := make([]map[string]any, 0, 16)
			for _, k := range keys {
				for _, e := range obj[k].([]any) {
					m, ok := e.(map[string]any)
					if !ok {
						continue
					}
					if _, exists := m["proto"]; !exists {
						m["proto"] = k
					}
					out = append(out, m)
				}
			}
			return out, nil
		}
	}
	return nil, errors.New("payload 既不是条目数组，也没有 items 或多列表结构")
}

// anyMaps 过滤出对象条目（数组里的标量条目无法做字段级 diff，跳过）。
func anyMaps(arr []any) []map[string]any {
	out := make([]map[string]any, 0, len(arr))
	for _, e := range arr {
		if m, ok := e.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out
}
