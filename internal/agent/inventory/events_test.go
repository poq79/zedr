package inventory

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

// ---------------------------------------------------------------- Diff 纯函数

func keyByName(m map[string]any) string {
	s, _ := m["name"].(string)
	return s
}

func findEvent(t *testing.T, evs []ChangeEvent, kind, key string) ChangeEvent {
	t.Helper()
	for _, ev := range evs {
		if ev.Kind == kind && ev.Key == key {
			return ev
		}
	}
	t.Fatalf("未找到事件 kind=%s key=%s, evs=%+v", kind, key, evs)
	return ChangeEvent{}
}

// 三类事件都要产出，字段级差异分类与 Before/After 条目都要正确。
func TestDiffThreeKinds(t *testing.T) {
	prev := `[{"name":"a","state":"running"},{"name":"b","state":"stopped"}]`
	cur := `[{"name":"a","state":"stopped","note":"new"},{"name":"c","state":"running"}]`

	evs, err := Diff(prev, cur, keyByName)
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	if len(evs) != 3 {
		t.Fatalf("应产出 3 个事件, got %d: %+v", len(evs), evs)
	}

	added := findEvent(t, evs, DiffAdded, "c")
	if added.After == nil || added.After["state"] != "running" {
		t.Fatalf("added 事件应带 after 条目: %+v", added)
	}
	if added.Before != nil {
		t.Fatalf("added 事件不应带 before 条目: %+v", added)
	}

	removed := findEvent(t, evs, DiffRemoved, "b")
	if removed.Before == nil || removed.Before["state"] != "stopped" {
		t.Fatalf("removed 事件应带 before 条目: %+v", removed)
	}
	if removed.After != nil {
		t.Fatalf("removed 事件不应带 after 条目: %+v", removed)
	}

	changed := findEvent(t, evs, DiffChanged, "a")
	if !reflect.DeepEqual(changed.ChangedFields, []string{"state"}) {
		t.Fatalf("changed 字段应为 [state], got %v", changed.ChangedFields)
	}
	if !reflect.DeepEqual(changed.Added, []string{"note"}) {
		t.Fatalf("新增字段应为 [note], got %v", changed.Added)
	}
	if len(changed.Removed) != 0 {
		t.Fatalf("不应有移除字段, got %v", changed.Removed)
	}
	if changed.Before["state"] != "running" || changed.After["state"] != "stopped" {
		t.Fatalf("changed 事件的 before/after 值不符: %+v", changed)
	}
	if !strings.Contains(changed.Detail, "state: running → stopped") {
		t.Fatalf("changed 摘要应含字段级前后值, got %q", changed.Detail)
	}
}

// 裸数组与 {"items":[...]} 包装必须产出完全一致的结果。
func TestDiffWrapperCompat(t *testing.T) {
	evs1, err := Diff(`[{"name":"a","v":1}]`, `[{"name":"a","v":2}]`, keyByName)
	if err != nil {
		t.Fatalf("裸数组 Diff: %v", err)
	}
	evs2, err := Diff(`{"items":[{"name":"a","v":1}]}`, `{"items":[{"name":"a","v":2}]}`, keyByName)
	if err != nil {
		t.Fatalf("items 包装 Diff: %v", err)
	}
	if !reflect.DeepEqual(evs1, evs2) {
		t.Fatalf("两种包装应产出一致事件:\n bare=%+v\n items=%+v", evs1, evs2)
	}
	if len(evs1) != 1 || evs1[0].Kind != DiffChanged {
		t.Fatalf("应产出 1 个 changed 事件, got %+v", evs1)
	}
}

// listeners 节的多列表包装：tcp/udp 合并 diff，条目注入 proto 字段，
// key 形如 "tcp|8443"。
func TestDiffMultiListMergedWithProto(t *testing.T) {
	prev := `{"tcp":[{"port":80,"pid":4}],"udp":[{"port":5353,"pid":88}]}`
	cur := `{"udp":[{"port":5353,"pid":88}],"tcp":[{"port":80,"pid":4},{"port":8443,"pid":999}]}`

	keyFn := func(m map[string]any) string {
		return fmt.Sprintf("%v|%v", m["proto"], m["port"])
	}
	evs, err := Diff(prev, cur, keyFn)
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	if len(evs) != 1 {
		t.Fatalf("应只新增 1 个监听条目, got %+v", evs)
	}
	if evs[0].Kind != DiffAdded || evs[0].Key != "tcp|8443" {
		t.Fatalf("应为 added tcp|8443, got %+v", evs[0])
	}
	if evs[0].After["proto"] != "tcp" {
		t.Fatalf("条目应注入 proto 字段: %+v", evs[0].After)
	}

	// udp 条目也走同一套主键（注入 udp 前缀）
	evs, err = Diff(`{"tcp":[],"udp":[{"port":5353,"pid":88}]}`, `{"tcp":[],"udp":[]}`, keyFn)
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	if len(evs) != 1 || evs[0].Kind != DiffRemoved || evs[0].Key != "udp|5353" {
		t.Fatalf("应产出 removed udp|5353, got %+v", evs)
	}
}

// 同一 payload 内主键冲突：先到先得（保证确定性），冲突本身不报错。
func TestDiffKeyConflictFirstWins(t *testing.T) {
	prev := `[{"name":"x","v":9},{"name":"x","v":1}]`
	cur := `[{"name":"x","v":1},{"name":"x","v":7}]`

	evs, err := Diff(prev, cur, keyByName)
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	if len(evs) != 1 || evs[0].Kind != DiffChanged {
		t.Fatalf("键冲突应先到先得（prev 首条 v=9 vs cur 首条 v=1）, got %+v", evs)
	}
	if evs[0].Before["v"] != float64(9) || evs[0].After["v"] != float64(1) {
		t.Fatalf("应取两侧首条比较, got %+v", evs[0])
	}
}

// keyFn 返回空串的条目无法跨轮追踪，跳过（不产生幽灵事件）。
func TestDiffEmptyKeySkipped(t *testing.T) {
	evs, err := Diff(`[{"v":1}]`, `[{"v":2}]`, keyByName)
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	if len(evs) != 0 {
		t.Fatalf("无主键条目应被跳过, got %+v", evs)
	}
}

// 事件顺序固定：added → removed → changed，各自按 key 升序。
func TestDiffStableOrder(t *testing.T) {
	prev := `[{"name":"c"},{"name":"a"},{"name":"b"},{"name":"z"},{"name":"y"}]`
	// z/y 两边都有（只是加了字段 v）→ 属于 changed；a/b/c 消失 → removed
	cur := `[{"name":"z","v":1},{"name":"y","v":1},{"name":"w"},{"name":"x"}]`

	evs, err := Diff(prev, cur, keyByName)
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	want := []struct{ kind, key string }{
		{DiffAdded, "w"}, {DiffAdded, "x"},
		{DiffRemoved, "a"}, {DiffRemoved, "b"}, {DiffRemoved, "c"},
		{DiffChanged, "y"}, {DiffChanged, "z"},
	}
	if len(evs) != len(want) {
		t.Fatalf("应产出 %d 个事件, got %d: %+v", len(want), len(evs), evs)
	}
	for i, w := range want {
		if evs[i].Kind != w.kind || evs[i].Key != w.key {
			t.Fatalf("第 %d 个事件应为 %s/%s, got %s/%s", i, w.kind, w.key, evs[i].Kind, evs[i].Key)
		}
	}
}

func entriesJSON(n int) string {
	list := make([]map[string]any, n)
	for i := range list {
		list[i] = map[string]any{"name": fmt.Sprintf("k%d", i)}
	}
	raw, err := json.Marshal(list)
	if err != nil {
		panic(err)
	}
	return string(raw)
}

// 条目数超过上限必须拒绝（防异常 payload 打爆内存），恰好在上限内要能算完。
func TestDiffEntryLimit(t *testing.T) {
	_, err := Diff(`[]`, entriesJSON(maxDiffEntries+1), keyByName)
	if err == nil {
		t.Fatal("超过上限应返回错误")
	}
	if !strings.Contains(err.Error(), fmt.Sprint(maxDiffEntries+1)) {
		t.Fatalf("错误信息应包含条目数, got %v", err)
	}

	evs, err := Diff(`[]`, entriesJSON(maxDiffEntries), keyByName)
	if err != nil {
		t.Fatalf("恰好 %d 条不应报错: %v", maxDiffEntries, err)
	}
	if len(evs) != maxDiffEntries {
		t.Fatalf("应产出 %d 个 added 事件, got %d", maxDiffEntries, len(evs))
	}
}

// 非法输入要报错而不是 panic。
func TestDiffInvalidInputs(t *testing.T) {
	if _, err := Diff(`{bad json`, `[]`, keyByName); err == nil {
		t.Fatal("prev 非法 JSON 应报错")
	}
	if _, err := Diff(`[]`, `{bad json`, keyByName); err == nil {
		t.Fatal("cur 非法 JSON 应报错")
	}
	if _, err := Diff(`[]`, `[]`, nil); err == nil {
		t.Fatal("keyFn 为 nil 应报错")
	}
	if _, err := Diff(`[]`, `{"items":"not-array"}`, keyByName); err == nil {
		t.Fatal("items 不是数组应报错")
	}
	// 空 payload 视为空列表：prev 为空 → 全部 added
	evs, err := Diff("", `[{"name":"a"}]`, keyByName)
	if err != nil {
		t.Fatalf("空 prev 应视为空列表: %v", err)
	}
	if len(evs) != 1 || evs[0].Kind != DiffAdded {
		t.Fatalf("空 prev 应产出 added, got %+v", evs)
	}
}

// ---------------------------------------------------------------- LastPayload 时序

// LastPayload 的时序语义：只在"发生变化的轮次"返回变化前 payload；
// 首轮建基线与未变化轮次都拿不到。
func TestLastPayloadLifecycle(t *testing.T) {
	m := newTestManager()
	cur := []map[string]any{{"name": "a", "state": "running"}}
	m.Register("services", func() (any, error) { return cur, nil })

	if n := m.Count(); n != 1 {
		t.Fatalf("Count 应为 1, got %d", n)
	}

	m.Snapshot() // 首轮建基线
	if _, ok := m.LastPayload("services"); ok {
		t.Fatal("首轮建基线不应有变化前 payload")
	}

	cur = []map[string]any{{"name": "a", "state": "stopped"}}
	got := m.Snapshot()
	if len(got) != 1 {
		t.Fatalf("变化轮应产出差量, got %d", len(got))
	}
	prev, ok := m.LastPayload("services")
	if !ok {
		t.Fatal("变化轮之后应能取到变化前 payload")
	}
	if !strings.Contains(prev, `"state":"running"`) {
		t.Fatalf("变化前 payload 应是旧版本, got %s", prev)
	}
	if prev == got[0].Payload {
		t.Fatal("LastPayload 必须是变化前版本，不能等于本轮 payload")
	}

	// 未变化轮次：prev 被清掉，语义保持"最近一次变化前"
	m.Snapshot()
	if _, ok := m.LastPayload("services"); ok {
		t.Fatal("未变化轮次不应保留 prev")
	}
}

// post 失败回滚后，重试轮的"变化前"payload 必须还原为正确版本——
// 否则 diff(prev==cur) 为空，这次变更的事件会被吞掉。
func TestLastPayloadRollbackOnPostFailure(t *testing.T) {
	m := newTestManager()
	cur := []map[string]any{{"name": "a"}}
	m.Register("s", func() (any, error) { return cur, nil })

	m.Snapshot() // 首轮建基线且上报成功（payload 状态落定为 P1）

	cur = []map[string]any{{"name": "a"}, {"name": "b"}}
	sections, prev := m.collect() // 变化轮（P1 → P2）
	if len(sections) != 1 {
		t.Fatalf("变化轮应产出 1 节, got %d", len(sections))
	}
	m.restore(prev) // 模拟 post 失败回滚

	if _, ok := m.LastPayload("s"); ok {
		t.Fatal("回滚后不应保留变化前 payload")
	}

	// 重试轮：同一数据重新算差量，变化前 payload 应还原为建基线那份
	if sections, _ = m.collect(); len(sections) != 1 {
		t.Fatal("回滚后同一数据应重新产出差量")
	}
	p, ok := m.LastPayload("s")
	if !ok {
		t.Fatal("重试轮应能取到变化前 payload")
	}
	if !strings.Contains(p, `"name":"a"`) || strings.Contains(p, `"name":"b"`) {
		t.Fatalf("重试轮的变化前 payload 应是建基线那份, got %s", p)
	}
}

// Diff 拿 LastPayload 与当前 payload 正好能还原三类事件（机制层串联）。
func TestDiffWithLastPayloadRoundTrip(t *testing.T) {
	m := newTestManager()
	cur := []map[string]any{{"name": "a", "state": "running"}}
	m.Register("services", func() (any, error) { return cur, nil })
	m.Snapshot()

	cur = []map[string]any{{"name": "a", "state": "stopped"}}
	got := m.Snapshot()
	prevPayload, ok := m.LastPayload("services")
	if !ok {
		t.Fatal("应有变化前 payload")
	}
	evs, err := Diff(prevPayload, got[0].Payload, keyByName)
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	if len(evs) != 1 || evs[0].Kind != DiffChanged || evs[0].Key != "a" {
		t.Fatalf("应产出 changed/a, got %+v", evs)
	}
}
