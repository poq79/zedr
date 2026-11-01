package persist

import (
	"sort"
	"strings"
)

// Item 是持久化基线条目的对外只读快照（值拷贝，不暴露内部 map 引用）。
type Item struct {
	// Key 是基线主键（"type|location|name" 形态，跨采集周期稳定）。
	Key string
	// Kind 是持久化类型（winapi.Persist* 常量）。老基线缺 type 列时
	// 从 key 首段兜底解析。
	Kind string
	// Location 是注册表路径 / 目录 / 任务路径；老基线缺列时为空。
	Location string
	// Value 是命令行或镜像路径。
	Value string
}

// Items 返回当前基线里的全部持久化条目（7 类自启动位置），按 Key 升序。
//
// 供 inventory 的 startup 节组装快照 payload；返回的是值拷贝，调用方
// 修改返回切片不会影响监控器内部状态。基线为空（干净机器或首轮扫描前）
// 返回空切片——对调用方这是正常情况，不是错误。
func (m *Monitor) Items() []Item {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Item, 0, len(m.items))
	for key, r := range m.items {
		kind := r.Type
		if kind == "" {
			// 老版本基线没有 type 列：winapi 侧所有 PersistItem.Key 都是
			// "type|rest" 形态，key 首段即类型，兜底解析保持老基线可用。
			if i := strings.IndexByte(key, '|'); i > 0 {
				kind = key[:i]
			}
		}
		out = append(out, Item{Key: key, Kind: kind, Location: r.Location, Value: r.Command})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}
