// Package allow 实现五级降噪流水线的第一级：白名单。
//
// 命中白名单的进程根本不进入检测引擎，从源头消除噪声。
// 白名单有两个来源：服务端下发的全局列表，以及本机运维人员手工添加的本地列表。
package allow

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Entry 是一条白名单。
type Entry struct {
	Type      string    `json:"type"`
	Value     string    `json:"value"`
	Note      string    `json:"note,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	Source    string    `json:"source"` // server | local
}

// List 是白名单集合。
type List struct {
	mu  sync.RWMutex
	set map[string]map[string]struct{} // type -> values

	local     []Entry
	localPath string
	hits      int64
	// entryMu 保护 entryHits（独立小锁）：Match 持 RLock 做集合查找
	// 热路径，不能为了计数升级成写锁；计数只进独立锁。
	entryMu   sync.Mutex
	entryHits map[string]int64 // "type:value" → 次数（本次运行期）
}

// 支持的白名单类型
const (
	TypeHash    = "hash"
	TypePath    = "path"
	TypeSigner  = "signer"
	TypePair    = "pair"    // parent.exe>child.exe
	TypeCmdLine = "cmdline" // 命令行包含片段
)

// New 创建白名单。
func New(localPath string) *List {
	l := &List{
		set:       make(map[string]map[string]struct{}, 5),
		localPath: localPath,
	}
	for _, t := range []string{TypeHash, TypePath, TypeSigner, TypePair, TypeCmdLine} {
		l.set[t] = make(map[string]struct{})
	}
	l.loadLocal()
	return l
}

// ReplaceServer 用服务端下发的列表覆盖"服务端来源"部分（本地条目保留）。
func (l *List) ReplaceServer(entries []Entry) {
	l.mu.Lock()
	defer l.mu.Unlock()

	for _, t := range []string{TypeHash, TypePath, TypeSigner, TypePair, TypeCmdLine} {
		l.set[t] = make(map[string]struct{})
	}
	for _, e := range l.local {
		l.set[e.Type][strings.ToLower(e.Value)] = struct{}{}
	}
	for _, e := range entries {
		if _, ok := l.set[e.Type]; !ok {
			continue
		}
		l.set[e.Type][strings.ToLower(strings.TrimSpace(e.Value))] = struct{}{}
	}
}

// EnsureLocal 幂等地加入一条本地白名单（已存在则跳过，不产生重复条目）。
//
// 用于程序自身安装目录/数据目录的自豁免：安全产品不应把自己的二进制当成可疑对象。
func (l *List) EnsureLocal(typ, value, note string) error {
	if _, ok := l.set[typ]; !ok {
		return os.ErrInvalid
	}
	key := strings.ToLower(value)

	l.mu.Lock()
	if _, exists := l.set[typ][key]; exists {
		l.mu.Unlock()
		return nil
	}
	l.set[typ][key] = struct{}{}
	l.local = append(l.local, Entry{
		Type: typ, Value: key, Note: note,
		CreatedAt: time.Now(), Source: "local",
	})
	local := append([]Entry(nil), l.local...)
	path := l.localPath
	l.mu.Unlock()

	return persist(path, local)
}

// AddLocal 追加一条本地白名单并落盘。
func (l *List) AddLocal(typ, value, note string) error {
	if _, ok := l.set[typ]; !ok {
		return os.ErrInvalid
	}
	l.mu.Lock()
	l.set[typ][strings.ToLower(value)] = struct{}{}
	l.local = append(l.local, Entry{
		Type: typ, Value: strings.ToLower(value), Note: note,
		CreatedAt: time.Now(), Source: "local",
	})
	local := append([]Entry(nil), l.local...)
	path := l.localPath
	l.mu.Unlock()

	return persist(path, local)
}

// RemoveLocal 删除一条本地白名单。
func (l *List) RemoveLocal(typ, value string) error {
	l.mu.Lock()
	kept := make([]Entry, 0, len(l.local))
	removed := false
	for _, e := range l.local {
		if e.Type == typ && strings.EqualFold(e.Value, value) {
			removed = true
			continue
		}
		kept = append(kept, e)
	}
	if !removed {
		l.mu.Unlock()
		return os.ErrNotExist
	}
	l.local = kept
	delete(l.set[typ], strings.ToLower(value))
	path := l.localPath
	l.mu.Unlock()

	return persist(path, kept)
}

// Local 返回本地白名单副本。
func (l *List) Local() []Entry {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return append([]Entry(nil), l.local...)
}

// Size 返回各类型条目数。
func (l *List) Size() map[string]int {
	l.mu.RLock()
	defer l.mu.RUnlock()
	out := make(map[string]int, len(l.set))
	for k, v := range l.set {
		out[k] = len(v)
	}
	return out
}

// Hits 返回累计命中次数。
func (l *List) Hits() int64 {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.hits
}

// EntryHitsSnapshot 返回按条目的命中快照与是否应上报。
// 列表非空就上报（哪怕全 0）：条目删除后服务端残留行要靠
// "整包替换"语义清理。
func (l *List) EntryHitsSnapshot() (map[string]int64, bool) {
	l.mu.RLock()
	nonEmpty := false
	for _, m := range l.set {
		if len(m) > 0 {
			nonEmpty = true
			break
		}
	}
	l.mu.RUnlock()

	l.entryMu.Lock()
	hits := len(l.entryHits)
	l.entryMu.Unlock()
	if !nonEmpty && hits == 0 {
		return nil, false
	}

	l.entryMu.Lock()
	out := make(map[string]int64, len(l.entryHits))
	for k, n := range l.entryHits {
		out[k] = n
	}
	l.entryMu.Unlock()
	return out, true
}

func (l *List) countEntry(typ, value string) {
	key := typ + ":" + strings.ToLower(value)
	l.entryMu.Lock()
	if l.entryHits == nil {
		l.entryHits = make(map[string]int64, 8)
	}
	l.entryHits[key]++
	l.entryMu.Unlock()
	l.hits++
}

// Match 判断进程是否被白名单豁免，返回命中的类型。
func (l *List) Match(hash, path, signer, parentName, procName, cmdline string) (bool, string) {
	l.mu.RLock()
	defer l.mu.RUnlock()

	if hash != "" {
		if _, ok := l.set[TypeHash][strings.ToLower(hash)]; ok {
			l.countEntry(TypeHash, hash)
			return true, TypeHash
		}
	}

	lp := strings.ToLower(path)
	if lp != "" {
		for v := range l.set[TypePath] {
			if v != "" && (lp == v || strings.HasPrefix(lp, v+`\`) || strings.Contains(lp, v)) {
				l.countEntry(TypePath, v)
				return true, TypePath
			}
		}
	}

	if signer != "" {
		if _, ok := l.set[TypeSigner][strings.ToLower(signer)]; ok {
			l.countEntry(TypeSigner, signer)
			return true, TypeSigner
		}
	}

	pair := strings.ToLower(parentName) + ">" + strings.ToLower(procName)
	if _, ok := l.set[TypePair][pair]; ok {
		l.countEntry(TypePair, pair)
		return true, TypePair
	}

	if cmdline != "" {
		lc := strings.ToLower(cmdline)
		for v := range l.set[TypeCmdLine] {
			if v != "" && strings.Contains(lc, v) {
				l.countEntry(TypeCmdLine, v)
				return true, TypeCmdLine
			}
		}
	}
	return false, ""
}

func (l *List) loadLocal() {
	if l.localPath == "" {
		return
	}
	raw, err := os.ReadFile(l.localPath)
	if err != nil {
		return
	}
	var entries []Entry
	if err := json.Unmarshal(raw, &entries); err != nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, e := range entries {
		if _, ok := l.set[e.Type]; !ok {
			continue
		}
		e.Source = "local"
		l.local = append(l.local, e)
		l.set[e.Type][strings.ToLower(e.Value)] = struct{}{}
	}
}

func persist(path string, entries []Entry) error {
	if path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o640); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
