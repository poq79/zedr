// Package winapi 的文件落地监控。
//
// 检测价值：绝大多数入侵都有一个"文件被写进磁盘，随后被执行"的环节。
// 只看进程创建会丢掉前半段，导致无法区分"用户自己装的软件"和
// "样本刚落地就被拉起"——而后者是恶意行为最强的前置特征。
//
// 实现方式：对少量高价值目录挂 ReadDirectoryChangesW 订阅。
// 相比全盘轮询，它由内核在变更发生时通知，几乎零空转开销。
package winapi

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unicode/utf16"
	"unsafe"
)

var procReadDirectoryChangesW = modKernel32.NewProc("ReadDirectoryChangesW")

const (
	fileListDirectory = 0x0001
	fileNotifyChangeFileName   = 0x0001
	fileNotifyChangeDirName    = 0x0002
	fileNotifyChangeSize       = 0x0008
	fileNotifyChangeLastWrite  = 0x0010
	fileFlagBackupSemantics    = 0x02000000
	openExisting               = 3

	fileActionAdded       = 1
	fileActionRemoved     = 2
	fileActionModified    = 3
	fileActionRenamedOld  = 4
	fileActionRenamedNew  = 5
)

// dropKey 是淘汰队列里的一项。
// 带上时间戳是为了准确判断"这条记录是否已经被后来的写入覆盖"。
type dropKey struct {
	key  string
	when time.Time
}

// Drop 是一条文件落地记录。
type Drop struct {
	Path string
	Dir  string
	When time.Time
}

// interestingExt 是值得关注的落地文件类型：可执行、脚本、以及会被系统
// 自动执行的容器（.lnk/.reg/.msi）。普通文档不记录，避免噪声。
var interestingExt = map[string]bool{
	".exe": true, ".dll": true, ".sys": true, ".scr": true, ".com": true,
	".bat": true, ".cmd": true, ".ps1": true, ".psm1": true,
	".vbs": true, ".vbe": true, ".js": true, ".jse": true, ".wsf": true, ".hta": true,
	".lnk": true, ".reg": true, ".msi": true, ".cpl": true, ".pif": true,
	".jar": true, ".py": true, ".sh": true,
}

// FileWatcher 监控若干目录的文件落地事件。
type FileWatcher struct {
	mu     sync.Mutex
	recent map[string]Drop // 规范化完整路径 -> 记录
	byBase map[string]Drop // 小写文件名 -> 最近一条
	order  []dropKey
	// baseOrder 与 order 同构，专门给 byBase 做 FIFO 淘汰。
	// 此前 byBase 只增不减：每出现一个新文件名就永久占一个 map 槽，
	// 长时间运行 + USN 补采会把这个"兜底索引"变成慢性内存泄漏。
	baseOrder []dropKey
	max       int

	handles []syscall.Handle
	stop    chan struct{}
	wg      sync.WaitGroup

	closed   atomic.Bool
	events   atomic.Int64
	dropped  atomic.Int64
	watched  []string
}

// WatchDirs 返回默认需要监控的落地目录（已去重、只保留存在的）。
func WatchDirs() []string {
	var cands []string
	add := func(p string) {
		if p == "" {
			return
		}
		if _, err := os.Stat(p); err == nil {
			cands = append(cands, p)
		}
	}

	add(os.Getenv("TEMP"))
	if up := os.Getenv("USERPROFILE"); up != "" {
		add(filepath.Join(up, "Downloads"))
		add(filepath.Join(up, "Desktop"))
		add(filepath.Join(up, "AppData", "Roaming"))
	}
	add(os.Getenv("PUBLIC"))
	add(os.Getenv("ProgramData"))
	if ad := os.Getenv("APPDATA"); ad != "" {
		add(filepath.Join(ad, `Microsoft\Windows\Start Menu\Programs\Startup`))
	}
	if pd := os.Getenv("ProgramData"); pd != "" {
		add(filepath.Join(pd, `Microsoft\Windows\Start Menu\Programs\Startup`))
	}

	// 去重（大小写不敏感）后排序，保证日志稳定
	seen := make(map[string]struct{}, len(cands))
	out := cands[:0]
	for _, c := range cands {
		k := strings.ToLower(c)
		if _, dup := seen[k]; dup {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}

// StartFileWatcher 启动对指定目录的落地监控。
// 单个目录挂载失败不影响其它目录，最终若一个都没挂上则返回错误。
func StartFileWatcher(dirs []string) (*FileWatcher, error) {
	w := &FileWatcher{
		recent: make(map[string]Drop, 1024),
		byBase: make(map[string]Drop, 1024),
		max:    4096,
		stop:   make(chan struct{}),
	}

	for _, d := range dirs {
		h, err := openDirForWatch(d)
		if err != nil {
			continue // 权限不足等：跳过该目录
		}
		w.handles = append(w.handles, h)
		w.watched = append(w.watched, d)
		w.wg.Add(1)
		go w.watchLoop(d, h)
	}
	if len(w.handles) == 0 {
		return nil, fmt.Errorf("没有可监控的目录（全部打开失败）")
	}
	return w, nil
}

// WatchedDirs 返回实际挂上监控的目录。
func (w *FileWatcher) WatchedDirs() []string { return w.watched }

// Events 返回已处理的落地事件数。
func (w *FileWatcher) Events() int64 { return w.events.Load() }

// Close 停止监控。
func (w *FileWatcher) Close() {
	if w.closed.Swap(true) {
		return
	}
	close(w.stop)
	// 关闭句柄会让阻塞中的 ReadDirectoryChangesW 立即返回
	for _, h := range w.handles {
		_ = syscall.CloseHandle(h)
	}
	w.wg.Wait()
}

func openDirForWatch(dir string) (syscall.Handle, error) {
	p, err := syscall.UTF16PtrFromString(dir)
	if err != nil {
		return syscall.InvalidHandle, err
	}
	h, err := syscall.CreateFile(p,
		fileListDirectory,
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE,
		nil,
		openExisting,
		fileFlagBackupSemantics,
		0,
	)
	if err != nil {
		return syscall.InvalidHandle, err
	}
	return h, nil
}

func (w *FileWatcher) watchLoop(dir string, h syscall.Handle) {
	defer w.wg.Done()

	buf := make([]byte, 64*1024)
	for {
		if w.closed.Load() {
			return
		}
		var returned uint32
		r, _, _ := procReadDirectoryChangesW.Call(
			uintptr(h),
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(len(buf)),
			1, // 递归监控子目录
			fileNotifyChangeFileName|fileNotifyChangeDirName|
				fileNotifyChangeSize|fileNotifyChangeLastWrite,
			uintptr(unsafe.Pointer(&returned)),
			0, 0,
		)
		if r == 0 || returned == 0 {
			// 句柄被关闭（Close）或目录不可访问：退出本目录的监控
			return
		}
		w.parse(dir, buf[:returned])
	}
}

// parse 解析 FILE_NOTIFY_INFORMATION 链表。
func (w *FileWatcher) parse(dir string, buf []byte) {
	const hdr = 12 // NextEntryOffset(4) + Action(4) + FileNameLength(4)
	off := 0
	for off+hdr <= len(buf) {
		next := int(*(*uint32)(unsafe.Pointer(&buf[off])))
		action := *(*uint32)(unsafe.Pointer(&buf[off+4]))
		nameLen := int(*(*uint32)(unsafe.Pointer(&buf[off+8])))

		if nameLen > 0 && off+hdr+nameLen <= len(buf) {
			raw := buf[off+hdr : off+hdr+nameLen]
			if name, ok := decodeUTF16LEStrict(raw); ok {
				// 只关心"新增/改名/修改"，删除不计入落地
				if action == fileActionAdded || action == fileActionRenamedNew || action == fileActionModified {
					w.record(filepath.Join(dir, decodePathSeparators(name)))
				}
			}
		}
		if next == 0 {
			return
		}
		off += next
	}
}

func decodePathSeparators(s string) string {
	if strings.ContainsRune(s, '\\') {
		return s
	}
	return s
}

// record 登记一条落地记录（按扩展名过滤）。
func (w *FileWatcher) record(full string) {
	ext := strings.ToLower(filepath.Ext(full))
	if !interestingExt[ext] {
		return
	}

	d := Drop{Path: full, Dir: filepath.Dir(full), When: time.Now()}

	w.mu.Lock()
	defer w.mu.Unlock()

	norm := NormalizePath(full)
	w.recent[norm] = d
	baseKey := strings.ToLower(filepath.Base(full))
	w.byBase[baseKey] = d
	w.order = append(w.order, dropKey{key: norm, when: d.When})
	w.baseOrder = append(w.baseOrder, dropKey{key: baseKey, when: d.When})
	w.events.Add(1)

	// FIFO 淘汰，防止长时间运行内存无界增长。
	//
	// 淘汰必须比对时间戳：同一路径可能被反复写入（编译器、下载器、解包工具），
	// 早期条目被淘汰时如果直接按 key 删除，会把**最新**的那条记录一起删掉，
	// 于是"刚落地的文件"反而查不到——这个 bug 只在同名文件重复落地时才暴露，
	// 极难复现，但会让检测在最关键的时刻失效。
	if len(w.order) > w.max {
		drop := len(w.order) - w.max
		for i := 0; i < drop; i++ {
			e := w.order[i]
			if cur, ok := w.recent[e.key]; ok && cur.When.Equal(e.when) {
				delete(w.recent, e.key)
			}
		}
		w.order = append([]dropKey(nil), w.order[drop:]...)
	}
	if len(w.baseOrder) > w.max {
		drop := len(w.baseOrder) - w.max
		for i := 0; i < drop; i++ {
			e := w.baseOrder[i]
			if cur, ok := w.byBase[e.key]; ok && cur.When.Equal(e.when) {
				delete(w.byBase, e.key)
			}
		}
		w.baseOrder = append([]dropKey(nil), w.baseOrder[drop:]...)
	}
}

// RecordDropByBase 登记一条"只知道文件名"的落地记录。
//
// 用途：USN Journal 断点补采。USN 记录只有 leaf name（完整路径需要
// OpenFileById 提权遍历，成本不划算），因此这里只写 byBase 兜底索引，
// 与 existing "路径解析不完整"时的查询口径一致。时间来自 USN 记录，
// 不是补采时刻——否则停机数小时前的落地会被误判成"刚刚落地"。
func (w *FileWatcher) RecordDropByBase(name string, when time.Time) bool {
	if w == nil {
		return false
	}
	base := filepath.Base(strings.TrimSpace(name))
	if base == "" || base == "." || base == `\` {
		return false
	}
	if !interestingExt[strings.ToLower(filepath.Ext(base))] {
		return false
	}
	if when.IsZero() {
		when = time.Now()
	}
	d := Drop{Path: base, When: when}
	key := strings.ToLower(base)

	w.mu.Lock()
	defer w.mu.Unlock()
	w.byBase[key] = d
	w.baseOrder = append(w.baseOrder, dropKey{key: key, when: d.When})
	w.events.Add(1)
	if len(w.baseOrder) > w.max {
		drop := len(w.baseOrder) - w.max
		for i := 0; i < drop; i++ {
			e := w.baseOrder[i]
			if cur, ok := w.byBase[e.key]; ok && cur.When.Equal(e.when) {
				delete(w.byBase, e.key)
			}
		}
		w.baseOrder = append([]dropKey(nil), w.baseOrder[drop:]...)
	}
	return true
}

// RecentByPath 查询某路径是否在 within 时间内落地过。
func (w *FileWatcher) RecentByPath(path string, within time.Duration) (Drop, bool) {
	if w == nil || path == "" {
		return Drop{}, false
	}
	w.mu.Lock()
	defer w.mu.Unlock()

	d, ok := w.recent[NormalizePath(path)]
	if !ok || time.Since(d.When) > within {
		return Drop{}, false
	}
	return d, true
}

// RecentByBase 按文件名兜底查询（路径解析不完整时使用）。
func (w *FileWatcher) RecentByBase(base string, within time.Duration) (Drop, bool) {
	if w == nil || base == "" {
		return Drop{}, false
	}
	w.mu.Lock()
	defer w.mu.Unlock()

	d, ok := w.byBase[strings.ToLower(base)]
	if !ok || time.Since(d.When) > within {
		return Drop{}, false
	}
	return d, true
}

// Recent 先按完整路径查，查不到再按文件名兜底。
func (w *FileWatcher) Recent(path string, within time.Duration) (Drop, bool) {
	if d, ok := w.RecentByPath(path, within); ok {
		return d, true
	}
	return w.RecentByBase(filepath.Base(path), within)
}

// NormalizePath 把路径规范化为可比较形式：
// 去掉 \\?\ / \??\ 前缀与首尾空白，统一小写。
func NormalizePath(p string) string {
	s := strings.TrimSpace(p)
	for {
		switch {
		case strings.HasPrefix(s, `\\?\`):
			s = s[4:]
			continue
		case strings.HasPrefix(s, `\??\`):
			s = s[4:]
			continue
		}
		break
	}
	return strings.ToLower(strings.ReplaceAll(s, "/", `\`))
}

func decodeUTF16LEStrict(raw []byte) (string, bool) {
	if len(raw) < 2 || len(raw)%2 != 0 {
		return "", false
	}
	u := make([]uint16, 0, len(raw)/2)
	for i := 0; i+1 < len(raw); i += 2 {
		u = append(u, uint16(raw[i])|uint16(raw[i+1])<<8)
	}
	return string(utf16.Decode(u)), true
}
