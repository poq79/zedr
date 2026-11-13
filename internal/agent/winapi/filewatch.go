//go:build windows
// +build windows

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
	"zedr/internal/agent/nettypes"

	"golang.org/x/sys/windows"
)

var procReadDirectoryChangesW = modKernel32.NewProc("ReadDirectoryChangesW")

const (
	fileListDirectory         = 0x0001
	fileNotifyChangeFileName  = 0x0001
	fileNotifyChangeDirName   = 0x0002
	fileNotifyChangeSize      = 0x0008
	fileNotifyChangeLastWrite = 0x0010
	fileFlagBackupSemantics   = 0x02000000
	openExisting              = 3

	fileActionAdded      = 1
	fileActionRemoved    = 2
	fileActionModified   = 3
	fileActionRenamedOld = 4
	fileActionRenamedNew = 5
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

// FileEvent 是分发给 OnFileEvent 回调的单条目录变更。
//
// 语义约定（消费方必读）：
//   - 一次改名产生两条事件：renamed_old（只有旧路径）+ renamed（新路径，
//     OldPath 为同一次 parse 缓冲里配对到的旧路径）。做"批量改后缀"类
//     速率统计只用 renamed，把 renamed_old 也计进去会双重计数；
//   - 改名目标不在监控树内时只会收到 renamed_old，不会收到 renamed；
//   - RDCW 不携带时间戳，When 是 parse 时刻而非变更发生时刻（USN 路径
//     才有真实时间）；删掉重写同名文件时 RDCW 顺序不保证，事件流不做排序；
//   - 回调在 watchLoop goroutine 里同步触发（每个监控目录一个 goroutine），
//     消费方自保证线程安全；回调内可以查询 FileWatcher（互不持锁），
//     但不要做耗时操作——会拖住所有目录的事件流。
//
// FileEvent 是文件事件的跨平台形状（nettypes 单一事实源）。
// Windows 实现由 RDCW 生产；Linux 侧由 inotify 生产同形状数据。
type FileEvent = nettypes.FileEvent

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

	// onEvent 用 atomic.Pointer 存：StartFileWatcher 之后 goroutine 已在跑，
	// 回调可能随时被 SetOnFileEvent 替换（或置 nil 关闭分发），不能用普通字段。
	onEvent atomic.Pointer[func(FileEvent)]

	closed  atomic.Bool
	events  atomic.Int64
	dropped atomic.Int64
	// overflow 是 RDCW 缓冲溢出（丢整批）的诚实计数：溢出说明该目录
	// 的变更速率超过 64KB/批的缓冲设计，暴露给状态页供运维判断。
	overflow atomic.Int64
	watched  []string
}

// SetOnFileEvent 设置全量事件回调（含删除/改名旧名，不受落地扩展名过滤）。
// 可在 StartFileWatcher 之后随时调用；传 nil 关闭分发。回调的线程安全
// 由消费方保证（见 FileEvent 注释）。
func (w *FileWatcher) SetOnFileEvent(cb func(FileEvent)) {
	w.onEvent.Store(&cb)
}

// emit 触发回调。读指针后解引用两步走，避免"读到一半被替换"的撕裂：
// atomic.Pointer 保证 Store/Load 各自原子，指针指向的 func 值一旦写入不再变。
func (w *FileWatcher) emit(ev FileEvent) {
	if p := w.onEvent.Load(); p != nil && *p != nil {
		(*p)(ev)
	}
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
		// Documents 是勒索软件的加密主战场（诱饵也在此），此前只有
		// USN 30s 滞后覆盖——加入 RDCW 后删除/改名/落地全部实时。
		// 代价：用户批量整理文档会进勒索速率窗口（观察级 medium，
		// 与"可能是人工操作"的口径一致，可接受）。
		add(filepath.Join(up, "Documents"))
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

// AddDir 动态追加监控目录（可移动介质到达时挂卷根目录用）。
//
// 线程纪律：handles/watched 的追加与 Close 的关闭都要持 w.mu——此前
// Close 不持锁是因为目录集合启动后不变；动态追加后两者可能并发。
// watchLoop 退出条件不变（closed 或句柄失效）；卷被拔出时句柄失效，
// watchLoop 自动退出，调用方通过 WatchedDirs 对比感知并清理记录。
func (w *FileWatcher) AddDir(dir string) error {
	if w.closed.Load() {
		return fmt.Errorf("filewatcher 已关闭")
	}
	h, err := openDirForWatch(dir)
	if err != nil {
		return err
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, d := range w.watched {
		if strings.EqualFold(d, dir) {
			_ = syscall.CloseHandle(h)
			return fmt.Errorf("目录已在监控中: %s", dir)
		}
	}
	w.handles = append(w.handles, h)
	w.watched = append(w.watched, dir)
	w.wg.Add(1)
	go w.watchLoop(dir, h)
	return nil
}

// Events 返回已处理的落地事件数。
func (w *FileWatcher) Events() int64 { return w.events.Load() }

// Overflow 返回缓冲溢出（丢整批）次数。>0 说明有目录变更速率超设计，
// 事件存在空洞——诚实暴露而不是假装无损。
func (w *FileWatcher) Overflow() int64 { return w.overflow.Load() }

// Close 停止监控。
func (w *FileWatcher) Close() {
	if w.closed.Swap(true) {
		return
	}
	close(w.stop)
	// 关闭句柄会让阻塞中的 ReadDirectoryChangesW 立即返回。
	// 持 w.mu 与 AddDir 的追加互斥：动态追加（USB 到达）可能正在进行。
	w.mu.Lock()
	for _, h := range w.handles {
		_ = syscall.CloseHandle(h)
	}
	w.mu.Unlock()
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
		r, _, callErr := procReadDirectoryChangesW.Call(
			uintptr(h),
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(len(buf)),
			1, // 递归监控子目录
			fileNotifyChangeFileName|fileNotifyChangeDirName|
				fileNotifyChangeSize|fileNotifyChangeLastWrite,
			uintptr(unsafe.Pointer(&returned)),
			0, 0,
		)
		if r == 0 {
			// 缓冲溢出（ERROR_MORE_DATA=234）：单批变更超过 64KB 缓冲
			//（解压/npm install 会触发）。此前这里直接退出监控——目录
			// 监控从此静默死亡，是比"丢一批事件"严重得多的稳定性 bug
			//（Wazuh 同位置只 warn 继续）。丢当批 + 计数，监控保住。
			if callErr == windows.ERROR_MORE_DATA {
				w.overflow.Add(1)
				continue
			}
			// 句柄被关闭（Close）或目录不可访问：退出本目录的监控
			return
		}
		if returned == 0 {
			return
		}
		w.parse(dir, buf[:returned])
	}
}

// parse 解析 FILE_NOTIFY_INFORMATION 链表。
//
// 每条记录两路分发：record() 维持既有落地索引口径（interestingExt 过滤
// 不变）；OnFileEvent 回调收全量事件——诱饵文件是文档扩展名，若沿用落地
// 过滤会收不到删除事件，勒索检测就成了瞎子。rename 配对只在同一次 parse
// 的缓冲内做（RDCW 把一对改名通知放在同一缓冲里送达，跨缓冲视为旧名未知）。
func (w *FileWatcher) parse(dir string, buf []byte) {
	const hdr = 12 // NextEntryOffset(4) + Action(4) + FileNameLength(4)
	off := 0
	pendingOld := ""
	for off+hdr <= len(buf) {
		next := int(*(*uint32)(unsafe.Pointer(&buf[off])))
		action := *(*uint32)(unsafe.Pointer(&buf[off+4]))
		nameLen := int(*(*uint32)(unsafe.Pointer(&buf[off+8])))

		if nameLen > 0 && off+hdr+nameLen <= len(buf) {
			raw := buf[off+hdr : off+hdr+nameLen]
			if name, ok := decodeUTF16LEStrict(raw); ok {
				w.dispatch(action, filepath.Join(dir, decodePathSeparators(name)), &pendingOld)
			}
		}
		if next == 0 {
			return
		}
		off += next
	}
}

// dispatch 把一条 RDCW 通知分流到落地索引与全量事件回调。
// pendingOld 携带本次缓冲内上一个未配对的 RENAMED_OLD 路径（跨缓冲不配对）。
func (w *FileWatcher) dispatch(action uint32, full string, pendingOld *string) {
	switch action {
	case fileActionAdded:
		w.record(full)
		w.emit(FileEvent{Kind: "added", Path: full, When: time.Now()})
	case fileActionRemoved:
		w.emit(FileEvent{Kind: "removed", Path: full, When: time.Now()})
	case fileActionModified:
		w.record(full)
		w.emit(FileEvent{Kind: "modified", Path: full, When: time.Now()})
	case fileActionRenamedOld:
		*pendingOld = full
		// 旧名单独发一条：改名出监控树时后续不会有 renamed，消费方靠它兜底
		w.emit(FileEvent{Kind: "renamed_old", Path: full, When: time.Now()})
	case fileActionRenamedNew:
		old := *pendingOld
		*pendingOld = ""
		w.record(full)
		w.emit(FileEvent{Kind: "renamed", Path: full, OldPath: old, When: time.Now()})
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
