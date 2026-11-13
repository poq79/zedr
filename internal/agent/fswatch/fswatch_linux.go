//go:build linux

// fswatch 的 Linux 实现：inotify 递归目录监控。
//
// 与 Windows RDCW 的结构差异：RDCW 单句柄递归整棵树；inotify 一个 watch
// 只覆盖"直接子项"，递归 = 初始 walk 全量挂 + 事件驱动补挂新目录。
//
// 关键实现决策（为什么这么写）：
//   - inotify fd 用 os.NewFile 包进 runtime poller：Read 走 netpoll 不占
//     死 OS 线程，且 Close 能立刻打断阻塞中的 Read（os.File 契约）——
//     比"裸 unix.Read 阻塞 + 另一 goroutine close"的写法安全，后者在
//     Linux 上 close 不保证唤醒阻塞中的 read，是经典悬挂；fsnotify
//     同款模式已在生产验证多年。
//   - 事件解析用 binary.NativeEndian：inotify 结构体字段是宿主字节序，
//     s390x 等 big-endian 平台不能硬编码 LittleEndian；记录可变长
//     （16 字节头 + Len 字节名字，Len 已含内核补的 4 字节对齐填充），
//     按 Len 步进，绝不能按固定 stride 切——那是 inotify 解析的经典错法。
//
// TODO(linux-实机)：上实机后需补验证——①事件真实到达与 Kind 映射抽样；
// ②新目录补挂的时序竞态实测；③高速变更下 IN_Q_OVERFLOW 计数；
// ④max_user_watches 配额下的 ENOSPC 行为。详见包注释的诚实边界。
package fswatch

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path"
	"path/filepath"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"zedr/internal/agent/nettypes"

	"golang.org/x/sys/unix"
)

// watchMask 是实际订阅的事件面，与 Windows RDCW 的
// FILE_NOTIFY_CHANGE_FILE_NAME|DIR_NAME|SIZE|LAST_WRITE 对齐：
//   - IN_CREATE / IN_DELETE ↔ 文件与目录的增删；
//   - IN_MODIFY ↔ LastWrite|Size（写入进行中即报，粒度与 RDCW 一致）；
//   - IN_CLOSE_WRITE ↔ 同一次写入的收尾：批内与 IN_MODIFY 去重后，兜住
//     "跨批次才 close 的长写"与 mmap 写盘（不产 IN_MODIFY）两个场景；
//   - IN_MOVED_FROM / IN_MOVED_TO ↔ RenamedOldName / RenamedNewName；
//   - IN_DELETE_SELF / IN_MOVE_SELF ↔ 监控根自身被删/改名（树管理用，
//     不产生文件事件）。
//
// 刻意不订阅：IN_OPEN / IN_ACCESS / IN_CLOSE_NOWRITE（纯噪声）、
// IN_ATTRIB（chmod/utimes——RDCW 无 ATTRIBUTES 对应物，订阅会让 touch
// 类元数据操作变成 modified，无谓抬高误报面）。
const watchMask = IN_CREATE | IN_DELETE | IN_MODIFY | IN_CLOSE_WRITE |
	IN_MOVED_FROM | IN_MOVED_TO | IN_DELETE_SELF | IN_MOVE_SELF

// readBufSize 单次 read 的事件缓冲，与 Windows RDCW 的 64KB 批缓冲同规格；
// 批次边界（一次 read）对应 Windows 的一次 parse，配对口径因此同级。
const readBufSize = 64 * 1024

// maxWatchPerWalk 单棵子树补挂 watch 的目录数上限。整目录移入监控树时
// 防止一棵巨树（mv /usr /tmp/x）打爆内核 watch 配额
// （fs.inotify.max_user_watches，典型 8192~65536），让后续 add 全部失败、
// 监控整体死亡。超限截断并 warn——部分覆盖好过全盘失明。
const maxWatchPerWalk = 2048

// Watch 递归监控若干目录的文件事件（Linux inotify）。
//
// 线程模型：单个事件循环 goroutine 承担 read/解析/分发/补挂 watch 的全部
// 工作（串行，无生产者竞争）；watches/byPath 只被它写，WatchedDirs 等
// 状态读侧用 mu 保护。回调用 atomic.Pointer 存（与 Windows FileWatcher
// 的 emit 同款两步解引用，防"读到一半被替换"的撕裂）。
type Watch struct {
	log *slog.Logger
	fd  int      // inotify fd（InotifyAddWatch 用）
	f   *os.File // 同一 fd 的 poller 包装；Close 打断阻塞中的 Read

	roots []string // Clean 去重后的监控根（DirsToWatch 的边界依据）

	mu      sync.Mutex
	watches map[int32]string // wd -> watch 目录路径（事件路径前缀的事实源）
	byPath  map[string]bool  // 路径 -> 已挂 watch（DirsToWatch 的 existing 快照源）

	onEvent atomic.Pointer[func(nettypes.FileEvent)]

	closed   atomic.Bool
	events   atomic.Int64
	overflow atomic.Int64
	wg       sync.WaitGroup
}

// New 创建监控器并启动事件循环；dirs 为监控根目录（会递归监控子目录）。
//
// 口径与 Windows 侧一致：单个目录不存在/无权限只 warn 跳过（canaryDirs
// 同款，不代建、不失败整体）；但一个都没挂上时返回错误——与
// winapi.StartFileWatcher 的"没有可监控的目录"口径相同，组合根必须
// 知道监控整体未生效，而不是拿着一个静默失明的监控器继续跑。
func New(dirs []string, log *slog.Logger) (*Watch, error) {
	if log == nil {
		log = slog.Default()
	}
	fd, err := unix.InotifyInit1(unix.IN_CLOEXEC)
	if err != nil {
		return nil, fmt.Errorf("fswatch: inotify_init1: %w", err)
	}
	w := &Watch{
		log:     log,
		fd:      fd,
		f:       os.NewFile(uintptr(fd), "inotify"),
		watches: make(map[int32]string, 64),
		byPath:  make(map[string]bool, 64),
	}

	// 根目录 Clean+去重：重复根会重复 walk；Clean 让 byPath 与
	// DirsToWatch 的 key 口径完全一致，避免 "/tmp/" 与 "/tmp" 各挂一份。
	seen := make(map[string]bool, len(dirs))
	for _, d := range dirs {
		c := filepath.Clean(d)
		if c == "" || c == "." || seen[c] {
			continue
		}
		seen[c] = true
		w.roots = append(w.roots, c)
	}

	mounted := 0
	for _, r := range w.roots {
		if w.addSubtree(r) {
			mounted++
		}
	}
	if mounted == 0 {
		_ = w.f.Close()
		return nil, fmt.Errorf("fswatch: 没有可监控的目录（全部挂载失败）")
	}

	w.wg.Add(1)
	go w.loop()
	return w, nil
}

// SetOnFileEvent 设置全量事件回调（含删除/改名旧名，不受落地扩展名过滤）。
// New 之后随时可调（事件流开始前设置即不丢首批事件）；传 nil 关闭分发。
// 回调在事件循环 goroutine 里同步触发，消费方不要在回调里做耗时操作
// （会拖住所有目录的事件流），也不要在回调里调 Close——wg.Wait 会等
// 本 goroutine，死锁。
func (w *Watch) SetOnFileEvent(fn func(nettypes.FileEvent)) {
	w.onEvent.Store(&fn)
}

// emit 触发回调，与 Windows FileWatcher.emit 同款两步解引用防撕裂：
// atomic.Pointer 保证 Store/Load 各自原子，指针指向的 func 值一旦写入不再变。
func (w *Watch) emit(ev nettypes.FileEvent) {
	if p := w.onEvent.Load(); p != nil && *p != nil {
		(*p)(ev)
	}
}

// WatchedDirs 返回当前实际挂上 watch 的目录（排序后，日志/状态页稳定）。
// 同一 inode 的别名路径（bind mount）只报先挂的那条——事件前缀的事实源。
func (w *Watch) WatchedDirs() []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := make([]string, 0, len(w.watches))
	for _, p := range w.watches {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// Events 返回已分发的文件事件数。
func (w *Watch) Events() int64 { return w.events.Load() }

// Overflow 返回内核事件队列溢出（IN_Q_OVERFLOW）次数。>0 说明变更速率
// 超过内核队列设计，事件流有洞——与 Windows RDCW 的 ERROR_MORE_DATA
// 计数同口径，诚实暴露而不是假装无损。
func (w *Watch) Overflow() int64 { return w.overflow.Load() }

// Close 停止事件循环并关闭所有 watch。
//
// inotify 模型是"单 fd 承载全部 watch"，关 fd 即全部撤销（内核随之清理，
// 无需逐个 InotifyRmWatch）。顺序纪律：先置 closed 再关文件——os.File
// 的 Close 会打断阻塞中的 Read（ErrClosed），循环退出后 wg.Wait 保证
// Close 返回时回调不再被触发；fd 归还与 Read 永不并发。
// 错误恒为 nil：签名保留 error 与组合根契约对齐。
func (w *Watch) Close() error {
	if w.closed.Swap(true) {
		return nil
	}
	_ = w.f.Close()
	w.wg.Wait()
	return nil
}

// loop 是唯一的事件循环 goroutine：read→解析→分发→补挂全部串行，回调
// 因此天然单线程（契约里"回调在事件循环 goroutine 触发"的依据）。
// 阻塞读走 runtime poller（os.NewFile 包装）：不占死 OS 线程，且 Close
// 能立刻打断阻塞中的 Read——这是不引入自唤醒管道的前提。
func (w *Watch) loop() {
	defer w.wg.Done()
	buf := make([]byte, readBufSize)
	for {
		n, err := w.f.Read(buf)
		if err != nil {
			if w.closed.Load() || errors.Is(err, os.ErrClosed) {
				return // Close 打断的正常退出路径
			}
			// 非关闭读失败：本循环死亡。与 Windows watchLoop 句柄失效
			// 退出的口径一致——记 warn 让死亡可见，不静默吞。
			w.log.Warn("fswatch_read_failed", "err", err.Error())
			return
		}
		if n > 0 {
			w.handleBatch(buf[:n])
		}
	}
}

// handleBatch 解析一次 read 的原始字节流并分发。解析纪律：事件记录可变长
// （16 字节头 + Len 字节名字，Len 已含内核补的 4 字节对齐填充），必须按
// Len 步进——按固定 stride 切，事件流一交错就把后面全部解歪。
func (w *Watch) handleBatch(buf []byte) {
	var (
		batch   []EventSpec
		newDirs []string
	)
	off := 0
	for off+unix.SizeofInotifyEvent <= len(buf) {
		wd := int32(binary.NativeEndian.Uint32(buf[off:]))
		mask := binary.NativeEndian.Uint32(buf[off+4:])
		cookie := binary.NativeEndian.Uint32(buf[off+8:])
		nameLen := int(binary.NativeEndian.Uint32(buf[off+12:]))
		end := off + unix.SizeofInotifyEvent + nameLen
		if nameLen < 0 || end > len(buf) {
			// 内核保证单次 read 返回完整事件序列，到这里说明缓冲异常。
			// 丢弃残包并 warn——把残包当事件解析会产生幽灵路径。
			w.log.Warn("fswatch_truncated_event", "offset", off, "batch_len", len(buf))
			break
		}

		switch {
		case mask&IN_Q_OVERFLOW != 0:
			// wd=-1、无名字。与 Windows ERROR_MORE_DATA 同级的诚实计数：
			// 溢出意味着事件流有洞，状态页要看得见。
			w.overflow.Add(1)
		case mask&IN_IGNORED != 0:
			// watch 已被内核移除（目录删除/卸载/配额回收）。立即清理映射：
			// wd 会被内核复用，留着旧路径前缀会让后来的事件张冠李戴。
			w.removeWatch(wd)
		default:
			dir := w.dirOf(wd)
			if dir == "" {
				break // 未知 wd：不产生路径就不产生事件（防御）
			}
			if mask&IN_DELETE_SELF != 0 {
				// 监控中的目录自身被删。watch 即刻失效（内核随后补 IGNORED，
				// remove 幂等）；warn 让"该子树从此失明"可见——与 Windows
				// 侧 watchLoop 句柄失效退出的可见性口径一致。
				w.log.Warn("fswatch_dir_deleted", "dir", dir)
				w.removeWatch(wd)
				break
			}
			if mask&IN_MOVE_SELF != 0 {
				// 监控根被改名：watch 仍有效，事件继续但路径前缀失真——
				// 与 Windows 侧"改名监控根后按旧前缀上报"行为一致，刻意
				// 保留 watch。摘掉 byPath 是为了停掉"往失真前缀下补挂
				// watch"的徒劳尝试（内核只会返回 ENOENT）。
				w.dropByPath(dir)
				break
			}
			if nameLen == 0 {
				break // 带内容的事件必有名字；无名即异常，防御性跳过
			}
			raw := buf[off+unix.SizeofInotifyEvent : end]
			if i := bytes.IndexByte(raw, 0); i >= 0 {
				raw = raw[:i] // 名字 NUL 填充（Len 含填充），只取第一个串
			}
			name := string(raw)
			if name == "" {
				break
			}
			batch = append(batch, EventSpec{Dir: dir, Name: name, Mask: mask, Cookie: cookie})
			// 目录创建/移入：事件驱动的递归监控。inotify 不递归，这是与
			// RDCW 单句柄最大的结构差异，也是补挂逻辑的触发点。
			if mask&IN_ISDIR != 0 && mask&(IN_CREATE|IN_MOVED_TO) != 0 {
				newDirs = append(newDirs, path.Join(dir, name))
			}
		}
		off = end
	}

	if len(batch) > 0 {
		out := MapBatch(batch, time.Now())
		if len(out) > 0 {
			w.events.Add(int64(len(out)))
			for _, ev := range out {
				w.emit(ev)
			}
		}
	}
	// 补挂放在分发之后：先让消费方看到"目录 added"，再展开子树——事件
	// 顺序（目录出现 → 子项事件）与真实发生顺序一致。已知盲区：补挂生效
	// 前落进新目录的事件会漏（inotify 结构性 TOCTOU，见包注释）。
	for _, nd := range newDirs {
		for _, seed := range DirsToWatch(w.pathSet(), w.roots, nd, true) {
			w.addSubtree(seed)
		}
	}
}

// addSubtree 递归挂 watch 到 root 及其全部子目录。不跟随符号链接
// （WalkDir 对 symlink 的 IsDir 为 false）：防环、不出监控树。
// 返回是否有任何 watch 覆盖。
func (w *Watch) addSubtree(root string) bool {
	added := 0
	truncated := false
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // 不可读的子树跳过：部分覆盖优先于整体失败
		}
		if !d.IsDir() {
			return nil
		}
		if w.hasWatch(p) {
			return nil
		}
		if added >= maxWatchPerWalk {
			truncated = true
			return fs.SkipAll
		}
		if w.addWatch(p) {
			added++
		}
		return nil
	})
	if truncated {
		w.log.Warn("fswatch_walk_truncated", "root", root, "limit", maxWatchPerWalk)
	}
	return added > 0
}

// addWatch 给单个目录挂 inotify watch，登记 wd→路径映射。返回是否已覆盖。
func (w *Watch) addWatch(p string) bool {
	wd, err := unix.InotifyAddWatch(w.fd, p, watchMask)
	if err != nil {
		if errors.Is(err, unix.ENOSPC) {
			// watch 配额耗尽：不杀循环（其它目录还能挂就继续），缺口记
			// 日志——诚实暴露比静默丢失好，运维可调 max_user_watches。
			w.log.Warn("fswatch_watch_quota", "path", p,
				"hint", "fs.inotify.max_user_watches")
		} else {
			w.log.Warn("fswatch_add_watch_failed", "path", p, "err", err.Error())
		}
		return false
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if prev, dup := w.watches[int32(wd)]; dup && prev != p {
		// 同一 inode 经两条路径挂 watch（bind mount/目录硬链接场景）：
		// 内核返回同一个 wd（只更新 mask）。保留先挂的路径前缀——事件
		// 将以此上报，两条路径互相冒名比只认一条更糟；后来的路径登记
		// byPath 防止反复重挂。
		w.log.Warn("fswatch_watch_alias", "existing", prev, "path", p)
		w.byPath[p] = true
		return true
	}
	w.watches[int32(wd)] = p
	w.byPath[p] = true
	return true
}

// removeWatch 清掉 wd 的双向映射（IGNORED/DELETE_SELF 路径）。
func (w *Watch) removeWatch(wd int32) {
	w.mu.Lock()
	defer w.mu.Unlock()
	p, ok := w.watches[wd]
	if !ok {
		return
	}
	delete(w.watches, wd)
	delete(w.byPath, p)
}

// dropByPath 只摘路径索引、保留 wd 映射：MOVE_SELF 后事件仍以旧前缀送达
// （watch 有效，前缀是既成事实），但不再把它当"可补挂的现存目录"。
func (w *Watch) dropByPath(p string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	delete(w.byPath, p)
}

func (w *Watch) dirOf(wd int32) string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.watches[wd]
}

func (w *Watch) hasWatch(p string) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.byPath[p]
}

// pathSet 返回已挂路径集合的快照，作为 DirsToWatch 的 existing 入参。
// 传快照而不是直接引用：DirsToWatch 是导出纯函数，不应与内部锁纠缠。
func (w *Watch) pathSet() map[string]bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := make(map[string]bool, len(w.byPath))
	for k := range w.byPath {
		out[k] = true
	}
	return out
}
