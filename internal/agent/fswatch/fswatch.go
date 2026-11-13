// Package fswatch 是 Linux 文件落地监控（inotify），产出与 Windows 侧
// winapi.FileWatcher（ReadDirectoryChangesW）语义一致的 nettypes.FileEvent。
//
// 【诚实边界，2026-11-14】本包未在 Linux 实机验证——当前开发环境只有
// Windows。验证口径为三条：
//  1. GOOS=linux 交叉编译 + go vet 通过（系统调用层编译期正确）；
//  2. 事件映射 / 改名配对 / 目录树计算全部收在本文件的纯逻辑里，
//     单测在 Windows 上跑绿（语义层正确）；
//  3. 系统调用与时序行为（事件到达、watch 生效时机）按内核手册实现，
//     尚未实机回放——上 Linux 实机后需补真实事件验证。
//
// 与 Windows RDCW 的语义对齐表（消费方必读，Kind 定义见 nettypes.FileEvent）：
//
//	RDCW action   ↔ inotify 来源
//	added         ← IN_CREATE；未配对的 IN_MOVED_TO 同映射（移入监控树=新出现）
//	removed       ← IN_DELETE
//	modified      ← IN_MODIFY；同批次紧随的 IN_CLOSE_WRITE 去重不重报
//	renamed_old   ← IN_MOVED_FROM（恒发，含配对成功的情况，RDCW 同口径）
//	renamed       ← IN_MOVED_TO 与同批 cookie 配对成功，OldPath=旧路径
//
// 改名配对与 Windows parse 同口径：只认同一次 read 批次（RDCW 是同一
// parse 缓冲），跨批次视为旧名未知。
//
// 与 Windows 侧的结构性差异 / 已知盲区（inotify 带来，必须诚实面对）：
//   - inotify 没有递归语义：递归 = 初始 walk 逐目录挂 watch + 事件驱动
//     补挂新目录。目录创建到 watch 生效之间落在该目录里的事件会漏
//     （TOCTOU 固有盲区，与 AGENTS §5.3 短命进程同类）；Windows 单句柄
//     递归无此窗口。
//   - 整目录移入监控树时，既有子树靠 walk 补挂，超上限部分不覆盖
//     （见 fswatch_linux.go 的 maxWatchPerWalk）。
//   - mmap 写盘不产生 IN_MODIFY；首次出现仍有 IN_CREATE，但对已有文件
//     的纯 mmap 修改不可见（IN_CLOSE_WRITE 兜住"close 收尾"的那部分）。
//   - 监控根自身被改名（IN_MOVE_SELF）：watch 仍有效但路径前缀失真——
//     与 Windows 侧"改名监控根后 RDCW 按旧前缀上报"行为一致，刻意保留。
//   - 符号链接不跟随（walk 不进 symlink 目录）：防环、不出监控树。
//
// 本文件刻意不写 //go:build：它是"neutral"层，只含常量数值、mask→Kind
// 映射、配对器与目录树计算，不触碰任何系统调用，因此在 Windows 上参与
// 编译与单测。路径拼接用 path（POSIX）而非 filepath——Linux 路径语义
// 是本包的定义域，这样 Windows 上跑单测才能得到与 Linux 一致的结果。
package fswatch

import (
	"path"
	"strings"
	"time"

	"zedr/internal/agent/nettypes"
)

// inotify 事件 mask 位（内核 ABI，include/uapi/linux/inotify.h；与
// x/sys/unix 同值）。放在 neutral 文件是为了 KindFromMask/MapBatch/
// fswatch_linux/测试四处共享同一套数值——linux 实现文件只管系统调用，
// 不做数值翻译，避免"两边各写一份常量"漂移。
// 刻意不订阅的噪声位（IN_OPEN/IN_ACCESS/IN_CLOSE_NOWRITE/IN_ATTRIB）
// 也在此定义，供测试与"订阅面为什么是这个"的注释引用。
const (
	IN_ACCESS        = 0x00000001
	IN_MODIFY        = 0x00000002
	IN_ATTRIB        = 0x00000004
	IN_CLOSE_WRITE   = 0x00000008
	IN_CLOSE_NOWRITE = 0x00000010
	IN_OPEN          = 0x00000020
	IN_MOVED_FROM    = 0x00000040
	IN_MOVED_TO      = 0x00000080
	IN_CREATE        = 0x00000100
	IN_DELETE        = 0x00000200
	IN_DELETE_SELF   = 0x00000400
	IN_MOVE_SELF     = 0x00000800
	IN_UNMOUNT       = 0x00002000
	IN_Q_OVERFLOW    = 0x00004000
	IN_IGNORED       = 0x00008000
	IN_ISDIR         = 0x40000000
)

// KindFromMask 把 inotify mask 映射为与 Windows RDCW 对齐的 Kind 字符串。
// 返回空串表示不产生文件事件（内核管理事件 / 未订阅噪声位），调用方直接丢弃。
//
// 判定顺序的讲究：
//   - IN_MOVED_TO 未配对时缺省 added（移入监控树 = 新文件出现）；配对
//     成功的 renamed 由 MapBatch 覆盖——本函数看不到批内上下文，只给缺省；
//   - IN_ISDIR 是修饰位：目录的创建/删除/改名同样映射 added/removed/
//     renamed_old（RDCW 的 FILE_NOTIFY_CHANGE_DIR_NAME 同口径），不单独成 Kind；
//   - IN_MODIFY 与 IN_CLOSE_WRITE 同映射 modified：两者是同一次写入的
//     不同阶段（进行中/收尾），同批内的去重由 MapBatch 负责，避免一次
//     写入双报抬高速率类检测的计数。
func KindFromMask(mask uint32) string {
	switch {
	case mask&IN_MOVED_FROM != 0:
		return "renamed_old"
	case mask&IN_MOVED_TO != 0:
		return "added"
	case mask&IN_CREATE != 0:
		return "added"
	case mask&IN_DELETE != 0:
		return "removed"
	case mask&IN_MODIFY != 0, mask&IN_CLOSE_WRITE != 0:
		return "modified"
	default:
		// IN_Q_OVERFLOW/IN_IGNORED/IN_DELETE_SELF/IN_MOVE_SELF/IN_UNMOUNT
		// 是内核与树管理事件（溢出计数、wd 清理在 linux 实现文件做）；
		// IN_OPEN/IN_ACCESS/IN_CLOSE_NOWRITE/IN_ATTRIB 是未订阅噪声位。
		return ""
	}
}

// EventSpec 是事件映射纯逻辑的最小输入面：linux 实现文件把解析出的
// unix.InotifyEvent 填成它，测试直接手工构造它——配对语义因此在
// Windows 上可测，不依赖任何系统调用。
type EventSpec struct {
	Dir    string // 事件所属 watch 目录（wd 对应的监控路径，事件路径前缀）
	Name   string // 内核给的相对名（NUL 已截断）；无名事件不入批
	Mask   uint32
	Cookie uint32 // 改名配对键：MOVED_FROM/MOVED_TO 同一次改名同 cookie
}

// MapBatch 把一次 read 解出的一批 inotify 事件映射为跨平台 FileEvent 流。
// 批次边界 = 一次 read 返回，与 Windows parse 缓冲同层级。
//
// 配对口径（与 Windows dispatch 的"同缓冲配对、跨缓冲视为旧名未知"逐条
// 对齐），三种结局：
//   - FROM+TO 同批同 cookie：renamed_old + renamed（OldPath=旧路径）——
//     renamed_old 恒发，消费方做速率统计只用 renamed，两条都计会双重计数；
//   - 只有 FROM（移出监控树，或 TO 落在下一批）：只有 renamed_old；
//   - 只有 TO（移入监控树）：added（无 OldPath）。
//
// 另做批内 modified 去重：同批已按 IN_MODIFY 报过 modified 的路径，紧随
// 的 IN_CLOSE_WRITE 不再重复报（一次 write+close 只算一次变更）。跨批次
// 不去重——RDCW 对持续写入的 LastWrite 同样会重复报，保持同噪声量级；
// 且不为它引入需要 (key, timestamp) 淘汰纪律的跨批状态（AGENTS §5.3：
// 同路径反复写入时按 key 直接删会误删最新记录——这里压根不建持久索引，
// 去重集随批次消亡，无淘汰问题）。
func MapBatch(batch []EventSpec, now time.Time) []nettypes.FileEvent {
	if len(batch) == 0 {
		return nil
	}
	pending := make(map[uint32]string, 4) // cookie -> 旧路径（本批内有效）
	modified := make(map[string]bool, 4)  // 本批内已报过 modified 的完整路径
	out := make([]nettypes.FileEvent, 0, len(batch))
	for _, e := range batch {
		if e.Name == "" {
			continue // 无名事件（Q_OVERFLOW/DELETE_SELF 等）不产生文件事件
		}
		full := path.Join(e.Dir, e.Name)
		switch {
		case e.Mask&IN_MOVED_FROM != 0:
			pending[e.Cookie] = full
			out = append(out, nettypes.FileEvent{Kind: "renamed_old", Path: full, When: now})
		case e.Mask&IN_MOVED_TO != 0:
			if old, ok := pending[e.Cookie]; ok {
				delete(pending, e.Cookie)
				out = append(out, nettypes.FileEvent{Kind: "renamed", Path: full, OldPath: old, When: now})
			} else {
				out = append(out, nettypes.FileEvent{Kind: "added", Path: full, When: now})
			}
		case e.Mask&IN_CLOSE_WRITE != 0 && modified[full]:
			// 同批 MODIFY 已报过这条路径的 modified，close 收尾不重复计
		default:
			kind := KindFromMask(e.Mask)
			if kind == "" {
				continue
			}
			if kind == "modified" {
				modified[full] = true
			}
			out = append(out, nettypes.FileEvent{Kind: kind, Path: full, When: now})
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// DirsToWatch 计算一条目录事件之后需要新挂 inotify watch 的种子路径。
// 这是"事件驱动递归监控"的判定核心：inotify 一个 watch 只覆盖直接子项，
// 新目录出现时必须显式补挂，监控树才能随文件系统生长。
//
// 参数：
//   - existing：当前已挂 watch 的路径集合（linux 实现传 byPath 快照，
//     key 与本函数内部的 Clean 规范化一致）；
//   - rootDirs：配置的监控根（与 New 入参同口径）；
//   - eventPath：本次事件的完整路径（watch 目录 + 相对名）；
//   - isDir：该事件是否目录（mask 含 IN_ISDIR）。
//
// 返回 nil = 无需动作：非目录、已在监控中、不在任何监控根之下（含监控根
// 被改名后失真前缀的衍生事件）都不补挂。返回值至多一个元素——种子本身；
// 种子若带着既有子树（整目录移入），子树展开由调用方 walk 完成（需要 IO，
// 本函数保持纯逻辑可测）。
func DirsToWatch(existing map[string]bool, rootDirs []string, eventPath string, isDir bool) []string {
	if !isDir {
		return nil
	}
	p := path.Clean(eventPath)
	if p == "" || p == "." || p == ".." {
		return nil
	}
	if existing[p] {
		return nil
	}
	if !underAnyRoot(p, rootDirs) {
		return nil
	}
	return []string{p}
}

// underAnyRoot 判断 p 是否落在某个监控根之内（含根自身）。
// 前缀比较必须带分隔符边界：监控根 /tmp 不能吞掉 /tmpfoo——给根拼上
// 分隔符再比较；根为顶层 "/" 时单独放行（拼出来会变成伪前缀 "//"）。
// 分隔符写死 "/"：本包是 Linux 路径定义域（path 包没有 Separator 常量，
// filepath.Separator 在 Windows 单测里是 "\\"，会让纯逻辑测试随平台变形）。
func underAnyRoot(p string, roots []string) bool {
	sep := "/"
	for _, r := range roots {
		r = path.Clean(r)
		if r == "" || r == "." {
			continue
		}
		if r == sep {
			return true
		}
		if p == r || strings.HasPrefix(p, r+sep) {
			return true
		}
	}
	return false
}
