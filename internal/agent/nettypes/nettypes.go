// Package nettypes 是跨平台数据形状的单一事实源：连接表、文件事件等
// "管线通用数据"在此定义，Windows（winapi）与 Linux（procfs/inotify）
// 两侧实现各自生产同形状数据。
//
// 为什么单独成包：winapi 在 Linux 构建里整个缺席，任何引用它的可移植
// 包（netwatch/状态层/组合根）都会被拖下水。类型别名
// （winapi.TCPConn = nettypes.TCPConn）让既有 Windows 调用方零改动，
// 而 Linux 侧只依赖本包。
package nettypes

import "time"

// TCPConn 是一条 TCP 连接快照（连接表采样产物）。State 用与 Windows
// GetExtendedTcpTable 相同的状态字符串（SYN_SENT/ESTABLISHED/TIME_WAIT…），
// Linux 侧由 /proc/net/tcp 的十六进制状态码映射而来，检测层才不用分叉。
type TCPConn struct {
	Proto      string
	LocalIP    string
	LocalPort  uint16
	RemoteIP   string
	RemotePort uint16
	State      string
	PID        uint32
}

// FileEvent 是一次文件系统事件（落地监控产物）。Kind 语义与 Windows
// RDCW 对齐："added"/"removed"/"modified"/"renamed"/"renamed_old"；
// Linux inotify 由 MOVED_FROM/MOVED_TO 配对映射出 renamed 语义。
type FileEvent struct {
	Kind    string // "added"/"removed"/"modified"/"renamed"/"renamed_old"
	Path    string // 完整路径（监控目录 + 相对名）
	OldPath string // 仅 renamed：配对到的旧路径；配对失败为空
	When    time.Time
}
