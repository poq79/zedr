//go:build linux

package collect

import (
	"fmt"
	"os"
	"strconv"

	"zedr/internal/model"
)

// describe 对单个进程做完整富化（Linux：/proc/[pid] 现场补齐）。
// rawProc 已带 PID/PPID/Name/CreateTime，这里补路径/命令行/用户/提权。
// 未在 Linux 实机验证；读取口径按 procfs ABI，解析逻辑在
// parse_procdata.go（neutral，Windows 上有单测锁定）。
func (c *Collector) describe(rp rawProc) ProcessInfo {
	pi := ProcessInfo{
		PID:       rp.PID,
		PPID:      rp.PPID,
		Name:      rp.Name,
		StartTime: createAt(rp.CreateTime),
	}
	if p, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", rp.PID)); err == nil {
		// 已删除的镜像显示 "path (deleted)"——保留后缀让检测层看到
		// "落地后删除再执行"的痕迹，与 Windows 侧文件监控语义对齐。
		pi.Path = p
	}
	if cmd, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", rp.PID)); err == nil {
		// 参数以 NUL 分隔；归一成空格连接（与 Windows 命令行展示口径一致，
		// 已知损失见 parseCmdline）
		pi.CmdLine = parseCmdline(cmd)
	}
	if uid, euid, ok := procUIDs(rp.PID); ok {
		pi.User = strconv.FormatInt(int64(uid), 10)
		pi.Elevated = euid == 0
	}
	pi.SessionID = 0 // Linux 无 Windows 会话概念；（v1 不做 seat 解析）
	return pi
}

// procUIDs 读 /proc/[pid]/status 并交给纯解析函数（取 real/effective
// uid，解析规则见 parseStatusUIDs）。
func procUIDs(pid uint32) (uid, euid int, ok bool) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return 0, 0, false
	}
	return parseStatusUIDs(data)
}

// pathOfLive 现场查询进程镜像路径（血缘第一层父进程兜底用）。
func (c *Collector) pathOfLive(pid uint32) string {
	p, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return ""
	}
	return p
}

// modulesOf：Linux 无单进程模块枚举的用户态等价 API（/proc/[pid]/maps
// 是内存映射，语义与 PE 装载模块不同，不硬凑）。
func (c *Collector) modulesOf(pid uint32) []model.ModuleInfo { return nil }

// KnownMachineProcesses 是 Linux 侧"几乎总在运行"的系统进程名。
// PID 1 可能是 systemd/init/容器里的任意入口——不列死，按名字匹配。
var KnownMachineProcesses = map[string]struct{}{
	"systemd": {}, "init": {}, "kthreadd": {}, "sshd": {}, "cron": {},
	"rsyslogd": {}, "dbus-daemon": {}, "systemd-journal": {}, "systemd-logind": {},
	"systemd-resolve": {}, "systemd-udevd": {},
}
