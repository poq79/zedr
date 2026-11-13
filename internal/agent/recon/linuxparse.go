package recon

// linuxparse.go — Linux procfs 文本格式的纯解析函数（无构建标签）。
//
// 为什么放中性文件：零系统 I/O，单测在 Windows 上即可跑全（本机无
// Linux 测试环境，验证口径见 AGENTS §6 / RESEARCH-LINUX-AGENT.md）。
// 采集入口（读 /proc + 调用这些函数）在 base_linux.go（linux 标签）。
//
// 未在 Linux 实机验证：字段位置按 proc(5) 手册页（man7.org）实现。

import (
	"strconv"
	"strings"
)

// parseProcStatStarttime 从 /proc/[pid]/stat 内容取 starttime（第 22 个
// 字段，开机后的 clock tick 数）。
//
// 关键陷阱：第 2 字段 comm 是括号包裹且**可以含空格与括号**的进程名
// （如 "((sd-pam))"），按空格切全会错位——必须先找到最后一个 ')' 再切
// 余下字段（stat 里 comm 之后不再出现 ')'，该口径正确）。
func parseProcStatStarttime(data []byte) (uint64, bool) {
	s := string(data)
	rparen := strings.LastIndexByte(s, ')')
	if rparen < 0 {
		return 0, false
	}
	fields := strings.Fields(s[rparen+1:])
	// rest 从 state（第 3 字段）开始；starttime 是第 22 字段 → 偏移 19
	if len(fields) < 20 {
		return 0, false
	}
	v, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil {
		return 0, false
	}
	return v, true
}

// parseProcStatBtime 从 /proc/stat 内容取 btime（系统启动的 unix 秒）。
// 缺该行返回 false——/proc/stat 格式随内核版本演进，缺行按未知处理，
// 调用方退回进程快照的 FirstSeen，不猜。
func parseProcStatBtime(data []byte) (int64, bool) {
	for _, line := range strings.Split(string(data), "\n") {
		// /proc/stat 行数固定几十行，线性扫没有成本问题
		if strings.HasPrefix(line, "btime ") {
			v, err := strconv.ParseInt(strings.TrimSpace(line[6:]), 10, 64)
			if err == nil && v > 0 {
				return v, true
			}
			return 0, false
		}
	}
	return 0, false
}

// procUserHZ 是 /proc 各字段使用的 USER_HZ（clock tick 频率）。
// Linux 用户态接口按 100 固定（内核对用户态导出恒为 100，与内核真实
// CONFIG_HZ 无关——见 proc(5)），v1 不做 sysconf 探测。
const procUserHZ = 100

// procStarttimeToUnix 把 starttime ticks 换算成 unix 秒（btime + ticks/HZ）。
// 返回值精度是秒级——与 Windows 侧 ProcessStartTime 的口径一致。
func procStarttimeToUnix(btime, ticks int64) int64 {
	return btime + ticks/procUserHZ
}
