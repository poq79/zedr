package linuxinv

// system.go — system / agent / tasks 三节。标量与聚合快照节
// （对应 Windows 组合根不做条级 diff 的 system/agent），输出 map 而非
// 条目数组；tasks 是轻量条目数组（diff 主键 = path）。

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// sysSection 组装 system 节。
//
// 与 Windows system 节的字段对照（app.invSystemSection）：boot_time/
// uptime_sec 同名同义；cpu/mem 从 /proc 取（等价物）；disks v1 未做
// （statfs 枚举挂载点属于后续批次，诚实缺席）；hostname/os/kernel/
// boot_id 是 Linux 追加字段（服务端按 future-field 兼容）。
//
// 任何子项失败只少字段不拖垮整节——诚实缺席好过用 0 冒充；
// 唯独 uptime 读不到时整节报错（没有开机时间，半个 system 节反而误导，
// 与 Windows 版 BootTime 失败同口径）。
func sysSection() (any, error) {
	upSec, err := readUptimeSeconds()
	if err != nil {
		return nil, fmt.Errorf("读 /proc/uptime 失败: %w", err)
	}
	out := map[string]any{
		"uptime_sec": int64(upSec),
	}
	if bt, ok := readBootTime(); ok {
		// boot_time 直接用 /proc/stat 的 btime（内核记录的启动 unix 秒），
		// 不用挂钟减 uptime 反推——NTP 校准会让挂钟减法漂移
		out["boot_time"] = time.Unix(bt, 0).UTC().Format(time.RFC3339)
	}
	if s := readFirstLine("/proc/sys/kernel/hostname"); s != "" {
		out["hostname"] = s
	} else if h, err := os.Hostname(); err == nil {
		out["hostname"] = h
	}
	if kv := readOSRelease(); kv != nil {
		if v := kv["PRETTY_NAME"]; v != "" {
			out["os"] = v
		}
		if v := kv["ID"]; v != "" {
			out["os_id"] = v
		}
		if v := kv["VERSION_ID"]; v != "" {
			out["os_version"] = v
		}
	}
	if s := readFirstLine("/proc/sys/kernel/osrelease"); s != "" {
		out["kernel"] = s
	}
	if s := readFirstLine("/proc/sys/kernel/random/boot_id"); s != "" {
		out["boot_id"] = s
	}
	if n := cpuCores(); n > 0 {
		out["cpu_cores"] = n
	}
	if total, free, ok := readMemInfo(); ok {
		out["mem_total_mb"] = total
		out["mem_free_mb"] = free
	}
	return out, nil
}

// readUptimeSeconds 读 /proc/uptime 首字段（秒，浮点）。
func readUptimeSeconds() (float64, error) {
	line := readFirstLine("/proc/uptime")
	if line == "" {
		return 0, fmt.Errorf("文件为空")
	}
	f := strings.Fields(line)
	if len(f) < 1 {
		return 0, fmt.Errorf("格式异常")
	}
	return strconv.ParseFloat(f[0], 64)
}

// readBootTime 从 /proc/stat 的 btime 行取系统启动 unix 秒。
func readBootTime() (int64, bool) {
	data, err := os.ReadFile("/proc/stat")
	if err != nil {
		return 0, false
	}
	for _, line := range strings.Split(string(data), "\n") {
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

// readOSRelease 解析 /etc/os-release（KEY=value，值去引号）。
// 路径是 freedesktop 标准两处；都没有返回 nil（极简容器镜像可能没有）。
func readOSRelease() map[string]string {
	for _, p := range []string{"/etc/os-release", "/usr/lib/os-release"} {
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		kv := map[string]string{}
		for _, raw := range strings.Split(string(data), "\n") {
			line := strings.TrimSpace(raw)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			i := strings.IndexByte(line, '=')
			if i < 0 {
				continue
			}
			k := line[:i]
			v := strings.Trim(line[i+1:], `"'`)
			kv[k] = v
		}
		if len(kv) > 0 {
			return kv
		}
	}
	return nil
}

// cpuCores 数 /proc/cpuinfo 的 processor 条目。架构差异兜底：部分
// 精简内核没有 cpuinfo，返回 0（字段缺席，不冒充 1 核）。
func cpuCores() int {
	data, err := os.ReadFile("/proc/cpuinfo")
	if err != nil {
		return 0
	}
	n := 0
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "processor") {
			n++
		}
	}
	return n
}

// readMemInfo 从 /proc/meminfo 取 MemTotal/MemAvailable（KB→MB）。
// 用 MemAvailable 而非 MemFree 作"free"口径：前者才是真正可分配的量
// （含可回收 page cache），与监控工具的可用内存语义一致。
func readMemInfo() (totalMB, freeMB uint64, ok bool) {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0, 0, false
	}
	var total, avail uint64
	haveTotal, haveAvail := false, false
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "MemTotal:") {
			total, _ = parseMemKB(line)
			haveTotal = true
		} else if strings.HasPrefix(line, "MemAvailable:") {
			avail, _ = parseMemKB(line)
			haveAvail = true
		}
	}
	if !haveTotal || !haveAvail {
		return 0, 0, false
	}
	return total / 1024, avail / 1024, true
}

func parseMemKB(line string) (uint64, bool) {
	f := strings.Fields(line)
	if len(f) < 2 {
		return 0, false
	}
	v, err := strconv.ParseUint(f[1], 10, 64)
	return v, err == nil
}

func readFirstLine(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	line := string(data)
	if i := strings.IndexByte(line, '\n'); i >= 0 {
		line = line[:i]
	}
	return strings.TrimSpace(line)
}

// ---------------------------------------------------------------- agent

// invAgentInfo 的 Linux 子集（字段名对齐 app 层 Windows invAgentInfo，
// json tag 同名）。collector/scan_interval_sec/rule_count/ioc_count/
// queue_dropped 需要探针运行态（app 层状态），linuxinv 拿不到也不伪造
// ——组合根若需要完整形状，应替换掉本节而不是改这里。
type invAgentInfo struct {
	Version   string `json:"version"`
	UptimeSec int64  `json:"uptime_sec"`
}

// agentSection 探针自述节。uptime 用探针自身进程的运行时长
// （/proc/self/stat starttime + /proc/stat btime），语义与 Windows 版
// 的 agent uptime 一致（不是系统开机时长）。
func agentSection() (any, error) {
	up, err := procSelfUptimeSeconds()
	if err != nil {
		return nil, err
	}
	return invAgentInfo{Version: AgentVersion, UptimeSec: int64(up)}, nil
}

// procSelfUptimeSeconds 探针进程自身已运行秒数。
// 进程年龄 = 系统 uptime - starttime/HZ：两个量都是"开机以来"的尺度
// （前者秒、后者 tick），相减得到进程已运行时长，全程不碰挂钟——
// 系统时钟被改（NTP 校准/时钟偏移）不会让 uptime 出现负数或跳变。
func procSelfUptimeSeconds() (float64, error) {
	sysUp, err := readUptimeSeconds()
	if err != nil {
		return 0, fmt.Errorf("读 /proc/uptime 失败: %w", err)
	}
	data, err := os.ReadFile("/proc/self/stat")
	if err != nil {
		return 0, fmt.Errorf("读 /proc/self/stat 失败: %w", err)
	}
	// starttime 是 /proc/[pid]/stat 第 22 字段（comm 后偏移 19）
	startTicks, ok := parseStatStarttime(data)
	if !ok {
		return 0, fmt.Errorf("解析 /proc/self/stat starttime 失败")
	}
	startSec := float64(startTicks) / procUserHZ
	elapsed := sysUp - startSec
	if elapsed < 0 {
		// 时钟/tick 边界（进程刚启动且 uptime 取样在先）钳到 0
		elapsed = 0
	}
	return elapsed, nil
}

// procUserHZ 是 procfs 时间字段的 USER_HZ（内核对用户态恒导出 100，
// 见 proc(5)；与内核 CONFIG_HZ 无关）。
const procUserHZ = 100

// parseStatStarttime 从 /proc/[pid]/stat 内容取 starttime ticks。
// comm 字段可含空格/括号（如 "((sd-pam))"），必须从最后一个 ')' 之后切。
func parseStatStarttime(data []byte) (uint64, bool) {
	s := string(data)
	rparen := strings.LastIndexByte(s, ')')
	if rparen < 0 {
		return 0, false
	}
	fields := strings.Fields(s[rparen+1:])
	if len(fields) < 20 {
		return 0, false
	}
	v, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil {
		return 0, false
	}
	return v, true
}

// ---------------------------------------------------------------- tasks

// invTaskItem 是 tasks 节条目（字段名对齐 Windows invTask 的
// path/name/state 三列；author/triggers/actions 等 Windows 富字段
// 来自任务 XML，cron 没有——v1 不伪造）。
type invTaskItem struct {
	Path  string `json:"path"`
	Name  string `json:"name"`
	State string `json:"state"`
}

// tasksSection 计划任务节（Linux 口径 = cron）。
//
// 覆盖：/etc/cron.d/*（系统包落的分片）、/etc/crontab、用户 crontab
// spool（/var/spool/cron/crontabs 与 /var/spool/cron，root 才能读，
// 读不到跳过——诚实边界）。systemd timer 不在这里：它已在 services 节
// 以 *.timer 单元出现（enumSystemdUnits 的口径），避免同一对象两节双报。
//
// state 恒 "present"：cron 文件的"启用/停用"没有离线可判的统一语义
// （注释掉整个文件是手工习惯，不是协议字段）。
func tasksSection() (any, error) {
	out := make([]invTaskItem, 0, 16)

	if ents, err := os.ReadDir("/etc/cron.d"); err == nil {
		names := make([]string, 0, len(ents))
		for _, e := range ents {
			if !e.IsDir() {
				names = append(names, e.Name())
			}
		}
		sort.Strings(names)
		for _, n := range names {
			out = append(out, invTaskItem{Path: filepath.Join("/etc/cron.d", n), Name: n, State: "present"})
		}
	}

	if fileExists("/etc/crontab") {
		out = append(out, invTaskItem{Path: "/etc/crontab", Name: "crontab", State: "present"})
	}

	for _, sp := range []string{"/var/spool/cron/crontabs", "/var/spool/cron"} {
		if ents, err := os.ReadDir(sp); err == nil {
			names := make([]string, 0, len(ents))
			for _, e := range ents {
				if !e.IsDir() {
					names = append(names, e.Name())
				}
			}
			sort.Strings(names)
			for _, n := range names {
				out = append(out, invTaskItem{Path: filepath.Join(sp, n), Name: "user:" + n, State: "present"})
			}
			break // 两个 spool 布局互斥（Debian/RedHat），命中一个即可
		}
	}

	// 按 path 排序保证 hash 稳定：枚举顺序不稳会让差量协议退化成每轮
	// 全量（Windows 组合根同一条纪律）。
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, nil
}

func fileExists(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && !fi.IsDir()
}
