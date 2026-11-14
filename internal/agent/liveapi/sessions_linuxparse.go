// 本文件 NEUTRAL：/sessions 的 utmp 纯解析逻辑（无 IO、无构建标签）。
// utmp 是二进制格式，逐字段偏移要能在 Windows 上跑单测锁定（手工构造的
// 夹具字节）；IO 壳（读 /var/run/utmp）在 sessions_linux.go。
//
// 未在 Linux 实机验证（待 Kali 复验）；验证口径 = GOOS=linux 交叉编译 +
// 本文件单测在 Windows 上运行。
//
// sessions_linuxparse.go：/var/run/utmp 二进制记录的纯 Go 解析（零依赖，
// 不引 utmp 相关库）+ /sessions Linux 投影。
//
// 布局口径：按 glibc /usr/include/bits/utmp.h 写死。x86_64（LP64）与
// i386（ILP32）两种布局的字段偏移如下（来源 = bits/utmp.h 字段顺序 +
// C 结构对齐规则；字符串区偏移两种布局相同，只有 ut_session/ut_tv 因
// long 宽度不同而错位）：
//
//	偏移  字段                  x86_64          i386
//	  0  short ut_type         2B              2B
//	  2  (对齐填充)             2B              2B
//	  4  pid_t ut_pid          4B              4B
//	  8  char ut_line[32]      32B             32B
//	 40  char ut_id[4]         4B              4B
//	 44  char ut_user[32]      32B             32B
//	 76  char ut_host[256]     256B            256B
//	332  struct exit_status    4B              4B
//	336  long ut_session       8B              4B
//	  —  struct timeval       sec@344(8B)     sec@340(4B)
//	  —                        usec@352(8B)    usec@344(4B)
//	  —  int32 ut_addr_v6[4]   @360 16B        @348 16B
//	  —  reserved[20]          @376 20B        @364 20B
//	  —  记录总长(含尾填充)     400B            384B
//
// 诚实边界：
//   - 大端架构（s390x）与 musl libc 布局未核实，靠"记录大小整除 + 逐
//     记录 ut_type 值域校验"守门——对不上就整表放弃并 note，绝不按错误
//     偏移硬解出乱码用户名（那是比"看不到会话"更糟的失真数据）；
//   - utmp 只反映 utmp 写入器（login/sshd/xdm）登记的会话，容器内 exec
//     /未走 PAM 的会话不在其中——与 Windows LSA 枚举的覆盖差异如实存在。
package liveapi

import (
	"encoding/binary"
	"sort"
	"strings"
)

// utmp 记录类型（bits/utmp.h 的 ut_type 枚举）。
const (
	utmpEmpty        = 0
	utmpRunLevel     = 1
	utmpBootTime     = 2
	utmpNewTime      = 3
	utmpOldTime      = 4
	utmpInitProcess  = 5
	utmpLoginProcess = 6
	utmpUserProcess  = 7 // 活跃用户会话（唯一进 /sessions 的类型）
	utmpDeadProcess  = 8
	utmpAccounting   = 9
)

// utmp 布局参数：记录总长 + 三个随 long 宽度错位的数值字段偏移。
// 字符串区偏移两种布局一致，直接用常量。
type utmpLayout struct {
	recSize     int
	offSession  int
	offTVSec    int
	offTVUseC   int
	timevalIs64 bool // tv_sec/tv_usec 是 8 字节 long（LP64）还是 4 字节
}

var (
	utmpLayoutAMD64 = utmpLayout{recSize: 400, offSession: 336, offTVSec: 344, offTVUseC: 352, timevalIs64: true}
	utmpLayout386   = utmpLayout{recSize: 384, offSession: 336, offTVSec: 340, offTVUseC: 344, timevalIs64: false}
)

// 字符串区偏移（两种布局一致，见文件头表格）。
const (
	utmpOffType = 0
	utmpOffPID  = 4
	utmpOffLine = 8  // ut_line[32]
	utmpOffID   = 40 // ut_id[4]
	utmpOffUser = 44 // ut_user[32]
	utmpOffHost = 76 // ut_host[256]
	utmpLenLine = 32
	utmpLenID   = 4
	utmpLenUser = 32
	utmpLenHost = 256
)

// linuxSessionItem 与 Windows sessions.go 的 sessionItem 逐字段对齐。
// 字段映射决策：
//   - logon_id：Windows 是 LUID；Linux 无对等标识。填 utmp 的 ut_pid
//     （登录进程号：sshd 子进程/login/xdm，可与 /procinfo 关联定位）。
//     不用 ut_session——主流 utmp 写入器把它留 0，整列 0 毫无区分度；
//   - domain：恒空（Linux 无域概念，不伪造）；
//   - logon_type：恒 0（SECURITY_LOGON_TYPE 是 Windows 枚举，硬套数字
//     是误导）；可读的 Linux 口径类型放 logon_type_name；
//   - logon_type_name：从 ut_line/ut_host 推导的诚实词汇（见
//     utmpSessionTypeName）——不是 Windows 枚举名，调查者看词汇即知口径；
//   - session：恒 0（Windows 终端会话号，Linux 无对等）；
//   - logon_time：ut_tv.tv_sec（unix 秒）；0 值 → null（与 Windows
//     "零值→null" 同口径，0 会伪装成 1970 年的登录）；
//   - auth_package：恒空（Linux 无认证包概念）。
type linuxSessionItem struct {
	LogonID       uint64 `json:"logon_id"`
	Username      string `json:"username"`
	Domain        string `json:"domain"`
	LogonType     uint32 `json:"logon_type"`
	LogonTypeName string `json:"logon_type_name"`
	Session       uint32 `json:"session"`
	LogonTime     *int64 `json:"logon_time"`
	AuthPackage   string `json:"auth_package"`
}

// parseUtmpActiveSessions 解析 utmp 全文，返回 USER_PROCESS 会话。
// 返回 ok=false 表示布局对不上（记录大小不整除或 ut_type 值域越界），
// 调用方整表放弃并 note——绝不输出按错误偏移解出的乱码。
//
// 布局选择：文件大小被 400 整除按 x86_64 口径解，否则被 384 整除按
// i386 口径解。两者冲突时（比如恰好被两者整除）优先 400：目标环境
// Kali 是 x86_64 glibc；i386 口径是老 32 位发行版的兜底。
func parseUtmpActiveSessions(data []byte) (items []linuxSessionItem, ok bool) {
	var lay utmpLayout
	switch {
	case len(data) == 0:
		return nil, true // 空文件 = 无会话（不是错误）
	case len(data)%utmpLayoutAMD64.recSize == 0:
		lay = utmpLayoutAMD64
	case len(data)%utmpLayout386.recSize == 0:
		lay = utmpLayout386
	default:
		return nil, false
	}

	// 先整表校验 ut_type 值域，再投影：半途发现布局不符时不能返回
	// 半表半垃圾的结果。
	for off := 0; off+lay.recSize <= len(data); off += lay.recSize {
		t := int(binary.LittleEndian.Uint16(data[off+utmpOffType:]))
		if t < utmpEmpty || t > utmpAccounting {
			return nil, false
		}
	}

	for off := 0; off+lay.recSize <= len(data); off += lay.recSize {
		t := int(binary.LittleEndian.Uint16(data[off+utmpOffType:]))
		if t != utmpUserProcess {
			continue
		}
		user := utmpString(data[off+utmpOffUser : off+utmpOffUser+utmpLenUser])
		if user == "" {
			// USER_PROCESS 却没有用户名的记录是写入器异常，宁缺毋滥
			continue
		}
		line := utmpString(data[off+utmpOffLine : off+utmpOffLine+utmpLenLine])
		host := utmpString(data[off+utmpOffHost : off+utmpOffHost+utmpLenHost])
		pid := binary.LittleEndian.Uint32(data[off+utmpOffPID:])

		item := linuxSessionItem{
			LogonID:       uint64(pid),
			Username:      user,
			LogonTypeName: utmpSessionTypeName(line, host),
		}
		sec := utmpTVSec(data[off:], &lay)
		if sec > 0 {
			ts := sec
			item.LogonTime = &ts
		}
		items = append(items, item)
	}
	return items, true
}

// utmpTVSec 按布局取 ut_tv.tv_sec。返回 0 = 未登记时间（投影为 null）。
func utmpTVSec(rec []byte, lay *utmpLayout) int64 {
	if lay.timevalIs64 {
		return int64(binary.LittleEndian.Uint64(rec[lay.offTVSec:]))
	}
	return int64(binary.LittleEndian.Uint32(rec[lay.offTVSec:]))
}

// utmpString 取定长字符串字段的 NUL 截断值（utmp 字段不一定以 NUL 结尾，
// 满长度使用是合法形态）。
func utmpString(field []byte) string {
	if i := strings.IndexByte(string(field), 0); i >= 0 {
		return string(field[:i])
	}
	return string(field)
}

// utmpSessionTypeName 从 ut_line/ut_host 推导会话形态的可读名。utmp 不
// 记录"登录方式"本体（ssh/telnet/local 无法区分），以下词汇是诚实的
// 形态归纳而非 Windows 枚举翻译：
//   - console：本地虚拟终端/控制台（tty*）
//   - remote：伪终端且登记了远端主机（ssh 落地等的典型形态）
//   - local-pts：伪终端无远端主机（tmux/screen、本地 X 终端的典型形态）
//   - display：X 显示会话（host 为 ":0" 形态）
//   - other：形态不明
func utmpSessionTypeName(line, host string) string {
	switch {
	case strings.HasPrefix(line, "tty"):
		return "console"
	case strings.HasPrefix(line, "pts/"), strings.HasPrefix(line, "ssh"):
		if host != "" && !strings.HasPrefix(host, ":") {
			return "remote"
		}
		return "local-pts"
	case strings.HasPrefix(host, ":"):
		return "display"
	default:
		return "other"
	}
}

// buildLinuxSessionsResult 是 /sessions 的纯投影（Windows sessionsResult
// 同形状：items 按 logon_time 倒序 + total；note 为 Linux 特有键）。
func buildLinuxSessionsResult(items []linuxSessionItem, note string) map[string]any {
	// 倒序与 Windows LogonSessions 同口径：最近的会话排最前；
	// 无时间戳的条目（logon_time=null）按 0 处理沉底。
	sort.Slice(items, func(i, j int) bool {
		ti, tj := int64(0), int64(0)
		if items[i].LogonTime != nil {
			ti = *items[i].LogonTime
		}
		if items[j].LogonTime != nil {
			tj = *items[j].LogonTime
		}
		return ti > tj
	})
	if items == nil {
		items = []linuxSessionItem{}
	}
	out := map[string]any{
		"items": items,
		"total": len(items),
	}
	if note != "" {
		out["note"] = note
	}
	return out
}

// utmpFixtureRecord 构造一条 utmp 记录（单测夹具用，非生产路径）：
// 把字段按布局写进定长字节，验证解析与构造互为镜像。
func utmpFixtureRecord(lay utmpLayout, typ int, pid uint32, line, id, user, host string, tvSec int64) []byte {
	rec := make([]byte, lay.recSize)
	binary.LittleEndian.PutUint16(rec[utmpOffType:], uint16(typ))
	binary.LittleEndian.PutUint32(rec[utmpOffPID:], pid)
	putUtmpField(rec[utmpOffLine:], utmpLenLine, line)
	putUtmpField(rec[utmpOffID:], utmpLenID, id)
	putUtmpField(rec[utmpOffUser:], utmpLenUser, user)
	putUtmpField(rec[utmpOffHost:], utmpLenHost, host)
	if lay.timevalIs64 {
		binary.LittleEndian.PutUint64(rec[lay.offTVSec:], uint64(tvSec))
		binary.LittleEndian.PutUint64(rec[lay.offTVUseC:], 0)
	} else {
		binary.LittleEndian.PutUint32(rec[lay.offTVSec:], uint32(tvSec))
		binary.LittleEndian.PutUint32(rec[lay.offTVUseC:], 0)
	}
	return rec
}

func putUtmpField(dst []byte, size int, val string) {
	if len(val) > size {
		val = val[:size]
	}
	copy(dst, val)
}
