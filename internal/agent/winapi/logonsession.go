package winapi

// logonsession.go：登录会话枚举（secur32 LSA 只读面）。
//
// 用途：识别"谁在这台机器上有活动会话"（交互/RDP/服务/网络凭据），
// 供侦察画像与"隐蔽登录"类判定使用。只读枚举，不触碰 LSA 策略句柄，
// 不需要特权——LsaEnumerateLogonSessions 对普通用户可用。
//
// 为什么走 LsaGetLogonSessionData 逐条取而不是找一次性的全量 API：
// LSA 本来就是这个口径（先枚举 LUID 列表，再逐个要详情），没有
// "一条调用拿全部"的导出接口；逐条失败跳过的语义正好符合
// "宁可少一条也不丢整表"的采集原则。

import (
	"fmt"
	"sort"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modSecur32 = windows.NewLazySystemDLL("secur32.dll")

	procLsaEnumerateLogonSessions = modSecur32.NewProc("LsaEnumerateLogonSessions")
	procLsaGetLogonSessionData    = modSecur32.NewProc("LsaGetLogonSessionData")
	procLsaFreeReturnBuffer       = modSecur32.NewProc("LsaFreeReturnBuffer")
)

// windowsEpochDelta100ns 是 1601-01-01（Windows 纪元）到 1970-01-01（Unix 纪元）
// 的 100ns 计数差值。FILETIME/LARGE_INTEGER 时间戳都是这个口径。
const windowsEpochDelta100ns = 116444736000000000

// lsaUnicodeString 对应 LSA_UNICODE_STRING（布局同 UNICODE_STRING：
// 两个 USHORT 后跟按指针对齐的 PWSTR，x64 上中间有 4 字节填充）。
// 与 ntproc.go 的 unicodeStr 分开定义：那边是 NT 内核口径，这里保持
// LSA 侧独立，避免以后两边结构演进互相牵连。
type lsaUnicodeString struct {
	Length        uint16 // 字节数（含结尾 NUL），转 UTF16 时按 Length/2 取
	MaximumLength uint16
	_             uint32 // 对齐填充（PWSTR 8 字节对齐）
	Buffer        *uint16
}

// lsaLuid 对应 LUID { DWORD LowPart; LONG HighPart }。
// 为什么不用 uint64：C 里 LUID 对齐是 4 字节，在 SECURITY_LOGON_SESSION_DATA
// 中紧跟在 Size(offset 0) 之后落在 offset 4；Go 若声明成 uint64 会按 8 字节
// 对齐插 4 字节填充，后面所有字段整体错位——错位后读到的是指针字段，
// 直接解引用就是段错误。
type lsaLuid struct {
	LowPart  uint32
	HighPart int32
}

// securityLogonSessionData 对应 LsaGetLogonSessionData 返回的结构。
//
// 布局以真机实测为准，不是 MSDN 文档的口径（2026-11-09，Windows Server
// 20348 x64 实测）：文档写的是 Size/LogonId/LogonType/Session/Sid/
// UserName/...，而真实内存里字符串在 Session/Sid 之前，且多出两个
// 未文档化占位。实测字节与 `klist sessions` 的 (LUID, 用户, 域, 认证包,
// 会话号, 登录类型) 逐字段对上（UMFD-1 会话=1 vs UMFD-2 会话=2 可区分
// @64/@68 两个相邻 DWORD）；按文档布局读会把 Domain 当 Username、
// AuthPackage 当 Domain、第三串读成乱码。
//
//	x64 实际布局（关键：LUID 对齐 4、字符串含指针对齐 8）：
//	Size         uint32    @0    实测 272（结构体总长）
//	LogonID      lsaLuid   @4
//	unknown0     uint32    @12   实测恒 0（含 RemoteInteractive 会话），语义未核实
//	UserName     16 字节   @16
//	LogonDomain  16 字节   @32
//	AuthPackage  16 字节   @48
//	LogonType    uint32    @64   SECURITY_LOGON_TYPE
//	Session      uint32    @68
//	LogonServer  PWSTR     @72
//	LogonTime    int64     @80   1601 纪元 100ns
//	unknown1     [2]uint32 @88   实测 (0x20000, 0)，语义未核实
//	Credentials  指针      @96
//
// @104..272 是内部扩展字段，未消费；Sid 也在其中（本实现不需要）。
// 我们只读前 88 字节稳定字段。
type securityLogonSessionData struct {
	Size        uint32
	LogonID     lsaLuid
	unknown0    uint32 // 占位保偏移；语义未核实，绝不消费
	UserName    lsaUnicodeString
	LogonDomain lsaUnicodeString
	AuthPackage lsaUnicodeString
	LogonType   uint32
	Session     uint32
	LogonServer *uint16
	LogonTime   int64
	unknown1    [2]uint32 // 占位保偏移；实测 (0x20000, 0)，绝不消费
	Credentials uintptr
}

// securityLogonSessionDataSizeAtLeast 是本实现实际要读的字节数下限
// （读到 LogonTime 结尾 = 88）。API 回报的 Size 小于它说明布局认知已失效，
// 宁可跳过该会话也不能越界读指针。
const securityLogonSessionDataSizeAtLeast = 88

// 包初始化时锁死布局：前缀必须精确等于 104（x64），否则指针字段错位，
// 与其静默读出垃圾指针崩溃，不如启动即失败。
var _ = func() bool {
	if unsafe.Sizeof(uintptr(0)) == 8 && unsafe.Sizeof(securityLogonSessionData{}) != 104 {
		panic("winapi: SECURITY_LOGON_SESSION_DATA x64 前缀布局异常（期望 104 字节），禁止带病采集")
	}
	return true
}()

// LogonSession 是一条登录会话。
type LogonSession struct {
	LogonID       uint64    // LUID 平铺成 64 位
	Username      string    // UTF16 → Go string
	Domain        string    // 登录域（本机会话通常是机器名）
	LogonType     uint32    // SECURITY_LOGON_TYPE 原始值
	LogonTypeName string    // 可读名，越界值给 unknown_N
	Session       uint32    // 终端会话号（交互/RDP 会话与 TSMF 对得上）
	LogonTime     time.Time // UTC；来源为零/负计数时归零值
	AuthPackage   string    // 认证包（Negotiate/Kerberos/NTLM）
}

// logonTypeNames 按 SECURITY_LOGON_TYPE 真实枚举值映射。
// 为什么是 map 而不是数组下标顺排：真实枚举在 1 处是空洞
// （UndefinedLogonType，从不下发），Interactive 的真实值是 2；
// 按 0-12 下标顺排会把交互登录标成 Network，属于直接误导检测。
// 名称沿用需求给定拼写（CachedUnclocked 是 ntsecapi.h 的历史拼写，保持原样）。
var logonTypeNames = map[uint32]string{
	0:  "System",
	2:  "Interactive",
	3:  "Network",
	4:  "Batch",
	5:  "Service",
	6:  "Proxy",
	7:  "UnlockInteractive",
	8:  "NetworkCleartext",
	9:  "NewCredentials",
	10: "RemoteInteractive",
	11: "CachedInteractive",
	12: "CachedRemoteInteractive",
	13: "CachedUnclocked",
}

func logonTypeName(t uint32) string {
	if n, ok := logonTypeNames[t]; ok {
		return n
	}
	return fmt.Sprintf("unknown_%d", t)
}

// LogonSessions 枚举当前系统全部登录会话，按 LogonTime 倒序。
//
// 单个会话取详情失败只跳过该条（LSA 里总有几个内部会话可能拒绝读详情），
// 不让一条坏数据毁掉整表；整体失败仅发生在枚举本身。
func LogonSessions() ([]LogonSession, error) {
	var count uint32
	var list *lsaLuid
	ret, _, _ := procLsaEnumerateLogonSessions.Call(
		uintptr(unsafe.Pointer(&count)),
		uintptr(unsafe.Pointer(&list)),
	)
	if uint32(ret) != 0 {
		return nil, fmt.Errorf("LsaEnumerateLogonSessions 失败: status=0x%x", uint32(ret))
	}
	if count == 0 || list == nil {
		return nil, nil
	}
	// 列表缓冲由 LSA 分配，必须整块释放；失败忽略——进程退出前
	// 最多泄漏一份 KB 级缓冲，不值得为此牺牲主流程。
	defer func() {
		_, _, _ = procLsaFreeReturnBuffer.Call(uintptr(unsafe.Pointer(list)))
	}()

	// 上限保护：count 是 LSA 回填的数字，正常几十条；防异常值打爆循环。
	if count > 4096 {
		count = 4096
	}
	sessions := unsafe.Slice(list, count)

	out := make([]LogonSession, 0, count)
	for i := range sessions {
		s, err := getLogonSessionData(&sessions[i])
		if err != nil {
			// 跳过坏会话继续：丢弃一条 vs 丢一整表，采集面宁前者。
			continue
		}
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].LogonTime.After(out[j].LogonTime)
	})
	return out, nil
}

// getLogonSessionData 取单个会话详情并立即拷贝成 Go 值。
// LSA 返回缓冲在 LsaFreeReturnBuffer 之后即失效，所以字符串必须在
// defer 释放之前完成 UTF16 → string 拷贝。
func getLogonSessionData(id *lsaLuid) (LogonSession, error) {
	var data *securityLogonSessionData
	ret, _, _ := procLsaGetLogonSessionData.Call(
		uintptr(unsafe.Pointer(id)),
		uintptr(unsafe.Pointer(&data)),
	)
	if uint32(ret) != 0 || data == nil {
		return LogonSession{}, fmt.Errorf("LsaGetLogonSessionData 失败: status=0x%x", uint32(ret))
	}
	defer func() {
		_, _, _ = procLsaFreeReturnBuffer.Call(uintptr(unsafe.Pointer(data)))
	}()

	// Size 是 LSA 回报的结构体字节数（文档口径）。小于我们要读的下限
	// 说明这块内存比认知的布局短，继续读就是越界——按坏会话丢弃。
	if data.Size != 0 && data.Size < securityLogonSessionDataSizeAtLeast {
		return LogonSession{}, fmt.Errorf("SECURITY_LOGON_SESSION_DATA.Size=%d 小于安全下限 %d",
			data.Size, securityLogonSessionDataSizeAtLeast)
	}

	return LogonSession{
		LogonID:       uint64(uint32(data.LogonID.HighPart))<<32 | uint64(data.LogonID.LowPart),
		Username:      lsaString(data.UserName),
		Domain:        lsaString(data.LogonDomain),
		LogonType:     data.LogonType,
		LogonTypeName: logonTypeName(data.LogonType),
		Session:       data.Session,
		LogonTime:     largeIntegerToTime(data.LogonTime),
		AuthPackage:   lsaString(data.AuthPackage),
	}, nil
}

// lsaString 把 LSA_UNICODE_STRING 拷成 Go string。
// Length 是字节数且应恒为偶数；Buffer 指向 LSA 缓冲内部，只在释放前有效。
func lsaString(us lsaUnicodeString) string {
	if us.Buffer == nil || us.Length == 0 || us.Length%2 != 0 {
		return ""
	}
	return windows.UTF16ToString(unsafe.Slice(us.Buffer, us.Length/2))
}

// largeIntegerToTime 把 1601 纪元 100ns 计数转成 UTC time.Time。
// 零/负/早于 Unix 纪元的计数一律归零值——调用方按"未知"处理，
// 不制造 1601 年的假时间戳（先秒后纳秒拆开算，避免乘 100 溢出 int64）。
func largeIntegerToTime(v int64) time.Time {
	if v <= windowsEpochDelta100ns {
		return time.Time{}
	}
	d := v - windowsEpochDelta100ns
	return time.Unix(d/10000000, (d%10000000)*100).UTC()
}
