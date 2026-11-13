//go:build windows
// +build windows

package winapi

// account_enum.go：本地账户与密码策略枚举（NetAPI，LIVE-TUNNEL §13.3）。
//
// 为什么用 NetAPI 而不是注册表 SAM：SAM 键默认连管理员都读不到，且
// 不同版本布局不稳定；NetUserEnum/NetUserModalsGet 是系统提供的唯一
// 稳定、只读、本地化的账户事实来源（内置账户名会被本地化，硬编码
// "Administrator"/"Guest" 在非英文系统上不可靠）。
//
// 数据来源与口径：
//   - NetUserEnum level 3：一次拿到名称/注释/标志位/密码年龄/最后登录；
//   - SID 用 LookupAccountName 反查（level 3 不含 SID；失败留空，
//     不因单个账户反查失败拖垮整表）；
//   - NetLocalGroupGetMembers：复用 security_windows.go 的 LocalAdmins
//     （已处理本地化组名与 SID 反查），这里只把成员名摊平成字符串；
//   - NetUserModalsGet level 0 读密码长度/有效期，level 3 补锁定阈值
//     （level 0 结构里没有锁定阈值；level 3 失败时按"不可得=0"处理）。
//
// 安全纪律：全部只读系统调用，不打开写权限、不执行命令、不触碰网络。
// 缓冲区由 NetAPI 分配，必须用 NetApiBufferFree 释放；所有字符串在
// 释放前转成 Go string。枚举受当前进程令牌权限约束：非管理员调用
// 可能返回 ERROR_ACCESS_DENIED（如实作为 error 上抛，由 handler 决定展示）。

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	procNetUserEnum      = modNetapi32.NewProc("NetUserEnum")
	procNetUserModalsGet = modNetapi32.NewProc("NetUserModalsGet")
)

const (
	// FILTER_NORMAL_ACCOUNT：只返回普通用户账户（排除机器账户/信任账户）。
	// 内置 Administrator/Guest 都属于普通账户，因此仍会出现在结果里。
	netFilterNormalAccount = 0x0002

	// USER_INFO_3 的 usri3_flags 位（lmaccess.h）。
	ufAccountDisable   = 0x0002  // 账户已禁用
	ufDontExpirePasswd = 0x10000 // 密码永不过期

	// USER_MODALS_INFO_0/3 的 level 号。
	netModalsLevel0 = 0
	netModalsLevel3 = 3

	// 0xFFFFFFFF 在 usrmod0_max_passwd_age 里表示"密码永不过期"，
	// 不是 49710 天；换算成天数时归一为 0（无有限天数可报）。
	netPasswordNeverAges = 0xFFFFFFFF

	// 单次枚举的页数上限：MAX_PREFERRED_LENGTH 正常一页拿全，
	// 这里只防 API 异常时 resume_handle 不前进导致死循环。
	netUserEnumMaxPages = 128

	// SID 理论最大长度（SECURITY_MAX_SID_SIZE）；LookupAccountName
	// 第一轮先问长度，这个常量只作为第二轮分配前的合理性上限。
	sidMaxSize = 68
)

// UserAccount 是一个本地用户账户的排查面快照（契约 §13.3 users[]）。
type UserAccount struct {
	Name                 string `json:"name"`
	SID                  string `json:"sid"`
	Disabled             bool   `json:"disabled"`
	PasswordNeverExpires bool   `json:"password_never_expires"`
	PasswordAgeDays      int    `json:"password_age_days"`
	LastLogonUnix        int64  `json:"last_logon_unix"`
	Comment              string `json:"comment"`
}

// LocalPolicy 是账户策略的三个关键阈值。
type LocalPolicy struct {
	MinPasswordLength  uint32 `json:"min_password_length"`
	MaxPasswordAgeDays uint32 `json:"max_age_days"`
	LockoutThreshold   uint32 `json:"lockout_threshold"`
}

// userInfo3 对齐 USER_INFO_3（x64/x86 均按指针宽度自然对齐）。
// 字段顺序必须与 lmaccess.h 完全一致；Go 对 *uint16/*byte 按指针宽度
// 对齐、uint32 按 4 字节对齐，与 C 编译器在同样 ABI 下的布局一致。
// 只声明到 PasswordExpired 为止的完整结构，绝不按"前 N 个字段"截断解析，
// 否则 sizeof 会小于真实步长、后续条目全部错位。
type userInfo3 struct {
	Name            *uint16
	Password        *uint16
	PasswordAge     uint32
	Priv            uint32
	HomeDir         *uint16
	Comment         *uint16
	Flags           uint32
	ScriptPath      *uint16
	AuthFlags       uint32
	FullName        *uint16
	UserComment     *uint16
	Parms           *uint16
	Workstations    *uint16
	LastLogon       uint32
	LastLogoff      uint32
	AcctExpires     uint32
	MaxStorage      uint32
	UnitsPerWeek    uint32
	LogonHours      *byte
	BadPwCount      uint32
	NumLogons       uint32
	LogonServer     *uint16
	CountryCode     uint32
	CodePage        uint32
	UserID          uint32
	PrimaryGroupID  uint32
	Profile         *uint16
	HomeDirDrive    *uint16
	PasswordExpired uint32
}

// userModalsInfo0 对齐 USER_MODALS_INFO_0（4 个 DWORD）。
type userModalsInfo0 struct {
	MinPasswordLen  uint32
	MaxPasswordAge  uint32
	MinPasswordAge  uint32
	PasswordHistLen uint32
}

// userModalsInfo3 对齐 USER_MODALS_INFO_3（3 个 DWORD）。
type userModalsInfo3 struct {
	LockoutDuration          uint32
	LockoutObservationWindow uint32
	LockoutThreshold         uint32
}

// LocalUsers 枚举本机全部普通用户账户。
//
// last_logon 的语义：NetAPI 返回的是 1970-01-01 UTC 起的秒数，0 表示
// "从未登录"（新建账户/只为服务运行创建的账户常见）。这里如实输出 0，
// 不把它替换成"当前时间"或负数——前端应把 0 显示为"从未登录"。
//
// password_age 是距上次设置密码的秒数，输出时向下取整为天；密码永不过期
// 的账户该字段仍表示"距上次改密"的真实时长，不因 UF_DONT_EXPIRE_PASSWD
// 而归零。
//
// 失败语义：NetUserEnum 本身失败才返回 error；单个账户的 SID 反查失败
// 只让该条 SID 为空（账户仍列出），避免一个异常账户让整页变空。
func LocalUsers() ([]UserAccount, error) {
	out := make([]UserAccount, 0, 32)
	var resume uint32
	for page := 0; ; page++ {
		if page >= netUserEnumMaxPages {
			return nil, fmt.Errorf("NetUserEnum 分页超过 %d 页，疑似 resume_handle 未推进", netUserEnumMaxPages)
		}

		var buf unsafe.Pointer
		var read, total uint32
		ret, _, _ := procNetUserEnum.Call(
			0,          // servername=nil：本机
			uintptr(3), // level 3：含 flags/password_age/last_logon
			uintptr(netFilterNormalAccount),
			uintptr(unsafe.Pointer(&buf)),
			uintptr(netPreferredLength), // 一次性分配整页
			uintptr(unsafe.Pointer(&read)),
			uintptr(unsafe.Pointer(&total)),
			uintptr(unsafe.Pointer(&resume)))
		if ret != 0 && ret != uintptr(windows.ERROR_MORE_DATA) {
			if buf != nil {
				_, _, _ = procNetApiBufferFree.Call(uintptr(buf))
			}
			return nil, netAPIError("NetUserEnum", ret)
		}

		if buf != nil && read > 0 {
			items := unsafe.Slice((*userInfo3)(buf), int(read))
			for i := range items {
				it := &items[i]
				name := utf16PtrString(it.Name)
				if name == "" {
					continue // 无名条目无法展示也无法反查 SID，跳过
				}
				out = append(out, UserAccount{
					Name:                 name,
					SID:                  lookupAccountSID(name),
					Disabled:             it.Flags&ufAccountDisable != 0,
					PasswordNeverExpires: it.Flags&ufDontExpirePasswd != 0,
					PasswordAgeDays:      int(it.PasswordAge / 86400),
					LastLogonUnix:        int64(it.LastLogon),
					Comment:              utf16PtrString(it.Comment),
				})
			}
		}
		if buf != nil {
			_, _, _ = procNetApiBufferFree.Call(uintptr(buf))
		}
		if ret == 0 {
			break
		}
		// ERROR_MORE_DATA 且本页 0 条：resume_handle 没有推进，继续循环
		// 只会得到同样的空页——按异常上抛，不静默返回半张表。
		if read == 0 {
			return nil, errors.New("NetUserEnum 返回 ERROR_MORE_DATA 但本页 0 条，无法继续分页")
		}
	}

	// 顺序稳定便于前端渲染与单测断言；大小写不敏感排序避免 A/a 分组跳动。
	sort.Slice(out, func(i, j int) bool {
		li, lj := strings.ToLower(out[i].Name), strings.ToLower(out[j].Name)
		if li != lj {
			return li < lj
		}
		return out[i].Name < out[j].Name
	})
	return out, nil
}

// Administrators 返回本地 Administrators 组的直接成员名。
//
// 复用 LocalAdmins：组名按内建 SID S-1-5-32-544 反查（本地化系统兼容），
// level 2 同时给 SID 与 domain\name。返回值保持 LocalAdmins 的排序。
// 注意只含"直接成员"：嵌套组里的用户不会被展开（NetLocalGroupGetMembers
// 不递归），与资产清单口径一致。
func Administrators() ([]string, error) {
	members, err := LocalAdmins()
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(members))
	for _, m := range members {
		if m.Name != "" {
			out = append(out, m.Name)
		}
	}
	return out, nil
}

// LocalPolicyInfo 读取本机账户策略。
//
// level 0 给最小密码长度/最大密码年龄；锁定阈值只在 level 3 里，
// 因此补一次 level 3。level 3 失败不拖垮整个结果：锁定阈值置 0
// （"不可得"），调用方仍能拿到密码长度与有效期。
func LocalPolicyInfo() (LocalPolicy, error) {
	var out LocalPolicy

	var buf unsafe.Pointer
	ret, _, _ := procNetUserModalsGet.Call(0, uintptr(netModalsLevel0), uintptr(unsafe.Pointer(&buf)))
	if ret != 0 {
		return out, netAPIError("NetUserModalsGet(level 0)", ret)
	}
	if buf == nil {
		return out, errors.New("NetUserModalsGet(level 0) 返回空缓冲区")
	}
	m0 := (*userModalsInfo0)(buf)
	out.MinPasswordLength = m0.MinPasswordLen
	out.MaxPasswordAgeDays = passwordAgeDays(m0.MaxPasswordAge)
	_, _, _ = procNetApiBufferFree.Call(uintptr(buf))

	var buf3 unsafe.Pointer
	ret, _, _ = procNetUserModalsGet.Call(0, uintptr(netModalsLevel3), uintptr(unsafe.Pointer(&buf3)))
	if ret == 0 && buf3 != nil {
		m3 := (*userModalsInfo3)(buf3)
		out.LockoutThreshold = m3.LockoutThreshold
	}
	if buf3 != nil {
		_, _, _ = procNetApiBufferFree.Call(uintptr(buf3))
	}
	return out, nil
}

// passwordAgeDays 把 NetAPI 的秒数阈值换算成天；0xFFFFFFFF 表示
// "永不过期/不设上限"，归一为 0（没有有限天数可报）。
func passwordAgeDays(seconds uint32) uint32 {
	if seconds == netPasswordNeverAges {
		return 0
	}
	return seconds / 86400
}

// lookupAccountSID 用本地 SAM 反查账户 SID；任何失败返回空串。
//
// 两轮调用：第一轮传空 SID 缓冲问所需长度（ERROR_INSUFFICIENT_BUFFER），
// 第二轮按长度分配。缓冲区用 []byte 承载再转 *windows.SID，避免依赖
// windows.SID 的 Go 结构体大小恰好等于系统需要的字节数。
func lookupAccountSID(name string) string {
	namePtr, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return ""
	}

	var sidSize, domainSize uint32
	var use uint32
	err = windows.LookupAccountName(nil, namePtr, nil, &sidSize, nil, &domainSize, &use)
	if err != nil && !errors.Is(err, windows.ERROR_INSUFFICIENT_BUFFER) {
		return ""
	}
	if sidSize == 0 || sidSize > sidMaxSize {
		return ""
	}

	sidBuf := make([]byte, sidSize)
	// domainBuf 必须在调用期间保持可达：长度来自第一轮，LSA 会写入
	// 反查到的域/计算机名。反查失败不需要这个值，只用于让 API 有处可写。
	var domainBuf []uint16
	var domainPtr *uint16
	if domainSize > 0 {
		domainBuf = make([]uint16, domainSize)
		domainPtr = &domainBuf[0]
	}
	err = windows.LookupAccountName(
		nil, namePtr,
		(*windows.SID)(unsafe.Pointer(&sidBuf[0])), &sidSize,
		domainPtr, &domainSize, &use)
	if err != nil {
		return ""
	}
	return (*windows.SID)(unsafe.Pointer(&sidBuf[0])).String()
}

// netAPIError 把 NET_API_STATUS 数值转成可 errors.Is 的 error。
// syscall.Errno 的底层整数就是 API 状态码，因此 ERROR_ACCESS_DENIED
// 等判断在调用方仍然成立（错误里带 operation 便于日志定位）。
func netAPIError(op string, status uintptr) error {
	if status == 0 {
		return nil
	}
	return fmt.Errorf("%s 失败: status=%d: %w", op, status, syscall.Errno(status))
}
