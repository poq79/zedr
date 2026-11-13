//go:build windows
// +build windows

// Package winapi 的敏感安全面采集（③：Defender / 防火墙 / 本地管理员组）。
//
// 为什么需要它：这三节是"防护还在不在"的一手事实，也是 T1562（削弱防御）
// 与 T1098（额外本地管理员）两条攻击路径的直接观测点——
//   - Defender 排除项新增：攻击者把自己的工具目录放进扫描白名单；
//   - 防火墙 profile 被关：横向移动前的铺路动作；
//   - 本地管理员组成员变化：新账户/新成员是最经典的持久化与提权落点。
//
// 它们进资产清单差量通道（app 侧 keyed diff）做变更告警，采集层只负责
// 把当前事实快照出来。
//
// 成本纪律同 inventory_windows.go：注册表 / NetAPI 单次快照，禁 COM、
// 禁网络 IO、禁新依赖；单次调用目标 <100ms；失败一律返回 error，不 panic。
// 本文件仅 Windows（文件名后缀约束，与包内其他文件一致）。
package winapi

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

var (
	modNetapi32               = windows.NewLazySystemDLL("netapi32.dll")
	procNetLocalGroupGetMemb  = modNetapi32.NewProc("NetLocalGroupGetMembers")
	procNetApiBufferFree      = modNetapi32.NewProc("NetApiBufferFree")
	procQueryServiceStatusApi = modAdvapi32.NewProc("QueryServiceStatus")
)

const (
	// SCM / 服务状态查询所需的最小权限面
	svcQueryStatus = 0x0004 // SERVICE_QUERY_STATUS
	serviceRunning = 4      // SERVICE_RUNNING

	// MAX_PREFERRED_LENGTH：让 NetLocalGroupGetMembers 一次性分配整表
	netPreferredLength = 0xFFFFFFFF
)

// ---------------------------------------------------------------- Defender

// DefenderInfo 是 Windows Defender 的防护面快照。
// 三个排除列表可能为空（干净机器的常态），不代表采集失败。
type DefenderInfo struct {
	ExclusionPaths      []string
	ExclusionProcesses  []string
	ExclusionExtensions []string
	// RealtimeState 取值 "on" / "off" / "unknown"：
	// off = 策略显式关闭实时保护 或 WinDefend 服务未运行；unknown = 两者都问不出来。
	RealtimeState string
}

// DefenderStatus 读取 Defender 排除项与实时保护状态。
//
// 排除项读 HKLM\...\Exclusions\{Paths,Processes,Extensions} 下条目名。
// 历史上有两种落盘布局（条目作为值名 / 作为子键名，随 Windows 版本与
// 写入方不同），这里把两种都读出来合并去重，避免只认一种导致漏报。
// 已知缺口：组策略下发的排除项在 HKLM\SOFTWARE\Policies\...\Exclusions，
// 属另一信任域，按本轮契约范围不采（需要时应在同处扩展，不动线协议）。
//
// 实时保护综合两路信号：Policies\Real-Time Protection\DisableRealtimeMonitoring
// （0/缺失=未禁用，1=禁用）+ WinDefend 服务运行态（SCM 简查，复用同包
// inventory_windows.go 已打开的 advapi32 句柄约定）。策略说关 → off；
// 服务没在跑 → off（防护事实上不在）；两者都确认不了 → unknown。
// 诚实缺席好过用 "on" 冒充——那会把"防护被关"伪装成"一切正常"。
func DefenderStatus() (DefenderInfo, error) {
	out := DefenderInfo{
		ExclusionPaths:      []string{},
		ExclusionProcesses:  []string{},
		ExclusionExtensions: []string{},
		RealtimeState:       "unknown",
	}

	// 排除项：任一子类读取失败记入 errs；键不存在（从未配置过排除）是
	// 空列表而非失败。全部数据源都问不出来才算整体失败。
	var errs []string
	for _, e := range []struct {
		key  string
		dst  *[]string
		name string
	}{
		{"Paths", &out.ExclusionPaths, "排除路径"},
		{"Processes", &out.ExclusionProcesses, "排除进程"},
		{"Extensions", &out.ExclusionExtensions, "排除扩展名"},
	} {
		got, err := defenderExclusionNames(e.key)
		if err != nil {
			errs = append(errs, e.name+": "+err.Error())
			continue
		}
		*e.dst = got
	}
	out.RealtimeState = defenderRealtimeState()
	if out.RealtimeState == "unknown" && len(errs) == 3 {
		return out, fmt.Errorf("Defender 状态采集全部失败: %s", strings.Join(errs, "; "))
	}
	return out, nil
}

// defenderExclusionNames 读一类排除项的条目名（值名 ∪ 子键名，去重排序）。
func defenderExclusionNames(kind string) ([]string, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Windows Defender\Exclusions\`+kind, registry.READ)
	if err != nil {
		if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
			return []string{}, nil // 从未配置过此类排除项：空，不是错
		}
		return nil, fmt.Errorf("打开 Exclusions\\%s 失败: %w", kind, err)
	}
	defer k.Close()

	seen := make(map[string]struct{}, 16)
	var out []string
	add := func(names []string) {
		for _, n := range names {
			n = strings.TrimSpace(n)
			if n == "" {
				continue
			}
			if _, dup := seen[n]; dup {
				continue
			}
			seen[n] = struct{}{}
			out = append(out, n)
		}
	}
	// 现行 MPPreference 把每条排除写成 REG_DWORD 值，名字即排除项
	if vals, err := k.ReadValueNames(-1); err == nil {
		add(vals)
	}
	// 部分版本/写入方把排除写成子键名
	if subs, err := k.ReadSubKeyNames(-1); err == nil {
		add(subs)
	}
	sort.Strings(out)
	return out, nil
}

// defenderRealtimeState 综合策略与服务状态给 out 实时保护判定。
func defenderRealtimeState() string {
	policyOff, policyKnown := false, false
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection`, registry.QUERY_VALUE); err == nil {
		if v, _, err := k.GetIntegerValue("DisableRealtimeMonitoring"); err == nil {
			policyKnown = true
			policyOff = v != 0
		}
		k.Close()
	}
	svcRunning, svcKnown := winDefendRunning()
	switch {
	case policyKnown && policyOff:
		return "off"
	case svcKnown && !svcRunning:
		return "off"
	case svcKnown && svcRunning:
		// 策略未禁用（或没写策略）且服务在跑：按 on 口径
		return "on"
	default:
		return "unknown"
	}
}

// winDefendRunning 简查 WinDefend 服务是否处于运行态（OpenSCManager →
// OpenService → QueryServiceStatus 三步，均只申请读权限）。
// known=false 表示查询链路本身失败（权限/服务缺失），与"没在跑"区分开。
func winDefendRunning() (running, known bool) {
	h, _, _ := procOpenSCManagerW.Call(0, 0, uintptr(scmConnect))
	if h == 0 {
		return false, false
	}
	defer func() { _, _, _ = procCloseServiceHandle.Call(h) }()

	namePtr, err := windows.UTF16PtrFromString("WinDefend")
	if err != nil {
		return false, false
	}
	hSvc, _, _ := procOpenServiceW.Call(h, uintptr(unsafe.Pointer(namePtr)), uintptr(svcQueryStatus))
	if hSvc == 0 {
		return false, false // 服务不存在（第三方接管）或无权查询
	}
	defer func() { _, _, _ = procCloseServiceHandle.Call(hSvc) }()

	// SERVICE_STATUS（x64）：7 个 DWORD，dwCurrentState 在偏移 4
	var st [7]uint32
	ret, _, _ := procQueryServiceStatusApi.Call(hSvc, uintptr(unsafe.Pointer(&st[0])))
	if ret == 0 {
		return false, false
	}
	return st[1] == serviceRunning, true
}

// ---------------------------------------------------------------- 防火墙

// FirewallProfile 是一个防火墙配置档的开关状态。
// Name 取值固定 domain / standard / public（对应注册表三个 profile 键）。
type FirewallProfile struct {
	Name    string
	Enabled bool
}

// FirewallProfiles 读三张防火墙配置档的 EnableFirewall 开关。
//
// 键存在但缺 EnableFirewall 值时按 Windows 默认（开启）处理并注明——
// 历史版本里该值确实可能缺席；整个 FirewallPolicy 键打不开才算失败。
// 输出顺序固定 domain → standard → public，保证节 hash 稳定。
func FirewallProfiles() ([]FirewallProfile, error) {
	base, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy`, registry.READ)
	if err != nil {
		return nil, fmt.Errorf("打开 FirewallPolicy 注册表键失败: %w", err)
	}
	defer base.Close()

	defs := []struct{ key, name string }{
		{"DomainProfile", "domain"},
		{"StandardProfile", "standard"},
		{"PublicProfile", "public"},
	}
	out := make([]FirewallProfile, 0, len(defs))
	for _, d := range defs {
		pk, err := registry.OpenKey(base, d.key, registry.QUERY_VALUE)
		if err != nil {
			return nil, fmt.Errorf("打开防火墙 %s 失败: %w", d.key, err)
		}
		enabled := true // 缺值 = Windows 默认开启
		if v, _, err := pk.GetIntegerValue("EnableFirewall"); err == nil {
			enabled = v != 0
		}
		pk.Close()
		out = append(out, FirewallProfile{Name: d.name, Enabled: enabled})
	}
	return out, nil
}

// ---------------------------------------------------------------- 本地管理员组

// AccountInfo 是本地管理员组的一个成员。
// SID 拿不到时留空（成员类型异常等），Name 仍保留——keyed diff 以名为键。
type AccountInfo struct {
	Name string
	SID  string
}

// localGroupMembersInfo2 对齐 LOCALGROUP_MEMBERS_INFO_2 的实际内存布局
// （x64 实测 24 字节步长）：PSID + SID_NAME_USE(4B) + 4B 对齐填充 + LPWSTR。
// 头文件文本里该结构只有 PSID+LPWSTR 两个字段，但真实落盘在两者之间还有
// 一个 sidusage 枚举——按字面两字段解析会把 usage 当成名字指针解引用
// （真机踩过：读出 0x1 直接段错误）。
type localGroupMembersInfo2 struct {
	// 字段用 unsafe.Pointer 而非 uintptr：NetAPI 返回的缓冲里的
	// SID/名字指针要保持"指针语义"解引用，uintptr→Pointer 的中途转换
	// 会触发 vet 的 unsafe 误用检查（GC 也可能在这两步之间移动目标）。
	SID   unsafe.Pointer
	Usage uint32
	_     uint32
	Name  unsafe.Pointer
}

// LocalAdmins 枚举本地 Administrators 组成员（NetLocalGroupGetMembers，
// level 2 同时给 SID 与 domain\name）。
//
// 组名不硬编码 "Administrators"：先从内建 SID S-1-5-32-544 反查本机组名
// （本地化系统上别名不同，硬编码在非英文系统会查空）。反查失败回退英文
// 名再试一次。NetAPI 缓冲用 NetApiBufferFree 统一释放，SID/名字在释放前
// 全部转成 Go 字符串。输出按名字排序保证节 hash 稳定。
func LocalAdmins() ([]AccountInfo, error) {
	groupName, err := builtinAdministratorsName()
	if err != nil {
		groupName = "Administrators" // 反查失败回退英文名（非本地化系统上必对）
	}
	groupPtr, err := windows.UTF16PtrFromString(groupName)
	if err != nil {
		return nil, fmt.Errorf("组名非法: %w", err)
	}

	// 缓冲指针全程保持 unsafe.Pointer 语义：作为 syscall 出参时传它的地址，
	// 之后所有解引用都基于指针本身，不做 uintptr 中转（见结构体注释）。
	var buf unsafe.Pointer
	var read, total uint32
	ret, _, _ := procNetLocalGroupGetMemb.Call(
		0, // servername=nil：本机
		uintptr(unsafe.Pointer(groupPtr)),
		2, // level 2：SID + domain\name
		uintptr(unsafe.Pointer(&buf)),
		uintptr(netPreferredLength),
		uintptr(unsafe.Pointer(&read)),
		uintptr(unsafe.Pointer(&total)),
		0) // resumehandle=nil：MAX_PREFERRED_LENGTH 下一次拿全
	if ret != 0 {
		return nil, fmt.Errorf("NetLocalGroupGetMembers(%s) 失败: status=%d", groupName, ret)
	}
	defer func() { _, _, _ = procNetApiBufferFree.Call(uintptr(buf)) }()

	out := make([]AccountInfo, 0, read)
	for i := uint32(0); i < read; i++ {
		e := (*localGroupMembersInfo2)(unsafe.Add(buf, uintptr(i)*unsafe.Sizeof(localGroupMembersInfo2{})))
		ai := AccountInfo{}
		if e.Name != nil {
			ai.Name = windows.UTF16PtrToString((*uint16)(e.Name))
		}
		if e.SID != nil {
			// String() 内部走 ConvertSidToStringSidW，失败返回空串——
			// 正好落进"拿不到 SID 就留空"的口径
			ai.SID = (*windows.SID)(e.SID).String()
		}
		out = append(out, ai)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// builtinAdministratorsName 从内建管理员 SID 反查本机组名（本地化兼容）。
func builtinAdministratorsName() (string, error) {
	sid, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return "", fmt.Errorf("构造内建管理员 SID 失败: %w", err)
	}
	name, _, _, err := sid.LookupAccount("")
	if err != nil {
		return "", fmt.Errorf("反查管理员组名失败: %w", err)
	}
	if name == "" {
		return "", errors.New("反查管理员组名为空")
	}
	return name, nil
}
