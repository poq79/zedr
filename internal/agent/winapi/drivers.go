//go:build windows
// +build windows

package winapi

// drivers.go：已加载内核驱动枚举（psapi 只读面）。
//
// 用途：rootkit/驱动持久化画像——谁加载了内核驱动、从哪加载、
// 原始文件大小与修改时间（时间戳异常是驱动落地伪造的常用信号）。
// EnumDeviceDrivers 是标准 psapi 导出，普通用户可用，无特权要求。
//
// 为什么路径要归一到 DOS 形态：GetDeviceDriverFileNameW 返回的是 NT
// 路径（\Device\HarddiskVolumeN\... 或 \SystemRoot\...），下游要拿它
// os.Stat 与展示，NT 路径两者都做不到，必须映射回盘符。

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modPsapi = windows.NewLazySystemDLL("psapi.dll")

	procEnumDeviceDrivers        = modPsapi.NewProc("EnumDeviceDrivers")
	procGetDeviceDriverFileNameW = modPsapi.NewProc("GetDeviceDriverFileNameW")
)

// DriverInfo 是一条已加载驱动。
type DriverInfo struct {
	Name  string    // 路径 basename，保持 API 返回的原始大小写
	Path  string    // 已归一（\Device\HarddiskVolumeN → 盘符）；无法映射时原样保留
	Size  int64     // os.Stat 的文件大小；拿不到（路径无法映射/文件消失）置 -1
	MTime time.Time // os.Stat 的修改时间；拿不到归零值
}

// driverEnumMaxDrivers 是单次枚举的硬上限：现代 Windows 加载的驱动
// 典型 100~400 个，4096 已经是异常环境的防炸阈值。
const driverEnumMaxDrivers = 4096

// LoadedDrivers 枚举当前已加载的全部内核驱动，按 Path 排序。
// 0 个驱动（成功返回空表）不是错误；API 调用失败才是 error。
func LoadedDrivers() ([]DriverInfo, error) {
	loadDosDriveMap()

	buf := make([]uintptr, 1024)
	var needed uint32
	ret, _, _ := procEnumDeviceDrivers.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf))*unsafe.Sizeof(uintptr(0)),
		uintptr(unsafe.Pointer(&needed)))
	if ret == 0 {
		if needed == 0 {
			return nil, fmt.Errorf("EnumDeviceDrivers 失败（未回填所需长度）")
		}
		// 缓冲不足：lpcbNeeded 回填的是所需字节数（官方样例按
		// cbNeeded/sizeof(LPVOID) 折算条数），扩容重试一次。
		n := needed/uint32(unsafe.Sizeof(uintptr(0))) + 16
		if n > driverEnumMaxDrivers {
			n = driverEnumMaxDrivers
		}
		buf = make([]uintptr, n)
		ret, _, _ = procEnumDeviceDrivers.Call(
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(len(buf))*unsafe.Sizeof(uintptr(0)),
			uintptr(unsafe.Pointer(&needed)))
		if ret == 0 {
			return nil, fmt.Errorf("EnumDeviceDrivers 重试失败")
		}
	}
	count := int(needed) / int(unsafe.Sizeof(uintptr(0)))
	if count > len(buf) {
		count = len(buf)
	}

	out := make([]DriverInfo, 0, count)
	for i := 0; i < count; i++ {
		if buf[i] == 0 {
			continue
		}
		raw := driverImageFileName(buf[i])
		if raw == "" {
			// 拿不到路径的条目（基址残留/瞬时卸载）没有分析价值，跳过
			continue
		}
		path := ntToDosPath(raw)
		info := DriverInfo{
			Name: filepath.Base(raw),
			Path: path,
			Size: -1, // 默认"拿不到"，Stat 成功再覆盖
		}
		if st, err := os.Stat(path); err == nil {
			info.Size = st.Size()
			info.MTime = st.ModTime()
		}
		out = append(out, info)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, nil
}

// driverImageFileName 取单个驱动的 NT 镜像路径（GetDeviceDriverFileNameW）。
func driverImageFileName(base uintptr) string {
	var buf [1024]uint16
	n, _, _ := procGetDeviceDriverFileNameW.Call(
		base, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	if n == 0 || n > uintptr(len(buf)) {
		return ""
	}
	return windows.UTF16ToString(buf[:n])
}

// ---------------------------------------------------------------- NT → DOS 路径归一

// driveMapEntry 是"NT 卷设备路径 → DOS 盘符"的一条映射。
type driveMapEntry struct {
	dev    string // 如 \Device\HarddiskVolume3
	letter string // 如 C:
}

var (
	driveMapOnce  sync.Once
	driveMap      []driveMapEntry
	systemRootDir string // %SystemRoot%，即 Windows 目录的 DOS 路径（如 C:\Windows）
)

// loadDosDriveMap 一次性建立卷映射表。
// 用 sync.Once 缓存的原因：LoadedDrivers 每次要遍历 26 个盘符的
// QueryDosDevice + 解析 SystemRoot 符号链接，驱动列表本身是分钟级
// 低频采集，盘符表在运行期几乎不变（USB 盘热插导致的短暂失真
// 只影响新落盘驱动，可接受）。
func loadDosDriveMap() {
	driveMapOnce.Do(func() {
		for c := 'A'; c <= 'Z'; c++ {
			dev, err := DevicePathForDriveLetter(string(c) + ":")
			if err != nil {
				continue // 无此盘符，正常
			}
			driveMap = append(driveMap, driveMapEntry{dev: dev, letter: strings.ToUpper(string(c)) + ":"})
		}
		systemRootDir = strings.TrimSuffix(os.Getenv("SystemRoot"), `\`)
	})
}

// ntToDosPath 把 GetDeviceDriverFileNameW 返回的 NT 路径归一为 DOS 路径。
//
// 处理四类形态：
//   - \Device\HarddiskVolumeN\rest → 盘符:\rest（26 盘符反查）
//   - \SystemRoot\rest → %SystemRoot%\rest（即 Windows 目录 + 剩余部分）
//   - \\?\ 前缀已是 Win32 命名空间，原样返回
//   - \??\ 前缀剥掉后按上述规则继续
//
// 无法映射的（\Device\000000xx 这类非卷设备）原样保留——瞎猜一个盘符
// 会让 os.Stat 指到错误文件，比"拿不到大小"危险得多。
func ntToDosPath(raw string) string {
	p := strings.TrimSpace(raw)
	if p == "" {
		return ""
	}
	if strings.HasPrefix(p, `\\?\`) {
		return p
	}
	// \??\ 是同一 Win32 路径的本地设备命名空间形态（\??\C:\...，第三方
	// 驱动路径实测出现），剥掉前缀即是 DOS 路径；剥完若仍是 NT 设备
	// 路径则继续走卷映射
	if strings.HasPrefix(p, `\??\`) {
		p = p[len(`\??\`):]
		if len(p) >= 2 && p[1] == ':' {
			return p
		}
	}
	// \SystemRoot 是指向启动卷 Windows 目录的符号链接。不能走
	// QueryDosDevice("SystemRoot")：它挂在 NT 命名空间根（\）而不是
	// \??（QueryDosDevice 只看后者，实测返回"找不到文件"）；
	// SystemRoot 环境变量就是同一目标的 DOS 形态（C:\Windows），
	// 系统恒设置，直接用它平移剩余部分。
	if len(p) >= len(`\SystemRoot`) && strings.EqualFold(p[:len(`\SystemRoot`)], `\SystemRoot`) && systemRootDir != "" {
		p = filepath.Join(systemRootDir, p[len(`\SystemRoot`):])
	}
	for _, m := range driveMap {
		if len(p) >= len(m.dev) && strings.EqualFold(p[:len(m.dev)], m.dev) {
			rest := strings.TrimPrefix(p[len(m.dev):], `\`)
			if rest == "" {
				return m.letter + `\`
			}
			return m.letter + `\` + rest
		}
	}
	return p
}
