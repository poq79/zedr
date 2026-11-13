//go:build windows
// +build windows

// Package winapi 的 USB/可移动介质采集（摆渡攻击 T1091 检测的采集层）。
//
// 主线方案（usbwatch）：周期 diff 可移动卷 → 新卷到达告警 + 该卷根目录
// 挂临时 RDCW 监控（复用 FileWatcher，接线在主线）。本文件提供它依赖的
// 两个纯采集原语：RemovableVolumes（当前在位的可移动卷）与
// UsbStorDevices（USBSTOR 注册表设备历史）。
//
// 诚实边界（调用方必须知道，否则会误读结果）：
//   - USBSTOR 枚举返回的是"曾经插过"的全部 USB 存储设备，含当前不在场的
//     ——它不是"现在插着什么"的清单；在位判定只能靠 RemovableVolumes
//     周期 diff，两者不要混用。
//   - LastWriteTime 是注册表键的最后写入时刻，不是接入时刻。它近似
//     "首次接入"（驱动枚举设备时写键），但重新插拔、驱动更新、系统写
//     Properties 子键都会刷新它——只当模糊时间线证据，别当精确时戳。
//   - 序列号键名可能含 & 与 #（如 "07A1...&0"，& 后是实例号）。本层只做
//     路径拼接不做转义（注册表键名本身不含 \，拼接安全）；Friendly 解析
//     只认 Ven_/Prod_ 段，不拿串号段凑数。
//   - GetDriveTypeW 报的是设备类型而非介质在位：空读卡器一样返回
//     DRIVE_REMOVABLE。调用方拿到盘符后对根目录的任何操作（挂 RDCW、
//     列目录）都可能因无介质失败，按"卷不可用"降级即可。
package winapi

import (
	"sort"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// driveRemovable 是 GetDriveTypeW 的 DRIVE_REMOVABLE（2）。
// driveFixed=3 的先例在 inventory_windows.go。这里必须正向匹配 2 而不是
// 写 != driveFixed：网络盘(4)/光驱(5)/RAM 盘(6) 同样不是可移动介质。
const driveRemovable = 2

// RemovableVolumes 返回当前可移动介质盘符（形如 "E:"），稳定排序。
//
// 只收 GetDriveTypeW == DRIVE_REMOVABLE(2)；固定盘/网络盘/光驱不收。
// 遍历 A..Z 天然有序，无需再排。GetLogicalDrives 失败返回空切片：
// 单次枚举失败不应打断调用方的周期 diff，下一轮自然重试。
//
// 边界：只判设备类型，不探介质在位（空读卡器也返回 2，见包注释）。
func RemovableVolumes() []string {
	out := make([]string, 0, 4)
	mask, err := windows.GetLogicalDrives()
	if err != nil {
		return out
	}
	for i := 0; i < 26; i++ {
		if mask&(1<<uint(i)) == 0 {
			continue
		}
		vol := string(rune('A'+i)) + ":"
		root, err := windows.UTF16PtrFromString(vol + `\`)
		if err != nil {
			continue // 纯 ASCII 路径不可能失败，防御性跳过
		}
		typ, _, _ := procGetDriveTypeW.Call(uintptr(unsafe.Pointer(root)))
		if typ != driveRemovable {
			continue
		}
		out = append(out, vol)
	}
	return out
}

// UsbStorDevice 是一条 USB 存储设备历史记录（来自 USBSTOR 枚举键）。
type UsbStorDevice struct {
	// Key 是注册表键相对路径（相对 HKLM\SYSTEM\CurrentControlSet\Enum），
	// 形如 USBSTOR\Disk&Ven_X&Prod_Y\<序列号>，作基线 diff 的稳定标识。
	// 序列号段可能含 & 与 #，消费方不要按 & 拆它。
	Key string
	// Friendly 是从设备类型键名解析的友好名："Ven_X Prod_Y"；
	// 解析失败给设备类型键名原串（即去掉串号后的键尾段）。
	Friendly string
	// LastWrite 是该序列号键的最后写入时刻（RegQueryInfoKey，经
	// registry.Key.Stat 取得）。近似"首次接入时刻"，非精确（见包注释）；
	// 序列号键与设备类型键都拿不到时为零值。
	LastWrite time.Time
}

// usbstorEnumPath 是 USBSTOR 枚举根键（相对 HKLM）。
const usbstorEnumPath = `SYSTEM\CurrentControlSet\Enum\USBSTOR`

// UsbStorDevices 枚举 HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR 的
// 直接子键（设备类型键，如 Disk&Ven_X&Prod_Y）与其子键（序列号键），
// 每个序列号键一条记录，按 Key 稳定排序（基线 diff 需要确定性输出）。
//
// 键不存在（本机从无 USB 存储历史）/无权限/枚举失败：返回空切片 +
// nil 错误——历史枚举失败不应打断主线；单个设备键失败只跳过该设备。
func UsbStorDevices() []UsbStorDevice {
	out := make([]UsbStorDevice, 0, 8)
	root, err := registry.OpenKey(registry.LOCAL_MACHINE, usbstorEnumPath, registry.READ)
	if err != nil {
		// 与 persist.go 同口径：权限不足/键不存在按"无数据"处理，不告警。
		return out
	}
	defer root.Close()

	devKeys, err := root.ReadSubKeyNames(-1)
	if err != nil {
		return out
	}
	for _, dev := range devKeys {
		out = append(out, usbstorEnumDevice(root, dev)...)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}

// usbstorEnumDevice 枚举一个设备类型键（如 Disk&Ven_X&Prod_Y）下的全部
// 序列号键。设备类型键本身的 LastWriteTime 作为串号键取不到时的兜底
// （串号键极少见地打不开时，记录仍带可用的近似时间）。
func usbstorEnumDevice(root registry.Key, dev string) []UsbStorDevice {
	dk, err := registry.OpenKey(root, dev, registry.READ)
	if err != nil {
		return nil
	}
	defer dk.Close()

	serials, err := dk.ReadSubKeyNames(-1)
	if err != nil {
		return nil
	}
	devWrite := keyLastWrite(dk)

	out := make([]UsbStorDevice, 0, len(serials))
	for _, serial := range serials {
		lastWrite := devWrite
		if sk, err := registry.OpenKey(dk, serial, registry.QUERY_VALUE); err == nil {
			if lw := keyLastWrite(sk); !lw.IsZero() {
				lastWrite = lw
			}
			sk.Close()
		}
		out = append(out, UsbStorDevice{
			Key:       `USBSTOR\` + dev + `\` + serial,
			Friendly:  usbstorFriendly(dev),
			LastWrite: lastWrite,
		})
	}
	return out
}

// usbstorFriendly 从 USBSTOR 设备类型键名解析友好名。
//
// 键名形如 "Disk&Ven_Kingston&Prod_DataTraveler_3.0"（可带 &Rev_ 段）：
// 取 Ven_/Prod_ 段（前缀大小写不敏感、段内保留原大小写）以空格连接，
// 规整为 "Ven_Kingston Prod_DataTraveler_3.0"。不含 Ven_/Prod_ 段的
// 非典型键名视为解析失败，返回原键名，保证 Friendly 恒非空。
func usbstorFriendly(deviceKey string) string {
	var keep []string
	for _, seg := range strings.Split(deviceKey, "&") {
		lower := strings.ToLower(seg)
		if strings.HasPrefix(lower, "ven_") || strings.HasPrefix(lower, "prod_") {
			keep = append(keep, seg)
		}
	}
	if len(keep) == 0 {
		return deviceKey
	}
	return strings.Join(keep, " ")
}

// keyLastWrite 返回键的最后写入时刻；失败返回零值 time.Time。
//
// 绑定方式：registry.Key.Stat 内部就是对当前句柄调 advapi32 的
// RegQueryInfoKey，KeyInfo.ModTime 再把 FILETIME 转成 time.Time——
// x/sys v0.49.0 已有现成封装，不需要走 LazyProc
// modAdvapi32.NewProc("RegQueryInfoKeyW")（那是给无封装场景准备的；
// LazyProc 的 err 恒非 nil、判错只看返回码，是本仓实锤，此处绕开了）。
func keyLastWrite(k registry.Key) time.Time {
	ki, err := k.Stat()
	if err != nil {
		return time.Time{}
	}
	return ki.ModTime()
}
