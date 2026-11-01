package winapi

// securitycheck.go：安全基线检查用的只读注册表 DWORD 读取（LIVE-TUNNEL §13.2）。
//
// 为什么单独抽一个 RegDWORD，而不是让 liveapi 直接用 registry.OpenKey：
//   - 基线检查的每一档都要区分三种结果——值存在、值/键不存在（按产品
//     默认值或"未配置"处理）、读取失败（权限等，必须降级为 info 而不是
//     猜一个值）。把这三态收口在一个函数里，10 个检查项就不会各写一遍
//     且写错错误分支；
//   - 只开 QUERY_VALUE，不申请写权限，也不暴露任何 Set/Delete 入口，
//     与 registry.go 的只读纪律一致。
//
// 注意不要去动 registry.go（v2 资产侦查的 RegGetValueW 封装），两者
// 面向不同数据类型：那边读字符串，这里读 DWORD，互不替代。

import (
	"errors"
	"fmt"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// RegDWORD 读取一个 REG_DWORD 值。
//
// 返回语义刻意分三态：
//   - (v, true, nil)：值存在且读出；
//   - (0, false, nil)：键或值不存在——调用方按"未配置"分支处理；
//   - (_, false, err)：打开键/读取值失败（权限、类型不是整数等）。
//     调用方应把错误当作"无法判断"，绝不拿默认值冒充测量结果。
//
// 键不存在也返回 ok=false：注册表 API 无法在单次调用里区分"键不存在"
// 与"值不存在"，而基线检查对两者的处理完全相同（都是未配置）。
func RegDWORD(root registry.Key, path, name string) (uint32, bool, error) {
	k, err := registry.OpenKey(root, path, registry.QUERY_VALUE)
	if err != nil {
		if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) ||
			errors.Is(err, windows.ERROR_PATH_NOT_FOUND) {
			return 0, false, nil
		}
		return 0, false, fmt.Errorf("打开注册表键 %q 失败: %w", path, err)
	}
	defer k.Close()

	v, _, err := k.GetIntegerValue(name)
	if err != nil {
		if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
			return 0, false, nil
		}
		return 0, false, fmt.Errorf("读取注册表值 %q\\%q 失败: %w", path, name, err)
	}
	// 安全开关在 Windows 上全部是 REG_DWORD。QWORD 超出 32 位时直接报错，
	// 不做静默截断——截断可能把 0x100000000 变成 0，把"异常配置"伪装成
	// "安全值"。
	if v > uint64(^uint32(0)) {
		return 0, false, fmt.Errorf("注册表值 %q\\%q 是 QWORD 且超出 DWORD 范围: %d", path, name, v)
	}
	return uint32(v), true, nil
}
