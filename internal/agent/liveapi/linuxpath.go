// 本文件 NEUTRAL：Linux 文件面的"纯逻辑"（无 IO、无构建标签）。
// 放在中性文件的原因：验证口径是"Windows 上跑纯逻辑单测"——带 linux
// 标签的文件在 Windows 上不参与编译，测试就覆盖不到；Linux 专属 IO 壳
// 在 platform_linux.go，这里只放可脱离平台验证的判定/映射函数。
//
// 未在 Linux 实机验证（本机无 Linux 测试环境）；验证口径 = GOOS=linux
// 交叉编译 + 本文件单测在 Windows 上运行。
package liveapi

// linuxpath.go：Linux 侧 fs* 端点的路径校验纯逻辑 + 文件属性映射。

import (
	"os"
	"path"
	"strings"

	"zedr/internal/platform/apperr"
)

// validateLinuxAbsPath 是 Linux 版 fs* 端点路径校验（validateFSPath 的
// Linux 实现，platform_linux.go 直通调用）。
//
// 刻意用 path 包（POSIX 语义）而不是 filepath：filepath.IsAbs 在 Windows
// 上要求盘符（"/tmp/x" 判 false），filepath.Clean 会把分隔符转成 "\\"——
// 本逻辑要在 Windows 编译下被单测锁定（验证口径），用 POSIX path 包才能
// 在两个构建平台上行为一致；Linux 生产构建下 path 与 filepath 等价。
//
// 与 Windows 规则的分治（LiveFS 移植雷区）：Windows 版要求 VolumeName
// 非空（`C:\`），Linux 绝对路径没有盘符概念——若复用 Windows 规则，
// Linux 的 `/tmp/x` 会被全部拒绝（历史记忆里踩过的坑）。Linux 规则：
//   - 非空（空 = 400）；
//   - 拒绝 NUL 字节（内核路径以 NUL 结尾，含 NUL 的请求只会造出截断
//     路径的误导性结果）；
//   - 以 / 起的绝对路径（拒绝相对路径，其语义随探针 cwd 漂移）；
//   - 不允许出现 `..` 路径段；
//   - Clean 后必须仍落在允许根（Linux 的允许根就是文件系统根 "/"）内。
//
// `..` 检查与 Windows 同理必须看原始输入：Clean 会把 `/a/../../b` 解析成
// `/b`，对 Clean 结果检查恒为假。逐段检查就是对穿越的拒绝——绝对路径
// 输入经 Clean 后不可能逃出 "/"，双保险的最后一道是"Clean 结果仍为绝对
// 路径"这个不变式断言（破坏它意味着平台语义被改坏，宁可请求失败）。
//
// 诚实边界：本校验不解析 symlink——调查面允许沿符号链接读（与 Windows
// 侧可读 reparse 点同口径），探针以只读方式运行，风险面与"直接输入该
// 路径"完全一致。
func validateLinuxAbsPath(raw string) (string, error) {
	if raw == "" {
		return "", apperr.Invalid("path 参数必填")
	}
	if strings.IndexByte(raw, 0) >= 0 {
		return "", apperr.Invalid("path 不允许包含 NUL 字节")
	}
	if !strings.HasPrefix(raw, "/") {
		return "", apperr.Invalid("path 必须是绝对路径（以 / 开头）")
	}
	for _, seg := range strings.Split(raw, "/") {
		if seg == ".." {
			return "", apperr.Invalid("path 不允许包含 ..")
		}
	}
	clean := path.Clean(raw)
	if !path.IsAbs(clean) {
		// 不变式断言：绝对路径输入经 Clean 必然仍绝对（仍在允许根内）。
		// 走到这里说明平台路径语义被破坏，按 400 拒绝而不是放行。
		return "", apperr.Invalid("path 解析后逃出根目录")
	}
	return clean, nil
}

// attrsFromStat 把 stat 信息映射成 Entry 的四个属性位（Linux 版 fileAttrs
// 钩子的纯映射部分）。映射口径是"诚实近似"而非硬凑 Windows 语义：
//   - Hidden：点开头文件（ls 不显示的约定，与 FILE_ATTRIBUTE_HIDDEN 的
//     用户语义一致）；
//   - Readonly：无任何写位（u/g/o 均不可写——与 FILE_ATTRIBUTE_READONLY
//     的"不可写"语义一致）；
//   - Reparse：符号链接（对应 Windows 的 reparse point 语义，前端据此
//     不进入搜索、显示跳转标记）；
//   - System：Linux 无"系统文件"属性语义，恒 false（不猜测，缺失即未知）。
func attrsFromStat(name string, mode os.FileMode) fileAttrFlags {
	return fileAttrFlags{
		Hidden:   strings.HasPrefix(name, "."),
		System:   false,
		Readonly: mode&0o222 == 0,
		Reparse:  mode&os.ModeSymlink != 0,
	}
}
