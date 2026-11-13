//go:build linux

package detect

// systemRoot 返回"系统目录"前缀（Linux 口径）。Windows 版用它判定模块
// 是否来自系统目录（c:\windows 前缀）；Linux 对应 /usr——发行版管理的
// 二进制几乎都在 /usr 下（usrmerge 后 /bin→/usr/bin）。未在 Linux 实机
// 验证，口径按 FHS 3.0 / usrmerge 惯例。
func systemRoot() string {
	return "/usr"
}
