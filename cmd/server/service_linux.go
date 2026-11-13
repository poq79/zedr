//go:build linux

package main

import "flag"

// serviceFlags 在 Linux 下不注册服务化旗子：进程生命周期归 systemd
// 管（单元文件见 scripts/deploy 的安装脚本），-install/-uninstall 是
// Windows SCM 概念。给一个提示位避免运维照搬 Windows 命令行踩坑。
func serviceFlags() {
	flag.Bool("install", false, "（仅 Windows）安装为 SCM 服务——Linux 请用 systemd 单元文件")
}

// serviceFlagsHandled Linux 恒 false：不拦截主流程。
func serviceFlagsHandled() bool { return false }

// runIfServiceMode Linux 恒 false：没有 SCM 拉起形态，永远走信号处理主流程。
func runIfServiceMode() bool { return false }
