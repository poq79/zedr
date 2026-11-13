//go:build windows
// +build windows

package main

// 登录自启动（HKCU Run key）。
//
// 为什么不用 HKLM / 服务 / 计划任务：托盘是用户会话进程，写 HKCU
// 不需要管理员权限，用户可以在托盘菜单里一键开关；这也和 Portmaster
// 安装器的做法一致（Notifier 的 Run 条目随安装写入、登录时启动）。

import (
	"fmt"
	"os"

	"golang.org/x/sys/windows/registry"
)

const (
	runKeyPath   = `Software\Microsoft\Windows\CurrentVersion\Run`
	runValueName = "Z-EDR Panel"
)

// autostartEnabled 检查托盘是否已写入登录自启动。
func autostartEnabled() bool {
	k, err := registry.OpenKey(registry.CURRENT_USER, runKeyPath, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer k.Close()
	v, _, err := k.GetStringValue(runValueName)
	return err == nil && v != ""
}

// setAutostart 写入或删除登录自启动条目。
// 条目内容固定为 "当前exe路径" -tray——用户把 exe 挪了位置后，
// 下次切换开关会自动纠正路径。
func setAutostart(on bool) error {
	k, err := registry.OpenKey(registry.CURRENT_USER, runKeyPath, registry.SET_VALUE|registry.QUERY_VALUE)
	if err != nil {
		return fmt.Errorf("打开注册表失败: %w", err)
	}
	defer k.Close()
	if !on {
		// 值不存在时 DeleteValue 返回错误，但语义上就是"已关闭"
		_ = k.DeleteValue(runValueName)
		return nil
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	return k.SetStringValue(runValueName, `"`+exe+`" -tray`)
}