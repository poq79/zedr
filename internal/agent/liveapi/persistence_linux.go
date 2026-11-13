//go:build linux

// persistence_linux.go：/persistence 的 Linux 实现（cron/systemd/autostart
// 轻量只读枚举）。
//
// 与 internal/agent/persist 枚举器是两份实现的原因：persist 包不在本次
// 移植的所有权范围内，其 Linux 枚举服务于检测管线的基线 diff（打分/去重/
// 基线语义）；本端点要的是"现在这张表上有什么"的一次性快照。解析逻辑
// （行语法）在 persist_linuxparse.go（中性，单测锁口径）。
//
// 与 Windows 版的线协议契约对齐：item 形状/排序/截断语义一致；三来源
// 映射到 counts 的三个既有键（前端零分叉），映射是刻意的语义对齐而非
// 硬凑——systemd unit 是"开机自跑的服务"（→ service）、cron 条目是
// "定时执行"（→ task）、XDG autostart/rc.local 是"登录/开机启动项"
// （→ startup）。Location 恒为来源文件绝对路径，调查者可直达原文。
//
// 预算口径：纯文件读取（几十个小文件），不设时间预算；条目上限与
// Windows 同（2000，超出截断 + truncated）。单文件读失败跳过不放大
// （目录被并发改动/权限差异是常态）。
//
// 未在 Linux 实机验证（本机无 Linux 测试环境）；验证口径 = GOOS=linux
// 交叉编译 + persist_linuxparse.go 纯逻辑单测。
package liveapi

// persistence_linux.go：持久化总览（Linux 口径）。

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"zedr/internal/platform/httpx"
)

// HandlePersistence 返回 GET /persistence 的 Linux handler（包级构造函数，
// 与 Windows 版同签名，liveapi.New 统一接线）。线协议形状（item/counts/
// 排序/截断）在中性文件 persist_linuxparse.go，双平台契约一致。
func HandlePersistence() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		raws := enumerateLinuxPersistence()
		httpx.WriteJSON(w, r, http.StatusOK, buildLinuxPersistenceResult(raws, time.Now().UTC()))
	}
}

// ---------------------------------------------------------------- 枚举（IO 壳）

// enumerateLinuxPersistence 收集全部三来源的原始条目。单文件/单目录读
// 失败静默跳过（权限差异/竞态是常态），能拿到多少拿多少。
func enumerateLinuxPersistence() []linuxPersistRaw {
	var out []linuxPersistRaw
	out = append(out, enumSystemdUnits()...)
	out = append(out, enumCronEntries()...)
	out = append(out, enumAutostartEntries()...)
	return out
}

// systemdUnitDirs 是 unit 文件的搜索目录（顺序即优先级：管理员覆盖 >
// 发行版自带）。real enabled 判定用"管理员目录有实体文件或被 .wants
// 引用"近似（真 enabled 态要 shell 出 systemctl，只读纪律不引入）。
var systemdUnitDirs = []string{"/etc/systemd/system", "/run/systemd/system", "/usr/lib/systemd/system"}

// enumSystemdUnits 枚举 *.service unit（user unit 的 ~/.config/systemd
// v1 不收——服务器场景机器级驻留为主，诚实边界）。
func enumSystemdUnits() []linuxPersistRaw {
	var out []linuxPersistRaw
	for _, dir := range systemdUnitDirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".service") {
				continue
			}
			path := filepath.Join(dir, e.Name())
			data, err := os.ReadFile(path)
			if err != nil {
				continue
			}
			exec, ok := parseSystemdUnitExec(data)
			if !ok {
				continue // 无 ExecStart 的 unit（timer 挂载目标等）不是执行驻留
			}
			// enabled 近似：/etc（管理员放置）= true；/run（运行时生成）
			// = true；仅 /usr/lib（发行版自带、未被覆盖/未启用）= false
			enabled := dir != "/usr/lib/systemd/system"
			out = append(out, linuxPersistRaw{
				Source:   "service",
				Name:     e.Name(),
				Command:  exec,
				Location: path,
				Enabled:  enabled,
			})
		}
	}
	return out
}

// enumCronEntries 枚举 /etc/crontab、/etc/cron.d/*、用户 spool。
func enumCronEntries() []linuxPersistRaw {
	var out []linuxPersistRaw

	// /etc/crontab 单文件
	if data, err := os.ReadFile("/etc/crontab"); err == nil {
		out = append(out, parseCrontabFile("/etc/crontab", data, true)...)
	}
	// /etc/cron.d/* 片段
	if entries, err := os.ReadDir("/etc/cron.d"); err == nil {
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			path := filepath.Join("/etc/cron.d", e.Name())
			if data, err := os.ReadFile(path); err == nil {
				out = append(out, parseCrontabFile(path, data, true)...)
			}
		}
	}
	// 用户 spool（Debian 系 /var/spool/cron/crontabs，RHEL 系
	// /var/spool/cron；两侧都试，行无 user 列）
	for _, dir := range []string{"/var/spool/cron/crontabs", "/var/spool/cron"} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			path := filepath.Join(dir, e.Name())
			if data, err := os.ReadFile(path); err == nil {
				for _, item := range parseCrontabFile(path, data, false) {
					item.User = e.Name() // spool 文件名即用户名（无 user 列的补偿口径）
					out = append(out, item)
				}
			}
		}
	}
	return out
}

// autostartDirsLocal 返回 XDG autostart 搜索目录（用户 > 全局；每次调用
// 现算，不做包级可变状态——handler 并发进入时共享切片是数据竞争）。
func autostartDirsLocal() []string {
	dirs := []string{"/etc/xdg/autostart", "/root/.config/autostart"}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		dirs = append([]string{filepath.Join(home, ".config", "autostart")}, dirs...)
	}
	return dirs
}

// enumAutostartEntries 枚举 XDG autostart .desktop + /etc/rc.local。
func enumAutostartEntries() []linuxPersistRaw {
	var out []linuxPersistRaw
	for _, dir := range autostartDirsLocal() {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".desktop") {
				continue
			}
			path := filepath.Join(dir, e.Name())
			data, err := os.ReadFile(path)
			if err != nil {
				continue
			}
			name, exec, hidden := parseAutostartDesktop(data)
			if exec == "" {
				continue // 无 Exec 的条目不构成执行驻留
			}
			if name == "" {
				name = e.Name()
			}
			out = append(out, linuxPersistRaw{
				Source:   "startup",
				Name:     name,
				Command:  exec,
				Location: path,
				// Hidden=true 桌面不启动，但仍是现场画像的一部分：
				// Enabled 如实为 false，调查者据此看见"被藏起来的项"
				Enabled: !hidden,
			})
		}
	}
	// rc.local：存在即可执行（由 rc-local.service 拉起）
	if data, err := os.ReadFile("/etc/rc.local"); err == nil {
		out = append(out, linuxPersistRaw{
			Source:   "startup",
			Name:     "/etc/rc.local",
			Command:  strings.TrimSpace(firstScriptCmd(data)),
			Location: "/etc/rc.local",
			Enabled:  true,
		})
	}
	return out
}

// firstScriptCmd 取 shell 脚本里首个非注释、非 shebang 的非空行。
func firstScriptCmd(data []byte) string {
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		return line
	}
	return ""
}
