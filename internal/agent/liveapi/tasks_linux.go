//go:build linux

// tasks_linux.go：/tasks 的 Linux 实现（IO 壳）。
//
// 两类调度面收敛成与 Windows Task Scheduler 同形的清单：
//  1. cron：/etc/crontab、/etc/cron.d/*、用户 spool（Debian
//     /var/spool/cron/crontabs、RHEL /var/spool/cron 两侧都试）——行语法
//     解析复用 persist_linuxparse.go 的 parseCrontabEntries；
//  2. systemd timer：顶层 *.timer unit（目录集合复用 persistence_linux.go
//     的 systemdUnitDirs），执行体/run-as 读配套 <name>.service（unit
//     惯例同目录；不在时回退 /usr/lib/systemd/system）。
//
// 与 Windows 版的取舍对齐：含禁用任务/含未启用 timer（攻击者落地后常
// 先禁用既有任务再建新任务，只看启用态会漏掉半边痕迹）；单文件/单
// unit 读失败跳过不放大；state 恒 unknown（Windows 既定口径）。
//
// 未在 Linux 实机验证（待 Kali 复验）；验证口径 = GOOS=linux 交叉编译 +
// tasks_linuxparse.go 纯逻辑单测。
package liveapi

// tasks_linux.go：计划任务全量详情（cron + systemd timer 口径）。

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"zedr/internal/platform/httpx"
)

// cronSpoolDirs 是用户 crontab 的两个发行版惯例位置（Debian 系多一层
// crontabs 目录；两侧都试，文件名即用户名）。
var cronSpoolDirs = []string{"/var/spool/cron/crontabs", "/var/spool/cron"}

// enumCronTaskItems 枚举三类 cron 来源并投影成任务条目。单文件读失败
// 静默跳过（目录被并发改动/权限差异是常态）。
func enumCronTaskItems() []linuxTaskItem {
	var out []linuxTaskItem
	appendFile := func(path string, data []byte, withUser bool, spoolUser string) {
		for _, e := range parseCrontabEntries(path, data, withUser) {
			if spoolUser != "" {
				e.User = spoolUser // spool 文件名即用户名（行内无 user 列的补偿口径）
			}
			out = append(out, cronEntryToTaskItem(path, e))
		}
	}
	if data, err := os.ReadFile("/etc/crontab"); err == nil {
		appendFile("/etc/crontab", data, true, "")
	}
	if ents, err := os.ReadDir("/etc/cron.d"); err == nil {
		for _, e := range ents {
			if e.IsDir() {
				continue
			}
			path := filepath.Join("/etc/cron.d", e.Name())
			if data, err := os.ReadFile(path); err == nil {
				appendFile(path, data, true, "")
			}
		}
	}
	for _, dir := range cronSpoolDirs {
		ents, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range ents {
			if e.IsDir() {
				continue
			}
			path := filepath.Join(dir, e.Name())
			if data, err := os.ReadFile(path); err == nil {
				appendFile(path, data, false, e.Name())
			}
		}
	}
	return out
}

// enumTimerTaskItems 枚举顶层 *.timer unit 并投影。同名去重按目录优先级
// first-wins（与 /services 同口径）；配套 service 的 User=/ExecStart 读
// 不到就留空。
func enumTimerTaskItems() []linuxTaskItem {
	// wants 集合：/etc/systemd/system/*.wants/ 下的链接名（与 /services
	// 同口径的 enabled 静态近似）。
	enabled := map[string]bool{}
	if ents, err := os.ReadDir("/etc/systemd/system"); err == nil {
		for _, e := range ents {
			if !e.IsDir() || !strings.HasSuffix(e.Name(), ".wants") {
				continue
			}
			if wants, err := os.ReadDir(filepath.Join("/etc/systemd/system", e.Name())); err == nil {
				for _, w := range wants {
					enabled[w.Name()] = true
				}
			}
		}
	}

	var out []linuxTaskItem
	seen := map[string]bool{}
	for _, dir := range systemdUnitDirs {
		ents, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range ents {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".timer") {
				continue
			}
			name := strings.TrimSuffix(e.Name(), ".timer")
			if seen[name] {
				continue
			}
			seen[name] = true
			path := filepath.Join(dir, e.Name())
			data, err := os.ReadFile(path)
			if err != nil {
				continue
			}
			info := parseLinuxUnit(data)
			svcExec, svcUser := readPairedServiceExec(dir, name)
			out = append(out, timerToTaskItem(path, name, info, enabled[e.Name()], svcExec, svcUser))
		}
	}
	return out
}

// readPairedServiceExec 读 timer 的配套 service unit（<name>.service）：
// 先找 timer 同目录（unit 文件惯例同目录放置），不在则回退
// /usr/lib/systemd/system（发行版自带 timer 常配发行版 service）。
// ExecStart 取完整命令行（含参数）与 User=（仅显式值）。
func readPairedServiceExec(timerDir, name string) (exec, user string) {
	for _, dir := range []string{timerDir, "/usr/lib/systemd/system"} {
		data, err := os.ReadFile(filepath.Join(dir, name+".service"))
		if err != nil {
			continue
		}
		info := parseLinuxUnit(data)
		return info.ExecStart, info.User
	}
	return "", ""
}

func (s *server) handleTasks(w http.ResponseWriter, r *http.Request) {
	filter := r.URL.Query().Get("filter")
	limit := queryInt(r, "limit", linuxTasksDefaultLimit, 1, linuxTasksMaxLimit)

	items := enumCronTaskItems()
	items = append(items, enumTimerTaskItems()...)
	httpx.WriteJSON(w, r, http.StatusOK, buildLinuxTasksResult(items, filter, limit))
}
