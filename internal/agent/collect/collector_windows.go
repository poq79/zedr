//go:build windows

package collect

import (
	"time"

	"zedr/internal/agent/winapi"
	"zedr/internal/model"
)

// describe 对单个进程做完整富化（Windows：NtQuery/Toolhelp 快照 + 现场
// 逐项补齐）。
func (c *Collector) describe(rp rawProc) ProcessInfo {
	pi := ProcessInfo{
		PID:  rp.PID,
		PPID: rp.PPID,
		Name: rp.Name,
	}
	if pi.Name == "" {
		if n, err := winapi.ImageNameOf(rp.PID); err == nil {
			pi.Name = n
		}
	}

	if path, err := winapi.ImagePath(rp.PID); err == nil {
		pi.Path = path
	}
	if cmd, err := winapi.CommandLine(rp.PID); err == nil {
		pi.CmdLine = cmd
	}
	if user, err := winapi.ProcessUser(rp.PID); err == nil {
		pi.User = user
	}
	if sid, err := winapi.SessionID(rp.PID); err == nil {
		pi.SessionID = sid
	}
	pi.Elevated = winapi.IsElevated(rp.PID)
	pi.IsWow64 = winapi.IsWow64(rp.PID)

	// 优先用来源给出的创建时间（已换算 Unix 纳秒），避免再发起一次系统调用
	if rp.CreateTime > 0 {
		pi.StartTime = createAt(rp.CreateTime)
	} else if ts, err := winapi.ProcessStartTime(rp.PID); err == nil && ts > 0 {
		pi.StartTime = time.Unix(ts, 0).UTC()
	}
	return pi
}

// pathOfLive 现场查询进程镜像路径（血缘第一层父进程兜底用）。
func (c *Collector) pathOfLive(pid uint32) string {
	p, err := winapi.ImagePath(pid)
	if err != nil {
		return ""
	}
	return p
}

// modulesOf 枚举进程装载模块（Windows 原生支持）。
func (c *Collector) modulesOf(pid uint32) []model.ModuleInfo {
	mods, err := winapi.ProcessModules(pid)
	if err != nil {
		return nil
	}
	out := make([]model.ModuleInfo, 0, len(mods))
	for _, m := range mods {
		out = append(out, model.ModuleInfo{
			Name: m.Name, Path: m.Path, BaseAddr: m.BaseAddr, Size: m.Size,
		})
	}
	return out
}

// KnownMachineProcesses 是 Windows 侧"几乎总在运行"的系统进程名。
var KnownMachineProcesses = map[string]struct{}{
	"system": {}, "smss.exe": {}, "csrss.exe": {}, "wininit.exe": {}, "winlogon.exe": {},
	"services.exe": {}, "lsass.exe": {}, "svchost.exe": {}, "explorer.exe": {},
	"spoolsv.exe": {}, "dwm.exe": {}, "fontdrvhost.exe": {}, "ctfmon.exe": {},
	"taskhostw.exe": {}, "sihost.exe": {}, "runtimebroker.exe": {}, "searchindexer.exe": {},
}
