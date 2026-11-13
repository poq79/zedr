//go:build windows
// +build windows

package winapi

// threads.go：进程线程枚举 + 起始地址 + 模块归属 + 匿名可执行内存判定。
//
// 数据源分三段：
//  1. CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD) 拿系统全部线程的 TID
//     （TH32CS_SNAPTHREAD 忽略 pid 参数，必须全量枚举后按 OwnerProcessID
//     过滤，这是 Win32 的既定行为）；
//  2. OpenThread(THREAD_QUERY_LIMITED_INFORMATION) +
//     NtQueryInformationThread(ThreadQuerySetWin32StartAddress=9) 拿线程
//     起始地址。优先 LIMITED_INFORMATION（权限面更小），但实测部分 Windows
//     版本对 class 9 只认 THREAD_QUERY_INFORMATION（LIMITED 返回
//     STATUS_ACCESS_DENIED），所以查询失败时降级到 QUERY_INFORMATION 重试
//     一次；两者都失败才计入 QueryFailed。
//  3. 起始地址与模块 [BaseAddr, BaseAddr+Size) 比对；未命中且能打开进程时
//     用 VirtualQueryEx 判断该地址是否落在 MEM_PRIVATE + 可执行区域——
//     这是"线程从堆/匿名映射起飞"的注入线索（比只看模块列表更直接）。
//
// 受保护进程的现实：OpenThread 或 NtQueryInformationThread 会失败，此时
// 该线程仍然作为一行返回（TID 本身是证据），start_address=0、module 空，
// 由 ThreadList.Skipped/QueryFailed 如实计数，handler 写进 note。

import (
	"errors"
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"

	"zedr/internal/model"
)

const (
	// ThreadQuerySetWin32StartAddress，NtQueryInformationThread 的信息类。
	threadQuerySetWin32StartAddress = 9

	// threadQueryInformation 是 THREAD_QUERY_INFORMATION：class 9 在部分
	// Windows 版本上拒绝 LIMITED_INFORMATION（0x800），需要这个更宽的权限
	// 做一次降级重试。
	threadQueryInformation = 0x0040

	// statusAccessDenied 是 NTSTATUS 的 STATUS_ACCESS_DENIED。
	statusAccessDenied = 0xC0000022

	// memPrivate 在 x/sys 里没有导出（只有 MEM_COMMIT 等），这里补上。
	memPrivate = 0x00020000
)

var procNtQueryInformationThread = modNtdll.NewProc("NtQueryInformationThread")

// ThreadRow 是 /threads 的线协议行（契约 §15.3 items 元素）。
type ThreadRow struct {
	TID             uint32 `json:"tid"`
	StartAddress    uint64 `json:"start_address"`
	Module          string `json:"module"`
	InAnonymousExec bool   `json:"in_anonymous_exec"`
}

// ThreadList 是一次线程枚举的完整结果。
type ThreadList struct {
	Rows  []ThreadRow
	Total int // Toolhelp 快照中属于该 PID 的线程数
	// Skipped 是 OpenThread 失败的线程数（受保护进程/线程在枚举与打开之间
	// 退出）；QueryFailed 是打开成功但起始地址查询失败的线程数。
	Skipped     int
	QueryFailed int
	// ProcessOpened 表示目标进程能否用 PROCESS_QUERY_INFORMATION 打开；
	// false 时 InAnonymousExec 全部为 false（"未知"被降级成"否"，note 必须
	// 说明这个口径）。
	ProcessOpened bool
	// ModulesKnown 表示是否有模块表可做归属。Deps.Modules 与 Toolhelp
	// 模块快照都失败时为 false，此时 module 全空。
	ModulesKnown bool
}

// ScanThreads 枚举 pid 的线程并完成起始地址/模块/匿名执行判定。
//
// mods 来自调用方（liveapi 的 Deps.Modules，即采集层的高成本模块接口）；
// 传 nil 时退回 Win32 Toolhelp 模块快照（ProcessModules），两者都不可用时
// ModulesKnown=false。
func ScanThreads(pid uint32, mods []model.ModuleInfo) (ThreadList, error) {
	out := ThreadList{Rows: []ThreadRow{}}
	if pid == 0 {
		return out, fmt.Errorf("pid 0 不是真实进程")
	}

	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPTHREAD, 0)
	if err != nil {
		return out, fmt.Errorf("线程快照失败: %w", err)
	}
	defer windows.CloseHandle(snap)

	var te windows.ThreadEntry32
	te.Size = uint32(unsafe.Sizeof(te))
	if err := windows.Thread32First(snap, &te); err != nil {
		if errors.Is(err, windows.ERROR_NO_MORE_FILES) {
			return out, nil
		}
		return out, fmt.Errorf("Thread32First 失败: %w", err)
	}

	tids := make([]uint32, 0, 64)
	for {
		if te.OwnerProcessID == pid {
			tids = append(tids, te.ThreadID)
		}
		te.Size = uint32(unsafe.Sizeof(te))
		if err := windows.Thread32Next(snap, &te); err != nil {
			break // ERROR_NO_MORE_FILES 是正常结束
		}
	}
	out.Total = len(tids)
	if out.Total == 0 {
		return out, nil
	}

	if mods == nil {
		if entries, err := ProcessModules(pid); err == nil {
			mods = make([]model.ModuleInfo, 0, len(entries))
			for _, m := range entries {
				mods = append(mods, model.ModuleInfo{
					Name: m.Name, Path: m.Path, BaseAddr: m.BaseAddr, Size: m.Size,
				})
			}
		}
	}
	out.ModulesKnown = mods != nil

	// 一次打开进程供所有线程的 VirtualQueryEx 判定复用；打不开时只影响
	// in_anonymous_exec（模块归属仍可用），不把整个请求判失败。
	hProc, procErr := windows.OpenProcess(processQueryInformation, false, pid)
	if procErr == nil {
		out.ProcessOpened = true
		defer windows.CloseHandle(hProc)
	}

	for _, tid := range tids {
		row := ThreadRow{TID: tid}
		th, err := windows.OpenThread(windows.THREAD_QUERY_LIMITED_INFORMATION, false, tid)
		if err != nil {
			out.Skipped++
			out.Rows = append(out.Rows, row)
			continue
		}
		start, status := queryThreadStartAddress(th)
		windows.CloseHandle(th)
		if status != 0 {
			// 降级重试：class 9 在部分版本上要求 THREAD_QUERY_INFORMATION。
			// 只在 ACCESS_DENIED 时重试，其它错误重试也没意义。
			if status == statusAccessDenied {
				if th2, err := windows.OpenThread(threadQueryInformation, false, tid); err == nil {
					start, status = queryThreadStartAddress(th2)
					windows.CloseHandle(th2)
				}
			}
		}
		if status != 0 {
			out.QueryFailed++
			out.Rows = append(out.Rows, row)
			continue
		}
		row.StartAddress = uint64(start)
		row.Module = moduleForAddress(mods, row.StartAddress)
		if row.Module == "" && out.ProcessOpened && start != 0 {
			var mbi windows.MemoryBasicInformation
			if err := windows.VirtualQueryEx(hProc, start, &mbi, unsafe.Sizeof(mbi)); err == nil {
				// 只有"私有 + 可执行"才算注入线索：MEM_IMAGE/MEM_MAPPED
				// 即使可执行也是正常模块/JIT，不在此列。
				row.InAnonymousExec = mbi.Type == memPrivate && isExecutableProtect(mbi.Protect)
			}
		}
		out.Rows = append(out.Rows, row)
	}
	return out, nil
}

// queryThreadStartAddress 调 NtQueryInformationThread(class 9) 取起始地址。
// 返回 NTSTATUS（0 = 成功），由调用方决定是否降级重试。
func queryThreadStartAddress(th windows.Handle) (uintptr, uint32) {
	var start uintptr
	var retLen uint32
	status, _, _ := procNtQueryInformationThread.Call(
		uintptr(th),
		threadQuerySetWin32StartAddress,
		uintptr(unsafe.Pointer(&start)),
		unsafe.Sizeof(start),
		uintptr(unsafe.Pointer(&retLen)),
	)
	if uint32(status) != 0 {
		return 0, uint32(status)
	}
	return start, 0
}

// ListThreads 是 ScanThreads 的简易封装（模块表走 Toolhelp）。
func ListThreads(pid uint32) ([]ThreadRow, error) {
	res, err := ScanThreads(pid, nil)
	if err != nil {
		return nil, err
	}
	return res.Rows, nil
}

// moduleForAddress 在线性表里找包含 addr 的模块。
// 模块数量通常 <300，线性扫描足够；不做排序是因为每次请求只调用一次。
func moduleForAddress(mods []model.ModuleInfo, addr uint64) string {
	if addr == 0 {
		return ""
	}
	for _, m := range mods {
		if m.BaseAddr == 0 || m.Size == 0 {
			continue
		}
		if addr >= m.BaseAddr && addr < m.BaseAddr+uint64(m.Size) {
			return m.Name
		}
	}
	return ""
}
