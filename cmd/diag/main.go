// Command zedr-diag 是探针采集层的自检工具。
//
// 用途：在目标终端上快速验证 Win32 采集能力是否正常（进程枚举、命令行、
// 账号解析、哈希、签名、TCP 表），排查"探针装了但采不到数据"这类问题。
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"zedr/internal/agent/winapi"
)

func main() {
	// -hold 让本进程在输出结果后继续存活指定时长。
	// 用途：作为"检测能力受控验证"的样本进程时，保证其生命周期跨越采集轮询周期，
	// 避免因进程过快退出导致漏检（这是用户态轮询采集固有的 TOCTOU 特性）。
	hold := flag.Duration("hold", 0, "输出结果后保持存活的时长，例如 15s")
	spawn := flag.String("spawn", "", "拉起一个子进程（空格分隔的命令行），用于模拟父子链攻击场景")
	compare := flag.Bool("compare", false, "对比两种进程枚举引擎的耗时与结果差异")
	etwWatch := flag.Duration("etw", 0, "实测 ETW 实时进程事件采集（需 -tags etw 编译）")
	persistCheck := flag.Bool("persist", false, "枚举持久化项（自启动）并输出分类统计")
	usnProbe := flag.Bool("usn", false, "实测 USN Journal 断点补采（TEMP 落探针文件后回读）")
	flag.Parse()

	fmt.Println("=== Z-EDR 采集层自检 ===")
	fmt.Printf("OS      : %s\n", winapi.OSVersion())
	fmt.Printf("Host    : %s\n", winapi.Hostname())
	fmt.Printf("User    : %s\n", winapi.CurrentUser())
	fmt.Printf("Arch    : %s/%s, CPUs=%d\n", runtime.GOOS, runtime.GOARCH, runtime.NumCPU())

	start := time.Now()
	procs, err := winapi.SnapshotProcesses()
	if err != nil {
		fmt.Printf("!! 进程快照失败: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Process : %d 个（快照耗时 %v）\n", len(procs), time.Since(start))

	sort.Slice(procs, func(i, j int) bool { return procs[i].PID < procs[j].PID })

	// 逐项采样若干进程验证能力
	var checkedPath, checkedCmd, checkedUser, checkedSig int
	for i, p := range procs {
		if i >= 400 {
			break
		}
		if _, err := winapi.ImagePath(p.PID); err == nil {
			checkedPath++
		}
		if i < 60 {
			if cmd, err := winapi.CommandLine(p.PID); err == nil && cmd != "" {
				checkedCmd++
			}
			if _, err := winapi.ProcessUser(p.PID); err == nil {
				checkedUser++
			}
		}
	}
	fmt.Printf("Path    : %d/%d 可读\n", checkedPath, min(400, len(procs)))
	fmt.Printf("Cmdline : %d/60 可读\n", checkedCmd)
	fmt.Printf("User    : %d/60 可解析\n", checkedUser)

	tcpStart := time.Now()
	conns, err := winapi.TCPConnections()
	if err != nil {
		fmt.Printf("!! TCP 表读取失败: %v\n", err)
	} else {
		total := 0
		for _, v := range conns {
			total += len(v)
		}
		fmt.Printf("Network : %d 条连接 / %d 个进程（耗时 %v）\n", total, len(conns), time.Since(tcpStart))
	}

	// 签名验证：用系统自带已签名文件做正样本
	sigCandidates := []string{
		`C:\Windows\System32\notepad.exe`,
		`C:\Windows\System32\cmd.exe`,
		`C:\Windows\explorer.exe`,
	}
	for _, c := range sigCandidates {
		if _, err := os.Stat(c); err != nil {
			continue
		}
		s := winapi.VerifySignature(c)
		if s.Valid {
			checkedSig++
		}
		fmt.Printf("Sign    : %-52s valid=%-5v code=0x%08x state=%-10s signer=%q\n",
			c, s.Valid, s.RawCode, s.State, s.Signer)
	}
	if checkedSig == 0 {
		fmt.Println("!! 未取得任何有效签名结果，请检查 wintrust.dll 调用")
	}

	// 哈希抽样
	if len(procs) > 0 {
		for _, p := range procs {
			path, err := winapi.ImagePath(p.PID)
			if err != nil || p.PID < 100 {
				continue
			}
			if h, size, err := hashFile(path); err == nil {
				fmt.Printf("Hash    : %s -> %s… (%d bytes)\n", path, h[:16], size)
				break
			}
		}
	}

	// 打印前 15 个进程作为样张
	fmt.Println("\n--- 进程样张 ---")
	for i, p := range procs {
		if i >= 15 {
			break
		}
		path, _ := winapi.ImagePath(p.PID)
		cmd, _ := winapi.CommandLine(p.PID)
		user, _ := winapi.ProcessUser(p.PID)
		if len(cmd) > 90 {
			cmd = cmd[:90] + "…"
		}
		fmt.Printf("%6d  ppid=%-6d %-28s %-18s %s\n", p.PID, p.PPID, p.Name, user, cmd)
		_ = path
	}
	// 可选：拉起子进程，模拟"某进程 → 命令解释器"的父子链
	if *spawn != "" {
		parts := strings.Fields(*spawn)
		if len(parts) > 0 {
			cmd := exec.Command(parts[0], parts[1:]...)
			if err := cmd.Start(); err != nil {
				fmt.Printf("拉起子进程失败: %v\n", err)
			} else {
				fmt.Printf("已拉起子进程: %s (pid=%d)\n", *spawn, cmd.Process.Pid)
			}
		}
	}

	if *persistCheck {
		checkPersistence()
	}
	if *usnProbe {
		checkUSN()
	}
	if *compare {
		compareCollectors()
	}
	if *etwWatch > 0 {
		testETW(*etwWatch)
	}

	fmt.Println("\n自检完成。")

	if *hold > 0 {
		fmt.Printf("按 -hold 参数保持存活 %s（供检测链路验证使用）\n", *hold)
		time.Sleep(*hold)
	}
}

func hashFile(path string) (string, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// checkUSN 端到端验证 USN 补采：先取基线，再在 TEMP 落一个探针文件，
// 然后从基线回读，确认能拿到该文件的创建/写入记录。
//
// 需要管理员权限 + NTFS；失败时输出明确原因，而不是静默显示"0 条"。
func checkUSN() {
	fmt.Println("\n--- USN Journal 断点补采 ---")
	dir := os.TempDir()
	vol, ok := winapi.USNVolumeOf(dir)
	if !ok {
		fmt.Printf("!! 无法从目录解析卷: %s（UNC/非盘符路径不支持）\n", dir)
		return
	}

	_, baseline, journalID, _, err := winapi.ReadUSNJournal(vol, 0, 0, 5000)
	if err != nil {
		fmt.Printf("!! USN 查询失败（需要管理员权限 + NTFS）: %v\n", err)
		return
	}
	fmt.Printf("卷=%s journal_id=%d baseline=0x%x\n", vol, journalID, baseline)

	f, err := os.CreateTemp(dir, "zedr-usn-probe-*.exe")
	if err != nil {
		fmt.Printf("!! 创建探针文件失败: %v\n", err)
		return
	}
	probe := f.Name()
	_, _ = f.WriteString("zedr usn probe")
	_ = f.Close()
	defer os.Remove(probe)

	time.Sleep(200 * time.Millisecond) // 给 USN 一个刷写窗口
	events, next, _, reset, err := winapi.ReadUSNJournal(vol, baseline, journalID, 5000)
	if err != nil {
		fmt.Printf("!! USN 回读失败: %v\n", err)
		return
	}
	found := false
	for _, ev := range events {
		if strings.EqualFold(ev.Name, filepath.Base(probe)) {
			found = true
			fmt.Printf("命中: %s @ %s (reason=0x%x)\n",
				ev.Name, ev.When.Format("15:04:05.000"), ev.Reason)
		}
	}
	fmt.Printf("回读 %d 条落地记录，next=0x%x reset=%v，探针文件命中=%v\n",
		len(events), next, reset, found)
	if !found {
		fmt.Println("!! 未回读到探针文件：可能 journal 未刷新、卷非 NTFS，或记录已被上限截断")
	}
}

// compareCollectors 对比 Toolhelp32 与 NtQuerySystemInformation 两种枚举方式。
// 用途：在目标 Windows 版本上评估新引擎能否替换旧引擎。
func compareCollectors() {
	fmt.Println("\n--- 采集引擎对比（各 20 次）---")

	// 预热，避免首次调用的加载开销污染数据
	_, _ = winapi.SnapshotProcesses()
	_ = winapi.ProbeNT()

	const rounds = 20

	t0 := time.Now()
	var toolhelpCount int
	for i := 0; i < rounds; i++ {
		list, err := winapi.SnapshotProcesses()
		if err != nil {
			fmt.Printf("Toolhelp32 失败: %v\n", err)
			return
		}
		toolhelpCount = len(list)
	}
	toolAvg := time.Since(t0) / rounds

	t1 := time.Now()
	var ntCount int
	for i := 0; i < rounds; i++ {
		list, err := winapi.SnapshotProcessesNT()
		if err != nil {
			fmt.Printf("NtQuerySystemInformation 失败: %v\n", err)
			fmt.Println("  => 该环境应使用 HG_AGENT_COLLECTOR=toolhelp")
			return
		}
		ntCount = len(list)
	}
	ntAvg := time.Since(t1) / rounds

	fmt.Printf("Toolhelp32             : %-8v  %d 个进程\n", toolAvg, toolhelpCount)
	fmt.Printf("NtQuerySystemInformation: %-8v  %d 个进程\n", ntAvg, ntCount)
	if ntAvg > 0 {
		fmt.Printf("加速比                  : %.1fx\n", float64(toolAvg)/float64(ntAvg))
	}
}

func truncateStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// checkPersistence 枚举本机持久化项并输出分类统计。
//
// 用途：在目标机器上确认"能枚举到哪些位置"。不同 Windows 版本、
// 不同权限下某些位置可能读不到（例如无管理员权限看不到部分服务），
// 这个命令能把差异直接摆出来，而不是等到线上发现基线项数明显偏少。
func checkPersistence() {
	fmt.Println("\n--- 持久化项（自启动）枚举 ---")
	start := time.Now()
	items, errs := winapi.EnumeratePersistence()
	elapsed := time.Since(start)

	byType := make(map[string]int, 8)
	for _, it := range items {
		byType[it.Type]++
	}

	fmt.Printf("共 %d 项，耗时 %v\n", len(items), elapsed)
	keys := make([]string, 0, len(byType))
	for k := range byType {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Printf("  %-22s %4d 项  (%s)\n", k, byType[k], winapi.PersistLocationLabel(k))
	}
	if len(errs) > 0 {
		fmt.Println("  部分位置枚举失败：")
		for _, e := range errs {
			fmt.Printf("    - %s\n", e)
		}
	}

	// 采样几条，确认命令行解析正确
	fmt.Println("  样例（前 3 条）：")
	for i, it := range items {
		if i >= 3 {
			break
		}
		p := winapi.PersistCommandPath(it.Command)
		fmt.Printf("    %-30s -> %s\n", truncateStr(it.Name, 30), truncateStr(p, 70))
	}
}
