// Command hgdiag 是探针采集层的自检工具。
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
	"runtime"
	"sort"
	"strings"
	"time"

	"hostguard/internal/agent/winapi"
)

func main() {
	// -hold 让本进程在输出结果后继续存活指定时长。
	// 用途：作为"检测能力受控验证"的样本进程时，保证其生命周期跨越采集轮询周期，
	// 避免因进程过快退出导致漏检（这是用户态轮询采集固有的 TOCTOU 特性）。
	hold := flag.Duration("hold", 0, "输出结果后保持存活的时长，例如 15s")
	spawn := flag.String("spawn", "", "拉起一个子进程（空格分隔的命令行），用于模拟父子链攻击场景")
	compare := flag.Bool("compare", false, "对比两种进程枚举引擎的耗时与结果差异")
	flag.Parse()

	fmt.Println("=== HostGuard 采集层自检 ===")
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

	if *compare {
		compareCollectors()
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
