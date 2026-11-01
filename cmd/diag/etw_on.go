//go:build windows && etw

package main

import (
	"fmt"
	"os/exec"
	"strings"
	"time"

	"zedr/internal/agent/winapi"
)

// testETW 实测 ETW 实时进程事件采集能力。
//
// 这是验证"能否解决短命进程漏检"的关键手段：
// 订阅期间拉起若干瞬间退出的进程，看事件流能否全部捕获。
func testETW(d time.Duration) {
	fmt.Printf("\n--- ETW 实时进程事件采集（订阅 %s）---\n", d)

	w, err := winapi.NewETWProcessWatcher("ZEDR-Diag")
	if err != nil {
		fmt.Printf("ETW 不可用: %v\n", err)
		fmt.Println("  => 探针不受影响：默认走快照轮询 + 文件落地监控")
		return
	}
	defer w.Close()
	fmt.Println("ETW 会话已建立，provider=Microsoft-Windows-Kernel-Process")

	go func() {
		for i := 0; i < 3; i++ {
			time.Sleep(400 * time.Millisecond)
			_ = exec.Command("cmd", "/c", "exit").Run() // 存活时间极短
		}
	}()

	deadline := time.After(d)
	seen, matched := 0, 0
	for {
		select {
		case ev, ok := <-w.Events():
			if !ok {
				fmt.Println("事件通道已关闭")
				return
			}
			seen++
			name := ev.Image
			if i := strings.LastIndexAny(name, `\/`); i >= 0 {
				name = name[i+1:]
			}
			if seen <= 25 {
				fmt.Printf("  [%s] pid=%-6d ppid=%-6d %-28s %s\n",
					ev.Time.Format("15:04:05.000"), ev.PID, ev.PPID, name, truncateStr(ev.CmdLine, 70))
			}
			if strings.EqualFold(name, "cmd.exe") && strings.Contains(strings.ToLower(ev.CmdLine), "/c exit") {
				matched++
			}
		case <-deadline:
			fmt.Printf("\n诊断计数 calls/provider/eventid/nodata/parsed = %s\n", w.Diag())
			fmt.Printf("共捕获 %d 条进程创建事件\n", seen)
			fmt.Printf("其中「瞬间退出」的测试进程: %d / 3\n", matched)
			return
		}
	}
}
