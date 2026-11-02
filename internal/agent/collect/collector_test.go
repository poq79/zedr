package collect

import (
	"testing"
	"time"
)

// 父进程退出后，历史条目必须保留路径/命令行——否则告警证据里的
// 攻击链只剩一串进程名，无法回答"父进程执行了什么"。
func TestAncestryFromHistoryKeepsFullIdentity(t *testing.T) {
	c := &Collector{
		known:   map[uint32]ProcessInfo{},
		history: map[uint32]historyEntry{},
		prev:    map[uint32]rawProc{},
	}
	exited := time.Now().Add(-time.Minute)
	c.history[7] = historyEntry{
		rawProc: rawProc{PID: 7, PPID: 4, Name: "powershell.exe"},
		Info: ProcessInfo{
			PID: 7, PPID: 4, Name: "powershell.exe",
			Path: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
			CmdLine: `powershell.exe -nop -enc SQBFAFgA`, StartTime: exited.Add(-time.Minute),
		},
		ExitedAt: exited,
	}
	snap := &Table{Procs: map[uint32]rawProc{
		100: {PID: 100, PPID: 7, Name: "payload.exe"},
	}}

	chain, parentAlive := c.Ancestry(snap, 100)
	if parentAlive {
		t.Fatal("parentAlive = true, want false（父进程已退出）")
	}
	if len(chain) != 1 {
		t.Fatalf("len(chain) = %d, want 1", len(chain))
	}
	if chain[0].Name != "powershell.exe" || chain[0].Cmd != `powershell.exe -nop -enc SQBFAFgA` {
		t.Fatalf("ancestor = %+v, 历史身份未带出", chain[0])
	}
	if chain[0].Path == "" {
		t.Fatal("ancestor path 为空，历史路径未带出")
	}
}

// PID 复用：历史条目里的"父进程"启动时间晚于子进程 = 同一个 PID 的
// 另一个实例，不能拼成假血缘。
func TestAncestryRejectsReusedPID(t *testing.T) {
	childStart := time.Now().Add(-time.Hour)
	c := &Collector{
		known: map[uint32]ProcessInfo{
			100: {PID: 100, Name: "child.exe", StartTime: childStart},
		},
		history: map[uint32]historyEntry{
			7: {
				rawProc: rawProc{PID: 7, PPID: 4, Name: "cmd.exe"},
				Info: ProcessInfo{
					PID: 7, Name: "cmd.exe", StartTime: childStart.Add(time.Minute),
				},
				ExitedAt: time.Now(),
			},
		},
		prev: map[uint32]rawProc{},
	}
	snap := &Table{Procs: map[uint32]rawProc{
		100: {PID: 100, PPID: 7, Name: "child.exe"},
	}}

	if chain, _ := c.Ancestry(snap, 100); len(chain) != 0 {
		t.Fatalf("chain = %+v, want empty（PID 复用不应连成父链）", chain)
	}
}

// 存活父进程直接用已富化身份，不再现场查询（父进程可能刚好退出）。
func TestAncestryUsesKnownIdentityForLiveParent(t *testing.T) {
	c := &Collector{
		known: map[uint32]ProcessInfo{
			7: {PID: 7, Name: "explorer.exe", Path: `C:\Windows\explorer.exe`, CmdLine: `C:\Windows\explorer.exe`},
		},
		history: map[uint32]historyEntry{},
		prev:    map[uint32]rawProc{},
	}
	snap := &Table{Procs: map[uint32]rawProc{
		100: {PID: 100, PPID: 7, Name: "cmd.exe"},
		7:   {PID: 7, Name: "explorer.exe"},
	}}

	chain, parentAlive := c.Ancestry(snap, 100)
	if !parentAlive {
		t.Fatal("parentAlive = false, want true")
	}
	if len(chain) != 1 || chain[0].Cmd == "" || chain[0].Path == "" {
		t.Fatalf("chain = %+v, want 富化后的父进程身份", chain)
	}
}
