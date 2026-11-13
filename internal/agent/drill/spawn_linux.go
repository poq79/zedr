//go:build linux

package drill

import (
	"context"
	"os/exec"
	"syscall"
)

// detachedProcess 在 Linux 下无对应概念（无控制台隐藏语义），恒 0——
// Setpgid = true 让演练子进程脱离探针进程组，探针退出不牵连子进程，
// 且子进程不会把信号传播回探针组。
const detachedProcess = 0

// spawnDetached 拉起子进程并后台回收（不 Wait 会泄漏进程句柄——探针
// 是长驻进程，积少成多）。未在 Linux 实机验证。
func spawnDetached(name string, args ...string) (*exec.Cmd, error) {
	cmd := exec.Command(name, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	go func() { _ = cmd.Wait() }()
	return cmd, nil
}

// runSync 同步执行一个快速子命令，带 syncWait 预算。
func runSync(ctx context.Context, name string, args ...string) (string, error) {
	cctx, cancel := context.WithTimeout(ctx, syncWait)
	defer cancel()
	cmd := exec.CommandContext(cctx, name, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	out, err := cmd.CombinedOutput()
	return string(out), err
}
