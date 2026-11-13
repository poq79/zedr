//go:build windows

package drill

import (
	"context"
	"os/exec"
	"syscall"
)

// detachedProcess 是 CREATE_NO_WINDOW（0x08000000），与 cmd/desktop 的
// spawn 先例一致：子进程拿一个不可见的控制台。演练 v1 曾用
// DETACHED_PROCESS（0x8），cmd/sc/reg 都正常、唯独 powershell.exe 会
// 163ms 内静默 exit 0（无控制台时初始化直接放弃），port_scan 步骤三轮
// E2E 全空转后定位到此处——拉控制台程序一律 CREATE_NO_WINDOW。
const detachedProcess = 0x08000000

// spawnDetached 拉起不共享控制台的子进程并后台回收（不 Wait 会泄漏
// 进程句柄——探针是长驻进程，积少成多）。
func spawnDetached(name string, args ...string) (*exec.Cmd, error) {
	cmd := exec.Command(name, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: detachedProcess}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	go func() { _ = cmd.Wait() }()
	return cmd, nil
}

// runSync 同步执行一个快速子命令（sc/reg），不闪现控制台。
// 单独给 syncWait 预算：sc/reg 极端情况（SCM 卡死）不能吃掉整个判定窗口。
func runSync(ctx context.Context, name string, args ...string) (string, error) {
	cctx, cancel := context.WithTimeout(ctx, syncWait)
	defer cancel()
	cmd := exec.CommandContext(cctx, name, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: detachedProcess}
	out, err := cmd.CombinedOutput()
	return string(out), err
}
