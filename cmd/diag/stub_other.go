//go:build !windows

// zedr-diag 的非 Windows 占位：采集自检依赖 Win32 API（进程枚举/签名/
// TCP 表等），Windows 之外没有可检的对象。提供真实可编译的 stub 而不是
// 把整个包锁进 windows 约束之外消失，是为了让 `GOOS=linux go vet ./...`
// 与 CI 的 linux job 对 ./... 有完整语义——diag 的缺失是显式已知边界，
// 不是 vet 静默漏过的包。
package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "zedr-diag 仅支持 Windows：采集层自检依赖 Win32 API（进程/签名/TCP 表），Linux 终端无此自检面。")
	os.Exit(1)
}
