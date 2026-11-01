//go:build !etw

package main

import (
	"fmt"
	"time"
)

// testETW 在未启用 etw 构建标签时给出明确提示，避免"参数存在但什么都不做"。
func testETW(d time.Duration) {
	_ = d
	fmt.Println("\n--- ETW 实时采集：本次构建未启用 ---")
	fmt.Println("  重新编译以启用：go build -tags etw -o bin/hgdiag.exe ./cmd/hgdiag")
	fmt.Println("  说明：该特性在部分 Windows 版本上 OpenTrace 可能失败，探针默认不依赖它。")
}
