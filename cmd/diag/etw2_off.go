//go:build windows && !etw2

package main

import (
	"fmt"
	"time"
)

// testETW2 的无 tag 占位：ETW 对照实验按"验证不过不进主干"纪律隔离在
// -tags etw2 之后（见 etw2_on.go）。
func testETW2(d time.Duration) {
	fmt.Println("ETW 对照实验需要 -tags etw2 构建：go build -tags etw2 -o bin/zedr-diag-etw2.exe ./cmd/diag")
}

func testETW2Attach(name string, d time.Duration) {
	fmt.Println("ETW attach 实验需要 -tags etw2 构建（同上）")
}
