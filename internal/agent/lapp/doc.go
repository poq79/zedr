// Package lapp 是 Linux 探针的组合根。
//
// 本包全部实现文件带 //go:build linux 标签，仅 Linux 构建参与编译；
// 这个中性文件只为让 Windows 侧 `go test ./...` 不因"包无文件"报
// setup failed（AGENTS §6 要求全仓测试全绿）。实现说明见 lapp.go
// 顶部包注释（能力对照与诚实边界）。
package lapp
