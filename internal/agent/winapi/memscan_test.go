//go:build windows
// +build windows

package winapi

// memscan_test.go：地址空间元数据扫描真机冒烟。
// 断言重点是"结构合理、绝不读内容、权限失败不 panic"，不比对具体区域数量。

import (
	"errors"
	"os"
	"testing"
)

func TestScanMemorySelf(t *testing.T) {
	res, err := ScanMemory(uint32(os.Getpid()))
	if err != nil {
		t.Fatalf("ScanMemory(self) 失败: %v", err)
	}
	if res.Committed == 0 || len(res.Regions) == 0 {
		t.Fatalf("本进程应至少有一个提交区域: committed=%d regions=%d", res.Committed, len(res.Regions))
	}
	if len(res.Regions) > memScanRegionMax {
		t.Fatalf("regions 超过上限: %d", len(res.Regions))
	}
	if len(res.Suspicious) > memScanSuspiciousMax {
		t.Fatalf("suspicious 超过上限: %d", len(res.Suspicious))
	}
	for _, region := range res.Regions {
		if region.Size == 0 {
			t.Errorf("区域大小不应为 0: %+v", region)
		}
		if region.Protect == "" {
			t.Errorf("保护位不应为空: %+v", region)
		}
		if region.Type == "" {
			t.Errorf("类型不应为空（提交区域必有 private/mapped/image）: %+v", region)
		}
	}
	for _, s := range res.Suspicious {
		if s.Size < minSuspiciousSize {
			t.Errorf("可疑区域应 ≥4KB: %+v", s)
		}
		if s.Protect == "" {
			t.Errorf("可疑区域保护位不应为空: %+v", s)
		}
	}
	t.Logf("regions=%d committed=%d private_exec=%d suspicious=%d truncated=%v",
		len(res.Regions), res.Committed, res.PrivateExec, res.SuspiciousTotal, res.Truncated)
}

func TestScanMemoryInvalidPID(t *testing.T) {
	if _, err := ScanMemory(0); !errors.Is(err, ErrMemScanProcessGone) {
		t.Fatalf("pid 0 期望 ErrMemScanProcessGone，实得 %v", err)
	}
	const ghost = uint32(0xFFFFFFF0)
	if _, err := ScanMemory(ghost); err == nil {
		t.Fatal("不存在的 pid 应返回错误")
	}
}

func TestScanMemoryProtectedPID(t *testing.T) {
	// PID 4 的地址空间在用户态不可读：要么 ACCESS_DENIED，要么被系统以
	// 参数无效拒绝，两者都算正常；关键是不 panic、不返回半截数据。
	_, err := ScanMemory(4)
	if err == nil {
		t.Skip("当前环境竟能打开 PID 4（极少见），跳过权限断言")
	}
	if !errors.Is(err, ErrMemScanAccessDenied) && !errors.Is(err, ErrMemScanProcessGone) {
		t.Fatalf("受保护进程错误应可归类，实得 %v", err)
	}
}

func TestScanMemoryNotepadSmoke(t *testing.T) {
	// 用系统里现成的 notepad.exe 做跨进程冒烟；没有就跳过（不拉起进程）。
	procs, err := SnapshotProcesses()
	if err != nil {
		t.Skipf("进程快照不可用: %v", err)
	}
	var pid uint32
	for _, p := range procs {
		if p.Name == "notepad.exe" {
			pid = p.PID
			break
		}
	}
	if pid == 0 {
		t.Skip("当前没有 notepad.exe 进程，跳过跨进程冒烟")
	}
	res, err := ScanMemory(pid)
	if err != nil {
		if errors.Is(err, ErrMemScanAccessDenied) {
			t.Skipf("notepad.exe 打不开（权限/保护）: %v", err)
		}
		t.Fatalf("ScanMemory(notepad) 失败: %v", err)
	}
	if len(res.Regions) == 0 {
		t.Fatalf("notepad 应有可枚举区域")
	}
}

func TestProtectString(t *testing.T) {
	cases := []struct {
		protect uint32
		want    string
	}{
		{0x01, "NO"},
		{0x02, "R"},
		{0x04, "RW"},
		{0x08, "WC"},
		{0x10, "E"},
		{0x20, "ER"},
		{0x40, "ERW"},
		{0x80, "EWC"},
		{0x04 | 0x100, "RW+G"},
		{0x20 | 0x200, "ER+NC"},
	}
	for _, tc := range cases {
		if got := protectString(tc.protect); got != tc.want {
			t.Errorf("protectString(0x%x) = %q, want %q", tc.protect, got, tc.want)
		}
	}
}

func TestMemTypeString(t *testing.T) {
	cases := map[uint32]string{
		memImage:   "image",
		memMapped:  "mapped",
		memPrivate: "private",
		0:          "",
		0x9999:     "",
	}
	for in, want := range cases {
		if got := memTypeString(in); got != want {
			t.Errorf("memTypeString(0x%x) = %q, want %q", in, got, want)
		}
	}
}
