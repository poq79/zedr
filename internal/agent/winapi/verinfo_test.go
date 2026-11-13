//go:build windows
// +build windows

package winapi

// verinfo_test.go：版本资源读取。真机冒烟：用系统自带文件验证
// VerQueryValue 链路（语系探测/字符串提取）在本机成立。

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestReadVersionInfoSystemBinary(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("仅 Windows")
	}
	// notepad.exe：任何 Windows 都有，且必带版本资源（微软签名文件口径）
	path := filepath.Join(os.Getenv("SystemRoot"), "System32", "notepad.exe")
	if _, err := os.Stat(path); err != nil {
		t.Skipf("notepad.exe 不可用: %v", err)
	}
	vi, err := ReadVersionInfo(path)
	if err != nil {
		t.Fatalf("ReadVersionInfo 失败: %v", err)
	}
	if vi == nil {
		t.Fatal("notepad.exe 应有版本资源")
	}
	if vi.Company == "" {
		t.Errorf("Company 为空: %+v", vi)
	}
	if vi.OriginalFilename == "" {
		t.Errorf("OriginalFilename 为空: %+v", vi)
	}
	t.Logf("company=%q product=%q desc=%q orig=%q",
		vi.Company, vi.Product, vi.Description, vi.OriginalFilename)
}

func TestReadVersionInfoNoResource(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("仅 Windows")
	}
	dir := t.TempDir()
	txt := filepath.Join(dir, "plain.txt")
	if err := os.WriteFile(txt, []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	vi, err := ReadVersionInfo(txt)
	if vi != nil || err != nil {
		t.Fatalf("无资源文件期望 (nil, nil) 实得 (%v, %v)", vi, err)
	}
	if vi, err := ReadVersionInfo(filepath.Join(dir, "missing.txt")); vi != nil || err != nil {
		t.Fatalf("不存在文件期望 (nil, nil) 实得 (%v, %v)", vi, err)
	}
}
