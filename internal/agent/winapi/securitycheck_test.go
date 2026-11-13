//go:build windows
// +build windows

package winapi

// securitycheck_test.go：RegDWORD 的三态语义（存在/不存在/读取失败）。
// 真机注册表读取；权限异常一律 skip，不让环境差异变成红灯。

import (
	"testing"

	"golang.org/x/sys/windows/registry"
)

func TestRegDWORDExistingValue(t *testing.T) {
	// EnableLUA 在 Windows 10/11 与 Server 2016+ 上恒为 REG_DWORD；
	// （CurrentBuild 看似"版本号"但实际是 REG_SZ，不能用来验证 DWORD 读取。）
	v, ok, err := RegDWORD(registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`, "EnableLUA")
	if err != nil {
		t.Skipf("读取 EnableLUA 失败（权限受限？）: %v", err)
	}
	if !ok {
		t.Fatal("EnableLUA 应存在，实际 ok=false")
	}
	if v > 1 {
		t.Logf("EnableLUA=%d（非常规值，仅记录）", v)
	}
}

func TestRegDWORDMissingKey(t *testing.T) {
	_, ok, err := RegDWORD(registry.LOCAL_MACHINE,
		`SOFTWARE\HostGuard-H5-NoSuchKey-9f3a`, "Whatever")
	if err != nil {
		t.Fatalf("键不存在应返回 ok=false 而非错误，实得: %v", err)
	}
	if ok {
		t.Fatal("不存在的键不应读出值")
	}
}

func TestRegDWORDMissingValue(t *testing.T) {
	_, ok, err := RegDWORD(registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`,
		"HostGuardH5NoSuchValue")
	if err != nil {
		t.Fatalf("值不存在应返回 ok=false 而非错误，实得: %v", err)
	}
	if ok {
		t.Fatal("不存在的值不应读出结果")
	}
}

func TestRegDWORDTypeMismatch(t *testing.T) {
	// CurrentBuild 是 REG_SZ：要求显示"读取失败"而不是把字符串硬转成 0。
	_, ok, err := RegDWORD(registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Windows NT\CurrentVersion`, "CurrentBuild")
	if err == nil {
		t.Fatalf("字符串值应返回类型错误（ok=%v）", ok)
	}
}

func TestRegDWORDInvalidPathNoPanic(t *testing.T) {
	// 内嵌 NUL 让 UTF16PtrFromString 直接失败，覆盖"参数级错误"分支。
	_, ok, err := RegDWORD(registry.LOCAL_MACHINE, "SOFTWARE\x00bad", "X")
	if err == nil || ok {
		t.Fatalf("非法路径应返回错误，实得 ok=%v err=%v", ok, err)
	}
}
