package winapi

// registry.go：只读注册表值读取（资产侦查 remote 类读 RDP 的 NLA 配置）。
//
// 为什么直接用 RegGetValueW 而不是 x/sys/registry 的 OpenKey+Get*Value：
// 资产侦查只需要"读一个值，读不到就用默认"，RegGetValue 是单次调用、
// 自动处理键不存在/值不存在，不会因为中间某步失败留下半个状态；
// 同时显式限定只接受 REG_SZ/REG_EXPAND_SZ/DWORD，避免把二进制值
// 误当字符串读出来。
//
// 本文件只提供读；不暴露 Set/Delete，也不打开写权限（KEY_READ 语义）。

import (
	"errors"
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

var procRegGetValueW = modAdvapi32.NewProc("RegGetValueW")

const (
	// RegGetValueW 的类型过滤标志（winreg.h）。
	// REG_EXPAND_SZ 单列：只给 RRF_RT_REG_SZ 时类型不匹配会返回
	// ERROR_UNSUPPORTED_TYPE，而 %SystemRoot% 型路径常见于系统配置。
	rrfRtRegSz       = 0x00000002
	rrfRtRegExpandSz = 0x00000004
	rrfRtRegDword    = 0x00000010

	// ERROR_FILE_NOT_FOUND / ERROR_PATH_NOT_FOUND：键或值不存在是
	// "没有配置"，不是读取失败（调用方按产品默认值处理）。
	errRegFileNotFound = 2
	errRegPathNotFound = 3
)

// RegReadString 读取一个字符串值（REG_SZ / REG_EXPAND_SZ，不展开 %VAR%）。
//
// 返回 found=false 表示键或值不存在；其他错误（权限、类型不匹配）
// 原样返回，由调用方决定是否降级。把"不存在"与"读失败"分开是刻意的：
// 前者用默认值即可，后者说明采集面有缺口，排障时需要看见。
func RegReadString(root registry.Key, subkey, name string) (val string, found bool, err error) {
	subPtr, err := windows.UTF16PtrFromString(subkey)
	if err != nil {
		return "", false, fmt.Errorf("注册表子键非法: %w", err)
	}
	namePtr, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return "", false, fmt.Errorf("注册表值名非法: %w", err)
	}

	// 先问所需字节数（pvData=nil 时 RegGetValue 只回填 size）
	var size uint32
	ret, _, _ := procRegGetValueW.Call(
		uintptr(root), uintptr(unsafe.Pointer(subPtr)), uintptr(unsafe.Pointer(namePtr)),
		uintptr(rrfRtRegSz|rrfRtRegExpandSz), 0, 0, uintptr(unsafe.Pointer(&size)))
	if ret == errRegFileNotFound || ret == errRegPathNotFound {
		return "", false, nil
	}
	if ret != 0 {
		return "", false, fmt.Errorf("RegGetValue(%s\\%s) 查询长度失败: errno=%d", subkey, name, ret)
	}
	if size == 0 {
		return "", true, nil // 空字符串是合法值
	}

	buf := make([]byte, size)
	ret, _, _ = procRegGetValueW.Call(
		uintptr(root), uintptr(unsafe.Pointer(subPtr)), uintptr(unsafe.Pointer(namePtr)),
		uintptr(rrfRtRegSz|rrfRtRegExpandSz), 0,
		uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)))
	if ret != 0 {
		return "", false, fmt.Errorf("RegGetValue(%s\\%s) 读取失败: errno=%d", subkey, name, ret)
	}
	// size 含结尾 NUL；UTF16ToString 遇到 NUL 自然停止，无需额外裁剪。
	u16 := unsafe.Slice((*uint16)(unsafe.Pointer(&buf[0])), len(buf)/2)
	return windows.UTF16ToString(u16), true, nil
}

// RegReadDWORD 读取一个 REG_DWORD 值。
//
// 与 RegReadString 同一口径：不存在返回 found=false，类型不匹配/权限
// 失败返回 error（不把"读失败"伪装成"没配置"，否则会静默用默认值
// 覆盖真实的安全配置）。
func RegReadDWORD(root registry.Key, subkey, name string) (val uint32, found bool, err error) {
	subPtr, err := windows.UTF16PtrFromString(subkey)
	if err != nil {
		return 0, false, fmt.Errorf("注册表子键非法: %w", err)
	}
	namePtr, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return 0, false, fmt.Errorf("注册表值名非法: %w", err)
	}

	var data uint32
	size := uint32(unsafe.Sizeof(data))
	ret, _, _ := procRegGetValueW.Call(
		uintptr(root), uintptr(unsafe.Pointer(subPtr)), uintptr(unsafe.Pointer(namePtr)),
		uintptr(rrfRtRegDword), 0,
		uintptr(unsafe.Pointer(&data)), uintptr(unsafe.Pointer(&size)))
	switch ret {
	case 0:
		return data, true, nil
	case errRegFileNotFound, errRegPathNotFound:
		return 0, false, nil
	default:
		return 0, false, fmt.Errorf("RegGetValue(%s\\%s) DWORD 读取失败: errno=%d", subkey, name, ret)
	}
}

// IsRegNotFound 判断错误是否属于"键/值不存在"（已由上面函数消化的
// 路径通常不会再走到这里，保留给调用方包装错误时使用）。
func IsRegNotFound(err error) bool {
	return errors.Is(err, windows.ERROR_FILE_NOT_FOUND) || errors.Is(err, windows.ERROR_PATH_NOT_FOUND)
}
