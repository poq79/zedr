//go:build windows
// +build windows

package winapi

// fileattr.go：Windows 文件属性查询封装（liveapi /fs 与 /fs/stat 的属性来源）。
//
// 为什么不用 os.Stat 的 FileMode：Go 在 Windows 上只把 readonly 位映射进
// 权限位，hidden/system/reparse 无法从 os.FileMode 完整还原；一次
// GetFileAttributes 直取原始属性位最直接、无歧义。

import "golang.org/x/sys/windows"

// FileAttrs 是调查面关心的四个文件属性布尔。
type FileAttrs struct {
	Hidden   bool // FILE_ATTRIBUTE_HIDDEN
	System   bool // FILE_ATTRIBUTE_SYSTEM
	Readonly bool // FILE_ATTRIBUTE_READONLY
	Reparse  bool // FILE_ATTRIBUTE_REPARSE_POINT（junction/符号链接）
}

// GetFileAttrs 查询文件属性；查询失败（文件在列目录与取属性之间消失、
// 无权限等）一律返回零值——单条目的属性未知不应放大成整次列举失败，
// 由调用方决定"属性全 false"如何呈现。
func GetFileAttrs(path string) FileAttrs {
	pathPtr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return FileAttrs{}
	}
	attrs, err := windows.GetFileAttributes(pathPtr)
	if err != nil || attrs == windows.INVALID_FILE_ATTRIBUTES {
		return FileAttrs{}
	}
	return FileAttrs{
		Hidden:   attrs&windows.FILE_ATTRIBUTE_HIDDEN != 0,
		System:   attrs&windows.FILE_ATTRIBUTE_SYSTEM != 0,
		Readonly: attrs&windows.FILE_ATTRIBUTE_READONLY != 0,
		Reparse:  attrs&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0,
	}
}
