package winapi

// verinfo.go：PE 版本资源（VS_VERSIONINFO）读取。
//
// 为什么不用纯 Go 解析：版本资源的字符串表按 (语言ID, 代码页) 索引，
// 语系组合由编译方决定；VerQueryValueW 原生完成块查找，比手撸
// VS_VERSIONINFO 二进制遍历少一大类对齐/填充 bug。
//
// 常见语系：0409（en-US）、0804（zh-CN），代码页 04b0（UTF-16LE，1200）、
// 04e4（1252）。无 Translation 块时按这几组常见组合兜底试探。

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

var modVersion = windows.NewLazySystemDLL("version.dll")

var (
	procGetFileVersionInfoSizeW = modVersion.NewProc("GetFileVersionInfoSizeW")
	procGetFileVersionInfoW     = modVersion.NewProc("GetFileVersionInfoW")
	procVerQueryValueW          = modVersion.NewProc("VerQueryValueW")
)

// VersionInfo 是调查面关心的四个版本资源字符串。
type VersionInfo struct {
	Company          string
	Product          string
	Description      string // FileDescription，资源管理器里显示的文件说明
	OriginalFilename string // 编译时声明的原始文件名，与实际名比对可发现伪装
}

// versionInfoKeys 是要提取的键：Go 字段名 → 资源键名。
var versionInfoKeys = [][2]string{
	{"Company", "CompanyName"},
	{"Product", "ProductName"},
	{"Description", "FileDescription"},
	{"OriginalFilename", "OriginalFilename"},
}

// ReadVersionInfo 读取文件版本资源；无版本资源（大多数脚本/文档/加壳样本）
// 返回 nil, nil——"没有版本信息"本身是排查信号，但不是错误。
func ReadVersionInfo(path string) (*VersionInfo, error) {
	pathPtr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, fmt.Errorf("ReadVersionInfo 路径非法: %w", err)
	}

	size, _, _ := procGetFileVersionInfoSizeW.Call(uintptr(unsafe.Pointer(pathPtr)), 0)
	if size == 0 {
		return nil, nil
	}
	// 版本资源大小上限 64MB 是理论值；防御性拒绝异常大的分配请求
	if size > 64<<20 {
		return nil, fmt.Errorf("版本资源异常过大: %d", size)
	}

	buf := make([]byte, size)
	ret, _, _ := procGetFileVersionInfoW.Call(
		uintptr(unsafe.Pointer(pathPtr)), 0, size,
		uintptr(unsafe.Pointer(&buf[0])))
	if ret == 0 {
		return nil, nil // 读失败按无资源降级，调用方不应为此收到 500
	}

	out := &VersionInfo{}
	langs := queryTranslations(buf)
	if len(langs) == 0 {
		// 无 Translation 块：试探常见 (lang, codepage) 组合
		langs = [][2]uint16{{0x0409, 0x04b0}, {0x0409, 0x04e4}, {0x0804, 0x04b0}, {0x0804, 0x04e4}}
	}
	for _, lc := range langs {
		for _, kv := range versionInfoKeys {
			if got := queryStringValue(buf, lc[0], lc[1], kv[1]); got != "" {
				setVersionField(out, kv[0], got)
			}
		}
	}
	if out.Company == "" && out.Product == "" && out.Description == "" && out.OriginalFilename == "" {
		return nil, nil // 语系全试仍无有效字符串 → 与无资源同义
	}
	return out, nil
}

func setVersionField(v *VersionInfo, field, val string) {
	switch field {
	case "Company":
		v.Company = val
	case "Product":
		v.Product = val
	case "Description":
		v.Description = val
	case "OriginalFilename":
		v.OriginalFilename = val
	}
}

// queryTranslations 读 \VarFileInfo\Translation 块：N 对 (langid, codepage)。
func queryTranslations(buf []byte) [][2]uint16 {
	// sub 必须是 unsafe.Pointer：VerQueryValue 输出的是块内指针，
	// 经 uintptr 中转会触发 vet 的 unsafe 误用告警
	var sub unsafe.Pointer
	var subLen uint32
	q, _ := windows.UTF16PtrFromString(`\VarFileInfo\Translation`)
	ret, _, _ := procVerQueryValueW.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(q)),
		uintptr(unsafe.Pointer(&sub)),
		uintptr(unsafe.Pointer(&subLen)))
	if ret == 0 || sub == nil || subLen < 4 {
		return nil
	}
	n := int(subLen) / 4
	if n > 64 { // 语系对理论极少，防御畸形资源
		n = 64
	}
	type langCP struct{ Lang, CP uint16 }
	pairs := unsafe.Slice((*langCP)(sub), n)
	out := make([][2]uint16, 0, n)
	for _, p := range pairs {
		out = append(out, [2]uint16{p.Lang, p.CP})
	}
	return out
}

// queryStringValue 读 \StringFileInfo\<lang><cp>\<key> 的 UTF-16 值。
func queryStringValue(buf []byte, lang, codepage uint16, key string) string {
	q, _ := windows.UTF16PtrFromString(fmt.Sprintf(`\StringFileInfo\%04x%04x\%s`, lang, codepage, key))
	var sub unsafe.Pointer
	var subLen uint32
	ret, _, _ := procVerQueryValueW.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(q)),
		uintptr(unsafe.Pointer(&sub)),
		uintptr(unsafe.Pointer(&subLen)))
	if ret == 0 || sub == nil || subLen < 2 {
		return ""
	}
	// VerQueryValue 的著名口径坑：对字符串子块 subLen 的单位是**字符数
	//（含 NUL 的 WCHAR 数）**，不是字节数（二进制块如 Translation 才是
	// 字节）。真机 dump 验证过："Microsoft Corporation\0" 返回 22。
	// 直接按 WORD 切，UTF16ToString 遇 NUL 停，天然容忍单位误差。
	n := subLen
	if n > 8192 { // 防御畸形资源，版本字符串不可能这么长
		n = 8192
	}
	ws := unsafe.Slice((*uint16)(sub), n)
	return windows.UTF16ToString(ws)
}
