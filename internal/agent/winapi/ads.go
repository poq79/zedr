package winapi

// ads.go：NTFS 备用数据流（ADS）枚举与 Zone.Identifier（MotW）读取。
//
// 为什么做：下载来源是排查"文件从哪来"的第一现场——浏览器/Office 把来源
// URL 写进 Zone.Identifier 流（Mark of the Web），加壳器/容器工具也会留下
// 命名流。Go 标准库没有流枚举 API，这里直接绑 FindFirstStreamW。
//
// 布局注意：WIN32_FIND_STREAM_DATA 是 8 字节 int64 + 296 个 WCHAR
// （= 600 字节），与 64 位对齐天然成立，无需额外填充。

import (
	"fmt"
	"os"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	procFindFirstStreamW = modKernel32.NewProc("FindFirstStreamW")
	procFindNextStreamW  = modKernel32.NewProc("FindNextStreamW")
)

// FindFirstStreamW/FindNextStreamW 用到的 GetLastError 值
// （syscall.Errno 保持底层类型，直接与 LazyProc 的 e 比较用）。
const (
	errnoFileNotFound = 0x2
	errnoPathNotFound = 0x3
	errnoHandleEOF    = 0x26 // 38：无更多流
)

// errno 把 LazyProc 返回的 error 断言回 syscall.Errno（失败时返回 0，
// 调用方 0 值没有专用语义分支，安全）。
func errno(e error) uint32 {
	if en, ok := e.(syscall.Errno); ok {
		return uint32(en)
	}
	return 0
}

// findStreamData 对应 WIN32_FIND_STREAM_DATA。
type findStreamData struct {
	Length     int64
	StreamName [296]uint16
}

// invalidFindStreamHandle 与 windows.InvalidHandle 等值（FindFirstStreamW
// 失败时返回的句柄值）。windows.InvalidHandle 类型是 windows.Handle，
// 这里保持 uintptr 便于与 NewProc 返回值直接比较。
const invalidFindStreamHandle = ^uintptr(0)

// Stream 是一个命名数据流：Name 为去装饰的流名（如 "zone.identifier"，
// 不含首尾的冒号与 :$DATA 后缀），Size 为流字节数。
// JSON tag 必须显式给出：前端按小写 name/size 读取，缺省会按 Go 字段名
// 序列化成 Name/Size，导致 v2 文件抽屉显示 undefined（本轮修复）。
type Stream struct {
	Name string `json:"name"`
	Size int64  `json:"size"`
}

// EnumerateStreams 枚举文件的命名数据流（排除主流 ::$DATA）。
//
// 错误分类（调用方依赖语义，不要合并）：
//   - 文件/路径不存在 → 包装 os.ErrNotExist 的错误；
//   - 无命名流（所有文件都有主流，因此"无流"只发生在目录/特殊对象上，
//     FindFirstStreamW 返回 ERROR_HANDLE_EOF）→ 返回 nil, nil；
//   - 其他失败 → 原样 error，调用方按内部错误呈现。
func EnumerateStreams(path string) ([]Stream, error) {
	pathPtr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, fmt.Errorf("EnumerateStreams 路径非法: %w", err)
	}

	var fsd findStreamData
	h, _, e := procFindFirstStreamW.Call(
		uintptr(unsafe.Pointer(pathPtr)), 0,
		uintptr(unsafe.Pointer(&fsd)), 0)
	if h == invalidFindStreamHandle {
		// LazyProc 的 e 是 GetLastError 快照：ERROR_FILE_NOT_FOUND(2) /
		// ERROR_PATH_NOT_FOUND(3) → 不存在；ERROR_HANDLE_EOF(38) → 无流
		switch errno(e) {
		case errnoFileNotFound, errnoPathNotFound:
			return nil, fmt.Errorf("EnumerateStreams %s: %w", path, os.ErrNotExist)
		case errnoHandleEOF:
			return nil, nil
		default:
			return nil, fmt.Errorf("FindFirstStreamW %s 失败: errno=%d", path, errno(e))
		}
	}
	defer windows.FindClose(windows.Handle(h))

	out := make([]Stream, 0, 4)
	for {
		name := windows.UTF16ToString(fsd.StreamName[:])
		// 只收录命名流：主流形如 "::$DATA"；命名流形如 ":name:$DATA"。
		// 其他属性流（:$BITMAP 等）对调查无意义，同样跳过（避免目录
		// 对象的内部流污染结果）。
		if strings.HasPrefix(name, ":") && strings.HasSuffix(name, ":$DATA") {
			if inner := name[1 : len(name)-len(":$DATA")]; inner != "" {
				out = append(out, Stream{Name: inner, Size: fsd.Length})
			}
		}
		h, _, e := procFindNextStreamW.Call(h, uintptr(unsafe.Pointer(&fsd)))
		if h == 0 {
			if errno(e) == errnoHandleEOF {
				break // 正常枚举结束
			}
			return nil, fmt.Errorf("FindNextStreamW %s 失败: errno=%d", path, errno(e))
		}
	}
	return out, nil
}

// ZoneInfo 是 Zone.Identifier（Mark of the Web）解析结果。
// 字符串字段原样保留，不做 URL 规范化——原始值就是取证证据。
type ZoneInfo struct {
	ZoneID       int    // 0=本机 1=本地内网 2=受信任 3=Internet 4=受限；名称映射放 liveapi 层
	ReferrerURL  string // 来源页面（ReferrerUrl）
	HostURL      string // 下载主机（HostUrl）
	DownloadTime string // 下载时刻（格式由写入方决定，原样透出）
}

// ReadZoneIdentifier 读取文件 zone.identifier 流并解析 key=value 行。
//
// 无该 ADS（绝大多数本机文件）是常态而非错误 → 返回 nil, nil；
// 流存在但 ZoneId 行缺失/非数字 → 视为无效 MotW，同样 nil, nil
// （半损坏的 MotW 不足以支撑"来自 Internet"的判定，宁缺毋滥）。
func ReadZoneIdentifier(path string) (*ZoneInfo, error) {
	// Go 的 os 层对不含 \\?\ 前缀的短路径原样传给 CreateFile，
	// 而 CreateFile 原生支持 "file:stream" 语法，因此直接拼流名打开。
	data, err := os.ReadFile(path + ":zone.identifier")
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		// 其余错误（权限/IO）对调用方没有可行动的差异，统一按"无 MotW"
		// 降级并记录原因字符串，避免 /ads 端点因单一流读取失败整体 500
		return nil, nil
	}

	zi := &ZoneInfo{ZoneID: -1}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue // [ZoneTransfer] 节头等无值行
		}
		key = strings.TrimSpace(key)
		val = strings.TrimSpace(val)
		switch {
		case strings.EqualFold(key, "ZoneId"):
			n, convErr := atoiStrict(val)
			if convErr != nil {
				return nil, nil // ZoneId 坏 → 整条 MotW 不可信（见函数注释）
			}
			zi.ZoneID = n
		case strings.EqualFold(key, "ReferrerUrl"):
			zi.ReferrerURL = val
		case strings.EqualFold(key, "HostUrl"):
			zi.HostURL = val
		case strings.EqualFold(key, "DownloadTime"):
			zi.DownloadTime = val
		}
	}
	if zi.ZoneID < 0 {
		return nil, nil
	}
	return zi, nil
}

// atoiStrict 严格十进制解析（拒绝空串与尾随垃圾）。
func atoiStrict(s string) (int, error) {
	n := 0
	if s == "" {
		return 0, fmt.Errorf("空串")
	}
	for _, c := range []byte(s) {
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("非数字: %q", s)
		}
		n = n*10 + int(c-'0')
		if n > 1<<30 { // ZoneId 实际取值 0-4，防御超长数字
			return 0, fmt.Errorf("数值过大: %q", s)
		}
	}
	return n, nil
}
