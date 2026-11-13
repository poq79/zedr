//go:build windows
// +build windows

package winapi

// shares.go：本地 SMB 共享枚举（资产侦查 remote 类）。
//
// 为什么用 NetShareEnum 而不是读注册表 LANMANServer\Shares：注册表里
// 是服务启动时加载的静态配置，NetShareEnum 反映的是"当前真实生效"的
// 共享（含运行时新增/删除），对暴露面盘查更准确；Remark/Path 也是
// 服务端已解析后的值，不需要自己拼。
//
// 只读：NetShareEnum 不改变共享状态；缓冲区由系统分配，必须用
// NetApiBufferFree 释放（与本包 security_windows.go 复用同一函数绑定）。

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

var procNetShareEnum = modNetapi32.NewProc("NetShareEnum")

const (
	shareLevel2 = 2
	// security_windows.go 已定义 netPreferredLength，同包不能重名；
	// 0xFFFFFFFF = MAX_PREFERRED_LENGTH：让系统一次性分配整表。
	sharePreferredLength = 0xFFFFFFFF
)

// ShareInfo 是一条本地 SMB 共享。
// JSON 字段即 recon remote 类 details.shares[] 的线协议（契约 §12.3）。
type ShareInfo struct {
	Name   string `json:"name"`
	Path   string `json:"path"`
	Remark string `json:"remark"`
}

// shareInfo2 对应 SHARE_INFO_2（x64 布局）：
// 4 个指针 + 3 个 DWORD（中间按指针宽度补齐），总 56 字节。
// 字段顺序必须与 netapi32.h 一致，否则解析出的 Path/Remark 会错位。
type shareInfo2 struct {
	NetName     *uint16
	Type        uint32
	Remark      *uint16
	Permissions uint32
	MaxUses     uint32
	CurrentUses uint32
	Path        *uint16
	Password    *uint16
}

// NetShares 枚举本机全部 SMB 共享（含 IPC$/ADMIN$/C$ 等特殊共享）。
//
// 特殊共享不做过滤：本函数的职责是"如实列出"，是否构成风险由
// recon 层按"非默认共享"判定（IPC$/ADMIN$ 是系统正常面，不应报风险）。
func NetShares() ([]ShareInfo, error) {
	out := make([]ShareInfo, 0, 16)
	var resume uint32
	for {
		var buf *byte
		var read, total uint32
		ret, _, _ := procNetShareEnum.Call(
			0, shareLevel2,
			uintptr(unsafe.Pointer(&buf)),
			uintptr(sharePreferredLength),
			uintptr(unsafe.Pointer(&read)),
			uintptr(unsafe.Pointer(&total)),
			uintptr(unsafe.Pointer(&resume)))
		// NERR_Success=0；ERROR_MORE_DATA=234 表示还有下一批。
		if ret != 0 && ret != uintptr(windows.ERROR_MORE_DATA) {
			return nil, fmt.Errorf("NetShareEnum 失败: errno=%d", ret)
		}
		if buf != nil && read > 0 {
			// SHARE_INFO_2 是 56 字节且自然对齐；用 unsafe.Slice 避免
			// 依赖每个字段的 unsafe.Add 偏移（结构体已按 x64 对齐）。
			items := unsafe.Slice((*shareInfo2)(unsafe.Pointer(buf)), int(read))
			for i := range items {
				it := &items[i]
				out = append(out, ShareInfo{
					Name:   utf16PtrString(it.NetName),
					Path:   utf16PtrString(it.Path),
					Remark: utf16PtrString(it.Remark),
				})
			}
		}
		if buf != nil {
			_, _, _ = procNetApiBufferFree.Call(uintptr(unsafe.Pointer(buf)))
		}
		if ret == 0 {
			break // 没有更多数据
		}
	}
	return out, nil
}

// utf16PtrString 读取可空 UTF-16 指针；nil 返回空串（IPC$ 等共享的
// Path 本来就没有磁盘路径）。
func utf16PtrString(p *uint16) string {
	if p == nil {
		return ""
	}
	return windows.UTF16PtrToString(p)
}
