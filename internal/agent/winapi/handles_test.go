//go:build windows
// +build windows

package winapi

// handles_test.go：句柄表枚举/类型缓存/名称解析/设备映射的真机冒烟。
// 断言只保持"能跑通、结构合理、不 panic"水位：句柄数量与具体名称随系统
// 状态变化，不能写死。

import (
	"os"
	"strings"
	"testing"
	"time"
	"unsafe"
)

func TestEnumerateHandlesSelf(t *testing.T) {
	pid := uint32(os.Getpid())
	rows, err := EnumerateHandles(pid)
	if err != nil {
		t.Fatalf("EnumerateHandles(self) 失败: %v", err)
	}
	if len(rows) < 10 {
		t.Fatalf("本进程句柄数异常偏少: %d", len(rows))
	}

	sawFile := false
	sawName := false
	for _, row := range rows {
		if row.Value == 0 {
			t.Errorf("句柄值不应为 0: %+v", row)
		}
		if row.Type == "" {
			t.Errorf("类型不应为空: %+v", row)
		}
		if row.Type == "File" {
			sawFile = true
		}
		if row.Name != "" {
			sawName = true
		}
	}
	if !sawFile {
		t.Errorf("本进程句柄中应至少有一个 File 类型（测试二进制会加载文件）")
	}
	if !sawName {
		t.Errorf("应至少解析出一个安全类型句柄名称（名称全空说明 NtQueryObject 路径未生效）")
	}
	if cachedTypeNameCount() == 0 {
		t.Errorf("类型名缓存应已建立")
	}
	t.Logf("本进程句柄 %d 个，类型缓存 %d 项", len(rows), cachedTypeNameCount())
}

func TestCollectHandlesTypeFilterAndStats(t *testing.T) {
	pid := uint32(os.Getpid())
	res, err := CollectHandles(pid, "file", 50, time.Second)
	if err != nil {
		t.Fatalf("CollectHandles 失败: %v", err)
	}
	if res.Total == 0 || len(res.Types) == 0 {
		t.Fatalf("按 File 过滤应命中句柄: total=%d types=%v", res.Total, res.Types)
	}
	for typ, n := range res.Types {
		if !strings.EqualFold(typ, "file") {
			t.Errorf("type 过滤不区分大小写，出现了 %q", typ)
		}
		if n <= 0 {
			t.Errorf("直方图计数应 > 0: %s=%d", typ, n)
		}
	}
	if len(res.Rows) > 50 {
		t.Errorf("limit=50 实得 %d 行", len(res.Rows))
	}
	// 尝试解析名称的数量不应超过返回行数（只解析展示行）。
	if res.NameAttempted > len(res.Rows) {
		t.Errorf("NameAttempted=%d 超过返回行数 %d", res.NameAttempted, len(res.Rows))
	}
}

func TestEnumerateHandlesUnknownPID(t *testing.T) {
	// 取一个几乎不可能存在的 PID；即使存在也不应报错，只是结果不同。
	const ghost = uint32(0xFFFFFFF0)
	rows, err := EnumerateHandles(ghost)
	if err != nil {
		t.Fatalf("不存在的 pid 不应返回错误: %v", err)
	}
	if len(rows) != 0 {
		t.Fatalf("不存在的 pid 不应有句柄: %d", len(rows))
	}
}

func TestResolveHandleNameRejectsUnsafeType(t *testing.T) {
	// Process/Thread 等类型不在白名单，必须直接拒绝（不发起 NtQueryObject）。
	if _, ok := resolveHandleName(uint32(os.Getpid()), 4, "Process"); ok {
		t.Fatal("非安全类型不应解析名称")
	}
}

func TestDevicePathMapping(t *testing.T) {
	dev, err := DevicePathForDriveLetter("c")
	if err != nil {
		// 极小概率没有 C:（非常规环境），按环境限制跳过。
		t.Skipf("C: 盘映射不可用: %v", err)
	}
	if !strings.HasPrefix(strings.ToLower(dev), `\device\`) {
		t.Fatalf("C: 应映射到 \\Device\\... 实得 %q", dev)
	}

	got, ok := NormalizeToDevicePath(`C:\Windows\notepad.exe`)
	if !ok {
		t.Fatal("NormalizeToDevicePath 应成功")
	}
	if !strings.HasPrefix(strings.ToLower(got), strings.ToLower(dev)) {
		t.Fatalf("规范化结果 %q 应以 %q 开头", got, dev)
	}
	if !strings.HasSuffix(strings.ToLower(got), `\windows\notepad.exe`) {
		t.Fatalf("路径尾部不匹配: %q", got)
	}

	// 已经是设备路径：原样接受。
	if _, ok := NormalizeToDevicePath(dev + `\Windows`); !ok {
		t.Fatal("设备路径应直接接受")
	}
	// UNC 无法用 QueryDosDevice 映射，必须返回 false 而不是瞎猜。
	if _, ok := NormalizeToDevicePath(`\\server\share\a.exe`); ok {
		t.Fatal("UNC 路径不应映射成功")
	}
	// 相对路径不映射。
	if _, ok := NormalizeToDevicePath(`Windows\notepad.exe`); ok {
		t.Fatal("相对路径不应映射成功")
	}
}

func TestUnicodeStringFromBufferRejectsOutOfRange(t *testing.T) {
	// 手工构造一个 Buffer 指针指向缓冲外的 UNICODE_STRING：必须拒绝，
	// 不能顺着内核给的野指针读内存。
	buf := make([]byte, 64)
	us := (*unicodeStr)(unsafe.Pointer(&buf[0]))
	us.Length = 4
	outside := uint16(0)
	us.Buffer = &outside // 指向另一块分配，不在 buf 区间内
	if _, ok := unicodeStringFromBuffer(buf); ok {
		t.Fatal("越界 Buffer 必须拒绝")
	}
}
