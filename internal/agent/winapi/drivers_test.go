//go:build windows
// +build windows

package winapi

// drivers_test.go：内核驱动枚举真机冒烟。

import (
	"strings"
	"testing"
	"time"
)

func TestLoadedDrivers(t *testing.T) {
	start := time.Now()
	drivers, err := LoadedDrivers()
	if err != nil {
		t.Fatalf("LoadedDrivers 失败: %v", err)
	}
	t.Logf("LoadedDrivers 耗时 %s，%d 条", time.Since(start), len(drivers))
	if len(drivers) == 0 {
		t.Fatal("运行中的系统至少应加载 1 个内核驱动")
	}

	// 排序校验
	for i := 1; i < len(drivers); i++ {
		if drivers[i-1].Path > drivers[i].Path {
			t.Errorf("结果未按 Path 排序: %q > %q", drivers[i-1].Path, drivers[i].Path)
		}
	}

	foundKernel := false
	for _, d := range drivers {
		low := strings.ToLower(d.Path)
		if strings.Contains(low, "ntoskrnl") || strings.HasSuffix(low, ".sys") {
			foundKernel = true
		}
		// Path 形态：归一后应为盘符 / \\?\ / \Device\（无法映射的原样回退）或空。
		// \Device\ 前缀是诚实的"映射失败保留原样"分支（如 \Device\000000xx
		// 非卷设备），不算错误。
		switch {
		case d.Path == "":
		case strings.HasPrefix(d.Path, `\\?\`):
		case strings.HasPrefix(d.Path, `\Device\`):
		case len(d.Path) >= 2 && d.Path[1] == ':': // 盘符
		default:
			t.Errorf("Path 形态异常（既非盘符也非 NT/Win32 路径）: %q", d.Path)
		}
		if d.Size == 0 {
			t.Errorf("驱动 %s 的 Size 为 0（合法文件不可能为空，疑似 Stat 结果污染）", d.Path)
		}
	}
	if !foundKernel {
		t.Error("驱动列表中未找到 ntoskrnl 或任何 .sys 后缀路径")
	}

	// ntoskrnl 应能拿到大小与 mtime（内核镜像普通用户可 Stat）
	for _, d := range drivers {
		if strings.Contains(strings.ToLower(d.Path), "ntoskrnl") {
			t.Logf("ntoskrnl: path=%s size=%d mtime=%s", d.Path, d.Size, d.MTime)
			break
		}
	}
}
