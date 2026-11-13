//go:build windows
// +build windows

package winapi

// recon_winapi_test.go：资产侦查新增的只读 WinAPI 封装测试。
// 注册表/共享枚举依赖真实系统，断言只保持"可读/不 panic/字段合理"水位；
// 非管理员环境允许跳过共享枚举（权限不足不等于实现错误）。

import (
	"encoding/json"
	"strings"
	"testing"

	"golang.org/x/sys/windows/registry"
)

func TestRegReadStringAndDWORD(t *testing.T) {
	const key = `SOFTWARE\Microsoft\Windows NT\CurrentVersion`
	product, found, err := RegReadString(registry.LOCAL_MACHINE, key, "ProductName")
	if err != nil {
		t.Fatalf("读取 ProductName 失败: %v", err)
	}
	if !found || strings.TrimSpace(product) == "" {
		t.Fatalf("ProductName 应存在且非空: found=%v val=%q", found, product)
	}
	t.Logf("ProductName=%q", product)

	// 不存在的值：found=false 且不是错误（调用方用默认值）。
	if _, found, err := RegReadString(registry.LOCAL_MACHINE, key, "HostGuardNoSuchValue"); err != nil || found {
		t.Fatalf("不存在的值期望 (false,nil)，实得 (found=%v,err=%v)", found, err)
	}
	// 不存在的键：同样按"没配置"处理。
	if _, found, err := RegReadString(registry.LOCAL_MACHINE, `SOFTWARE\HostGuardNoSuchKey`, "x"); err != nil || found {
		t.Fatalf("不存在的键期望 (false,nil)，实得 (found=%v,err=%v)", found, err)
	}

	// DWORD：CurrentMajorVersionNumber 在 Win10+ 存在；老系统缺失也合法。
	major, found, err := RegReadDWORD(registry.LOCAL_MACHINE, key, "CurrentMajorVersionNumber")
	if err != nil {
		t.Fatalf("读取 CurrentMajorVersionNumber 失败: %v", err)
	}
	if found && major < 6 {
		t.Fatalf("CurrentMajorVersionNumber 取值异常: %d", major)
	}
	t.Logf("CurrentMajorVersionNumber found=%v val=%d", found, major)
}

func TestNetSharesNoPanic(t *testing.T) {
	shares, err := NetShares()
	if err != nil {
		// 非管理员/受限令牌下 NetShareEnum 可能 ACCESS_DENIED；
		// 这是环境限制，不是封装错误。
		t.Skipf("NetShareEnum 不可用（可能权限不足）: %v", err)
	}
	t.Logf("本地共享 %d 条", len(shares))
	for _, s := range shares {
		if strings.TrimSpace(s.Name) == "" {
			t.Errorf("共享名不应为空: %+v", s)
		}
		if strings.Contains(s.Name, "::$DATA") {
			t.Errorf("共享名不应含 ADS 装饰: %q", s.Name)
		}
	}
}

func TestStreamJSONTags(t *testing.T) {
	raw, err := json.Marshal(Stream{Name: "zone.identifier", Size: 123})
	if err != nil {
		t.Fatal(err)
	}
	got := string(raw)
	if !strings.Contains(got, `"name"`) || !strings.Contains(got, `"size"`) {
		t.Fatalf("Stream JSON 应使用小写 name/size，实得 %s", got)
	}
	if strings.Contains(got, `"Name"`) || strings.Contains(got, `"Size"`) {
		t.Fatalf("Stream JSON 不应出现 Go 字段名，实得 %s", got)
	}
}
