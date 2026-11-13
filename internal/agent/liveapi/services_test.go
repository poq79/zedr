//go:build windows
// +build windows

package liveapi

// services_test.go：/services 的真机冒烟（结构完整性 + filter/state/limit 语义）。
// 服务枚举依赖 SCM，无法离线注入，非 Windows 直接 skip。

import (
	"net/http"
	"net/url"
	"runtime"
	"strings"
	"testing"
)

func TestServicesRealSmoke(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("仅 Windows")
	}
	h := http.HandlerFunc((&server{}).handleServices)

	code, body := doGet(t, h, "/services")
	if code == http.StatusInternalServerError {
		t.Skipf("当前环境无法枚举服务: %v", body)
	}
	if code != http.StatusOK {
		t.Fatalf("期望 200 实得 %d body=%v", code, body)
	}
	d := dataOf(t, body)
	total, _ := d["total"].(float64)
	if total <= 0 {
		t.Fatal("Windows 必有服务，total 应 > 0")
	}
	items, ok := d["items"].([]any)
	if !ok || len(items) == 0 {
		t.Fatalf("items 应非空: %v", d["items"])
	}

	firstName := ""
	for i, raw := range items {
		m, ok := raw.(map[string]any)
		if !ok {
			t.Fatalf("items[%d] 不是对象: %T", i, raw)
		}
		name, _ := m["name"].(string)
		if name == "" {
			t.Errorf("items[%d].name 为空: %v", i, m)
		}
		for _, f := range []string{"display_name", "state", "start_mode", "path_name", "account"} {
			if _, ok := m[f].(string); !ok {
				t.Errorf("items[%d].%s 不是字符串: %T", i, f, m[f])
			}
		}
		if i == 0 {
			firstName = name
		}
	}
	t.Logf("services total=%d returned=%d", int(total), len(items))

	// filter 生效：用首条服务名的前缀做子串过滤，至少应匹配到它自己
	if firstName != "" {
		prefix := firstName
		if len(prefix) > 4 {
			prefix = prefix[:4]
		}
		code, body = doGet(t, h, "/services?filter="+url.QueryEscape(prefix))
		if code != http.StatusOK {
			t.Fatalf("filter 请求期望 200 实得 %d", code)
		}
		fd := dataOf(t, body)
		fItems, _ := fd["items"].([]any)
		if len(fItems) == 0 {
			t.Errorf("filter=%q 应至少匹配到首条服务", prefix)
		}
		if fTotal, _ := fd["total"].(float64); int(fTotal) != int(total) {
			t.Errorf("total 应为过滤前全量 %d 实得 %d", int(total), int(fTotal))
		}
	}

	// filter 无匹配子串 → total 仍是全量、items 空、truncated false
	code, body = doGet(t, h, "/services?filter=__no_such_service_substring_zz__")
	if code != http.StatusOK {
		t.Fatalf("期望 200 实得 %d", code)
	}
	d = dataOf(t, body)
	if n, _ := d["total"].(float64); int(n) != int(total) {
		t.Errorf("无匹配 filter 下 total 应仍为全量 %d 实得 %d", int(total), int(n))
	}
	if items, _ := d["items"].([]any); len(items) != 0 {
		t.Errorf("无匹配 filter 下 items 应为空: %d", len(items))
	}
	if d["truncated"] != false {
		t.Error("无匹配 filter 不应标记 truncated")
	}

	// state=running：任何已启动的 Windows 必有运行中服务，且逐条核对 state
	code, body = doGet(t, h, "/services?state=running")
	if code != http.StatusOK {
		t.Fatalf("期望 200 实得 %d", code)
	}
	d = dataOf(t, body)
	rItems, ok := d["items"].([]any)
	if !ok || len(rItems) == 0 {
		t.Fatal("state=running 应非空（已启动的 Windows 必有运行中服务）")
	}
	for _, raw := range rItems {
		m := raw.(map[string]any)
		if s, _ := m["state"].(string); !strings.EqualFold(s, "running") {
			t.Errorf("state=running 过滤后混入 %q: %v", s, m["name"])
		}
	}

	// limit=1：恰 1 条且 truncated 为真（服务数 > 1 恒成立）
	code, body = doGet(t, h, "/services?limit=1")
	if code != http.StatusOK {
		t.Fatalf("期望 200 实得 %d", code)
	}
	d = dataOf(t, body)
	if items, _ := d["items"].([]any); len(items) != 1 {
		t.Errorf("limit=1 应返回 1 条实得 %d", len(items))
	}
	if d["truncated"] != true {
		t.Error("total>limit 时应标记 truncated")
	}
}
