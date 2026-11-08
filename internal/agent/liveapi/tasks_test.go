package liveapi

// tasks_test.go：/tasks 的真机冒烟（结构完整性 + filter/limit 语义）。
// 计划任务枚举依赖真实文件树，无法离线注入，非 Windows 直接 skip。

import (
	"net/http"
	"net/url"
	"runtime"
	"strings"
	"testing"
)

func TestTasksRealSmoke(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("仅 Windows")
	}
	h := http.HandlerFunc((&server{}).handleTasks)

	code, body := doGet(t, h, "/tasks")
	if code == http.StatusInternalServerError {
		t.Skipf("当前环境无法枚举计划任务: %v", body)
	}
	if code != http.StatusOK {
		t.Fatalf("期望 200 实得 %d body=%v", code, body)
	}
	d := dataOf(t, body)
	total, _ := d["total"].(float64)
	if total <= 0 {
		t.Fatal("Windows 必有计划任务，total 应 > 0")
	}
	items, ok := d["items"].([]any)
	if !ok || len(items) == 0 {
		t.Fatalf("items 应非空: %v", d["items"])
	}

	firstPath := ""
	for i, raw := range items {
		m, ok := raw.(map[string]any)
		if !ok {
			t.Fatalf("items[%d] 不是对象: %T", i, raw)
		}
		path, _ := m["path"].(string)
		name, _ := m["name"].(string)
		if path == "" || name == "" {
			t.Errorf("items[%d] path/name 为空: %v", i, m)
		}
		if _, ok := m["enabled"].(bool); !ok {
			t.Errorf("items[%d].enabled 不是 bool: %T", i, m["enabled"])
		}
		if _, ok := m["triggers"].([]any); !ok {
			t.Errorf("items[%d].triggers 不是数组（nil 应已收敛为空数组）: %T", i, m["triggers"])
		}
		if _, ok := m["actions"].([]any); !ok {
			t.Errorf("items[%d].actions 不是数组: %T", i, m["actions"])
		}
		if i == 0 {
			firstPath = path
		}
	}
	t.Logf("tasks total=%d returned=%d", int(total), len(items))

	// filter 生效：取首条的路径片段作为 filter，至少应匹配到它自己
	if firstPath != "" {
		seg := strings.ToLower(firstPath)
		seg = strings.TrimPrefix(seg, `\`)
		code, body = doGet(t, h, "/tasks?filter="+url.QueryEscape(seg))
		if code != http.StatusOK {
			t.Fatalf("filter 请求期望 200 实得 %d", code)
		}
		fd := dataOf(t, body)
		fItems, _ := fd["items"].([]any)
		if len(fItems) == 0 {
			t.Errorf("filter=%q 应至少匹配到首条任务", seg)
		}
		if fTotal, _ := fd["total"].(float64); int(fTotal) != int(total) {
			t.Errorf("total 应为过滤前全量 %d 实得 %d", int(total), int(fTotal))
		}
	}

	// filter 无匹配子串 → total 仍是全量、items 空、truncated false
	code, body = doGet(t, h, "/tasks?filter=__no_such_task_substring_zz__")
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

	// limit=1：items 恰 1 条且 truncated 为真（total>1 在真实 Windows 上恒成立）
	code, body = doGet(t, h, "/tasks?limit=1")
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
