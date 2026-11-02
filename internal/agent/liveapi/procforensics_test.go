package liveapi

// procforensics_test.go：进程取证四端点（§15）的 handler 契约测试。
// 真机数据随系统状态变化，断言以结构/字段/note 语义为主，不写死数量。

import (
	"net/http"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"zedr/internal/agent/winapi"
)

func selfPIDQuery() string {
	return strconv.Itoa(os.Getpid())
}

func TestHandlesEndpointSelf(t *testing.T) {
	h := New(Deps{StartTime: time.Now()})
	code, body := doGet(t, h, "/handles?pid="+selfPIDQuery())
	if code != http.StatusOK {
		t.Fatalf("期望 200 实得 %d body=%v", code, body)
	}
	d := dataOf(t, body)
	if pid, _ := d["pid"].(float64); uint32(pid) != uint32(os.Getpid()) {
		t.Errorf("pid 回显不符: %v", d["pid"])
	}
	total, _ := d["total"].(float64)
	if total < 10 {
		t.Fatalf("本进程句柄总数异常偏少: %v", d["total"])
	}
	types, ok := d["types"].(map[string]any)
	if !ok || len(types) == 0 {
		t.Fatalf("types 直方图缺失: %v", d["types"])
	}
	items, ok := d["items"].([]any)
	if !ok || len(items) == 0 {
		t.Fatalf("items 缺失: %v", d["items"])
	}
	// 契约字段：value/type/name
	first, _ := items[0].(map[string]any)
	for _, key := range []string{"value", "type", "name"} {
		if _, ok := first[key]; !ok {
			t.Errorf("items 元素缺少字段 %q: %v", key, first)
		}
	}
	if note, _ := d["note"].(string); note == "" {
		t.Error("note 不应为空（必须如实标注覆盖度）")
	}
	if _, ok := d["truncated"].(bool); !ok {
		t.Errorf("truncated 应为布尔: %v", d["truncated"])
	}
	t.Logf("types=%v note=%v", types, d["note"])
}

func TestHandlesEndpointValidation(t *testing.T) {
	h := New(Deps{StartTime: time.Now()})
	for _, target := range []string{
		"/handles",
		"/handles?pid=0",
		"/handles?pid=4",
		"/handles?pid=-1",
		"/handles?pid=abc",
	} {
		if code, _ := doGet(t, h, target); code != http.StatusBadRequest {
			t.Errorf("%s 期望 400 实得 %d", target, code)
		}
	}
	// limit 越界只钳制，不报错。
	if code, _ := doGet(t, h, "/handles?pid="+selfPIDQuery()+"&limit=99999"); code != http.StatusOK {
		t.Errorf("limit 越界应被钳制而不是报错，实得 %d", code)
	}
}

func TestThreadsEndpointSelf(t *testing.T) {
	h := New(Deps{StartTime: time.Now()})
	code, body := doGet(t, h, "/threads?pid="+selfPIDQuery())
	if code != http.StatusOK {
		t.Fatalf("期望 200 实得 %d body=%v", code, body)
	}
	d := dataOf(t, body)
	items, ok := d["items"].([]any)
	if !ok || len(items) == 0 {
		t.Fatalf("items 缺失: %v", d["items"])
	}
	first, _ := items[0].(map[string]any)
	for _, key := range []string{"tid", "start_address", "module", "in_anonymous_exec"} {
		if _, ok := first[key]; !ok {
			t.Errorf("items 元素缺少字段 %q: %v", key, first)
		}
	}
	if note, _ := d["note"].(string); note == "" {
		t.Error("note 不应为空")
	}
}

func TestThreadsEndpointValidation(t *testing.T) {
	h := New(Deps{StartTime: time.Now()})
	for _, target := range []string{
		"/threads",
		"/threads?pid=0",
		"/threads?pid=4",
	} {
		if code, _ := doGet(t, h, target); code != http.StatusBadRequest {
			t.Errorf("%s 期望 400 实得 %d", target, code)
		}
	}
}

func TestMemScanEndpointSelf(t *testing.T) {
	h := New(Deps{StartTime: time.Now()})
	code, body := doGet(t, h, "/memscan?pid="+selfPIDQuery())
	if code != http.StatusOK {
		t.Fatalf("期望 200 实得 %d body=%v", code, body)
	}
	d := dataOf(t, body)
	counts, ok := d["counts"].(map[string]any)
	if !ok {
		t.Fatalf("counts 缺失: %v", d["counts"])
	}
	if regions, _ := counts["regions"].(float64); regions < 1 {
		t.Fatalf("本进程 regions 应 ≥1: %v", counts)
	}
	if _, ok := counts["private_exec"].(float64); !ok {
		t.Errorf("counts.private_exec 缺失: %v", counts)
	}
	if _, ok := counts["suspicious"].(float64); !ok {
		t.Errorf("counts.suspicious 缺失: %v", counts)
	}
	if regions, ok := d["regions"].([]any); !ok || len(regions) == 0 {
		t.Fatalf("regions 缺失: %v", d["regions"])
	}
	if _, ok := d["suspicious"].([]any); !ok {
		t.Errorf("suspicious 应为数组: %v", d["suspicious"])
	}
	note, _ := d["note"].(string)
	// 固定说明是用户点名要求的护栏，逐字校验关键短语。
	for _, must := range []string{"仅返回地址空间元数据", "不读取/不传输任何内存内容", "受保护进程打不开时跳过"} {
		if !strings.Contains(note, must) {
			t.Errorf("note 缺少固定说明 %q: %q", must, note)
		}
	}
}

func TestMemScanEndpointValidationAndGuard(t *testing.T) {
	h := New(Deps{StartTime: time.Now()})
	if code, _ := doGet(t, h, "/memscan"); code != http.StatusBadRequest {
		t.Errorf("缺 pid 期望 400 实得 %d", code)
	}
	if code, _ := doGet(t, h, "/memscan?pid=4"); code != http.StatusBadRequest {
		t.Errorf("pid 4 期望 400 实得 %d", code)
	}

	// 显式 false（大小写不敏感）→ 403；true → 放行。
	t.Setenv("HG_AGENT_MEMSCAN_ENABLED", "FALSE")
	if code, body := doGet(t, h, "/memscan?pid="+selfPIDQuery()); code != http.StatusForbidden {
		t.Errorf("禁用时期望 403 实得 %d body=%v", code, body)
	} else if msg := errMsg(t, body); !strings.Contains(msg, "禁用") {
		t.Errorf("403 文案应说明已禁用: %q", msg)
	}
	t.Setenv("HG_AGENT_MEMSCAN_ENABLED", "true")
	if code, _ := doGet(t, h, "/memscan?pid="+selfPIDQuery()); code != http.StatusOK {
		t.Errorf("启用时期望 200 实得 %d", code)
	}
}

func TestHandleOwnersStructure(t *testing.T) {
	h := New(Deps{StartTime: time.Now()})
	code, body := doGet(t, h, "/handleowners?path="+`C%3A%5CWindows%5Cnotepad.exe`)
	if code != http.StatusOK {
		t.Fatalf("期望 200 实得 %d body=%v", code, body)
	}
	d := dataOf(t, body)
	if d["path"] != `C:\Windows\notepad.exe` {
		t.Errorf("path 回显不符: %v", d["path"])
	}
	for _, key := range []string{"scanned", "resolved", "owners", "truncated", "note"} {
		if _, ok := d[key]; !ok {
			t.Errorf("缺少字段 %q: %v", key, d)
		}
	}
	owners, ok := d["owners"].([]any)
	if !ok {
		t.Fatalf("owners 应为数组: %v", d["owners"])
	}
	// 结果可能为空（没有进程打开该文件），但结构必须完整、note 必须非空。
	for _, raw := range owners {
		owner, _ := raw.(map[string]any)
		for _, key := range []string{"pid", "name", "path"} {
			if _, ok := owner[key]; !ok {
				t.Errorf("owner 缺少字段 %q: %v", key, owner)
			}
		}
	}
	note, _ := d["note"].(string)
	if note == "" {
		t.Fatal("note 不应为空（必须如实标注部分覆盖）")
	}
	if !strings.Contains(note, "可能不完整") {
		t.Errorf("note 应说明覆盖度: %q", note)
	}
	t.Logf("scanned=%v resolved=%v owners=%d note=%s", d["scanned"], d["resolved"], len(owners), note)
}

func TestHandleOwnersValidation(t *testing.T) {
	h := New(Deps{StartTime: time.Now()})
	for _, target := range []string{
		"/handleowners",
		"/handleowners?path=",
		"/handleowners?path=notepad.exe",
		"/handleowners?path=" + `%5C%5C.%5CC%3A%5Cx`,
	} {
		if code, _ := doGet(t, h, target); code != http.StatusBadRequest {
			t.Errorf("%s 期望 400 实得 %d", target, code)
		}
	}
}

func TestHandleOwnersUnmappedDrive(t *testing.T) {
	// Q: 在绝大多数环境不存在；存在就跳过，避免误判。
	if _, err := winapi.DevicePathForDriveLetter("Q:"); err == nil {
		t.Skip("Q: 盘存在，跳过未映射盘符断言")
	}
	h := New(Deps{StartTime: time.Now()})
	code, body := doGet(t, h, "/handleowners?path="+`Q%3A%5Csample.bin`)
	if code != http.StatusOK {
		t.Fatalf("未映射盘符期望 200 实得 %d", code)
	}
	d := dataOf(t, body)
	if note, _ := d["note"].(string); !strings.Contains(note, "无法把该路径映射") {
		t.Errorf("note 应说明无法映射: %q", note)
	}
	if owners, ok := d["owners"].([]any); !ok || len(owners) != 0 {
		t.Errorf("未映射盘符不应有 owners: %v", d["owners"])
	}
}

func TestForensicsRoutesRegistered(t *testing.T) {
	// 防止路由漏注册：四个路径必须各自命中 handler（用非法参数拿到 400
	// 即证明不是 404）。
	h := New(Deps{StartTime: time.Now()})
	for _, target := range []string{"/handles", "/handleowners", "/threads", "/memscan"} {
		code, _ := doGet(t, h, target)
		if code == http.StatusNotFound {
			t.Errorf("%s 未注册（404）", target)
		}
	}
}
