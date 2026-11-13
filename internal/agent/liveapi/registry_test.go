//go:build windows
// +build windows

package liveapi

// registry_test.go：/registry 的真机冒烟 + 路径校验单测。
// 真机部分读 HKLM\SOFTWARE\Microsoft（Windows 环境必有），非 Windows skip；
// handler 不依赖 Deps，直接构造空 server 调用（与 baseline/accounts 同法）。

import (
	"net/http"
	"runtime"
	"testing"
)

func TestRegistryRealSmoke(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("仅 Windows")
	}
	h := http.HandlerFunc((&server{}).handleRegistry)

	// 1. HKLM\SOFTWARE\Microsoft：必有键，子键必非空。
	// 显式给 max_subkeys=1000：该键在真实机器上可能超过默认 200
	//（服务器镜像常见数百至上千），"未截断"断言只在未触顶时检查，
	// 避免对具体机器的键数做脆弱假设；默认档的截断语义由
	// max_subkeys=2 用例单独验证。
	code, body := doGet(t, h, "/registry?path=HKLM\\SOFTWARE\\Microsoft&max_subkeys=1000")
	if code != http.StatusOK {
		t.Fatalf("期望 200 实得 %d body=%v", code, body)
	}
	d := dataOf(t, body)
	if d["exists"] != true {
		t.Fatalf("HKLM\\SOFTWARE\\Microsoft 应存在: %v", d["exists"])
	}
	if d["path"] != `HKLM\SOFTWARE\Microsoft` {
		t.Errorf("path 应为规范形态: %v", d["path"])
	}
	subs, ok := d["subkeys"].([]any)
	if !ok || len(subs) == 0 {
		t.Fatalf("HKLM\\SOFTWARE\\Microsoft 子键应非空: %v", d["subkeys"])
	}
	if d["truncated_subkeys"] != false {
		if len(subs) < 1000 {
			t.Errorf("未触 max_subkeys=1000 上限却标记截断: %v", d["truncated_subkeys"])
		} else {
			t.Log("本机 Microsoft 子键超过 1000，跳过未截断断言")
		}
	}
	t.Logf("HKLM\\SOFTWARE\\Microsoft subkeys=%d", len(subs))

	// 2. CurrentVersion\Run：values 数组合法（可能为空），项结构完整
	code, body = doGet(t, h, "/registry?path=HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run")
	if code != http.StatusOK {
		t.Fatalf("期望 200 实得 %d body=%v", code, body)
	}
	d = dataOf(t, body)
	if d["exists"] != true {
		t.Fatalf("Run 键应存在: %v", d["exists"])
	}
	values, ok := d["values"].([]any)
	if !ok {
		t.Fatalf("values 不是数组: %T", d["values"])
	}
	for i, raw := range values {
		v, ok := raw.(map[string]any)
		if !ok {
			t.Fatalf("values[%d] 不是对象: %T", i, raw)
		}
		if _, ok := v["name"].(string); !ok {
			t.Errorf("values[%d].name 不是字符串（默认值名应为空串）: %T", i, v["name"])
		}
		typ, _ := v["type"].(string)
		if typ == "" {
			t.Errorf("values[%d].type 为空", i)
		}
		// data 可为 null（error 标注时），但 error 与 data 不能同时缺席
		if _, hasData := v["data"]; !hasData {
			t.Errorf("values[%d] 缺 data 字段", i)
		}
	}
	t.Logf("CurrentVersion\\Run values=%d", len(values))

	// 3. 大小写不敏感：根键与子键小写形态也能查到
	code, body = doGet(t, h, "/registry?path=hklm/software/microsoft")
	if code != http.StatusOK {
		t.Fatalf("期望 200 实得 %d body=%v", code, body)
	}
	if dataOf(t, body)["exists"] != true {
		t.Error("小写/正斜杠路径应等价解析")
	}

	// 4. 不存在的键 → 200 exists:false（学 /fs/stat 语义，不是 404）
	code, body = doGet(t, h, "/registry?path=HKLM\\SOFTWARE\\__zedr_probe_no_such_key__")
	if code != http.StatusOK {
		t.Fatalf("键不存在应 200 实得 %d body=%v", code, body)
	}
	d = dataOf(t, body)
	if d["exists"] != false {
		t.Errorf("不存在键 exists 应为 false: %v", d["exists"])
	}
	if subs, _ := d["subkeys"].([]any); subs == nil {
		t.Error("exists:false 时 subkeys 应为空数组而非 null")
	}

	// 5. max_subkeys 截断：Microsoft 子键远多于 2，截断标记必须为真
	code, body = doGet(t, h, "/registry?path=HKLM\\SOFTWARE\\Microsoft&max_subkeys=2")
	if code != http.StatusOK {
		t.Fatalf("期望 200 实得 %d", code)
	}
	d = dataOf(t, body)
	if got, _ := d["subkeys"].([]any); len(got) != 2 {
		t.Errorf("max_subkeys=2 应返回 2 项实得 %d", len(got))
	}
	if d["truncated_subkeys"] != true {
		t.Error("被截断时应标记 truncated_subkeys")
	}
}

func TestRegistryPathValidation(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("仅 Windows")
	}
	h := http.HandlerFunc((&server{}).handleRegistry)

	cases := []struct {
		name, target string
	}{
		{"非法根键", "/registry?path=HKXX\\Foo"},
		{"缺根键", "/registry?path=SOFTWARE"},
		{"含 ..", "/registry?path=HKLM\\..\\SOFTWARE"},
		{"结尾空段", "/registry?path=HKLM\\SOFTWARE\\Microsoft\\"},
		{"中间空段", "/registry?path=HKLM\\\\SOFTWARE"},
		{"空 path", "/registry"},
		{"空 path 显式", "/registry?path="},
	}
	for _, c := range cases {
		code, body := doGet(t, h, c.target)
		if code != http.StatusBadRequest {
			t.Errorf("%s: 期望 400 实得 %d body=%v", c.name, code, body)
			continue
		}
		if m := errMsg(t, body); m == "" {
			t.Errorf("%s: 错误消息为空", c.name)
		}
	}
}
