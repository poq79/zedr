//go:build windows
// +build windows

package liveapi

// search_test.go：/fs/search 端点 + matchWildcard 单元表驱动。
// 临时目录树真实文件系统；truncated 分支靠注入极小预算验证。

import (
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// buildSearchTree 构造：
//
//	root/a.txt  root/notes.md
//	root/sub/b.exe(MZ头)  root/sub/deep/c.log
func buildSearchTree(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	sub := filepath.Join(root, "sub")
	deep := filepath.Join(sub, "deep")
	for _, d := range []string{sub, deep} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	files := map[string][]byte{
		filepath.Join(root, "a.txt"):    []byte("hello"),
		filepath.Join(root, "notes.md"): []byte("md"),
		filepath.Join(sub, "b.exe"):     []byte("MZ" + "payload"),
		filepath.Join(deep, "c.log"):    []byte("log"),
	}
	for p, c := range files {
		if err := os.WriteFile(p, c, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// searchNames 提取搜索结果条目的 path（相对路径）列表。
func searchNames(t *testing.T, body map[string]any) []string {
	t.Helper()
	raw, err := json.Marshal(body["entries"])
	if err != nil {
		t.Fatal(err)
	}
	var hits []struct {
		Path string `json:"path"`
	}
	if err := json.Unmarshal(raw, &hits); err != nil {
		t.Fatalf("entries 结构不符: %v raw=%s", err, raw)
	}
	out := make([]string, 0, len(hits))
	for _, h := range hits {
		out = append(out, h.Path)
	}
	return out
}

func TestSearchDepthAndPattern(t *testing.T) {
	root := buildSearchTree(t)
	h := New(Deps{StartTime: time.Now()})

	cases := []struct {
		name  string
		query string
		want  []string
	}{
		{"默认深度2-根层txt", "pattern=*.txt", []string{"a.txt"}},
		{"深度1不含深层log", "pattern=*.log&depth=1", nil},
		{"深度3触达c.log", "pattern=*.log&depth=3", []string{`sub\deep\c.log`}},
		{"精确名", "pattern=a.txt", []string{"a.txt"}},
		{"大小写不敏感", "pattern=A.TXT", []string{"a.txt"}},
		// pattern=* 也匹配目录名：sub\deep 是 level2 条目（depth=2 内），
		// 其内容（c.log）在 level3 不出现
		{"全部-默认深度2", "pattern=*", []string{"sub", `sub\deep`, "a.txt", "notes.md", `sub\b.exe`}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, body := doGet(t, h, "/fs/search?path="+url.QueryEscape(root)+"&"+tc.query)
			if code != http.StatusOK {
				t.Fatalf("期望 200 实得 %d body=%v", code, body)
			}
			d := dataOf(t, body)
			if d["truncated"] != false {
				t.Errorf("正常完成 truncated 应为 false: %v", d["truncated"])
			}
			got := searchNames(t, d)
			if len(got) != len(tc.want) {
				t.Fatalf("结果集不符: got=%v want=%v", got, tc.want)
			}
			for i, w := range tc.want {
				// 排序口径（目录优先+casefold）下顺序可对拍
				if got[i] != w {
					t.Fatalf("第 %d 项期望 %q 实得 %q（全部 %v）", i, w, got[i], got)
				}
			}
			// dir 定位字段（前端联调补充契约）：根层 "."、子目录相对路径
			dirs, _ := json.Marshal(d["entries"])
			var hits []struct {
				Path string `json:"path"`
				Dir  string `json:"dir"`
			}
			_ = json.Unmarshal(dirs, &hits)
			for _, hit := range hits {
				if hit.Dir == "" {
					t.Errorf("dir 字段缺失: %+v", hit)
				}
			}
			if len(hits) > 0 && hits[len(hits)-1].Dir == "." && hits[len(hits)-1].Path != "a.txt" && hits[len(hits)-1].Path != "notes.md" {
				t.Errorf("根层命中 dir 应为 \".\": %+v", hits)
			}
		})
	}
}

func TestSearchLimitAndTruncated(t *testing.T) {
	root := buildSearchTree(t)
	h := New(Deps{StartTime: time.Now()})

	// limit=1：命中即停，不算 truncated（limit 是调用方要的上限）
	code, body := doGet(t, h, "/fs/search?path="+url.QueryEscape(root)+"&pattern=*&limit=1")
	if code != http.StatusOK {
		t.Fatalf("期望 200 实得 %d", code)
	}
	d := dataOf(t, body)
	if names := searchNames(t, d); len(names) != 1 {
		t.Fatalf("limit=1 期望 1 条实得 %v", names)
	}
	if d["truncated"] != false {
		t.Errorf("limit 截断不应标 truncated: %v", d["truncated"])
	}

	// 预算超时：注入负预算（WithTimeout 对 dur<=0 同步取消，不依赖
	// runtime timer 的调度时机——同步测试里 1ns 定时器可能来不及触发）
	old := searchBudget
	searchBudget = -time.Nanosecond
	defer func() { searchBudget = old }()
	code, body = doGet(t, h, "/fs/search?path="+url.QueryEscape(root)+"&pattern=*.txt")
	if code != http.StatusOK {
		t.Fatalf("期望 200 实得 %d", code)
	}
	if dataOf(t, body)["truncated"] != true {
		t.Fatalf("预算超时应 truncated=true")
	}
}

func TestSearchQuickFlags(t *testing.T) {
	root := buildSearchTree(t)
	h := New(Deps{StartTime: time.Now()})

	code, body := doGet(t, h, "/fs/search?path="+url.QueryEscape(root)+"&pattern=*.exe")
	if code != http.StatusOK {
		t.Fatalf("期望 200 实得 %d", code)
	}
	raw, _ := json.Marshal(dataOf(t, body)["entries"])
	var hits []struct {
		Path  string `json:"path"`
		Quick struct {
			PE     bool `json:"pe"`
			ADS    bool `json:"ads"`
			Hidden bool `json:"hidden"`
			System bool `json:"system"`
		} `json:"quick"`
	}
	if err := json.Unmarshal(raw, &hits); err != nil {
		t.Fatalf("quick 结构不符: %v raw=%s", err, raw)
	}
	if len(hits) != 1 || hits[0].Path != `sub\b.exe` {
		t.Fatalf("期望命中 sub\\b.exe: %+v", hits)
	}
	if !hits[0].Quick.PE {
		t.Errorf("b.exe 有 MZ 头，quick.pe 应为 true: %+v", hits[0])
	}

	// ADS 快检：真实挂一条流（非 NTFS 卷 skip）
	bexe := filepath.Join(root, "sub", "b.exe")
	if err := os.WriteFile(bexe+":zone.identifier", []byte("[ZoneTransfer]\nZoneId=3\n"), 0o644); err != nil {
		t.Skipf("本卷不支持 ADS: %v", err)
	}
	code, body = doGet(t, h, "/fs/search?path="+url.QueryEscape(root)+"&pattern=*.exe")
	if code != http.StatusOK {
		t.Fatalf("期望 200 实得 %d", code)
	}
	raw, _ = json.Marshal(dataOf(t, body)["entries"])
	hits = nil
	if err := json.Unmarshal(raw, &hits); err != nil {
		t.Fatal(err)
	}
	if len(hits) != 1 || !hits[0].Quick.ADS {
		t.Fatalf("挂流后 quick.ads 应为 true: %+v", hits)
	}
}

func TestSearchValidation(t *testing.T) {
	root := buildSearchTree(t)
	h := New(Deps{StartTime: time.Now()})

	// pattern 必填（空 pattern = 全树枚举，成本模型不同）
	if code, _ := doGet(t, h, "/fs/search?path="+url.QueryEscape(root)); code != http.StatusBadRequest {
		t.Fatalf("空 pattern 期望 400")
	}
	// 起点是文件 → 400
	if code, _ := doGet(t, h, "/fs/search?path="+url.QueryEscape(filepath.Join(root, "a.txt"))+"&pattern=*"); code != http.StatusBadRequest {
		t.Fatalf("文件起点期望 400")
	}
	// 起点不存在 → 404
	if code, _ := doGet(t, h, "/fs/search?path="+url.QueryEscape(filepath.Join(root, "gone"))+"&pattern=*"); code != http.StatusNotFound {
		t.Fatalf("不存在起点期望 404")
	}
	// depth/limit 越界钳制（不报错）
	if code, _ := doGet(t, h, "/fs/search?path="+url.QueryEscape(root)+"&pattern=*&depth=99&limit=99999"); code != http.StatusOK {
		t.Fatalf("越界参数应被钳制而非报错，实得 %d", code)
	}
}

func TestMatchWildcard(t *testing.T) {
	cases := []struct {
		pat, s string
		want   bool
	}{
		{"*.exe", "tool.exe", true},
		{"*.exe", "tool.exe.bak", false},
		{"*", "anything.txt", true},
		{"a?c", "abc", true},
		{"a?c", "ac", false},
		{"a*c", "abc", true},
		{"a*c", "abxxc", true},
		{"a*c", "abxx", false},
		{"*.*", "noext", false},
		{"", "", true},
		{"", "x", false},
		{"a**b", "axxb", true},   // 连续星号
		{"**", "anything", true}, // 纯星号
		{"abc", "abc", true},
		{"a?b*c", "axbxxc", true}, // 混合回溯
	}
	for _, tc := range cases {
		if got := matchWildcard(tc.pat, tc.s); got != tc.want {
			t.Errorf("matchWildcard(%q,%q) = %v, want %v", tc.pat, tc.s, got, tc.want)
		}
	}
}
