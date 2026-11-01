package recon

// recon_test.go：入口/分类过滤/并发编排/panic 兜底/超时截断，
// 以及"合成数据六类都能出结果"的冒烟测试。

import (
	"context"
	"strings"
	"testing"
	"time"

	"zedr/internal/agent/state"
	"zedr/internal/agent/winapi"
)

func TestParseCategories(t *testing.T) {
	all := Categories()
	cases := []struct {
		raw  string
		want []string
		err  bool
	}{
		{"", all, false},
		{"web,AI", []string{"web", "ai"}, false},
		{" ai , db ,ai", []string{"ai", "db"}, false},
		{"web,bogus", nil, true},
		{"web,,ai", nil, true},
	}
	for _, tc := range cases {
		got, err := ParseCategories(tc.raw)
		if tc.err {
			if err == nil {
				t.Fatalf("ParseCategories(%q) 期望错误", tc.raw)
			}
			continue
		}
		if err != nil {
			t.Fatalf("ParseCategories(%q) 意外错误: %v", tc.raw, err)
		}
		if strings.Join(got, ",") != strings.Join(tc.want, ",") {
			t.Fatalf("ParseCategories(%q) = %v 期望 %v", tc.raw, got, tc.want)
		}
	}
}

func TestRunRejectsUnknownCategory(t *testing.T) {
	if _, err := Run(context.Background(), Deps{}, []string{"nope"}); err == nil {
		t.Fatal("未知分类应返回错误")
	}
}

func TestRunSyntheticAllCategories(t *testing.T) {
	procs := []state.ProcRow{
		{PID: 301, Name: "nginx.exe", Path: `C:\nginx\nginx.exe`, CmdLine: `nginx.exe -c C:\missing\nginx.conf`},
		{PID: 302, Name: "ollama.exe", CmdLine: "ollama serve"},
		{PID: 303, Name: "redis-server.exe", CmdLine: "redis-server"},
		{PID: 304, Name: "teamviewer.exe", CmdLine: `"C:\Program Files\TeamViewer\TeamViewer.exe"`},
		{PID: 305, Name: "jupyter-notebook.exe", CmdLine: "jupyter-notebook --no-browser"},
		{PID: 306, Name: "vmmem", CmdLine: ""},
	}
	rows := []winapi.NetRow{
		listenRow(8080, 301),
		listenRow(11434, 302),
		listenRow(6379, 303),
		listenRow(8888, 305),
	}
	res, err := Run(context.Background(), Deps{
		Procs:   func() []state.ProcRow { return procs },
		Netstat: func() []winapi.NetRow { return rows },
		Probe:   false,
		Now:     func() time.Time { return time.Unix(1700000000, 0) },
	}, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(res.Categories) != len(Categories()) {
		t.Fatalf("类别数期望 %d 实得 %d", len(Categories()), len(res.Categories))
	}
	if res.GeneratedAt != "2023-11-14T22:13:20Z" {
		t.Fatalf("generated_at 未使用注入时钟: %q", res.GeneratedAt)
	}
	if res.Probed || res.Truncated {
		t.Fatalf("被动模式不应 probed/truncated: probed=%v truncated=%v", res.Probed, res.Truncated)
	}
	for _, cat := range res.Categories {
		if len(cat.Items) == 0 {
			t.Errorf("分类 %s 期望至少 1 条资产，实际 0（findings=%v）", cat.Key, cat.Findings)
		}
	}
	byKey := make(map[string]Category, len(res.Categories))
	for _, c := range res.Categories {
		byKey[c.Key] = c
	}
	if findItem(byKey["web"], "nginx") == nil {
		t.Errorf("web 类未识别 nginx")
	}
	if findItem(byKey["ai"], "ollama") == nil {
		t.Errorf("ai 类未识别 ollama")
	}
	if findItem(byKey["db"], "redis") == nil {
		t.Errorf("db 类未识别 redis")
	}
	if findItem(byKey["remote"], "teamviewer") == nil {
		t.Errorf("remote 类未识别 teamviewer")
	}
	if findItem(byKey["dev"], "jupyter") == nil {
		t.Errorf("dev 类未识别 jupyter")
	}
	if findItem(byKey["virt"], "wsl") == nil {
		t.Errorf("virt 类未识别 wsl/vmmem")
	}
}

func TestRunCategoryFilter(t *testing.T) {
	res, err := Run(context.Background(), Deps{}, []string{"ai", "web"})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(res.Categories) != 2 || res.Categories[0].Key != "ai" || res.Categories[1].Key != "web" {
		t.Fatalf("分类过滤/顺序不符: %+v", res.Categories)
	}
}

func TestRunDetectorPanicRecovered(t *testing.T) {
	b := newBase(Deps{})
	cat := runDetector(context.Background(), "web", func(context.Context, *base) (Category, error) {
		panic("boom")
	}, b)
	if cat.Key != "web" {
		t.Fatalf("panic 后仍应返回对应类目，实得 %+v", cat)
	}
	if len(cat.Findings) == 0 || !strings.Contains(cat.Findings[0].Detail, "boom") {
		t.Fatalf("panic 应转成类目级说明: %+v", cat.Findings)
	}
}

func TestRunTruncatedOnCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // 模拟预算/上游请求已取消
	res, err := Run(ctx, Deps{}, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !res.Truncated {
		t.Fatal("上游 ctx 已取消时应置 truncated=true")
	}
	if len(res.Categories) != len(Categories()) {
		t.Fatalf("仍应返回全部类目占位: %d", len(res.Categories))
	}
}
