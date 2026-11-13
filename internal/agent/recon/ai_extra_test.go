//go:build windows

// ai_extra_test.go：2026-11 追加产品表（Hermes/dsh/OpenHands/CrewAI/
// LangServe/终端 Agent）的关键判定。
package recon

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"zedr/internal/agent/state"
	"zedr/internal/agent/winapi"
)

func TestDSHVersionAtLeastFixed(t *testing.T) {
	cases := []struct {
		version string
		fixed   bool
	}{
		{"0.1.1", false},
		{"0.1.2-alpha.1", false},
		{"0.1.2-alpha.2", true},
		{"0.1.2-alpha.2.1", true},
		{"0.1.2-alpha.10", true},
		{"0.1.2-beta", true},
		{"0.1.2", true},
		{"0.2.0", true},
		{"", false},
		{"not-a-version", false},
	}
	for _, tc := range cases {
		if got := dshVersionAtLeast(tc.version); got != tc.fixed {
			t.Errorf("dshVersionAtLeast(%q) = %v 期望 %v", tc.version, got, tc.fixed)
		}
	}
}

func TestDetectDSHCriticalCVE(t *testing.T) {
	root := t.TempDir()
	pkgDir := filepath.Join(root, "node_modules", "@deepseek-ai", "dsh")
	if err := os.MkdirAll(pkgDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pkgDir, "package.json"), []byte(`{"name":"@deepseek-ai/dsh","version":"0.1.1"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	cmdline := `node "` + filepath.Join(pkgDir, "cli.js") + `" web`
	b := newTestBase(
		[]state.ProcRow{{PID: 501, Name: "node.exe", CmdLine: cmdline}},
		[]winapi.NetRow{listenRow(3080, 501)},
		false, // dsh 判定不依赖网络探测
	)
	cat, err := detectAI(context.Background(), b)
	if err != nil {
		t.Fatalf("detectAI: %v", err)
	}
	item := findItem(cat, "dsh")
	if item == nil {
		t.Fatalf("未识别 dsh: %+v", cat.Items)
	}
	if item.Exposure.Level != LevelCritical {
		t.Fatalf("受影响版本期望 critical 实得 %q", item.Exposure.Level)
	}
	if item.Details["version"] != "0.1.1" {
		t.Fatalf("package.json version 未读到: %v", item.Details["version"])
	}
	if affected, _ := item.Details["cve_affected"].(bool); !affected {
		t.Fatalf("cve_affected 期望 true: %v", item.Details)
	}
	if !hasFindingLevel(cat, LevelCritical) {
		t.Fatalf("应有 critical finding: %+v", cat.Findings)
	}
}

func TestDetectAIClaudePluginsDir(t *testing.T) {
	home := t.TempDir()
	t.Setenv("USERPROFILE", home)
	if err := os.MkdirAll(filepath.Join(home, ".claude", "plugins"), 0o755); err != nil {
		t.Fatal(err)
	}
	cmdline := `node "C:\Users\dev\AppData\Roaming\npm\node_modules\@anthropic-ai\claude-code\cli.js"`
	b := newTestBase(
		[]state.ProcRow{{PID: 502, Name: "node.exe", CmdLine: cmdline}},
		nil,
		false,
	)
	cat, _ := detectAI(context.Background(), b)
	item := findItem(cat, "claude-code")
	if item == nil {
		t.Fatalf("未识别 claude-code: %+v", cat.Items)
	}
	if exists, _ := item.Details["config_dir_exists"].(bool); !exists {
		t.Fatalf("config_dir_exists 期望 true: %v", item.Details)
	}
	if exists, _ := item.Details["plugins_dir_exists"].(bool); !exists {
		t.Fatalf("plugins_dir_exists 期望 true: %v", item.Details)
	}
	foundPlugin := false
	for _, f := range item.Findings {
		if strings.Contains(f, "插件目录") {
			foundPlugin = true
		}
	}
	if !foundPlugin {
		t.Fatalf("插件目录 finding 缺失: %+v", item.Findings)
	}
	if item.Exposure.Level != LevelMedium {
		t.Fatalf("插件目录存在期望 medium 实得 %q", item.Exposure.Level)
	}
}

func TestDetectAILangServeOpenAPI(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			_, _ = io.WriteString(w, `<html><title>LangServe</title></html>`)
		case "/openapi.json":
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"openapi":"3.1.0","paths":{"/invoke":{}}}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	port := serverPort(t, srv)

	b := newTestBase(
		[]state.ProcRow{{PID: 503, Name: "uvicorn.exe", CmdLine: "uvicorn langserve_app:app"}},
		[]winapi.NetRow{listenRow(port, 503)},
		true,
	)
	cat, _ := detectAI(context.Background(), b)
	item := findItem(cat, "langserve")
	if item == nil {
		t.Fatalf("未识别 langserve: %+v", cat.Items)
	}
	if authOf(item) != AuthOpen {
		t.Fatalf("/openapi.json 200 期望 open 实得 %q", authOf(item))
	}
	if item.Exposure.Level != LevelHigh {
		t.Fatalf("LangServe open 期望 high 实得 %q", item.Exposure.Level)
	}
}

func TestDetectAIHermesGatewayAuth(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			_, _ = io.WriteString(w, `<html><title>Hermes</title></html>`)
		case "/v1/models":
			w.WriteHeader(http.StatusUnauthorized)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	port := serverPort(t, srv)

	b := newTestBase(
		[]state.ProcRow{{PID: 504, Name: "hermes.exe", CmdLine: "hermes gateway --port 8642"}},
		[]winapi.NetRow{listenRow(port, 504)},
		true,
	)
	cat, _ := detectAI(context.Background(), b)
	item := findItem(cat, "hermes-gateway")
	if item == nil {
		t.Fatalf("未识别 hermes-gateway: %+v", cat.Items)
	}
	if authOf(item) != AuthRequired {
		t.Fatalf("401 期望 auth_required 实得 %q", authOf(item))
	}
	if hint, _ := item.Details["auth_hint"].(string); hint == "" {
		t.Fatalf("gateway 401 应带 auth_hint: %v", item.Details)
	}
	if _, ok := item.Details["config_dir"]; !ok {
		t.Fatalf("应输出 config_dir: %v", item.Details)
	}
	if hasFindingLevel(cat, LevelHigh) {
		t.Fatalf("有认证的 gateway 不应报 high: %+v", cat.Findings)
	}
}
