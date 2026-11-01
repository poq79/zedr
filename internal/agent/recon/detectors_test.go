package recon

// detectors_test.go：六类 detector 的合成数据测试。
// AI/db 用 httptest/真实回环 TCP 在随机端口模拟产品；Netstat 行由测试
// 合成（端口 = 测试服务器实际端口），走完整 detect→probe→finding 链路。

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"zedr/internal/agent/state"
	"zedr/internal/agent/winapi"
)

func newTestBase(procs []state.ProcRow, rows []winapi.NetRow, probe bool) *base {
	return newBase(Deps{
		Procs:   func() []state.ProcRow { return procs },
		Netstat: func() []winapi.NetRow { return rows },
		Probe:   probe,
		Now:     func() time.Time { return time.Unix(1700000000, 0) },
	})
}

func serverPort(t *testing.T, srv *httptest.Server) uint16 {
	t.Helper()
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("解析 httptest URL: %v", err)
	}
	var port int
	if _, err := fmt.Sscanf(u.Port(), "%d", &port); err != nil || port < 1 || port > 65535 {
		t.Fatalf("httptest 端口异常: %q", u.Port())
	}
	return uint16(port)
}

func listenRow(port uint16, pid uint32) winapi.NetRow {
	return winapi.NetRow{
		Proto: "tcp", LocalIP: "127.0.0.1", LocalPort: port,
		RemoteIP: "0.0.0.0", RemotePort: 0, State: "LISTEN", PID: pid,
	}
}

func findItem(cat Category, kind string) *AssetItem {
	for i := range cat.Items {
		if cat.Items[i].Kind == kind {
			return &cat.Items[i]
		}
	}
	return nil
}

func authOf(item *AssetItem) string {
	s, _ := item.Details["auth_state"].(string)
	return s
}

func hasFindingLevel(cat Category, level string) bool {
	for _, f := range cat.Findings {
		if f.Level == level {
			return true
		}
	}
	return false
}

func TestDetectAIOllamaOpen(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/plain")
			_, _ = io.WriteString(w, "Ollama is running")
		case "/api/tags":
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"models":[{"name":"qwen2.5:7b"},{"name":"deepseek-r1:8b"}]}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	port := serverPort(t, srv)

	b := newTestBase(
		[]state.ProcRow{{PID: 101, Name: "ollama.exe", Path: `C:\tools\ollama.exe`, CmdLine: "ollama serve"}},
		[]winapi.NetRow{listenRow(port, 101)},
		true,
	)
	cat, err := detectAI(context.Background(), b)
	if err != nil {
		t.Fatalf("detectAI: %v", err)
	}
	item := findItem(cat, "ollama")
	if item == nil {
		t.Fatalf("未识别到 ollama: %+v", cat.Items)
	}
	if got := authOf(item); got != AuthOpen {
		t.Fatalf("auth_state 期望 open 实得 %q", got)
	}
	if item.Exposure.Level != LevelHigh {
		t.Fatalf("exposure 期望 high 实得 %q", item.Exposure.Level)
	}
	models, ok := item.Details["models"].([]string)
	if !ok || len(models) != 2 || models[0] != "qwen2.5:7b" {
		t.Fatalf("models 解析不符: %#v", item.Details["models"])
	}
	if !hasFindingLevel(cat, LevelHigh) {
		t.Fatalf("匿名可访问应产生 high finding: %+v", cat.Findings)
	}
	if item.Endpoint == "" || !strings.Contains(item.Endpoint, fmt.Sprintf(":%d", port)) {
		t.Fatalf("endpoint 不符: %q", item.Endpoint)
	}
}

func TestDetectAIVLLMModels(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			_, _ = io.WriteString(w, "<html><title>vLLM</title></html>")
		case "/v1/models":
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"object":"list","data":[{"id":"qwen2.5-7b-instruct"},{"id":"llama-3-8b"}]}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	port := serverPort(t, srv)

	b := newTestBase(
		[]state.ProcRow{{PID: 102, Name: "vllm.exe", CmdLine: "vllm serve qwen"}},
		[]winapi.NetRow{listenRow(port, 102)},
		true,
	)
	cat, _ := detectAI(context.Background(), b)
	item := findItem(cat, "vllm")
	if item == nil {
		t.Fatalf("未识别到 vllm: %+v", cat.Items)
	}
	if authOf(item) != AuthOpen {
		t.Fatalf("vllm auth_state 期望 open 实得 %q", authOf(item))
	}
	models, _ := item.Details["models"].([]string)
	if len(models) != 2 || models[0] != "qwen2.5-7b-instruct" {
		t.Fatalf("vllm models 不符: %#v", item.Details["models"])
	}
}

func TestDetectAIN8NAuthRequired(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.WriteHeader(http.StatusUnauthorized)
		case "/healthz":
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"status":"ok"}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	port := serverPort(t, srv)

	b := newTestBase(
		[]state.ProcRow{{PID: 103, Name: "n8n.exe", CmdLine: "n8n start"}},
		[]winapi.NetRow{listenRow(port, 103)},
		true,
	)
	cat, _ := detectAI(context.Background(), b)
	item := findItem(cat, "n8n")
	if item == nil {
		t.Fatalf("未识别到 n8n: %+v", cat.Items)
	}
	if got := authOf(item); got != AuthRequired {
		t.Fatalf("n8n 401 期望 auth_required 实得 %q", got)
	}
	if hasFindingLevel(cat, LevelHigh) {
		t.Fatalf("要求认证不应产生 high finding: %+v", cat.Findings)
	}
	if item.Exposure.Level != LevelLow {
		t.Fatalf("仅回环 + 有认证期望 low 实得 %q", item.Exposure.Level)
	}
}

// startRedisPONG 启动一个只回 +PONG 的 Redis 假服务（随机回环端口）。
func startRedisPONG(t *testing.T) (uint16, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("监听回环端口失败: %v", err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 64)
				n, _ := c.Read(buf)
				if strings.Contains(strings.ToUpper(string(buf[:n])), "PING") {
					_, _ = c.Write([]byte("+PONG\r\n"))
				}
			}(conn)
		}
	}()
	addr := ln.Addr().(*net.TCPAddr)
	return uint16(addr.Port), func() { _ = ln.Close() }
}

func TestDetectDBRedisNoAuth(t *testing.T) {
	port, stop := startRedisPONG(t)
	defer stop()

	b := newTestBase(
		[]state.ProcRow{{PID: 201, Name: "redis-server.exe", CmdLine: `"C:\Redis\redis-server.exe" redis.conf`}},
		[]winapi.NetRow{listenRow(port, 201)},
		true,
	)
	cat, err := detectDB(context.Background(), b)
	if err != nil {
		t.Fatalf("detectDB: %v", err)
	}
	item := findItem(cat, "redis")
	if item == nil {
		t.Fatalf("未识别到 redis: %+v", cat.Items)
	}
	if got := authOf(item); got != AuthOpen {
		t.Fatalf("PING +PONG 期望 open 实得 %q", got)
	}
	if item.Exposure.Level != LevelHigh {
		t.Fatalf("redis 无认证期望 high 实得 %q", item.Exposure.Level)
	}
	if !hasFindingLevel(cat, LevelHigh) {
		t.Fatalf("redis 无认证应有 high finding: %+v", cat.Findings)
	}
}

func TestDetectDBDockerCritical(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/version" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"ApiVersion":"1.43","Version":"27.0.0","Os":"windows"}`)
	}))
	defer srv.Close()
	port := serverPort(t, srv)

	b := newTestBase(
		[]state.ProcRow{{PID: 202, Name: "dockerd.exe", CmdLine: "dockerd --host=tcp://127.0.0.1:2375"}},
		[]winapi.NetRow{listenRow(port, 202)},
		true,
	)
	cat, _ := detectDB(context.Background(), b)
	item := findItem(cat, "docker")
	if item == nil {
		t.Fatalf("未识别到 docker: %+v", cat.Items)
	}
	if got := authOf(item); got != AuthOpen {
		t.Fatalf("匿名 /version 期望 open 实得 %q", got)
	}
	if item.Exposure.Level != LevelCritical {
		t.Fatalf("docker API 期望 critical 实得 %q", item.Exposure.Level)
	}
	if item.Details["version"] != "27.0.0" {
		t.Fatalf("version 解析不符: %v", item.Details["version"])
	}
	if !hasFindingLevel(cat, LevelCritical) {
		t.Fatalf("docker API 应有 critical finding: %+v", cat.Findings)
	}
}

func TestDetectAIPassiveNoProbe(t *testing.T) {
	b := newTestBase(
		[]state.ProcRow{{PID: 104, Name: "ollama.exe", CmdLine: "ollama serve"}},
		[]winapi.NetRow{listenRow(11434, 104)},
		false,
	)
	cat, _ := detectAI(context.Background(), b)
	item := findItem(cat, "ollama")
	if item == nil {
		t.Fatal("被动模式仍应识别进程指纹")
	}
	if got := authOf(item); got != AuthUnknown {
		t.Fatalf("被动模式 auth_state 期望 unknown 实得 %q", got)
	}
	if item.Exposure.Level != LevelLow {
		t.Fatalf("仅回环被动期望 low 实得 %q", item.Exposure.Level)
	}
}
