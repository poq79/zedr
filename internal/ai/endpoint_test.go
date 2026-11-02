package ai

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// Base URL 自带版本段（OpenAI /v1、火山方舟 /api/v3、Agent Plan
// /api/plan/v3、Gemini /v1beta/openai）时不能再补 /v1。
func TestAPIEndpoint(t *testing.T) {
	cases := []struct {
		name, base, endpoint, want string
	}{
		{"bare host", "https://api.deepseek.com", "/chat/completions", "https://api.deepseek.com/v1/chat/completions"},
		{"openai v1", "https://api.openai.com/v1", "/chat/completions", "https://api.openai.com/v1/chat/completions"},
		{"trailing slash", "https://api.deepseek.com/v1/", "/models", "https://api.deepseek.com/v1/models"},
		{"padded", "  http://127.0.0.1:8000/v1/  ", "/chat/completions", "http://127.0.0.1:8000/v1/chat/completions"},
		{"ark payg", "https://ark.cn-beijing.volces.com/api/v3", "/chat/completions", "https://ark.cn-beijing.volces.com/api/v3/chat/completions"},
		{"ark agent plan", "https://ark.cn-beijing.volces.com/api/plan/v3", "/chat/completions", "https://ark.cn-beijing.volces.com/api/plan/v3/chat/completions"},
		{"ark coding plan", "https://ark.cn-beijing.volces.com/api/coding/v3", "/models", "https://ark.cn-beijing.volces.com/api/coding/v3/models"},
		{"gemini compat", "https://generativelanguage.googleapis.com/v1beta/openai", "/chat/completions", "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions"},
		{"ollama bare", "http://localhost:11434", "/chat/completions", "http://localhost:11434/v1/chat/completions"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := apiEndpoint(c.base, c.endpoint); got != c.want {
				t.Fatalf("apiEndpoint(%q) = %q, want %q", c.base, got, c.want)
			}
		})
	}
}

func TestHasVersionSuffixRejectsLookalikes(t *testing.T) {
	for _, base := range []string{
		"https://example.com/api",
		"https://example.com/v",
		"https://example.com/vx",
		"https://example.com/v1xyz",
		"https://example.com/version",
	} {
		if hasVersionSuffix(base) {
			t.Fatalf("hasVersionSuffix(%q) = true, want false", base)
		}
	}
}

// 拨测必须把 Key 送到、路径不重复拼 /v1；模型列表 404 时回退对话探测。
func TestProbeOpenAIVersionedBaseSendsAuth(t *testing.T) {
	var paths []string
	var auth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		auth = r.Header.Get("Authorization")
		switch r.URL.Path {
		case "/api/plan/v3/models":
			http.NotFound(w, r) // 套餐端点通常没有模型列表
		case "/api/plan/v3/chat/completions":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"pong"}}],"usage":{"total_tokens":1}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)

	res := ProbeOpenAI(srv.URL+"/api/plan/v3", "ark-plan-key", "deepseek-v4.1-flash-economy", 5*time.Second)
	if !res.OK {
		t.Fatalf("拨测应成功，得到: %s", res.Detail)
	}
	if auth != "Bearer ark-plan-key" {
		t.Fatalf("Authorization = %q, want Bearer ark-plan-key", auth)
	}
	want := []string{"/api/plan/v3/models", "/api/plan/v3/chat/completions"}
	if strings.Join(paths, ",") != strings.Join(want, ",") {
		t.Fatalf("请求路径 = %v, want %v", paths, want)
	}
}

// Key 没送到时的 401 要明确指出原因，而不是只回显服务商原文。
func TestProbeOpenAIEmptyKey401Explains(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":{"code":"AuthenticationError","message":"the API key or AK/SK in the request is missing or invalid."}}`))
	}))
	t.Cleanup(srv.Close)

	res := ProbeOpenAI(srv.URL, "", "m", 5*time.Second)
	if res.OK {
		t.Fatal("401 不应判为成功")
	}
	if !strings.Contains(res.Detail, "未携带 API Key") {
		t.Fatalf("空 Key 的 401 应解释原因，得到: %s", res.Detail)
	}

	res = ProbeOpenAI(srv.URL, "bad-key", "m", 5*time.Second)
	if res.OK || !strings.Contains(res.Detail, "套餐不匹配") {
		t.Fatalf("无效 Key 的 401 应提示核对套餐，得到: %s", res.Detail)
	}
}

// 真实研判路径同样要遵守版本段规则（拨测与推理不能各走一套拼接）。
func TestOpenAICompatibleVersionedBasePath(t *testing.T) {
	var gotPath, gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotAuth = r.URL.Path, r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"ok"}}],"usage":{"total_tokens":3}}`))
	}))
	t.Cleanup(srv.Close)

	b := NewOpenAICompatible(srv.URL+"/api/v3", "sk-test", "m", 5*time.Second)
	if _, _, err := b.chat(context.Background(), "sys", "user", 16); err != nil {
		t.Fatalf("chat 失败: %v", err)
	}
	if gotPath != "/api/v3/chat/completions" {
		t.Fatalf("请求路径 = %q, want /api/v3/chat/completions", gotPath)
	}
	if gotAuth != "Bearer sk-test" {
		t.Fatalf("Authorization = %q", gotAuth)
	}
}
