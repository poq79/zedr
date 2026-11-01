package recon

// probe_test.go：探测红线单测。
// 覆盖：回环校验（表驱动）、跨地址重定向拒绝、2s 超时语义、64KB 读取上限、
// 40 次总预算、TCP 目标校验。

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestValidateProbeURLLoopbackOnly(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		ok   bool
	}{
		{"ipv4 loopback", "http://127.0.0.1:8080/", true},
		{"ipv4 loopback range", "http://127.1.2.3:1/", true},
		{"ipv6 loopback", "http://[::1]:8080/", true},
		{"public ip", "http://8.8.8.8:80/", false},
		{"localhost name", "http://localhost:8080/", false},
		{"localhost.com", "http://localhost.com:8080/", false},
		{"unspecified", "http://0.0.0.0:8080/", false},
		{"https", "https://127.0.0.1:8080/", false},
		{"userinfo", "http://user:pass@127.0.0.1:8080/", false},
		{"missing port", "http://127.0.0.1/", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			u, err := url.Parse(tc.raw)
			if err != nil {
				t.Fatalf("url.Parse: %v", err)
			}
			err = validateProbeURL(u)
			if tc.ok && err != nil {
				t.Fatalf("%s 应允许，实得 %v", tc.raw, err)
			}
			if !tc.ok && err == nil {
				t.Fatalf("%s 应拒绝，实际通过", tc.raw)
			}
		})
	}
}

func TestProbeRejectsCrossAddressRedirect(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://8.8.8.8:9/steal", http.StatusFound)
	}))
	defer srv.Close()

	pc := newProbeClient(10, time.Second)
	resp := pc.get(context.Background(), srv.URL+"/")
	if resp.Err == nil {
		t.Fatalf("跨地址重定向必须返回错误，实得 status=%d", resp.Status)
	}
	if !strings.Contains(resp.Err.Error(), "跨地址重定向") &&
		!strings.Contains(resp.Err.Error(), "回环") {
		t.Fatalf("错误信息应说明拒绝原因，实得 %v", resp.Err)
	}
}

func TestProbeAllowsSameOriginRedirect(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			http.Redirect(w, r, "/ok", http.StatusFound)
			return
		}
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	pc := newProbeClient(10, time.Second)
	resp := pc.get(context.Background(), srv.URL+"/")
	if resp.Err != nil || resp.Status != 200 || string(resp.Body) != "ok" {
		t.Fatalf("同地址重定向应允许: err=%v status=%d body=%q", resp.Err, resp.Status, resp.Body)
	}
}

func TestProbeTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(250 * time.Millisecond)
		_, _ = w.Write([]byte("late"))
	}))
	defer srv.Close()

	pc := newProbeClient(10, 40*time.Millisecond)
	start := time.Now()
	resp := pc.get(context.Background(), srv.URL+"/")
	if resp.Err == nil {
		t.Fatal("超时探测必须返回错误")
	}
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Fatalf("超时应在 2s 预算附近返回，实际耗时 %v", elapsed)
	}
}

func TestProbeBodyLimit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("A", 100<<10)))
	}))
	defer srv.Close()

	pc := newProbeClient(10, time.Second)
	resp := pc.get(context.Background(), srv.URL+"/")
	if resp.Err != nil {
		t.Fatalf("探测失败: %v", resp.Err)
	}
	if len(resp.Body) != probeBodyLimit {
		t.Fatalf("响应读取应截断到 %d 字节，实得 %d", probeBodyLimit, len(resp.Body))
	}
}

func TestProbeBudget(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	pc := newProbeClient(2, time.Second)
	for i := 0; i < 2; i++ {
		if resp := pc.get(context.Background(), srv.URL+"/"); resp.Err != nil {
			t.Fatalf("第 %d 次探测不应失败: %v", i+1, resp.Err)
		}
	}
	resp := pc.get(context.Background(), srv.URL+"/")
	if !errors.Is(resp.Err, errProbeBudget) {
		t.Fatalf("第 3 次应命中预算闸，实得 %v", resp.Err)
	}
}

func TestDialTCPRejectsNonLoopback(t *testing.T) {
	pc := newProbeClient(10, time.Second)
	if _, err := pc.dialTCP(context.Background(), "8.8.8.8", 80); !errors.Is(err, errProbeNonLocal) {
		t.Fatalf("非回环 TCP 目标应拒绝，实得 %v", err)
	}
	// localhost 这种域名同样不允许（必须先由调用方解析成字面量 IP）
	if _, err := pc.dialTCP(context.Background(), "localhost", 80); !errors.Is(err, errProbeNonLocal) {
		t.Fatalf("域名目标应拒绝，实得 %v", err)
	}
}
