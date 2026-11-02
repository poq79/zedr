package uplink

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"zedr/internal/model"
)

// 心跳/本地状态展示依赖"终端实际应用的版本"，而不是服务端最新版本。
// 这里锁死三条语义：200 更新、304 保持、版本回退拒绝且不污染本地版本。
func TestRuleVersionTracksAppliedBundle(t *testing.T) {
	var served int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("If-None-Match"); got == `"7"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", `"7"`)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{"version": served, "rules": []any{}, "allowlist": []any{}},
		})
	}))
	defer srv.Close()

	c := New(srv.URL, "", t.TempDir(), 16)
	served = 7
	if _, _, err := c.FetchRules(t.Context()); err != nil {
		t.Fatalf("FetchRules: %v", err)
	}
	if got := c.RuleVersion(); got != 7 {
		t.Fatalf("RuleVersion = %d, want 7", got)
	}

	// 304：服务端无更新，本地版本保持不变
	if _, notModified, err := c.FetchRules(t.Context()); err != nil || !notModified {
		t.Fatalf("FetchRules(304) = notModified=%v err=%v", notModified, err)
	}
	if got := c.RuleVersion(); got != 7 {
		t.Fatalf("RuleVersion after 304 = %d, want 7", got)
	}
}

func TestRuleVersionRollbackRejected(t *testing.T) {
	version := 9
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{"version": version, "rules": []any{}, "allowlist": []any{}},
		})
	}))
	defer srv.Close()

	c := New(srv.URL, "", t.TempDir(), 16)
	if _, _, err := c.FetchRules(t.Context()); err != nil {
		t.Fatalf("FetchRules(v9): %v", err)
	}
	version = 4
	if _, _, err := c.FetchRules(t.Context()); err == nil {
		t.Fatal("FetchRules(v4) 应拒绝版本回退")
	}
	if got := c.RuleVersion(); got != 9 {
		t.Fatalf("RuleVersion after rejected rollback = %d, want 9", got)
	}
}

// ---------------------------------------------------------------- 持久队列

func enrolled(t *testing.T, dir string, max int) *Client {
	t.Helper()
	c := New("http://127.0.0.1:1", "", dir, max)
	c.mu.Lock()
	c.creds = &Credentials{AgentID: "agent-test", Secret: "secret-test"}
	c.mu.Unlock()
	return c
}

func env(fp string) model.AlertEnvelope {
	return model.AlertEnvelope{
		Fingerprint: fp, Title: "test " + fp,
		Verdict: model.VerdictSuspicious, Severity: model.SeverityLow,
	}
}

func TestSpoolPersistsAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	c1 := enrolled(t, dir, 100)
	if c1.QueueMode() != "disk" {
		t.Fatalf("QueueMode = %q, want disk", c1.QueueMode())
	}
	c1.Enqueue(env("fp-1"))
	c1.Enqueue(env("fp-2"))
	if got := c1.Pending(); got != 2 {
		t.Fatalf("Pending before restart = %d, want 2", got)
	}
	c1.spool.close() // 模拟进程退出，释放活跃段句柄

	// 新进程打开同一数据目录：未送达告警必须还在
	c2 := enrolled(t, dir, 100)
	if got := c2.Pending(); got != 2 {
		t.Fatalf("Pending after restart = %d, want 2", got)
	}

	got := collectServed(t, c2)
	if len(got) != 2 || got[0] != "fp-1" || got[1] != "fp-2" {
		t.Fatalf("served = %v, want [fp-1 fp-2]", got)
	}
	if got := c2.Pending(); got != 0 {
		t.Fatalf("Pending after flush = %d, want 0", got)
	}
	c2.spool.close()

	// 再重启一次：已送达的段不应复活
	c3 := enrolled(t, dir, 100)
	if got := c3.Pending(); got != 0 {
		t.Fatalf("Pending after third start = %d, want 0", got)
	}
}

func TestSpoolOverflowDropsOldest(t *testing.T) {
	dir := t.TempDir()
	c := enrolled(t, dir, 3)
	for _, fp := range []string{"a", "b", "c", "d", "e"} {
		c.Enqueue(env(fp))
	}
	if got := c.Pending(); got > 3 {
		t.Fatalf("Pending = %d, want <= 3", got)
	}
	if got := c.Dropped(); got < 2 {
		t.Fatalf("Dropped = %d, want >= 2", got)
	}

	got := collectServed(t, c)
	// 最旧的被淘汰，保留的是最近的（具体条数受分段粒度影响，但必须连续到 e）
	if len(got) == 0 || got[len(got)-1] != "e" {
		t.Fatalf("served = %v, want newest 'e' present", got)
	}
	for _, fp := range got {
		if fp == "a" || fp == "b" {
			t.Fatalf("served = %v, 最旧告警不应保留", got)
		}
	}
}

func collectServed(t *testing.T, c *Client) []string {
	t.Helper()
	var mu sync.Mutex
	var got []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req model.AlertBatchRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("decode batch: %v", err)
		}
		mu.Lock()
		for _, a := range req.Alerts {
			got = append(got, a.Fingerprint)
		}
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{}}`))
	}))
	defer srv.Close()

	c.baseURL = srv.URL
	if _, err := c.Flush(t.Context()); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	return append([]string(nil), got...)
}
