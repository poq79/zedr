package uplink

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
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
