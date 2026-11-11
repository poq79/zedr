package uplink

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

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

// ---------------------------------------------------------------- 重试策略

// fastRetry 把退避调到毫秒级（测试只关心拆分与送达，不关心等待）。
func fastRetry(t *testing.T) {
	t.Helper()
	oldBase, oldMax := retryBaseDelay, retryMaxDelay
	retryBaseDelay, retryMaxDelay = time.Millisecond, 4*time.Millisecond
	t.Cleanup(func() { retryBaseDelay, retryMaxDelay = oldBase, oldMax })
}

// 批次重试脚本：按请求序号返回状态码（脚本之外一律 200），并记录
// 每批的条数与送达的 fingerprint。
type batchScript struct {
	mu       sync.Mutex
	statuses []int
	sizes    []int
	served   []string
}

func (b *batchScript) server(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req model.AlertBatchRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("decode batch: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		b.mu.Lock()
		status := http.StatusOK
		if len(b.sizes) < len(b.statuses) {
			status = b.statuses[len(b.sizes)]
		}
		b.sizes = append(b.sizes, len(req.Alerts))
		if status == http.StatusOK { // 只记真正送达的（失败请求不算送达）
			for _, a := range req.Alerts {
				b.served = append(b.served, a.Fingerprint)
			}
		}
		b.mu.Unlock()
		if status != http.StatusOK {
			w.WriteHeader(status)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{}}`))
	}))
}

func (b *batchScript) snapshot() (sizes []string, served []string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, s := range b.sizes {
		sizes = append(sizes, fmt.Sprint(s))
	}
	return sizes, append([]string(nil), b.served...)
}

// 连败 ≥2 次触发对半拆分：500→500 之后整批拆成两个半批并全部送达。
// 服务端曾因大批查重慢而 20s 超时 500——"整批永远过不去"必须能收敛。
func TestSpoolRetrySplitsAfterConsecutiveFailures(t *testing.T) {
	fastRetry(t)
	script := &batchScript{statuses: []int{500, 500}}
	srv := script.server(t)
	defer srv.Close()

	c := enrolled(t, t.TempDir(), 100)
	for i := 0; i < 6; i++ {
		c.Enqueue(env(fmt.Sprintf("fp-%d", i)))
	}
	c.baseURL = srv.URL

	// 第一轮：整批 500（连败 1 次）→ 不拆分，整批保留
	if _, err := c.Flush(t.Context()); err == nil {
		t.Fatal("第一轮应失败")
	}
	if sizes, _ := script.snapshot(); len(sizes) != 1 || sizes[0] != "6" {
		t.Fatalf("首次失败不应拆分, sizes=%v", sizes)
	}
	if got := c.Pending(); got != 6 {
		t.Fatalf("Pending = %d, want 6", got)
	}

	// 第二轮：整批再 500（连败 2 次）→ 拆成 3+3，两个半批全部送达
	if _, err := c.Flush(t.Context()); err != nil {
		t.Fatalf("第二轮 Flush: %v", err)
	}
	sizes, served := script.snapshot()
	want := []string{"6", "6", "3", "3"}
	if len(sizes) != len(want) {
		t.Fatalf("请求序列 = %v, want %v", sizes, want)
	}
	for i := range want {
		if sizes[i] != want[i] {
			t.Fatalf("请求序列 = %v, want %v（对半拆分未发生）", sizes, want)
		}
	}
	if len(served) != 6 {
		t.Fatalf("送达 %d 条, want 6: %v", len(served), served)
	}
	seen := map[string]bool{}
	for _, fp := range served {
		seen[fp] = true
	}
	for i := 0; i < 6; i++ {
		if !seen[fmt.Sprintf("fp-%d", i)] {
			t.Fatalf("fp-%d 未送达: %v", i, served)
		}
	}
	if got := c.Pending(); got != 0 {
		t.Fatalf("Pending = %d, want 0", got)
	}
	if got := c.Dropped(); got != 0 {
		t.Fatalf("Dropped = %d, want 0（瞬时失败绝不丢弃）", got)
	}
}

// 首次 500 不拆分：一次网络抖动不应把批打碎。
func TestSpoolFirstFailureKeepsWholeBatch(t *testing.T) {
	fastRetry(t)
	script := &batchScript{statuses: []int{500}}
	srv := script.server(t)
	defer srv.Close()

	c := enrolled(t, t.TempDir(), 100)
	for i := 0; i < 4; i++ {
		c.Enqueue(env(fmt.Sprintf("fp-%d", i)))
	}
	c.baseURL = srv.URL

	if _, err := c.Flush(t.Context()); err == nil {
		t.Fatal("应失败")
	}
	if sizes, _ := script.snapshot(); len(sizes) != 1 || sizes[0] != "4" {
		t.Fatalf("首次失败应整批保留重试, sizes=%v", sizes)
	}
	if got := c.Pending(); got != 4 {
		t.Fatalf("Pending = %d, want 4", got)
	}
}

// 400 参数错误不重试整批：直接对半拆分定位坏记录；拆到单条仍被拒的
// 记录单独清除并计数，其余记录正常送达——坏记录不再阻塞队列。
func TestSpoolParamRejectionIsolatesBadRecord(t *testing.T) {
	fastRetry(t)
	var mu sync.Mutex
	var served []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req model.AlertBatchRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		for _, a := range req.Alerts {
			if a.Fingerprint == "fp-bad" {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
		}
		mu.Lock()
		for _, a := range req.Alerts {
			served = append(served, a.Fingerprint)
		}
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{}}`))
	}))
	defer srv.Close()

	c := enrolled(t, t.TempDir(), 100)
	for _, fp := range []string{"fp-1", "fp-2", "fp-bad", "fp-4"} {
		c.Enqueue(env(fp))
	}
	c.baseURL = srv.URL

	sent, err := c.Flush(t.Context())
	if err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if sent != 3 {
		t.Fatalf("sent = %d, want 3", sent)
	}
	mu.Lock()
	got := append([]string(nil), served...)
	mu.Unlock()
	gotSet := map[string]bool{}
	for _, fp := range got {
		gotSet[fp] = true
	}
	for _, fp := range []string{"fp-1", "fp-2", "fp-4"} {
		if !gotSet[fp] {
			t.Fatalf("fp=%s 未送达: %v", fp, got)
		}
	}
	if gotSet["fp-bad"] {
		t.Fatalf("被拒收记录不应送达: %v", got)
	}
	if got := c.Pending(); got != 0 {
		t.Fatalf("Pending = %d, want 0（坏记录不应阻塞队列）", got)
	}
	if got := c.Dropped(); got != 1 {
		t.Fatalf("Dropped = %d, want 1（拒收必须计数可见）", got)
	}
}

// 持续 5xx 下一轮轮拆分逐步收敛但绝不丢弃：拆到单条仍失败就整批保留，
// 语义始终是 at-least-once（重复投递由服务端 fingerprint 去重兜底）。
func TestSpoolNeverDropsOnTransientFailures(t *testing.T) {
	fastRetry(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := enrolled(t, t.TempDir(), 100)
	for i := 0; i < 6; i++ {
		c.Enqueue(env(fmt.Sprintf("fp-%d", i)))
	}
	c.baseURL = srv.URL

	for round := 0; round < 5; round++ {
		if _, err := c.Flush(t.Context()); err == nil {
			t.Fatal("持续 500 下 Flush 应失败")
		}
	}
	if got := c.Pending(); got != 6 {
		t.Fatalf("Pending = %d, want 6", got)
	}
	if got := c.Dropped(); got != 0 {
		t.Fatalf("Dropped = %d, want 0", got)
	}
}

// 429 限流不算参数错误：必须走重试路径（退避后重试），不能被当成
// "请求非法"跳过。
func TestRateLimitIsRetriedNotSkipped(t *testing.T) {
	if isParamRejection(&statusError{status: http.StatusTooManyRequests, msg: "x"}) {
		t.Fatal("429 不应视为参数错误")
	}
	if !isParamRejection(&statusError{status: http.StatusBadRequest, msg: "x"}) {
		t.Fatal("400 应视为参数错误")
	}
	if !isParamRejection(&statusError{status: 422, msg: "x"}) {
		t.Fatal("422 应视为参数错误")
	}
	if isParamRejection(&statusError{status: http.StatusUnauthorized, msg: "x"}) {
		t.Fatal("401 可能因重新注册恢复，不应视为参数错误")
	}
	if isParamRejection(fmt.Errorf("网络错误")) {
		t.Fatal("网络错误不应视为参数错误")
	}
}

// 退避抖动必须落在 ±30% 区间内：抖动是防重启风暴后重试齐拍的，
// 越界即失去意义。
func TestJitterBackoffRange(t *testing.T) {
	base := time.Second
	lo, hi := base*7/10, base*13/10
	for i := 0; i < 2000; i++ {
		d := jitter30(base)
		if d < lo || d > hi {
			t.Fatalf("jitter30(1s) = %v, 超出 ±30%% 范围 [%v, %v]", d, lo, hi)
		}
	}
	if got := jitter30(0); got != 0 {
		t.Fatalf("jitter30(0) = %v, want 0", got)
	}
	// 连败越深退避越长（指数），但封顶 8s
	if d := backoffDelay(2); d < retryBaseDelay*7/10 || d > retryBaseDelay*13/10 {
		t.Fatalf("连败 2 次的退避应约为基础值: %v", d)
	}
	if d := backoffDelay(99); d > retryMaxDelay*13/10 {
		t.Fatalf("退避应封顶 8s±30%%: %v", d)
	}
}
