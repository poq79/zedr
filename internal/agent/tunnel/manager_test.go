package tunnel

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hashicorp/yamux"
)

// comb 假服务端 hijack 后的合成连接（与生产侧 streamConn 同理：
// bufio 缓冲里可能已有 101 之后到达的字节，直接给裸 conn 会丢数据）。
// 显式覆盖 Read 的原因同 streamConn：双嵌入会产生 Read 歧义选择器。
type comb struct {
	r *bufio.Reader
	net.Conn
}

func (c comb) Read(p []byte) (int, error) { return c.r.Read(p) }

// testCreds 返回恒定凭证的 Creds 实现。
func testCreds(agentID, secret string) func() (string, string, bool) {
	return func() (string, string, bool) { return agentID, secret, true }
}

// testYamuxConfig 单测用 yamux 配置：关日志、关 keepalive
// （net.Pipe 一端无人读时写会永久阻塞，keepalive 会触发写）。
func testYamuxConfig() *yamux.Config {
	cfg := yamux.DefaultConfig()
	cfg.LogOutput = io.Discard
	cfg.EnableKeepAlive = false
	return cfg
}

// requireEvent 在超时内等到 channel 事件，否则 FailNow。
func requireEvent[T any](t *testing.T, ch <-chan T, timeout time.Duration, what string) T {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(timeout):
		t.Fatalf("%s：%v 内未观察到事件", what, timeout)
		var zero T
		return zero
	}
}

// ---------------------------------------------------------------- 场景 1

// TestManagerEntersHourlyModeOn404 验证退避状态机：对端 404 → 立即
// 进入静默模式（onModeChange 翻转为 true），并按注入的"小时"节奏持续重试。
func TestManagerEntersHourlyModeOn404(t *testing.T) {
	var reqCount atomic.Int64
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqCount.Add(1)
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(ts.Close)

	flips := make(chan bool, 8)
	m := New(nil, Options{
		ServerURL: ts.URL,
		Creds:     testCreds("a-1", "s-1"),
		Handler:   http.NotFoundHandler(),
	})
	// 注入：静默节奏缩到 25ms；正常退避起点压到 500ms——
	// 若状态机错误地留在正常模式，300ms 窗口内不可能凑够 3 个新请求
	m.opts.unsupportedRetry = 25 * time.Millisecond
	m.opts.retryBase = 500 * time.Millisecond
	m.opts.retryMax = 500 * time.Millisecond
	m.opts.jitterFrac = 0
	m.opts.dialTimeout = 2 * time.Second
	m.opts.onModeChange = func(unsupported bool) { flips <- unsupported }

	ctx, cancel := context.WithCancel(context.Background())
	started := make(chan struct{})
	go func() { close(started); m.Start(ctx) }()
	<-started
	t.Cleanup(func() { cancel(); <-m.Done() })

	if f := requireEvent(t, flips, 5*time.Second, "进入静默模式"); !f {
		t.Fatalf("首次状态翻转应为进入静默模式，got %v", f)
	}

	// 静默模式下按 25ms 节奏持续重试
	base := reqCount.Load()
	deadline := time.Now().Add(300 * time.Millisecond)
	for time.Now().Before(deadline) {
		if reqCount.Load() >= base+3 {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("静默模式重试节奏异常：300ms 内新增请求数 %d（期望 >=3）", reqCount.Load()-base)
}

// ---------------------------------------------------------------- 场景 2

// TestManagerServeRoundTripAndReconnect 走通完整链路：升级 → yamux →
// 服务端开流发 HTTP 请求 → 探针侧 http.Server 应答 200；服务端主动断开
// 会话后探针自动重连并再次完成往返；Stop 后 Start 干净退出。
func TestManagerServeRoundTripAndReconnect(t *testing.T) {
	var conns atomic.Int64
	roundTrips := make(chan int, 8)
	var mu sync.Mutex
	var serverSessions []*yamux.Session

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hj, ok := w.(http.Hijacker)
		if !ok {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		conn, rw, err := hj.Hijack()
		if err != nil {
			return
		}
		if _, err := conn.Write([]byte("HTTP/1.1 101 Switching Protocols\r\n" +
			"Connection: Upgrade\r\nUpgrade: hg-tunnel/1\r\n\r\n")); err != nil {
			_ = conn.Close()
			return
		}
		sess, err := yamux.Server(comb{r: rw.Reader, Conn: conn}, testYamuxConfig())
		if err != nil {
			_ = conn.Close()
			return
		}
		mu.Lock()
		serverSessions = append(serverSessions, sess)
		mu.Unlock()
		n := int(conns.Add(1))

		// 中心端开流：向探针 liveapi 发一个 GET /probe
		if stream, err := sess.Open(); err == nil {
			_, _ = stream.Write([]byte("GET /probe HTTP/1.1\r\nHost: tunnel\r\nConnection: close\r\n\r\n"))
			resp, err := http.ReadResponse(bufio.NewReader(stream), &http.Request{Method: http.MethodGet})
			if err == nil && resp.StatusCode == http.StatusOK {
				roundTrips <- n
			}
		}

		if n == 1 {
			// 第一次往返后主动断开，验证探针按退避重连
			time.Sleep(50 * time.Millisecond)
			_ = sess.Close()
		}
		// n>=2：会话保持，直到测试结束 cleanup 统一关闭
	}))
	t.Cleanup(ts.Close)
	t.Cleanup(func() {
		mu.Lock()
		defer mu.Unlock()
		for _, s := range serverSessions {
			_ = s.Close()
		}
	})

	probeMux := http.NewServeMux()
	probeMux.HandleFunc("/probe", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	m := New(nil, Options{
		ServerURL: ts.URL,
		Creds:     testCreds("a-1", "s-1"),
		Handler:   probeMux,
	})
	m.opts.retryBase = 5 * time.Millisecond
	m.opts.retryMax = 20 * time.Millisecond
	m.opts.jitterFrac = 0
	m.opts.dialTimeout = 3 * time.Second

	go m.Start(context.Background())
	t.Cleanup(m.Stop)

	if n := requireEvent(t, roundTrips, 5*time.Second, "首次往返"); n != 1 {
		t.Fatalf("首次往返应来自第 1 条连接，got %d", n)
	}
	if n := requireEvent(t, roundTrips, 5*time.Second, "断线重连后的第二次往返"); n != 2 {
		t.Fatalf("第二次往返应来自第 2 条连接，got %d", n)
	}

	// Stop 后 Start 必须干净退出（无 goroutine 卡死）
	m.Stop()
	select {
	case <-m.Done():
	case <-time.After(3 * time.Second):
		t.Fatal("Stop 后 3s 内 Start 未退出")
	}
}

// ---------------------------------------------------------------- 场景 3

// TestManagerWaitsForCreds 验证凭证未就绪时循环等待、就绪后自动开跑。
func TestManagerWaitsForCreds(t *testing.T) {
	var ready atomic.Bool
	var reqCount atomic.Int64
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqCount.Add(1)
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(ts.Close)

	m := New(nil, Options{
		ServerURL: ts.URL,
		Creds: func() (string, string, bool) {
			if ready.Load() {
				return "a-1", "s-1", true
			}
			return "", "", false
		},
		Handler: http.NotFoundHandler(),
	})
	m.opts.credsWait = 10 * time.Millisecond
	m.opts.dialTimeout = 2 * time.Second

	go m.Start(context.Background())
	t.Cleanup(m.Stop)

	time.Sleep(80 * time.Millisecond)
	if n := reqCount.Load(); n != 0 {
		t.Fatalf("凭证未就绪时不应发起请求，got %d", n)
	}
	ready.Store(true)

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if reqCount.Load() >= 1 {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("凭证就绪后 3s 内未发起请求")
}

// ---------------------------------------------------------------- 场景 4

// TestStopDuringBackoff 验证停在长退避里也能立即退出（无 goroutine 泄漏）。
func TestStopDuringBackoff(t *testing.T) {
	m := New(nil, Options{
		// 端口 1 基本必然拒绝连接：先失败一次进入退避
		ServerURL: "http://127.0.0.1:1",
		Creds:     testCreds("a-1", "s-1"),
		Handler:   http.NotFoundHandler(),
	})
	m.opts.retryBase = time.Hour // 卡在退避里
	m.opts.jitterFrac = 0
	m.opts.dialTimeout = 2 * time.Second

	go m.Start(context.Background())
	time.Sleep(100 * time.Millisecond) // 让第一轮拨号失败、进入退避

	m.Stop()
	select {
	case <-m.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("退避中的 Stop 未在 2s 内退出")
	}
}

// ---------------------------------------------------------------- 场景 5

// TestUpgradeRejectedStatusClassification 验证非 101 响应的分类：
// 404/400 → errUnsupported（静默模式）；401 → 普通失败（指数退避）。
func TestUpgradeRejectedStatusClassification(t *testing.T) {
	cases := []struct {
		status int
		want   error
	}{
		{http.StatusNotFound, errUnsupported},
		{http.StatusBadRequest, errUnsupported},
		{http.StatusUnauthorized, nil}, // nil = 普通错误
	}
	for _, tc := range cases {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(tc.status)
		}))
		m := New(nil, Options{
			ServerURL: ts.URL,
			Creds:     testCreds("a-1", "s-1"),
			Handler:   http.NotFoundHandler(),
		})
		conn, err := net.DialTimeout("tcp", ts.Listener.Addr().String(), 2*time.Second)
		if err != nil {
			t.Fatalf("status %d: 拨号失败: %v", tc.status, err)
		}
		rwc, err := m.upgrade(conn, "a-1", "s-1")
		if rwc != nil {
			t.Fatalf("status %d: 失败时不应返回连接", tc.status)
		}
		if tc.want == nil {
			if err == nil {
				t.Fatalf("status %d: 应返回错误", tc.status)
			}
			if err == errUnsupported {
				t.Fatalf("status %d: 不应分类为不支持", tc.status)
			}
		} else if err != tc.want {
			t.Fatalf("status %d: err = %v，期望 %v", tc.status, err, tc.want)
		}
		ts.Close()
	}
}
