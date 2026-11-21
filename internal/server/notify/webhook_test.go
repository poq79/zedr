package notify

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"zedr/internal/server/domain"
)

// TestWebhookDeliversSignedPayload 验证通知会以正确签名投递，
// 且接收方可以用共享密钥验证来源（这是 webhook 的核心安全契约）。
func TestWebhookDeliversSignedPayload(t *testing.T) {
	const secret = "test-shared-secret"

	type received struct {
		body     []byte
		sig      string
		event    string
		gotAlert bool
	}
	ch := make(chan received, 1)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		ch <- received{body: body, sig: r.Header.Get("X-ZEDR-Signature"), event: r.Header.Get("X-ZEDR-Event")}
		w.WriteHeader(200)
	}))
	defer srv.Close()

	n := New(srv.URL, secret, 3*time.Second, testLogger())
	defer n.Close()

	alert := domain.Alert{
		ID: "a-1", Hostname: "pc-1", Title: "测试告警",
		Verdict: domain.VerdictSuspicious, Severity: domain.SeverityHigh, Score: 66,
		ProcessName: "evil.exe", CreatedAt: time.Now(),
	}
	n.Ingest(alert)

	select {
	case r := <-ch:
		if r.event != "alert.created" {
			t.Fatalf("事件头 = %q", r.event)
		}
		// 用共享密钥重算签名比对
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write(r.body)
		want := "sha256=" + hex.EncodeToString(mac.Sum(nil))
		if r.sig != want {
			t.Fatalf("签名不匹配：got %q want %q", r.sig, want)
		}
		var p WebhookPayload
		if err := json.Unmarshal(r.body, &p); err != nil {
			t.Fatalf("载荷解析失败: %v", err)
		}
		if p.ID != "a-1" || p.Hostname != "pc-1" || p.Score != 66 {
			t.Fatalf("载荷字段缺失: %+v", p)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("未收到 webhook 通知")
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if s, _, _ := n.Stats(); s == 1 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("sent 计数未更新")
}

// TestWebhookBackpressureDoesNotBlock 验证队列满时 Ingest 非阻塞——
// 通知是旁路，绝不能拖慢告警入库主链路。
func TestWebhookBackpressureDoesNotBlock(t *testing.T) {
	// 端点故意挂起不响应：队列会被填满并开始丢弃
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 模拟永不响应的慢服务器：等 client 断开（request context 取消）
		// 再退出。不能用 select{}——handler goroutine 永不返回会让
		// srv.Close() 的 WaitGroup 永久挂死（GitHub Actions linux job
		// 实测 10min 超时整包失败；本机因 worker 时序侥幸不触发）。
		<-r.Context().Done()
	}))
	defer srv.Close()

	n := New(srv.URL, "", 100*time.Millisecond, testLogger())
	defer n.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < queueSize+100; i++ {
			n.Ingest(domain.Alert{ID: "x", CreatedAt: time.Now()})
		}
	}()

	select {
	case <-done:
		// 正常：说明 Ingest 全程非阻塞
	case <-time.After(3 * time.Second):
		t.Fatal("Ingest 在队列满时发生阻塞")
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, _, d := n.Stats(); d > 0 {
			return // 至少丢弃了一条：背压生效
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("队列满后应有丢弃计数")
}

// TestNilNotifierIsSafe 验证未启用通知时所有调用安全（调用方无需判空）。
func TestNilNotifierIsSafe(t *testing.T) {
	var n *Notifier
	n.Ingest(domain.Alert{ID: "x", CreatedAt: time.Now()})
	s, f, d := n.Stats()
	if s != 0 || f != 0 || d != 0 {
		t.Fatalf("nil 通知器应返回零统计，实际 %d/%d/%d", s, f, d)
	}
	n.Close() // 不应 panic
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}
