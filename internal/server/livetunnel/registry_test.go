package livetunnel

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"testing"

	"github.com/hashicorp/yamux"

	"zedr/internal/platform/apperr"
)

func testLog() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// testYamuxConfig 单测配置：关日志、关 keepalive——net.Pipe 一端无人读时
// 写会永久阻塞，keepalive 的周期性 ping 会在测试收尾后触发这种写。
func testYamuxConfig() *yamux.Config {
	cfg := yamux.DefaultConfig()
	cfg.LogOutput = io.Discard
	cfg.EnableKeepAlive = false
	return cfg
}

// newPipeSession 建一对真实 yamux 会话（net.Pipe 对拉），
// 只返回 client 侧供注册表测试使用，两端 cleanup 统一关闭。
func newPipeSession(t *testing.T) *yamux.Session {
	t.Helper()
	a, b := net.Pipe()
	cs, err := yamux.Client(a, testYamuxConfig())
	if err != nil {
		t.Fatalf("yamux.Client: %v", err)
	}
	ss, err := yamux.Server(b, testYamuxConfig())
	if err != nil {
		t.Fatalf("yamux.Server: %v", err)
	}
	t.Cleanup(func() {
		_ = cs.Close()
		_ = ss.Close()
	})
	return cs
}

func TestRegistryReplaceClosesOldSession(t *testing.T) {
	reg := NewRegistry(testLog())

	s1 := newPipeSession(t)
	reg.Add("a-1", s1)
	if reg.Len() != 1 {
		t.Fatalf("Add 后 Len = %d，期望 1", reg.Len())
	}
	c1, ok := reg.Get("a-1")
	if !ok || c1.sess != s1 {
		t.Fatal("Get 应返回第一个会话的 Client")
	}

	s2 := newPipeSession(t)
	reg.Add("a-1", s2) // 同 ID 顶替

	if !s1.IsClosed() {
		t.Fatal("旧会话应已被 Close")
	}
	if s2.IsClosed() {
		t.Fatal("新会话不应被关闭")
	}
	c2, ok := reg.Get("a-1")
	if !ok || c2.sess != s2 {
		t.Fatal("替换后 Get 应返回新会话的 Client")
	}
	if reg.Len() != 1 {
		t.Fatalf("替换不应增加 Len，got %d", reg.Len())
	}
}

func TestRegistryRemoveMatchesByPointer(t *testing.T) {
	reg := NewRegistry(testLog())

	s1 := newPipeSession(t)
	reg.Add("a-1", s1)
	s2 := newPipeSession(t)
	reg.Add("a-1", s2) // s1 被顶替并关闭

	// 迟到的旧会话清理：旧指针绝不能误删新会话
	reg.Remove("a-1", s1)
	if _, ok := reg.Get("a-1"); !ok {
		t.Fatal("用旧指针 Remove 不应删除新会话")
	}

	reg.Remove("a-1", s2) // 指针匹配：正常注销
	if _, ok := reg.Get("a-1"); ok {
		t.Fatal("指针匹配的 Remove 应删除条目")
	}
	if reg.Len() != 0 {
		t.Fatalf("注销后 Len = %d，期望 0", reg.Len())
	}
}

func TestClientSemaphore(t *testing.T) {
	s := newPipeSession(t)
	c := newClient(s)
	ctx := context.Background()

	// 前 4 个 Acquire 全部成功
	for i := 0; i < maxInFlightPerAgent; i++ {
		if err := c.Acquire(ctx); err != nil {
			t.Fatalf("第 %d 个 Acquire 应成功: %v", i+1, err)
		}
	}

	// 第 5 个立即失败且为 429 语义
	err := c.Acquire(ctx)
	var ae *apperr.Error
	if !errors.As(err, &ae) {
		t.Fatalf("第 %d 个 Acquire 应返回 apperr，got %v", maxInFlightPerAgent+1, err)
	}
	if ae.Code != apperr.CodeTooManyRequests {
		t.Fatalf("错误码 = %s，期望 too_many_requests", ae.Code)
	}

	// Release 后可再 Acquire
	c.Release()
	if err := c.Acquire(ctx); err != nil {
		t.Fatalf("Release 后应可再 Acquire: %v", err)
	}
	c.Release()

	// 已取消的 ctx 直接失败
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	if err := c.Acquire(cctx); err == nil {
		t.Fatal("已取消 ctx 的 Acquire 应失败")
	}
}
