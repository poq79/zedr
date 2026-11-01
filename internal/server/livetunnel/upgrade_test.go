package livetunnel

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/yamux"

	"zedr/internal/platform/apperr"
)

// pipeConn 探针侧的合成连接（等价于探针包的 streamConn：bufio 缓冲里
// 可能已有 101 之后到达的 yamux 字节，直接给裸 conn 会丢数据）。
// 显式覆盖 Read 的原因同 streamConn：双嵌入会产生 Read 歧义选择器。
type pipeConn struct {
	r *bufio.Reader
	net.Conn
}

func (c pipeConn) Read(p []byte) (int, error) { return c.r.Read(p) }

// yamuxTestListener 会话 → listener 适配（与探针侧 Manager 同构的测试替身）
type yamuxTestListener struct{ sess *yamux.Session }

func (l yamuxTestListener) Accept() (net.Conn, error) { return l.sess.Accept() }
func (l yamuxTestListener) Close() error              { return l.sess.Close() }
func (l yamuxTestListener) Addr() net.Addr            { return tunnelTestAddr{} }

type tunnelTestAddr struct{}

func (tunnelTestAddr) Network() string { return "tunnel" }
func (tunnelTestAddr) String() string  { return "tunnel" }

// rawUpgrade 模拟探针发手工升级请求，返回原始响应供断言。
func rawUpgrade(t *testing.T, addr, agentID, secret, version string) (*http.Response, *bufio.Reader, net.Conn) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		t.Fatalf("探针拨号失败: %v", err)
	}
	var b strings.Builder
	b.WriteString("GET /api/v1/agent/tunnel HTTP/1.1\r\n")
	b.WriteString("Host: " + addr + "\r\n")
	b.WriteString("X-Agent-Id: " + agentID + "\r\n")
	b.WriteString("Authorization: Bearer " + secret + "\r\n")
	b.WriteString("Connection: Upgrade\r\n")
	b.WriteString("Upgrade: hg-tunnel/1\r\n")
	b.WriteString("X-ZEDR-Tunnel-Version: " + version + "\r\n\r\n")
	if _, err := conn.Write([]byte(b.String())); err != nil {
		t.Fatalf("发送升级请求失败: %v", err)
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatalf("读取升级响应失败: %v", err)
	}
	return resp, br, conn
}

// fakeAgentDial 完成升级并返回 yamux 客户端会话。
func fakeAgentDial(t *testing.T, serverURL, agentID, secret string) *yamux.Session {
	t.Helper()
	resp, br, conn := rawUpgrade(t, strings.TrimPrefix(serverURL, "http://"), agentID, secret, "1")
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("期望 101，got %d", resp.StatusCode)
	}
	sess, err := yamux.Client(pipeConn{r: br, Conn: conn}, testYamuxConfig())
	if err != nil {
		t.Fatalf("yamux.Client: %v", err)
	}
	t.Cleanup(func() { _ = sess.Close() })
	return sess
}

// TestUpgradeHandlerFullChain 全链路：探针手工升级请求 → 101 → 双端
// yamux 建立 → 中心端 Client.HTTP 发请求 → 挂在会话上的探针 http.Server
// 应答 200，往返成功。
func TestUpgradeHandlerFullChain(t *testing.T) {
	reg := NewRegistry(testLog())
	sessions := make(chan *yamux.Session, 4)

	handler := UpgradeHandler(testLog(),
		func(agentID, secret string) error {
			if agentID != "a-1" || secret != "s-1" {
				return apperr.Unauthenticated("凭证不匹配")
			}
			return nil
		},
		func(agentID string, sess *yamux.Session) {
			reg.Add(agentID, sess)
			sessions <- sess
		})
	ts := httptest.NewServer(handler)
	t.Cleanup(ts.Close)

	sess := fakeAgentDial(t, ts.URL, "a-1", "s-1")

	// 探针侧在会话上挂 http.Server（与生产 Manager 同构）
	probeMux := http.NewServeMux()
	probeMux.HandleFunc("/ping", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	})
	agentSrv := &http.Server{Handler: probeMux, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = agentSrv.Serve(yamuxTestListener{sess}) }()
	t.Cleanup(func() { _ = agentSrv.Close() })

	select {
	case <-sessions:
	case <-time.After(5 * time.Second):
		t.Fatal("5s 内未收到 onSession 回调")
	}

	cli, ok := reg.Get("a-1")
	if !ok {
		t.Fatal("Registry 中找不到 a-1")
	}
	if err := cli.Acquire(context.Background()); err != nil {
		t.Fatalf("Acquire 失败: %v", err)
	}
	defer cli.Release()

	resp, err := cli.HTTP().Get("http://tunnel/ping")
	if err != nil {
		t.Fatalf("经隧道请求失败: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("期望 200，got %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), `"ok":true`) {
		t.Fatalf("响应体不符: %s", body)
	}
}

// TestUpgradeHandlerAuthRejected 鉴权失败必须走规范 JSON 错误（401），
// 且绝不触发 onSession。
func TestUpgradeHandlerAuthRejected(t *testing.T) {
	handler := UpgradeHandler(testLog(), func(_, _ string) error {
		return apperr.Unauthenticated("凭证不匹配")
	}, func(string, *yamux.Session) {
		t.Error("鉴权失败不应触发 onSession")
	})
	ts := httptest.NewServer(handler)
	t.Cleanup(ts.Close)

	resp, err := http.Get(ts.URL + "/api/v1/agent/tunnel")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("期望 401，got %d", resp.StatusCode)
	}
	var eb struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&eb); err != nil {
		t.Fatalf("错误体不是规范 JSON: %v", err)
	}
	if eb.Error.Code != string(apperr.CodeUnauthenticated) {
		t.Fatalf("错误码 = %s，期望 unauthenticated", eb.Error.Code)
	}
}

// TestUpgradeHandlerRejectsNonUpgrade 携带合法凭证但缺升级头/版本不对
// 的请求必须 400（探针据此判定"对端不支持"），且连接不被劫持。
func TestUpgradeHandlerRejectsNonUpgrade(t *testing.T) {
	handler := UpgradeHandler(testLog(), func(_, _ string) error { return nil },
		func(string, *yamux.Session) {
			t.Error("非升级请求不应触发 onSession")
		})
	ts := httptest.NewServer(handler)
	t.Cleanup(ts.Close)
	addr := strings.TrimPrefix(ts.URL, "http://")

	t.Run("plain_get", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/agent/tunnel", nil)
		req.Header.Set("X-Agent-Id", "a-1")
		req.Header.Set("Authorization", "Bearer s-1")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("期望 400，got %d", resp.StatusCode)
		}
	})

	t.Run("wrong_version", func(t *testing.T) {
		resp, _, conn := rawUpgrade(t, addr, "a-1", "s-1", "99")
		defer func() { _ = conn.Close() }()
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("期望 400，got %d", resp.StatusCode)
		}
	})
}
