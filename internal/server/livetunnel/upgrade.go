package livetunnel

import (
	"bufio"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/hashicorp/yamux"

	"zedr/internal/platform/apperr"
	"zedr/internal/platform/httpx"
)

const (
	// upgradeProtocol 升级协议标识（契约 §3.1：Upgrade: hg-tunnel/1）
	upgradeProtocol = "hg-tunnel/1"
	// tunnelVersion 当前隧道协议版本。探针携带 X-ZEDR-Tunnel-Version，
	// 服务端只接受自己认识的版本；未来不兼容变更靠它做门禁
	// （老服务端拒绝新版本探针 → 探针转每小时静默重试，不会反复报错）
	tunnelVersion = "1"
	// keepAliveInterval yamux 保活间隔（契约 §3.1 固定配置）
	keepAliveInterval = 20 * time.Second
)

// UpgradeHandler 返回隧道升级端点（挂载于 GET /api/v1/agent/tunnel）。
//
// authenticate 复用终端鉴权（与心跳同一套 Authenticate + CheckSecret，
// 由 W2 接线注入），失败时以规范 JSON 错误输出；onSession 在 yamux
// 会话建立后被调用（W2 据此 Registry.Add，并用 sess.CloseChan() 挂
// 掉线清理）。
//
// 安全模型（契约 §4）：隧道建立即完成双向信任——探针持凭证、连接是
// 探针自己拨出的出站连接；探针侧 liveapi 因此不做每请求鉴权
// （无监听面，物理上只有服务端可达）。
func UpgradeHandler(log *slog.Logger, authenticate func(agentID, secret string) error, onSession func(agentID string, sess *yamux.Session)) http.Handler {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		agentID := r.Header.Get("X-Agent-Id")
		secret := bearerToken(r)
		if agentID == "" || secret == "" {
			httpx.WriteError(w, r, apperr.Unauthenticated("缺少终端身份凭证"))
			return
		}
		if err := authenticate(agentID, secret); err != nil {
			httpx.WriteError(w, r, err)
			return
		}
		if !isUpgradeRequest(r) {
			// 非 101 的规范错误 JSON：探针收到即判定"对端不支持"，回退静默重试
			httpx.WriteError(w, r, apperr.Invalid("该端点仅接受 %s 升级请求", upgradeProtocol))
			return
		}

		hj, ok := w.(http.Hijacker)
		if !ok {
			// 理论不可达（本端点只挂直连 HTTP/TLS 服务），防御性兜底
			httpx.WriteError(w, r, apperr.Internal(errors.New("当前连接不支持协议升级")))
			return
		}
		conn, rw, err := hj.Hijack()
		if err != nil {
			// Hijack 失败后 ResponseWriter 已不可用，只能记日志放弃
			log.Error("tunnel_hijack_failed", "agent_id", agentID, "error", err.Error())
			return
		}

		// 成功后手写 101：Hijack 之后 ResponseWriter 已失效，
		// 必须直接往裸 conn 写响应
		resp := "HTTP/1.1 101 Switching Protocols\r\n" +
			"Connection: Upgrade\r\n" +
			"Upgrade: " + upgradeProtocol + "\r\n" +
			"X-ZEDR-Tunnel-Version: " + tunnelVersion + "\r\n\r\n"
		if _, err := conn.Write([]byte(resp)); err != nil {
			log.Warn("tunnel_101_write_failed", "agent_id", agentID, "error", err.Error())
			_ = conn.Close()
			return
		}

		// 关键：把 Hijack 返回的 bufio.Reader 与裸 conn 合成一个 ReadWriteCloser。
		// 为什么——Go HTTP 服务器从连接读请求时用了缓冲，缓冲区里可能已躺着
		// 紧跟升级请求到达的字节（探针 yamux 的首批帧）。只把裸 conn 交给
		// yamux 会静默丢掉这些字节，造成协议流错位、会话玄学挂死
		// （docs/LIVE-TUNNEL.md §3.1 明确要求两侧都按此处理）。
		rwc := &hijackedStream{buf: rw.Reader, conn: conn}
		sess, err := yamux.Server(rwc, tunnelConfig())
		if err != nil {
			log.Warn("tunnel_yamux_handshake_failed", "agent_id", agentID, "error", err.Error())
			_ = rwc.Close()
			return
		}
		log.Debug("tunnel_session_established", "agent_id", agentID, "remote", conn.RemoteAddr())
		onSession(agentID, sess)
	})
}

// isUpgradeRequest 校验方法、Connection/Upgrade 头（token 大小写不敏感）
// 与协议版本。逐项收紧的理由：这是把裸连接交出去前的最后一道闸，
// 误升级非隧道流量等于把任意外部请求升级成可信通道。
func isUpgradeRequest(r *http.Request) bool {
	if r.Method != http.MethodGet {
		return false
	}
	if !strings.EqualFold(strings.TrimSpace(r.Header.Get("Upgrade")), upgradeProtocol) {
		return false
	}
	connUpgrade := false
	for _, v := range r.Header.Values("Connection") {
		for _, tok := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(tok), "Upgrade") {
				connUpgrade = true
			}
		}
	}
	if !connUpgrade {
		return false
	}
	return r.Header.Get("X-ZEDR-Tunnel-Version") == tunnelVersion
}

// bearerToken 从 Authorization 头解析 Bearer 令牌。
// 与 api.go 的终端鉴权同格式，但本包不 import server/api——
// 隧道内核要保持对路由层的零依赖（api.go 反过来 import 本包）。
func bearerToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if len(auth) > len(prefix) && strings.EqualFold(auth[:len(prefix)], prefix) {
		return strings.TrimSpace(auth[len(prefix):])
	}
	return ""
}

// tunnelConfig 契约 §3.1 的固定 yamux 配置：保活 20s、写超时 10s，其余默认。
// LogOutput 必须非 nil（yamux VerifyConfig 要求 Logger/LogOutput 二选一），
// 用 io.Discard：yamux 内部日志是裸文本，混进 stderr 会污染结构化日志流。
func tunnelConfig() *yamux.Config {
	cfg := yamux.DefaultConfig()
	cfg.KeepAliveInterval = keepAliveInterval
	cfg.ConnectionWriteTimeout = 10 * time.Second
	cfg.LogOutput = io.Discard
	return cfg
}

// hijackedStream 合成 Hijack 后的读写关闭对象：Read 走服务端缓冲，
// Write/Close 走裸 conn。地址与 deadline 方法一并补齐——yamux 会探测
// 这些可选接口取对端地址（日志）与做写超时。
type hijackedStream struct {
	buf  *bufio.Reader
	conn net.Conn
}

func (h *hijackedStream) Read(p []byte) (int, error)  { return h.buf.Read(p) }
func (h *hijackedStream) Write(p []byte) (int, error) { return h.conn.Write(p) }
func (h *hijackedStream) Close() error                { return h.conn.Close() }
func (h *hijackedStream) LocalAddr() net.Addr         { return h.conn.LocalAddr() }
func (h *hijackedStream) RemoteAddr() net.Addr        { return h.conn.RemoteAddr() }
func (h *hijackedStream) SetDeadline(t time.Time) error {
	return h.conn.SetDeadline(t)
}
func (h *hijackedStream) SetReadDeadline(t time.Time) error {
	return h.conn.SetReadDeadline(t)
}
func (h *hijackedStream) SetWriteDeadline(t time.Time) error {
	return h.conn.SetWriteDeadline(t)
}
