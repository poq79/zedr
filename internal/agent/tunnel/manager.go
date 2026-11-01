// Package tunnel 维护探针侧"实时隧道"反连（docs/LIVE-TUNNEL.md §3.3）：
// 向服务端发 HTTP/1.1 升级请求，101 后把连接交给 yamux 复用，并在
// 会话上以 http.Server 服务只读 liveapi mux——服务端即可随时开流发起
// 实时查询。探针零监听不变量不破坏：隧道是纯出站长连接。
//
// 心跳、检测、上报循环与本包完全无关（指令链路兜底不变）：
// 隧道断开只影响实时查询（服务端 503 tunnel_not_connected）。
package tunnel

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/yamux"
)

// Options 隧道管理器配置。导出字段由 W2 接线层（app/config）填充；
// 未导出字段是内部可调参数，零值取默认，仅供单测注入。
type Options struct {
	// ServerURL 服务端基址（http:// 或 https://），可带路径前缀
	ServerURL string

	// Creds 返回终端凭证；ok=false 表示尚未注册（循环低频等待重查）。
	// 建议传 uplink.Client.TunnelCreds——锁内快照，避免与重注册竞争
	Creds func() (agentID, secret string, ok bool)

	// Handler 挂在隧道会话上的只读 mux（liveapi），只读铁律由它保证
	Handler http.Handler

	// KeepAlive yamux 保活间隔，默认 20s（契约 §3.1）
	KeepAlive time.Duration

	// ---- 以下为内部可调参数（零值 = 默认），单测注入用 ----
	retryBase        time.Duration // 指数退避起点，默认 1s
	retryMax         time.Duration // 指数退避封顶，默认 30s
	unsupportedRetry time.Duration // 对端不支持时的静默重试间隔，默认 1h
	jitterFrac       float64       // 抖动比例，默认 0.2（±20%）
	dialTimeout      time.Duration // 升级握手读写预算，默认 10s
	credsWait        time.Duration // 凭证未就绪时的轮询间隔，默认 10s
	heldReset        time.Duration // 会话存活超过此时长则清零退避，默认 30s
	// onModeChange 在"正常↔静默"翻转时回调（单测观察状态机用）
	onModeChange func(unsupported bool)
}

// Manager 维护一条到服务端的实时隧道：断线自动重连、退避、静默降级。
type Manager struct {
	log *slog.Logger

	opts Options
	// serverHost/reqPath 从 ServerURL 解析：Host 头 + 升级目标路径
	// （兼容 baseURL 带路径前缀的部署形态，与 uplink 的拼接语义一致）
	serverHost string
	reqPath    string

	startOnce sync.Once
	stopOnce  sync.Once
	stopCh    chan struct{}
	doneOnce  sync.Once
	doneCh    chan struct{}
}

// New 创建管理器并解析 ServerURL；配置错误不在 New 直接失败，
// 而是留给循环按 errBadConfig 低频重试并记一次 error（探针其余
// 功能不因隧道配置错误而瘫痪）。
func New(log *slog.Logger, opts Options) *Manager {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	// 防御：Handler 为 nil 时 http.Server 会落到 DefaultServeMux，
	// 那等于把隧道交给全局路由——绝不允许，显式换成 404
	if opts.Handler == nil {
		opts.Handler = http.NotFoundHandler()
	}
	if opts.KeepAlive <= 0 {
		opts.KeepAlive = 20 * time.Second
	}
	if opts.retryBase <= 0 {
		opts.retryBase = time.Second
	}
	if opts.retryMax <= 0 {
		opts.retryMax = 30 * time.Second
	}
	if opts.unsupportedRetry <= 0 {
		opts.unsupportedRetry = time.Hour
	}
	if opts.jitterFrac <= 0 {
		opts.jitterFrac = 0.2
	}
	if opts.dialTimeout <= 0 {
		opts.dialTimeout = 10 * time.Second
	}
	if opts.credsWait <= 0 {
		opts.credsWait = 10 * time.Second
	}
	if opts.heldReset <= 0 {
		opts.heldReset = 30 * time.Second
	}

	m := &Manager{
		log:    log,
		opts:   opts,
		stopCh: make(chan struct{}),
		doneCh: make(chan struct{}),
	}
	if u, err := url.Parse(opts.ServerURL); err == nil && u.Host != "" {
		m.serverHost = u.Host
		m.reqPath = strings.TrimSuffix(u.Path, "/") + "/api/v1/agent/tunnel"
	}
	return m
}

// Start 阻塞运行重连循环；由调用方放到独立 goroutine（app 启动序列）。
// 只能调用一次，重复调用立即返回。随 ctx 取消或 Stop() 退出。
func (m *Manager) Start(ctx context.Context) {
	m.startOnce.Do(func() { m.run(ctx) })
}

// Stop 请求停止循环（幂等、不阻塞）。需要等待完全退出时用 Done()，
// 例如优雅停机序列里给一个有限预算。
func (m *Manager) Stop() {
	m.stopOnce.Do(func() { close(m.stopCh) })
}

// Done 返回循环完全退出后关闭的通道（未 Start 过则永不关闭）。
func (m *Manager) Done() <-chan struct{} { return m.doneCh }

var (
	// errUnsupported 对端不认识隧道端点（404/400）：老版本服务端，
	// 属持久状态而非瞬时故障，转每小时静默重试
	errUnsupported = errors.New("tunnel: 对端不支持隧道升级")
	// errBadConfig 本地配置不可用（URL 非法/协议不支持）：记一次
	// error 后按低频轮询，等运行期配置被修复（或永远等下去）
	errBadConfig = errors.New("tunnel: ServerURL 配置无效")
)

func (m *Manager) run(ctx context.Context) {
	defer m.doneOnce.Do(func() { close(m.doneCh) })

	if m.opts.Creds == nil {
		// 接线遗漏：与其每轮 panic，不如明确退出并留下可定位的日志
		m.log.Error("tunnel_bad_config", "detail", "Options.Creds 未设置，隧道循环退出")
		return
	}

	// Stop() 与外部 ctx 的汇合点：任一方触发都取消派生 ctx，
	// 循环内所有阻塞点（拨号/睡眠/Serve）都挂在派生 ctx 上
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		select {
		case <-m.stopCh:
			cancel()
		case <-ctx.Done():
		}
	}()

	bo := newTunnelBackoff(m.opts.retryBase, m.opts.retryMax, m.opts.jitterFrac)
	badConfigLogged := false // 仅本 goroutine 读写，无需锁

	for {
		if ctx.Err() != nil {
			m.log.Debug("tunnel_stopped", "reason", "context_done")
			return
		}

		agentID, secret, ok := m.opts.Creds()
		if !ok || agentID == "" || secret == "" {
			// 注册是异步完成的：凭证未就绪是正常态，低频轮询直到出现
			if !sleepCtx(ctx, m.opts.credsWait) {
				return
			}
			continue
		}

		held, err := m.runOnce(ctx, agentID, secret)
		badConfig := false
		switch {
		case ctx.Err() != nil:
			return
		case errors.Is(err, errBadConfig):
			badConfig = true
			if !badConfigLogged {
				badConfigLogged = true
				m.log.Error("tunnel_bad_config", "server_url", m.opts.ServerURL)
			}
		case errors.Is(err, errUnsupported):
			if bo.setUnsupported(true) {
				m.log.Info("tunnel_unsupported",
					"server", m.serverHost,
					"detail", "对端不认识隧道端点(404/400)，转为每小时静默重试")
				if m.opts.onModeChange != nil {
					m.opts.onModeChange(true)
				}
			}
		case err != nil:
			bo.bump()
			m.log.Warn("tunnel_attempt_failed", "error", err.Error())
		case held >= m.opts.heldReset:
			// 健康长会话正常结束：从头退避，保证下次闪断能快速重连
			bo.reset()
		default:
			// 会话建立后秒断：按失败计，防对端反复闪断打出重连风暴
			bo.bump()
		}

		if held > 0 {
			// 只要成功建立过会话就翻回正常模式（哪怕这次又断了）：
			// "支持与否"只由握手结果决定，与本次存活时长无关
			if bo.setUnsupported(false) {
				m.log.Info("tunnel_recovered",
					"server", m.serverHost,
					"detail", "对端恢复支持隧道，恢复正常重试节奏")
				if m.opts.onModeChange != nil {
					m.opts.onModeChange(false)
				}
			}
		}

		// 休眠节奏：配置错误 > 静默模式 > 指数退避，三者互不污染
		var d time.Duration
		switch {
		case badConfig:
			d = m.opts.credsWait
		case bo.unsupported:
			d = jitterDur(m.opts.unsupportedRetry, m.opts.jitterFrac)
		default:
			d = bo.delay()
		}
		if !sleepCtx(ctx, d) {
			return
		}
	}
}

// runOnce 完成"拨号 → 升级 → 会话服务"一个完整生命周期，阻塞到会话
// 结束或 ctx 取消。held 为会话存活时长（101 成功到退出）；未建立会话
// 时为 0。失败调用方统一按分类进退避。
func (m *Manager) runOnce(ctx context.Context, agentID, secret string) (held time.Duration, err error) {
	conn, err := m.dial(ctx)
	if err != nil {
		return 0, err
	}
	rwc, err := m.upgrade(conn, agentID, secret)
	if err != nil {
		return 0, err // upgrade 失败时已负责关闭 conn
	}

	cfg := yamux.DefaultConfig()
	// 契约 §3.1：KeepAliveInterval=20s、ConnectionWriteTimeout=10s，其余默认。
	// LogOutput 必须非 nil（yamux 校验强制 Logger/LogOutput 二选一），
	// 用 io.Discard 防止裸文本日志混进 stderr 的结构化日志流
	cfg.KeepAliveInterval = m.opts.KeepAlive
	cfg.ConnectionWriteTimeout = 10 * time.Second
	cfg.LogOutput = io.Discard

	sess, err := yamux.Client(rwc, cfg)
	if err != nil {
		_ = rwc.Close()
		return 0, fmt.Errorf("yamux 握手失败: %w", err)
	}
	establishedAt := time.Now()
	m.log.Info("tunnel_established", "server", m.serverHost, "agent_id", agentID)

	// 停机联动：ctx 取消时立刻关会话，Accept/Serve 随之解除阻塞；
	// done 关闭后 watcher 退出，不泄漏
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			_ = sess.Close()
		case <-done:
		}
	}()

	srv := &http.Server{
		Handler: m.opts.Handler,
		// 只防慢请求头攻击。有意不设 WriteTimeout/IdleTimeout：
		// 隧道内是流式响应（fs/read 字节直通），写超时会掐断长传输，
		// 时间预算由各 handler 自带（契约 §3.3）
		ReadHeaderTimeout: 10 * time.Second,
	}
	serveErr := srv.Serve(yamuxListener{sess})
	_ = sess.Close()
	_ = srv.Close() // 兜底终结 Serve 返回后仍卡在死流上的 handler

	held = time.Since(establishedAt)
	if ctx.Err() != nil {
		return held, ctx.Err()
	}
	if serveErr != nil {
		m.log.Info("tunnel_dropped", "held_sec", held.Seconds(), "error", serveErr.Error())
		return held, fmt.Errorf("隧道服务循环退出: %w", serveErr)
	}
	return held, nil
}

// dial 建立到服务端的 TCP/TLS 连接。
func (m *Manager) dial(ctx context.Context) (net.Conn, error) {
	u, err := url.Parse(m.opts.ServerURL)
	if err != nil || u.Host == "" {
		return nil, errBadConfig
	}
	d := &net.Dialer{Timeout: m.opts.dialTimeout}
	switch strings.ToLower(u.Scheme) {
	case "http":
		return d.DialContext(ctx, "tcp", u.Host)
	case "https":
		// 默认根证书校验（ServerName 由 crypto/tls 从拨号地址推导），
		// 与 uplink 的 http.Client 同一套信任链。隧道承载终端身份
		// 凭证，绝不引入 InsecureSkipVerify
		td := tls.Dialer{NetDialer: d, Config: &tls.Config{}}
		return td.DialContext(ctx, "tcp", u.Host)
	default:
		return nil, errBadConfig
	}
}

// upgrade 手工写 HTTP/1.1 升级请求并读取响应，成功返回合并后的读写流。
//
// 为什么手工写而不用 http.Client：101 之后需要把同一条 TCP 连接无缝
// 交给 yamux，net/http 不会交出连接（Hijack 只有服务端有），手工写
// 请求 + http.ReadResponse 是最薄的实现。失败时本函数负责关闭 conn。
func (m *Manager) upgrade(conn net.Conn, agentID, secret string) (io.ReadWriteCloser, error) {
	reqPath := m.reqPath
	if reqPath == "" {
		reqPath = "/api/v1/agent/tunnel"
	}
	// 头顺序与契约 §3.1 一致；secret 只出现在这条连接上，绝不进日志
	var b strings.Builder
	b.WriteString("GET " + reqPath + " HTTP/1.1\r\n")
	b.WriteString("Host: " + m.serverHost + "\r\n")
	b.WriteString("X-Agent-Id: " + agentID + "\r\n")
	b.WriteString("Authorization: Bearer " + secret + "\r\n")
	b.WriteString("Connection: Upgrade\r\n")
	b.WriteString("Upgrade: hg-tunnel/1\r\n")
	b.WriteString("X-HG-Tunnel-Version: 1\r\n\r\n")

	// 握手整体一个预算（写请求 + 读响应），101 后必须清除——
	// 会话是长连接，残留 deadline 会在静默期掐死 keepalive
	_ = conn.SetDeadline(time.Now().Add(m.opts.dialTimeout))
	if _, err := conn.Write([]byte(b.String())); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("发送升级请求失败: %w", err)
	}

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodGet})
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("读取升级响应失败: %w", err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		// 错误体只为排障可读性限量丢弃，不信任其内容
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
		_ = resp.Body.Close()
		_ = conn.Close()
		if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusBadRequest {
			return nil, errUnsupported
		}
		return nil, fmt.Errorf("隧道升级被拒绝: HTTP %d", resp.StatusCode)
	}

	_ = conn.SetDeadline(time.Time{})
	return streamConn{r: br, Conn: conn}, nil
}
