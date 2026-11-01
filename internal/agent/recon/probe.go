package recon

// probe.go：主动探测客户端 —— 资产侦查唯一允许发起网络请求的出口。
//
// 安全红线（docs/LIVE-TUNNEL.md §12.4）逐条落地：
//  1. 只探回环：URL/dial 目标必须是字面量 IP 且 IsLoopback（127.0.0.0/8、::1），
//     拒绝 localhost/域名/0.0.0.0，从根上杜绝被诱导探测外部主机；
//  2. 只 GET：Transport 层不提供其他方法，调用方也无写接口；
//  3. 无凭据：不设 CookieJar、不加 Authorization、URL 不允许 userinfo；
//  4. 2s 超时、≤64KB 读取、总请求 ≤40（HTTP 与 TCP 共用计数闸）；
//  5. 不跟随跨地址重定向：CheckRedirect 校验新目标仍为同一回环地址；
//  6. Proxy: nil 显式清空：否则系统代理/HTTP_PROXY 会把 127.0.0.1
//     探测劫持到代理，静默 502（本仓库踩过的坑）。

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

var (
	errProbeBudget   = errors.New("探测次数已达上限")
	errProbeNonLocal = errors.New("目标不是回环地址")
)

// probeClient 是带预算闸的探测客户端；并发安全（detector 六类并发）。
type probeClient struct {
	client  *http.Client
	timeout time.Duration
	limit   int32
	used    atomic.Int32
}

// probeResp 是一次 HTTP 探测结果。非 2xx 不是错误：401/403 本身就是
// 认证挑战证据，调用方按 Status 判定。
type probeResp struct {
	Status int
	Header http.Header
	Body   []byte
	URL    string
	Err    error
}

// newProbeClient 构造探测客户端。timeout 同时用于 HTTP 单次请求与
// TCP 拨号/读取；limit 是整次侦查共享的请求上限。
func newProbeClient(limit int, timeout time.Duration) *probeClient {
	if limit <= 0 {
		limit = maxProbeRequests
	}
	if timeout <= 0 {
		timeout = probeTimeout
	}
	transport := &http.Transport{
		// 关键：显式 nil。http.Transport 默认 ProxyFromEnvironment，
		// 本机服务探测会被代理劫持（127.0.0.1 也会走代理）。
		Proxy:               nil,
		DisableKeepAlives:   true,
		MaxIdleConnsPerHost: 1,
		TLSHandshakeTimeout: timeout,
		// 不允许 http.Client 自动解压：压缩炸弹会绕过 64KB 读取上限
		// 的"网络字节"意义（解压后体积不受控）。
		DisableCompression: true,
	}
	pc := &probeClient{timeout: timeout, limit: int32(limit)}
	pc.client = &http.Client{
		Transport: transport,
		Timeout:   timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) == 0 {
				return errors.New("非法重定向")
			}
			if len(via) >= 2 {
				return errors.New("重定向次数过多")
			}
			// 只允许同一 host:port 内的路径重定向；跨地址一律拒绝，
			// 防止 302 把探测引到非回环目标。
			if !strings.EqualFold(req.URL.Host, via[0].URL.Host) {
				return fmt.Errorf("拒绝跨地址重定向: %s", req.URL.Host)
			}
			if err := validateProbeURL(req.URL); err != nil {
				return err
			}
			if !pc.allow() {
				return errProbeBudget
			}
			return nil
		},
	}
	return pc
}

// allow 原子占用一次探测预算。
func (p *probeClient) allow() bool {
	return p.used.Add(1) <= p.limit
}

// validateProbeURL 是红线 1/3 的唯一实现：scheme 只允许 http，
// host 必须是字面量回环 IP，禁止 userinfo 与非 http 端口。
func validateProbeURL(u *url.URL) error {
	if u == nil {
		return errors.New("空探测目标")
	}
	if !strings.EqualFold(u.Scheme, "http") {
		return fmt.Errorf("探测只允许 http: %q", u.Scheme)
	}
	if u.User != nil {
		return errors.New("探测 URL 不允许携带凭据")
	}
	host := u.Hostname()
	if host == "" {
		return errors.New("探测目标缺少主机")
	}
	// 域名一律拒绝：net.ParseIP 失败即非字面量 IP（localhost 也不放行，
	// 避免 hosts 文件/解析器把目标指到别处）。
	ip := net.ParseIP(host)
	if ip == nil {
		return fmt.Errorf("%w: %q 不是字面量 IP", errProbeNonLocal, host)
	}
	if !ip.IsLoopback() {
		return fmt.Errorf("%w: %s", errProbeNonLocal, ip)
	}
	port := u.Port()
	if port == "" {
		return errors.New("探测目标缺少端口")
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return fmt.Errorf("探测端口非法: %q", port)
	}
	return nil
}

// get 发起一次 GET 探测。URL 会先过红线校验；错误返回给调用方静默降级。
func (p *probeClient) get(ctx context.Context, raw string) probeResp {
	out := probeResp{URL: raw}
	u, err := url.Parse(raw)
	if err != nil {
		out.Err = fmt.Errorf("URL 解析失败: %w", err)
		return out
	}
	if err := validateProbeURL(u); err != nil {
		out.Err = err
		return out
	}
	if !p.allow() {
		out.Err = errProbeBudget
		return out
	}

	ctx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		out.Err = err
		return out
	}
	req.Header.Set("User-Agent", "HostGuard-Recon/1.0")
	// 不设 Accept-Encoding 之外的协商头；DisableCompression 已禁自动 gzip。

	resp, err := p.client.Do(req)
	if err != nil {
		out.Err = err
		return out
	}
	defer resp.Body.Close()
	out.Status = resp.StatusCode
	out.Header = resp.Header
	body, err := io.ReadAll(io.LimitReader(resp.Body, probeBodyLimit))
	if err != nil {
		out.Err = fmt.Errorf("读取响应失败: %w", err)
		return out
	}
	out.Body = body
	return out
}

// dialTCP 按同一红线建立一次裸 TCP 探测连接（redis/mysql 等协议探测）。
// 调用方负责 Close；预算与 HTTP 共用。
func (p *probeClient) dialTCP(ctx context.Context, ip string, port uint16) (net.Conn, error) {
	parsed := net.ParseIP(strings.Trim(ip, "[]"))
	if parsed == nil || !parsed.IsLoopback() {
		return nil, fmt.Errorf("%w: %s", errProbeNonLocal, ip)
	}
	if !p.allow() {
		return nil, errProbeBudget
	}
	d := net.Dialer{Timeout: p.timeout}
	ctx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(parsed.String(), strconv.Itoa(int(port))))
	if err != nil {
		return nil, err
	}
	// 读写都受 2s 约束：服务端不说话时不能无限等（PG/MSSQL 握手即如此）。
	_ = conn.SetDeadline(time.Now().Add(p.timeout))
	return conn, nil
}

// tcpExchange 发送 payload 后读取最多 readLen 字节；readWait 用于
// 服务端"不主动说话"的协议（PostgreSQL/MSSQL），到点按无横幅处理，
// 不把连接成功误判成失败。
func (p *probeClient) tcpExchange(ctx context.Context, ip string, port uint16, payload []byte, readLen int, readWait time.Duration) ([]byte, error) {
	conn, err := p.dialTCP(ctx, ip, port)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	if len(payload) > 0 {
		if err := conn.SetWriteDeadline(time.Now().Add(p.timeout)); err != nil {
			return nil, err
		}
		if _, err := conn.Write(payload); err != nil {
			return nil, err
		}
	}
	if readLen <= 0 {
		return nil, nil
	}
	if readWait <= 0 || readWait > p.timeout {
		readWait = p.timeout
	}
	if err := conn.SetReadDeadline(time.Now().Add(readWait)); err != nil {
		return nil, err
	}
	buf := make([]byte, readLen)
	n, err := conn.Read(buf)
	if n > 0 {
		// 读到部分数据即成功；超时后 n=0 才按无横幅处理。
		return buf[:n], nil
	}
	if err != nil {
		return nil, err
	}
	return nil, nil
}

// tcpBanner 建立连接后读最多 readLen 字节横幅。
//
// 关键语义：connected=true 与 err 可以同时成立——PostgreSQL/MSSQL 在
// 客户端发 startup/prelogin 前不主动说话，读超时是正常协议行为，
// 不能据此说"连不上"。调用方用 connected 判定端口可达，用 banner
// 判定版本；超时错误只作为 readErr 附带。
func (p *probeClient) tcpBanner(ctx context.Context, ip string, port uint16, readLen int, readWait time.Duration) (banner []byte, connected bool, readErr error) {
	conn, err := p.dialTCP(ctx, ip, port)
	if err != nil {
		return nil, false, err
	}
	defer conn.Close()
	if readWait <= 0 || readWait > p.timeout {
		readWait = p.timeout
	}
	if err := conn.SetReadDeadline(time.Now().Add(readWait)); err != nil {
		return nil, true, err
	}
	buf := make([]byte, readLen)
	n, err := conn.Read(buf)
	if n > 0 {
		return buf[:n], true, nil
	}
	return nil, true, err
}
