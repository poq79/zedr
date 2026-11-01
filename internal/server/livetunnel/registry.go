// Package livetunnel 维护"中心 → 探针"实时隧道的传输层内核：
// 升级握手、会话注册表与代理客户端。
//
// 隧道由探针反连建立（探针零监听、零入站，docs/LIVE-TUNNEL.md §1）：
// 探针发 HTTP/1.1 升级请求，101 后连接交给 yamux 复用，中心端随时
// 对每个探针开流发起只读 HTTP 查询，探针侧 http.Server 在流上应答。
// 本包只提供传输原语；REST 路由、RBAC、审计、参数钳制由 W2 接线层
// （internal/server/api/live.go）完成——执法点必须留在中心代理侧。
package livetunnel

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"sync"

	"github.com/hashicorp/yamux"

	"hostguard/internal/platform/apperr"
)

// maxInFlightPerAgent 每 agent 在途实时查询上限。
//
// 为什么在这里钳：yamux 不限制打开方并发，若不设防，前端一个卡住的
// 大目录遍历就能占满探针侧 http.Server 的处理能力，拖垮同主机其他
// 实时查询。实时查询是交互式操作，超限立即拒绝（前端显示"忙"）
// 而不是排队——排队只会让操作员以为界面卡死。
const maxInFlightPerAgent = 4

// Registry 维护 agentID → 隧道会话的映射。
//
// 会话与本进程同生命周期（单实例 SQLite 架构，TRADEOFFS §9.2）；
// 迁 HA/PostgreSQL 时需要跨实例粘性路由，届时与指令通道一并设计。
type Registry struct {
	log *slog.Logger

	mu     sync.Mutex
	agents map[string]*Client
}

// NewRegistry 创建注册表。
func NewRegistry(log *slog.Logger) *Registry {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Registry{log: log, agents: make(map[string]*Client)}
}

// Add 注册新会话；同 ID 已有会话时先关旧会话再替换。
//
// 场景：探针重连（旧会话实际已死但 Remove 还没被调用）或探针重启。
// 旧会话必须立刻关闭——yamux keepalive 会把半死连接拖很久，
// 且旧 Client 的在途请求只有会话关闭后才会以错误退出。
func (r *Registry) Add(agentID string, sess *yamux.Session) {
	r.mu.Lock()
	old := r.agents[agentID]
	r.agents[agentID] = newClient(sess)
	r.mu.Unlock()

	if old != nil {
		r.log.Debug("tunnel_session_replaced", "agent_id", agentID, "remote", sess.RemoteAddr())
		_ = old.Close()
		return
	}
	r.log.Debug("tunnel_session_added", "agent_id", agentID, "remote", sess.RemoteAddr())
}

// Remove 注销会话。按指针匹配而非仅按 ID：
// 重连风暴里旧会话的延迟清理可能晚于新会话注册，
// 只按 ID 删会把刚注册的新会话误删，导致"明明在线却 503"。
func (r *Registry) Remove(agentID string, sess *yamux.Session) {
	r.mu.Lock()
	cur, ok := r.agents[agentID]
	if ok && cur.sess == sess {
		delete(r.agents, agentID)
	} else {
		ok = false
	}
	r.mu.Unlock()

	if ok {
		r.log.Debug("tunnel_session_removed", "agent_id", agentID)
		_ = sess.Close() // 指针匹配才关：不匹配时绝不碰（可能是）新会话
	}
}

// Get 返回该 agent 的代理客户端；ok=false 表示隧道未连接
// （代理层据此返回 503 tunnel_not_connected）。
func (r *Registry) Get(agentID string) (*Client, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	c, ok := r.agents[agentID]
	return c, ok
}

// Len 返回当前在册会话数（运营指标/测试用）。
func (r *Registry) Len() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.agents)
}

// Track 注册会话并托管其掉线清理：CloseChan 关闭时按指针摘除。
//
// 为什么清理归属在这里：UpgradeHandler 的 onSession 回调只管"进来"，
// "会话死了必须从表里消失"若无明确归属，注册表会积攒僵尸会话，
// Get 一直返回打不通的 Client，探针明明在线却持续 503。
func (r *Registry) Track(agentID string, sess *yamux.Session) {
	r.Add(agentID, sess)
	go func() {
		<-sess.CloseChan()
		r.Remove(agentID, sess)
	}()
}

// ---------------------------------------------------------------- Client

// Client 是单个探针隧道的代理客户端：HTTP 出口 + 每 agent 并发闸。
//
// 用法（W2 代理层约定）：
//
//	cli, ok := reg.Get(agentID)
//	if !ok { ... 503 tunnel_not_connected }
//	if err := cli.Acquire(r.Context()); err != nil { ... 429 }
//	defer cli.Release()
//	resp, err := cli.HTTP().Do(req) // 超时用请求 ctx 控制
type Client struct {
	sess *yamux.Session
	sem  chan struct{}
	http *http.Client
}

func newClient(sess *yamux.Session) *Client {
	c := &Client{
		sess: sess,
		sem:  make(chan struct{}, maxInFlightPerAgent),
	}
	c.http = &http.Client{
		// 为什么不设 Client.Timeout：不同端点预算差异大（ping 5s /
		// fs/hash 30s），统一超时要么掐断慢端点要么放过快端点，
		// 预算由代理层按端点用请求 ctx 控制
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				// network/addr 参数无意义：目的地恒为该会话背后的探针 liveapi
				return openStreamCtx(ctx, c.sess)
			},
			// 隧道内没有连接池的意义：一条 HTTP 连接 = 一条 yamux 流。
			// 禁 keep-alive 防止响应结束后流被池缓存占住
			// （并发已由信号量钳制，复用只增加状态管理面）
			DisableKeepAlives: true,
		},
	}
	return c
}

// Acquire 占用一个在途名额。超限立即失败（不排队等待名额释放）。
func (c *Client) Acquire(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case c.sem <- struct{}{}:
		return nil
	default:
		return apperr.TooManyRequests("该主机的实时查询并发已达上限，请稍后重试")
	}
}

// Release 归还在途名额，必须与 Acquire 成对调用。
func (c *Client) Release() {
	<-c.sem
}

// HTTP 返回经隧道的 HTTP 客户端。URL 的 host 部分无意义
// （拨号恒定指向本会话），约定用 "http://tunnel/" 占位。
func (c *Client) HTTP() *http.Client { return c.http }

// Close 关闭底层 yamux 会话（Registry 替换/注销时调用）。
func (c *Client) Close() error {
	return c.sess.Close()
}

// openStreamCtx 带取消地打开 yamux 流。
//
// 为什么不直接 sess.Open()：v0.1.2 的 Open() 不接收 ctx，而代理层的
// 端点预算靠 ctx 落地。竞态窗口（ctx 先取消、流后建立）里建立的流
// 必须显式回收，否则泄漏一条占用 synCh 配额的僵尸流。
func openStreamCtx(ctx context.Context, sess *yamux.Session) (net.Conn, error) {
	type openResult struct {
		conn net.Conn
		err  error
	}
	ch := make(chan openResult, 1)
	go func() {
		conn, err := sess.Open()
		ch <- openResult{conn, err}
	}()
	select {
	case r := <-ch:
		return r.conn, r.err
	case <-ctx.Done():
		// 迟到的流由这里回收；ch 带缓冲保证 goroutine 能退出
		go func() {
			if r := <-ch; r.err == nil {
				_ = r.conn.Close()
			}
		}()
		return nil, ctx.Err()
	}
}
