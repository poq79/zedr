package tunnel

import (
	"bufio"
	"net"

	"github.com/hashicorp/yamux"
)

// streamConn 把升级握手后的 bufio.Reader 与裸 conn 合成一个 ReadWriteCloser。
//
// 为什么必须合成（docs/LIVE-TUNNEL.md §3.1）：升级响应经 bufio 读取后，
// 缓冲区里可能已躺着与 101 同批到达的字节（服务端 yamux 的 keepalive
// ping / 窗口更新）。只把裸 conn 交给 yamux 会静默丢掉这些字节，
// 协议流错位且极难排查——服务端侧（livetunnel.hijackedStream）同理。
//
// 为什么显式覆盖 Read 而不是直接嵌入 *bufio.Reader：net.Conn 与
// bufio.Reader 都声明了 Read，双嵌入会变成歧义选择器（vet 直接报错）。
type streamConn struct {
	r *bufio.Reader
	net.Conn
}

func (c streamConn) Read(p []byte) (int, error) { return c.r.Read(p) }

// yamuxListener 把 yamux 会话适配成 net.Listener：服务端每新开一条流
// 就是一条"入站连接"，http.Server.Serve 只需要 Accept/Close/Addr 三件套。
type yamuxListener struct{ sess *yamux.Session }

func (l yamuxListener) Accept() (net.Conn, error) { return l.sess.Accept() }
func (l yamuxListener) Close() error              { return l.sess.Close() }
func (l yamuxListener) Addr() net.Addr            { return tunnelAddr{} }

// tunnelAddr 是隧道流的占位地址：流量跑在复用连接的流里，真实对端
// 地址没有意义，但 http.Server 及部分库路径要求 Addr() 返回非 nil。
type tunnelAddr struct{}

func (tunnelAddr) Network() string { return "tunnel" }
func (tunnelAddr) String() string  { return "tunnel" }
