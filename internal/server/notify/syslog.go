// Package notify 的 Syslog 输出：企业 SIEM 接入的标准通道。
//
// 为什么有 Webhook 还要 Syslog：
// 企业环境里 Splunk/QRadar/态势感知几乎都原生吃 syslog，而 webhook
// 需要对方开发接收端。CEF 是 ArcSight 定制、被主流 SIEM 广泛解析的格式，
// 用它而不是裸 JSON，能让"接入"这个动作在 SIEM 侧变成零开发。
//
// 通道语义与 Webhook 一致：UDP 尽力而为、队列满即丢、绝不反压告警主链路。
package notify

import (
	"fmt"
	"net"
	"strings"
	"sync/atomic"

	"hostguard/internal/server/domain"
)

// SyslogNotifier 通过 UDP 发送 CEF 格式告警。
type SyslogNotifier struct {
	conn  net.Conn
	queue chan domain.Alert
	abort chan struct{}

	sent    atomic.Int64
	failed  atomic.Int64
	dropped atomic.Int64
}

// syslogQueueSize 与 webhook 一致：通知是旁路，宁可丢不可堵。
const syslogQueueSize = 256

// NewSyslog 创建 syslog 输出器。addr 形如 "siem.corp.local:514"；空则返回 nil。
func NewSyslog(addr string, log interface{ Warn(string, ...any) }) *SyslogNotifier {
	if addr == "" {
		return nil
	}
	conn, err := net.Dial("udp", addr)
	if err != nil {
		// UDP Dial 几乎不会失败（无连接），失败通常是地址格式错误
		if log != nil {
			log.Warn("syslog_dial_failed", "addr", addr, "err", err)
		}
		return nil
	}
	n := &SyslogNotifier{
		conn:  conn,
		queue: make(chan domain.Alert, syslogQueueSize),
		abort: make(chan struct{}),
	}
	go n.loop()
	return n
}

// Ingest 非阻塞入队。
func (n *SyslogNotifier) Ingest(a domain.Alert) {
	if n == nil {
		return
	}
	select {
	case n.queue <- a:
	default:
		n.dropped.Add(1)
	}
}

// Stats 返回 (已发送, 失败, 丢弃)。
func (n *SyslogNotifier) Stats() (sent, failed, dropped int64) {
	if n == nil {
		return 0, 0, 0
	}
	return n.sent.Load(), n.failed.Load(), n.dropped.Load()
}

// Close 停止发送并关闭连接。
func (n *SyslogNotifier) Close() {
	if n == nil {
		return
	}
	select {
	case <-n.abort:
	default:
		close(n.abort)
	}
	_ = n.conn.Close()
}

func (n *SyslogNotifier) loop() {
	for {
		select {
		case <-n.abort:
			return
		case a := <-n.queue:
			if _, err := n.conn.Write([]byte(FormatCEF(a))); err != nil {
				n.failed.Add(1)
			} else {
				n.sent.Add(1)
			}
		}
	}
}

// FormatCEF 把告警渲染成一行 CEF。
//
// CEF 头部 7 段：Version|Device Vendor|Device Product|Device Version|
// Signature ID|Name|Severity。Severity 用 0-10 数值（CEF 标准），
// 映射：low=3 medium=5 high=7 critical=10。
// 扩展字段全部放 cs1-cs3 具名对，主流 SIEM 开箱即可映射成报表维度。
func FormatCEF(a domain.Alert) string {
	sev := 3
	switch a.Severity {
	case "medium":
		sev = 5
	case "high":
		sev = 7
	case "critical":
		sev = 10
	}

	// CEF 头部的 Name 字段不能含 | 与 \，统一替换
	name := strings.NewReplacer("|", "/", "\\", "/").Replace(a.Title)

	var b strings.Builder
	fmt.Fprintf(&b, "CEF:0|HostGuard|SecServer|0.6.0|HostGuardAlert|%s|%d|",
		cefEscape(name), sev)
	fmt.Fprintf(&b, "cs1Label=Host cs1=%s ", cefEscape(a.Hostname))
	fmt.Fprintf(&b, "cs2Label=Process cs2=%s ", cefEscape(a.ProcessName))
	fmt.Fprintf(&b, "cs3Label=MITRE cs3=%s ", cefEscape(strings.Join(a.MITRE, ",")))
	fmt.Fprintf(&b, "fname=%s ", cefEscape(a.ImagePath))
	if a.HashSHA256 != "" {
		fmt.Fprintf(&b, "fileHash=%s ", a.HashSHA256)
	}
	fmt.Fprintf(&b, "suser=%s ", cefEscape(a.ProcUser))
	fmt.Fprintf(&b, "cs4Label=Verdict cs4=%s ", string(a.Verdict))
	fmt.Fprintf(&b, "cn1Label=Score cn1=%d", a.Score)
	return b.String()
}

// cefEscape 处理扩展字段值：CEF 里 \ 与 = 需要转义，换行会破坏单行语义。
func cefEscape(s string) string {
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "=", "\\=")
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", "")
	return s
}
