// Package notify 提供告警外发通知。
//
// 目前的实现是 Webhook：告警入库后向配置的 URL 推送 JSON 载荷，
// 并用共享密钥计算 HMAC-SHA256 签名放在 X-ZEDR-Signature 头，
// 接收方可以验证"这条通知确实来自本服务端且未被篡改"。
//
// 设计要点：
//   - 单 worker + 有界队列：通知是尽力而为的旁路，绝不能反压告警入库主链路。
//     队列满直接丢弃并计数（在 /metrics 可见），不阻塞、不重试轰炸。
//   - 失败只记日志：webhook 目标的可用性不该影响安全事件的记录。
package notify

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net/http"
	"sync/atomic"
	"time"

	"zedr/internal/server/domain"
)

// WebhookPayload 是推送给接收方的载荷。字段是告警的扁平投影：
// 接收方大概率只关心"哪台机器、什么东西、多严重"，
// 不应被迫理解完整的 Evidence 结构。
type WebhookPayload struct {
	ID          string    `json:"id"`
	Hostname    string    `json:"hostname"`
	Title       string    `json:"title"`
	Summary     string    `json:"summary"`
	Verdict     string    `json:"verdict"`
	Severity    string    `json:"severity"`
	Score       int       `json:"score"`
	ProcessName string    `json:"process_name"`
	ImagePath   string    `json:"image_path"`
	CmdLine     string    `json:"cmdline"`
	User        string    `json:"user"`
	Hash        string    `json:"hash_sha256"`
	Signed      bool      `json:"signed"`
	RuleIDs     []string  `json:"rule_ids"`
	MITRE       []string  `json:"mitre"`
	OccurredAt  time.Time `json:"occurred_at"`
}

// queueSize 是通知队列容量。按"每秒几十条告警 × webhook 秒级延迟"估算，
// 256 足以吸收常见突发；满即丢——对通知而言，丢一条比阻塞检测链路好得多。
const queueSize = 256

// Notifier 消费告警流并发送 webhook。
type Notifier struct {
	url    string
	secret string
	client *http.Client
	log    *slog.Logger

	queue chan domain.Alert
	abort chan struct{}

	sent    atomic.Int64
	failed  atomic.Int64
	dropped atomic.Int64
	stopped atomic.Bool
}

// New 创建通知器并启动 worker。url 为空时返回 nil（未启用），
// 所有方法都做了 nil 接收保护，调用方无需判空。
func New(url, secret string, timeout time.Duration, log *slog.Logger) *Notifier {
	if url == "" {
		return nil
	}
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	n := &Notifier{
		url:    url,
		secret: secret,
		client: &http.Client{Timeout: timeout},
		log:    log,
		queue:  make(chan domain.Alert, queueSize),
		abort:  make(chan struct{}),
	}
	go n.loop()
	return n
}

// Ingest 把告警放进通知队列；满则丢弃并计数。非阻塞。
func (n *Notifier) Ingest(a domain.Alert) {
	if n == nil || n.stopped.Load() {
		return
	}
	select {
	case n.queue <- a:
	default:
		n.dropped.Add(1)
	}
}

// Stats 返回 (已发送, 失败, 丢弃) 计数，供 /metrics 暴露。
func (n *Notifier) Stats() (sent, failed, dropped int64) {
	if n == nil {
		return 0, 0, 0
	}
	return n.sent.Load(), n.failed.Load(), n.dropped.Load()
}

// Close 停止 worker。队列中未发出的通知直接放弃——停机场景下
// 尽力清空反而拖慢关闭，且这些告警本身已落库，不丢数据只丢通知。
func (n *Notifier) Close() {
	if n == nil {
		return
	}
	n.stopped.Store(true)
	close(n.abort)
}

func (n *Notifier) loop() {
	for {
		select {
		case <-n.abort:
			return
		case a := <-n.queue:
			n.deliver(a)
		}
	}
}

func (n *Notifier) deliver(a domain.Alert) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	payload, err := json.Marshal(toPayload(a))
	if err != nil {
		n.failed.Add(1)
		return
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, n.url, bytes.NewReader(payload))
	if err != nil {
		n.failed.Add(1)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-ZEDR-Event", "alert.created")
	req.Header.Set("X-ZEDR-Signature", sign(payload, n.secret))

	resp, err := n.client.Do(req)
	if err != nil {
		n.failed.Add(1)
		n.log.Warn("webhook_deliver_failed", "alert_id", a.ID, "err", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		n.failed.Add(1)
		n.log.Warn("webhook_rejected", "alert_id", a.ID, "status", resp.StatusCode)
		return
	}
	n.sent.Add(1)
}

func toPayload(a domain.Alert) WebhookPayload {
	return WebhookPayload{
		ID:          a.ID,
		Hostname:    a.Hostname,
		Title:       a.Title,
		Summary:     a.Summary,
		Verdict:     string(a.Verdict),
		Severity:    string(a.Severity),
		Score:       a.Score,
		ProcessName: a.ProcessName,
		ImagePath:   a.ImagePath,
		CmdLine:     a.CmdLine,
		User:        a.ProcUser,
		Hash:        a.HashSHA256,
		Signed:      a.Signed,
		RuleIDs:     a.RuleIDs,
		MITRE:       a.MITRE,
		OccurredAt:  a.CreatedAt,
	}
}

// sign 计算 HMAC-SHA256 签名（hex）。secret 为空时返回空串，
// 接收方据此可区分"未配置签名"与"签名不匹配"。
func sign(payload []byte, secret string) string {
	if secret == "" {
		return ""
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}
