// email.go —— SMTP 邮件渠道（net/smtp 纯标准库）。
//
// 设计取舍：
//   - 面向"STARTTLS + 明文口令"的内网中继场景够用：有凭据时优先协商
//     STARTTLS；中继不提供 STARTTLS 时，标准库 PlainAuth 会拒绝明文发送
//     ——这是刻意的安全默认，不提供绕过开关（无认证的 IP 信任中继不受影响）。
//   - 无 HTML、无附件：告警邮件是"让人去看管理台"的信号，不是报告。
//   - 正文 base64 编码（7-bit 安全，不依赖中继的 8BITMIME 能力），
//     非 ASCII 头按 RFC 2047 B 编码并按 75 字符上限折叠。

package notify

import (
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net"
	"net/mail"
	"net/smtp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"zedr/internal/server/domain"
)

const (
	// emailSessionTimeout 是 SMTP 会话整体 deadline。一次发送含 greeting/
	// EHLO/STARTTLS/MAIL/RCPT/DATA/QUIT 多次往返，1s 级会话超时会误伤正常
	// 中继；拨号仍用 IM 渠道同口径的 imSendTimeout（1s 级）。
	emailSessionTimeout = 15 * time.Second
)

// EmailConfig 是邮件渠道参数（来源：HG_SERVER_SMTP_* / HG_SERVER_ALERT_EMAIL_TO）。
type EmailConfig struct {
	Host string
	Port int    // 0 视为 25
	User string // 空则匿名发送
	Pass string
	From string // "addr@host" 或 "Name <addr@host>"（信封 MAIL FROM 用纯地址）
	To   []string
}

// NewEmail 创建邮件渠道（纯文本字段表 + 多收件人）。
// 主机/收件人/发件人任一缺失即返回 nil（未启用）。
func NewEmail(cfg EmailConfig, log *slog.Logger) *imChannel {
	if cfg.Host == "" || len(cfg.To) == 0 || cfg.From == "" {
		return nil
	}
	if cfg.Port <= 0 {
		cfg.Port = 25
	}
	p, err := mail.ParseAddress(cfg.From)
	if err != nil {
		// LoadConfig 已校验过；防御性兜底：非法地址宁可不发也不带病运行
		if log != nil {
			log.Warn("email_notifier_disabled", "reason", "invalid from address")
		}
		return nil
	}
	fromAddr := p.Address // 信封发件人（MAIL FROM，纯地址）
	fromHdr := p.String() // 头部 From（保留显示名形式）

	c := newIMChannel(log)
	c.send = func(a domain.Alert) {
		v := viewOf(a)
		msg := buildEmailRFC822(fromHdr, cfg.To, cardTitle(v), buildEmailBody(v), time.Now())
		if err := sendEmail(cfg, fromAddr, msg); err != nil {
			c.reportFail("email", a, err)
			return
		}
		c.sent.Add(1)
	}
	// 限流摘要：邮件渠道同样接入防风暴（过滤在共享 dispatch 里），
	// 摘要以固定主题的纯文本邮件发出，正文即摘要文案。
	c.sendText = func(text string) error {
		msg := buildEmailRFC822(fromHdr, cfg.To, "[Z-EDR] 通知摘要", text, time.Now())
		return sendEmail(cfg, fromAddr, msg)
	}
	c.start()
	return c
}

// sendEmail 走一次完整 SMTP 会话（单连接逐 RCPT 投递给全部收件人）。
func sendEmail(cfg EmailConfig, fromAddr string, msg []byte) error {
	addr := net.JoinHostPort(cfg.Host, strconv.Itoa(cfg.Port))
	conn, err := net.DialTimeout("tcp", addr, imSendTimeout)
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(emailSessionTimeout))

	cl, err := smtp.NewClient(conn, cfg.Host)
	if err != nil {
		return err
	}
	defer cl.Close()

	// 有凭据就必须加密传输：STARTTLS 由服务器能力协商，
	// 不提供时由 PlainAuth 拒绝明文认证（安全默认，无绕过开关）。
	if ok, _ := cl.Extension("STARTTLS"); ok {
		if err := cl.StartTLS(&tls.Config{ServerName: cfg.Host}); err != nil {
			return fmt.Errorf("starttls: %w", err)
		}
	}
	if cfg.User != "" {
		auth := smtp.PlainAuth("", cfg.User, cfg.Pass, cfg.Host)
		if err := cl.Auth(auth); err != nil {
			return fmt.Errorf("auth: %w", err)
		}
	}
	if err := cl.Mail(fromAddr); err != nil {
		return fmt.Errorf("mail from: %w", err)
	}
	for _, rcpt := range cfg.To {
		if err := cl.Rcpt(rcpt); err != nil {
			return fmt.Errorf("rcpt %s: %w", rcpt, err)
		}
	}
	w, err := cl.Data()
	if err != nil {
		return fmt.Errorf("data: %w", err)
	}
	// textproto 的 DotWriter 自动做点填充（透明处理正文中的孤立点）
	if _, err := w.Write(msg); err != nil {
		return fmt.Errorf("write body: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("close data: %w", err)
	}
	return cl.Quit()
}

// buildEmailBody 渲染纯文本字段表（与 IM 卡片同一套投影，全部已脱敏）。
func buildEmailBody(v alertView) string {
	return strings.Join([]string{
		"主机: " + orDash(v.hostname),
		"进程: " + orDash(v.process),
		"得分: " + v.score,
		"MITRE: " + orDash(v.mitre),
		"",
		"摘要: " + orDash(v.summary),
		"",
		"告警 ID: " + v.alertID,
		"时间: " + v.viewTime(),
		"",
		"-- Z-EDR",
	}, "\r\n")
}

// buildEmailRFC822 组装完整邮件（纯函数：now 注入，便于单测头格式/多收件人/编码）。
// 行尾一律 CRLF（RFC 5322）。
func buildEmailRFC822(from string, to []string, subject, body string, now time.Time) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "From: %s\r\n", from)
	fmt.Fprintf(&b, "To: %s\r\n", strings.Join(to, ", "))
	fmt.Fprintf(&b, "Subject: %s\r\n", encodeRFC2047(subject))
	fmt.Fprintf(&b, "Date: %s\r\n", now.Format(time.RFC1123Z))
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: text/plain; charset=UTF-8\r\n")
	b.WriteString("Content-Transfer-Encoding: base64\r\n\r\n")
	b.WriteString(wrapBase64([]byte(body)))
	return []byte(b.String())
}

// encodeRFC2047 对非 ASCII 头文本做 B 编码；纯 ASCII 原样返回。
// encoded-word 上限 75 字符，按 UTF-8 字符边界把原文切成 <=45 字节的块
// （45B -> 60 字符 base64 -> 72 字符 encoded-word），块间用 CRLF+WSP 折叠。
func encodeRFC2047(s string) string {
	if isASCII(s) {
		return s
	}
	const maxChunk = 45
	var words []string
	for len(s) > 0 {
		n := len(s)
		if n > maxChunk {
			n = maxChunk
			for n > 0 && !utf8.RuneStart(s[n]) {
				n--
			}
		}
		words = append(words, "=?UTF-8?B?"+base64.StdEncoding.EncodeToString([]byte(s[:n]))+"?=")
		s = s[n:]
	}
	return strings.Join(words, "\r\n ")
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] > 0x7F {
			return false
		}
	}
	return true
}

// wrapBase64 base64 编码并按 76 字符折行（RFC 2045）。
func wrapBase64(src []byte) string {
	enc := base64.StdEncoding.EncodeToString(src)
	var b strings.Builder
	for len(enc) > 76 {
		b.WriteString(enc[:76])
		b.WriteString("\r\n")
		enc = enc[76:]
	}
	b.WriteString(enc)
	return b.String()
}
