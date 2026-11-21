// dingtalk.go —— 钉钉自定义机器人渠道（actionCard 消息）。
//
// "加签"安全设置按钉钉官方规则实现（开放平台 · 自定义机器人 · 加签）：
//
//	stringToSign = timestamp(毫秒) + "\n" + secret
//	sign         = base64( HMAC-SHA256(key=secret, msg=stringToSign) )
//
// timestamp 与 URL 编码后的 sign 以 query 参数追加在机器人 webhook 地址上。
// 注意 secret 既是 HMAC key 又参与 message——这是官方文档的写法，不是笔误。

package notify

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"
	"strconv"
	"time"

	"zedr/internal/server/domain"
)

// NewDingTalk 创建钉钉渠道（actionCard：markdown 正文 + 可选跳转按钮）。
// url 为空返回 nil（未启用）；secret 可空：机器人未启用"加签"时直接
// POST 原地址。
func NewDingTalk(url, secret, consoleURL string, log *slog.Logger) *imChannel {
	if url == "" {
		return nil
	}
	c := newIMChannel(log)
	c.checkResp = dingRespOK
	c.send = func(a domain.Alert) {
		payload := buildDingTalkCard(a, consoleURL)
		// 每条消息现算签名：timestamp 是毫秒级时间戳且有时效（官方 1 小时），
		// 队列积压期间用旧时间戳会被拒收，不能在构造函数里算好存起来。
		if err := c.postJSON(dingSignedURL(url, secret, time.Now().UnixMilli()), payload); err != nil {
			c.reportFail("dingtalk", a, err)
			return
		}
		c.sent.Add(1)
	}
	// 限流摘要卡：text 类型（文案含"告警"关键词，关键词安全设置的机器人也能收）
	c.sendText = func(text string) error {
		return c.postJSON(dingSignedURL(url, secret, time.Now().UnixMilli()),
			map[string]any{"msgtype": "text", "text": map[string]any{"content": text}})
	}
	c.start()
	return c
}

// dingRespOK 校验钉钉业务码：钉钉对签名错误/关键词不匹配/频控等一律
// 返回 HTTP 200 + errcode!=0，只看状态码会漏掉最常见的配置类失败。
func dingRespOK(body []byte) error {
	var r struct {
		Errcode int64  `json:"errcode"`
		Errmsg  string `json:"errmsg"`
	}
	if err := json.Unmarshal(body, &r); err != nil {
		return nil
	}
	if r.Errcode != 0 {
		return fmt.Errorf("errcode %d: %s", r.Errcode, r.Errmsg)
	}
	return nil
}

// dingSignedURL 生成带 timestamp/sign 的 webhook 地址；未配 secret 时原样返回。
func dingSignedURL(rawURL, secret string, ts int64) string {
	if secret == "" {
		return rawURL
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		// webhook 地址在启用场景必然可解析（http/https），防御性兜底
		return rawURL
	}
	q := u.Query()
	q.Set("timestamp", strconv.FormatInt(ts, 10))
	q.Set("sign", dingSign(secret, ts))
	// Query.Encode 会对 sign 做 URL 编码（base64 的 +/= 转义），与官方要求一致
	u.RawQuery = q.Encode()
	return u.String()
}

// dingSign 实现钉钉官方加签算法：
//
//	stringToSign = timestamp + "\n" + secret
//	sign         = base64(HMAC-SHA256(key=secret, msg=stringToSign))
func dingSign(secret string, ts int64) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(strconv.FormatInt(ts, 10) + "\n" + secret))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

// buildDingTalkCard 构造 actionCard：markdown 正文，字段与飞书卡片一致。
func buildDingTalkCard(a domain.Alert, consoleURL string) map[string]any {
	v := viewOf(a)
	text := "### " + cardTitle(v) + "\n\n" +
		"- **主机**：" + orDash(v.hostname) + "\n" +
		"- **进程**：" + orDash(v.process) + "\n" +
		"- **得分**：" + v.score + "\n" +
		"- **MITRE**：" + orDash(v.mitre) + "\n\n" +
		"**摘要**：" + orDash(v.summary) + "\n\n" +
		"> 告警 ID：" + v.alertID + " • " + v.viewTime()
	ac := map[string]any{
		"title": cardTitle(v),
		"text":  text,
	}
	if consoleURL != "" {
		ac["btnOrientation"] = "0"
		ac["btns"] = []any{
			map[string]any{"title": "查看并处置", "actionURL": consoleURL + "/#/alerts?open=" + a.ID},
		}
	}
	return map[string]any{"msgtype": "actionCard", "actionCard": ac}
}
