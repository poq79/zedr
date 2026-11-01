// slack.go —— Slack incoming webhook 渠道。
//
// 用经典 attachments 载荷（而非 Block Kit）：incoming webhook 对它
// 零配置可用，字段语义（color/fields/title_link）也最贴合告警场景。

package notify

import (
	"log/slog"

	"hostguard/internal/server/domain"
)

// NewSlack 创建 Slack 渠道（attachments + fields）。
// url 为空返回 nil（未启用）。
func NewSlack(url, consoleURL string, log *slog.Logger) *imChannel {
	if url == "" {
		return nil
	}
	c := newIMChannel(log)
	// Slack 2xx 即成功，无需业务码校验
	c.send = func(a domain.Alert) {
		if err := c.postJSON(url, buildSlackPayload(a, consoleURL)); err != nil {
			c.reportFail("slack", a, err)
			return
		}
		c.sent.Add(1)
	}
	// 限流摘要卡：顶层 text 即普通消息
	c.sendText = func(text string) error {
		return c.postJSON(url, map[string]any{"text": text})
	}
	c.start()
	return c
}

// slackColor 映射严重度到 Slack attachment 颜色（语义色，Slack 官方保留字）：
// critical/high=danger，medium=warning，low 及以下=good。
func slackColor(severity string) string {
	switch severity {
	case "critical", "high":
		return "danger"
	case "medium":
		return "warning"
	default:
		return "good"
	}
}

// buildSlackPayload 构造 attachments 载荷，字段与飞书/钉钉卡片一致；
// "告警 ID"字段是未配置管理台地址时的占位落点（不硬编码 URL）。
func buildSlackPayload(a domain.Alert, consoleURL string) map[string]any {
	v := viewOf(a)
	att := map[string]any{
		"color": slackColor(string(a.Severity)),
		"title": cardTitle(v),
		"text":  orDash(v.summary),
		"fields": []any{
			slackField("主机", v.hostname, true),
			slackField("进程", v.process, true),
			slackField("得分", v.score, true),
			slackField("MITRE", orDash(v.mitre), true),
			slackField("告警 ID", v.alertID, true),
		},
		"footer": "HostGuard • " + v.viewTime(),
		"ts":     a.CreatedAt.Unix(),
	}
	if consoleURL != "" {
		att["title_link"] = consoleURL
	}
	return map[string]any{"attachments": []any{att}}
}

func slackField(title, value string, short bool) map[string]any {
	return map[string]any{"title": title, "value": value, "short": short}
}
