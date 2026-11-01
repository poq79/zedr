package notify

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"zedr/internal/server/domain"
)

// secretAlert 是标准测试告警：摘要里埋了明文口令，
// 用于断言每个渠道在"出产品"之前确实脱敏（纵深防御的最后一道）。
func secretAlert() domain.Alert {
	return domain.Alert{
		ID: "a-9", AgentID: "agent-1", Hostname: "pc-1",
		Title:   "可疑命令执行",
		Summary: `运行 psexec.exe -password=hunter2 完成横向移动`,
		Verdict: domain.VerdictSuspicious, Severity: domain.SeverityCritical, Score: 87,
		ProcessName: "evil.exe", MITRE: []string{"T1059.001", "T1021.002"},
		CreatedAt: time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC),
	}
}

// waitFor 轮询等待异步投递结果（单 worker 模型，计数在发送后更新）。
func waitFor(t *testing.T, cond func() bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal(msg)
}

// ---- JSON 断言辅助：字符串键进对象、整数键进数组 ----

func jget(t *testing.T, v any, path ...any) any {
	t.Helper()
	cur := v
	for i, k := range path {
		switch key := k.(type) {
		case string:
			m, ok := cur.(map[string]any)
			if !ok {
				t.Fatalf("路径 %v: 期望对象，实际 %T", path[:i], cur)
			}
			cur = m[key]
		case int:
			arr, ok := cur.([]any)
			if !ok {
				t.Fatalf("路径 %v: 期望数组，实际 %T", path[:i], cur)
			}
			if key >= len(arr) {
				t.Fatalf("路径 %v 越界（长度 %d）", path[:i+1], len(arr))
			}
			cur = arr[key]
		}
	}
	return cur
}

func jstr(t *testing.T, v any, path ...any) string {
	t.Helper()
	s, ok := jget(t, v, path...).(string)
	if !ok {
		t.Fatalf("路径 %v 不是字符串", path)
	}
	return s
}

func jbody(t *testing.T, body []byte) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		t.Fatalf("请求体不是合法 JSON: %v\n%s", err, body)
	}
	return m
}

// --------------------------------------------------------------- 飞书

// TestFeishuDeliversInteractiveCard 验证：请求体是 interactive 卡片、
// critical 映射红色模板、字段齐全、口令在卡片里被脱敏、
// 配置管理台地址时"前往处理"按钮指向它。
func TestFeishuDeliversInteractiveCard(t *testing.T) {
	ch := make(chan []byte, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		ch <- b
		fmt.Fprint(w, `{"code":0,"msg":"success"}`)
	}))
	defer srv.Close()

	const console = "https://hg.example.com"
	f := NewFeishu(srv.URL, console, testLogger())
	defer f.Close()
	f.Ingest(secretAlert())

	var body []byte
	select {
	case body = <-ch:
	case <-time.After(3 * time.Second):
		t.Fatal("未收到飞书卡片请求")
	}
	waitFor(t, func() bool {
		s, _, _ := f.Stats()
		return s == 1
	}, "发送成功后 sent 计数应为 1")

	root := jbody(t, body)
	if jstr(t, root, "msg_type") != "interactive" {
		t.Fatalf("msg_type = %v，期望 interactive", root["msg_type"])
	}
	header := jget(t, root, "card", "header").(map[string]any)
	if jstr(t, header, "template") != "red" { // critical → 红
		t.Fatalf("模板色 = %v，期望 red", header["template"])
	}
	title := jstr(t, header, "title", "content")
	if !strings.Contains(title, "[Z-EDR][CRITICAL]") || !strings.Contains(title, "可疑命令执行") {
		t.Fatalf("标题不符合「[Z-EDR][严重度] 标题」契约: %q", title)
	}

	// 字段：主机/进程/得分/MITRE（第一个 div 的 fields，lark_md 双行内容）
	got := map[string]string{}
	fields := jget(t, root, "card", "elements", 0, "fields").([]any)
	for _, fl := range fields {
		content := jstr(t, fl, "text", "content")
		parts := strings.SplitN(content, "\n", 2)
		val := ""
		if len(parts) > 1 {
			val = parts[1]
		}
		got[strings.Trim(parts[0], "*")] = val
	}
	want := map[string]string{
		"主机": "pc-1", "进程": "evil.exe", "得分": "87",
		"MITRE": "T1059.001, T1021.002",
	}
	for k, w := range want {
		if got[k] != w {
			t.Fatalf("字段 %s = %q，期望 %q", k, got[k], w)
		}
	}

	// 脱敏：口令明文不得出现，且摘要已打码
	if strings.Contains(string(body), "hunter2") {
		t.Fatal("口令明文出现在飞书卡片中——脱敏失效")
	}
	if !strings.Contains(string(body), "***") {
		t.Fatal("摘要未按命令行口径打码")
	}

	// "前往处理"按钮指向配置的管理台地址
	elements := jget(t, root, "card", "elements").([]any)
	btnURL := ""
	for _, el := range elements {
		m, ok := el.(map[string]any)
		if ok && m["tag"] == "action" {
			btnURL = jstr(t, m, "actions", 0, "url")
		}
	}
	if btnURL != console {
		t.Fatalf("前往处理按钮 URL = %q，期望 %q", btnURL, console)
	}
}

// TestFeishuCardWithoutConsoleURLHasNoFakeLink 验证未配置管理台地址时
// 不伪造 URL：无 action 按钮、无 http 字样，仅落告警 ID 占位供检索。
func TestFeishuCardWithoutConsoleURLHasNoFakeLink(t *testing.T) {
	b, err := json.Marshal(buildFeishuCard(secretAlert(), ""))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "http") {
		t.Fatalf("未配置 ConsoleURL 时卡片不应含任何链接: %s", b)
	}
	root := jbody(t, b)
	for _, el := range jget(t, root, "card", "elements").([]any) {
		if m, ok := el.(map[string]any); ok && m["tag"] == "action" {
			t.Fatal("无管理台地址时不应渲染「前往处理」按钮")
		}
	}
	if !strings.Contains(string(b), "a-9") {
		t.Fatal("应以告警 ID 作为占位落点")
	}
}

// TestFeishuSeverityTemplate 验证严重度→飞书模板色映射。
func TestFeishuSeverityTemplate(t *testing.T) {
	cases := map[string]string{
		"critical": "red", "high": "red",
		"medium": "orange", "low": "grey", "": "grey",
	}
	for sev, want := range cases {
		if got := feishuTemplateColor(sev); got != want {
			t.Fatalf("feishu 模板色 %q → %q，期望 %q", sev, got, want)
		}
	}
}

// --------------------------------------------------------------- 钉钉

// TestDingTalkSignAndActionCard 验证：加签 query 符合官方算法且 URL 编码正确
// （Query 取值会解码，与重算值逐字符相等即证明编码往返无损）、
// 原有 query 参数保留、actionCard 结构与脱敏生效。
func TestDingTalkSignAndActionCard(t *testing.T) {
	const secret = "ding-secret"

	type recv struct {
		body   []byte
		rawURL *url.URL
	}
	ch := make(chan recv, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		ch <- recv{body: b, rawURL: r.URL}
		fmt.Fprint(w, `{"errcode":0,"errmsg":"ok"}`)
	}))
	defer srv.Close()

	const console = "https://hg.example.com"
	d := NewDingTalk(srv.URL+"?access_token=tok123", secret, console, testLogger())
	defer d.Close()
	d.Ingest(secretAlert())

	select {
	case g := <-ch:
		q := g.rawURL.Query()
		ts, err := strconv.ParseInt(q.Get("timestamp"), 10, 64)
		if err != nil {
			t.Fatalf("timestamp 参数缺失或非法: %v", err)
		}
		now := time.Now().UnixMilli()
		if ts > now || now-ts > 60_000 {
			t.Fatalf("timestamp 不在合理窗口内: %d（now %d）", ts, now)
		}
		// 独立复算官方规则：sign = base64(HMAC-SHA256(secret, ts + "\n" + secret))
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write([]byte(strconv.FormatInt(ts, 10) + "\n" + secret))
		want := base64.StdEncoding.EncodeToString(mac.Sum(nil))
		if q.Get("sign") != want {
			t.Fatalf("sign = %q，期望 %q", q.Get("sign"), want)
		}
		if q.Get("access_token") != "tok123" {
			t.Fatal("追加签名参数时丢失了原有 query")
		}

		root := jbody(t, g.body)
		if jstr(t, root, "msgtype") != "actionCard" {
			t.Fatalf("msgtype = %v，期望 actionCard", root["msgtype"])
		}
		ac := jget(t, root, "actionCard").(map[string]any)
		title := jstr(t, ac, "title")
		if !strings.Contains(title, "[Z-EDR][CRITICAL]") {
			t.Fatalf("标题契约不符: %q", title)
		}
		text := jstr(t, ac, "text")
		for _, want2 := range []string{"pc-1", "evil.exe", "87", "T1059.001", "***", "a-9"} {
			if !strings.Contains(text, want2) {
				t.Fatalf("卡片正文缺少 %q:\n%s", want2, text)
			}
		}
		if strings.Contains(text, "hunter2") {
			t.Fatal("口令明文出现在钉钉卡片中——脱敏失效")
		}
		if jstr(t, ac, "btns", 0, "actionURL") != console {
			t.Fatalf("按钮 actionURL = %v，期望 %s", ac["btns"], console)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("未收到钉钉请求")
	}
}

// TestDingTalkBusinessCodeFailure 验证 HTTP 200 + errcode!=0 计入 failed
// （钉钉对配置类错误返回 200，只看状态码会漏报）。
func TestDingTalkBusinessCodeFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"errcode":310000,"errmsg":"sign not match"}`)
	}))
	defer srv.Close()

	d := NewDingTalk(srv.URL, "s", "", testLogger())
	defer d.Close()
	d.Ingest(secretAlert())

	waitFor(t, func() bool {
		_, fl, _ := d.Stats()
		return fl == 1
	}, "errcode!=0 应计入 failed")
	if s, _, _ := d.Stats(); s != 0 {
		t.Fatalf("业务失败不应计入 sent，实际 %d", s)
	}
}

// --------------------------------------------------------------- Slack

// TestSlackDeliversAttachment 验证 attachments 结构、颜色映射、字段与脱敏。
func TestSlackDeliversAttachment(t *testing.T) {
	ch := make(chan []byte, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		ch <- b
		fmt.Fprint(w, "ok")
	}))
	defer srv.Close()

	const console = "https://hg.example.com"
	alert := secretAlert()
	s := NewSlack(srv.URL, console, testLogger())
	defer s.Close()
	s.Ingest(alert)

	var body []byte
	select {
	case body = <-ch:
	case <-time.After(3 * time.Second):
		t.Fatal("未收到 Slack 请求")
	}

	root := jbody(t, body)
	att := jget(t, root, "attachments", 0).(map[string]any)
	if att["color"] != "danger" { // critical → danger
		t.Fatalf("color = %v，期望 danger", att["color"])
	}
	if title := att["title"].(string); !strings.Contains(title, "[Z-EDR][CRITICAL]") {
		t.Fatalf("标题契约不符: %q", title)
	}
	if att["title_link"] != console {
		t.Fatalf("title_link = %v，期望 %s", att["title_link"], console)
	}
	text := att["text"].(string)
	if strings.Contains(text, "hunter2") {
		t.Fatal("口令明文出现在 Slack 消息中——脱敏失效")
	}
	if !strings.Contains(text, "***") {
		t.Fatal("摘要未打码")
	}
	fields := att["fields"].([]any)
	if len(fields) != 5 {
		t.Fatalf("fields 数 = %d，期望 5（主机/进程/得分/MITRE/告警 ID）", len(fields))
	}
	f0 := fields[0].(map[string]any)
	if f0["title"] != "主机" || f0["value"] != "pc-1" || f0["short"] != true {
		t.Fatalf("主机字段不符: %v", f0)
	}
	if ts, ok := att["ts"].(float64); !ok || int64(ts) != alert.CreatedAt.Unix() {
		t.Fatalf("ts = %v，期望 %d", att["ts"], alert.CreatedAt.Unix())
	}
}

// TestSlackSeverityColor 验证严重度→Slack 颜色映射。
func TestSlackSeverityColor(t *testing.T) {
	cases := map[string]string{
		"critical": "danger", "high": "danger",
		"medium": "warning", "low": "good", "info": "good",
	}
	for sev, want := range cases {
		if got := slackColor(sev); got != want {
			t.Fatalf("slack 颜色 %q → %q，期望 %q", sev, got, want)
		}
	}
}

// --------------------------------------------------------------- 邮件

// TestBuildEmailRFC822 验证头格式、多收件人、主题 RFC2047 编码、
// 正文 base64 编码与 CRLF 行尾（纯函数测试，不跑真实 SMTP）。
func TestBuildEmailRFC822(t *testing.T) {
	now := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	body := "主机: pc-1\r\n进程: evil.exe\r\n得分: 87"
	msg := string(buildEmailRFC822("hg@example.com",
		[]string{"a@x.com", "b@y.com"},
		"[Z-EDR][CRITICAL] 可疑命令执行",
		body, now))

	for _, want := range []string{
		"From: hg@example.com\r\n",
		"To: a@x.com, b@y.com\r\n", // 多收件人逗号并列
		"MIME-Version: 1.0\r\n",
		"Content-Type: text/plain; charset=UTF-8\r\n",
		"Content-Transfer-Encoding: base64\r\n",
		"Date: Sun, 01 Nov 2026 12:00:00 +0000\r\n",
	} {
		if !strings.Contains(msg, want) {
			t.Fatalf("邮件缺少头 %q\n---\n%s", want, msg)
		}
	}

	// 主题：B 编码后可完整还原
	subj := headerValue(t, msg, "Subject")
	if decoded := decodeRFC2047(t, subj); decoded != "[Z-EDR][CRITICAL] 可疑命令执行" {
		t.Fatalf("主题解码不符: %q", decoded)
	}

	// 正文：base64 还原一致
	rest := msg[strings.Index(msg, "\r\n\r\n")+4:]
	raw, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(rest, "\r\n", ""))
	if err != nil {
		t.Fatalf("正文 base64 非法: %v", err)
	}
	if string(raw) != body {
		t.Fatalf("正文还原不符:\n got %q\nwant %q", raw, body)
	}

	// 行尾：不得出现裸 LF
	if strings.Count(msg, "\n") != strings.Count(msg, "\r\n") {
		t.Fatal("存在裸 LF 行尾，违反 RFC 5322")
	}

	// 纯 ASCII 主题不编码
	ascii := string(buildEmailRFC822("f@x.com", []string{"t@x.com"}, "plain subject", "b", now))
	if !strings.Contains(ascii, "Subject: plain subject\r\n") {
		t.Fatalf("ASCII 主题不应编码: %s", ascii)
	}
}

// TestEmailSubjectFolding 验证超长中文主题按 encoded-word 75 字符上限
// 折叠，且折叠后拼接解码可完整还原。
func TestEmailSubjectFolding(t *testing.T) {
	long := "[Z-EDR][CRITICAL] " + strings.Repeat("横向移动告警，", 30)
	msg := string(buildEmailRFC822("f@x.com", []string{"t@x.com"}, long, "b", time.Now()))
	subj := headerValue(t, msg, "Subject")
	for _, w := range strings.Split(subj, "\r\n ") {
		if len(w) > 75 {
			t.Fatalf("encoded-word 超长（%d 字符）: %q", len(w), w)
		}
		if !strings.HasPrefix(w, "=?UTF-8?B?") || !strings.HasSuffix(w, "?=") {
			t.Fatalf("非法 encoded-word: %q", w)
		}
	}
	if decoded := decodeRFC2047(t, subj); decoded != long {
		t.Fatalf("折叠后还原不符:\n got %q\nwant %q", decoded, long)
	}
}

// headerValue 取头值（含折叠续行），供编码断言用。
func headerValue(t *testing.T, msg, name string) string {
	t.Helper()
	lines := strings.Split(msg, "\r\n")
	for i, line := range lines {
		if strings.HasPrefix(line, name+": ") {
			out := strings.TrimPrefix(line, name+": ")
			for j := i + 1; j < len(lines) && len(lines[j]) > 0 &&
				(lines[j][0] == ' ' || lines[j][0] == '\t'); j++ {
				out += "\r\n" + lines[j]
			}
			return out
		}
	}
	t.Fatalf("缺少头 %s", name)
	return ""
}

// decodeRFC2047 解开测试中构造的 B 编码 encoded-word 序列。
func decodeRFC2047(t *testing.T, v string) string {
	t.Helper()
	var sb strings.Builder
	const prefix = "=?UTF-8?B?"
	for _, part := range strings.Split(v, "\r\n ") {
		if !strings.HasPrefix(part, prefix) {
			sb.WriteString(part) // 未编码的 ASCII 片段
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(strings.TrimSuffix(strings.TrimPrefix(part, prefix), "?="))
		if err != nil {
			t.Fatalf("encoded-word base64 非法: %v", err)
		}
		sb.Write(raw)
	}
	return sb.String()
}

// --------------------------------------------------------------- 失败与禁用

// TestFeishuFailureCounted 验证两类失败都计入 failed 且不 panic：
// HTTP 5xx 与 HTTP 200 + 业务码非 0；失败不重试、不阻塞 Ingest。
func TestFeishuFailureCounted(t *testing.T) {
	srv500 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv500.Close()

	f := NewFeishu(srv500.URL, "", testLogger())
	f.Ingest(secretAlert())
	waitFor(t, func() bool {
		_, fl, _ := f.Stats()
		return fl == 1
	}, "HTTP 500 应计入 failed")
	if s, _, _ := f.Stats(); s != 0 {
		t.Fatalf("失败不应计入 sent，实际 %d", s)
	}
	f.Close()

	srvBiz := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"code":19021,"msg":"sign match fail"}`)
	}))
	defer srvBiz.Close()

	f2 := NewFeishu(srvBiz.URL, "", testLogger())
	f2.Ingest(secretAlert())
	waitFor(t, func() bool {
		_, fl, _ := f2.Stats()
		return fl == 1
	}, "业务码非 0 应计入 failed")
	f2.Close()
}

// TestDisabledChannelsSendNothing 空配置必须返回 nil（零构造、零请求）；
// nil 渠道的全部方法安全，与 Notifier 的 nil 约定一致。
func TestDisabledChannelsSendNothing(t *testing.T) {
	if NewFeishu("", "https://x", testLogger()) != nil {
		t.Fatal("空 URL 的飞书渠道应返回 nil")
	}
	if NewDingTalk("", "s", "", testLogger()) != nil {
		t.Fatal("空 URL 的钉钉渠道应返回 nil")
	}
	if NewSlack("", "", testLogger()) != nil {
		t.Fatal("空 URL 的 Slack 渠道应返回 nil")
	}
	if NewEmail(EmailConfig{Host: "smtp.x.com", Port: 25, From: "f@x.com"}, testLogger()) != nil {
		t.Fatal("缺收件人的邮件渠道应返回 nil")
	}
	if NewEmail(EmailConfig{Host: "smtp.x.com", Port: 25,
		From: "not-an-email", To: []string{"a@x.com"}}, testLogger()) != nil {
		t.Fatal("非法发件人应返回 nil")
	}
	if NewEmail(EmailConfig{Host: "smtp.x.com", From: "f@x.com",
		To: []string{"a@x.com", "b@y.com"}}, testLogger()) == nil {
		t.Fatal("合法配置的邮件渠道不应返回 nil")
	}

	// nil 渠道调用安全（方法集挂在 *imChannel 上，与 Notifier 的 nil 约定一致）
	var c *imChannel
	c.Ingest(secretAlert())
	c.Close()
	if s, fl, d := c.Stats(); s != 0 || fl != 0 || d != 0 {
		t.Fatalf("nil 渠道统计应为零，实际 %d/%d/%d", s, fl, d)
	}
}
