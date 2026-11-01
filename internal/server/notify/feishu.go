// feishu.go —— 飞书卡片渠道 + 新增通知渠道的公共骨架。
//
// 与既有 Notifier(webhook)/SyslogNotifier 的关系：
//   - 接收模型同构：有界队列 + 单 worker + 非阻塞 Ingest + 满即丢计数
//     （照抄 webhook.go 的模式——通知是尽力而为的旁路，绝不反压告警主链路）；
//   - 既有两个实现一字未改，只补一个结构化接口 Channel（它们的方法集
//     本就与之匹配），app.go 的订阅循环面向接口统一分发；
//   - 严重度过滤不在这里做：治理口径（HG_SERVER_WEBHOOK_MIN_SEVERITY）
//     只存在于订阅循环一处，渠道自身一律不重复实现过滤逻辑。
//
// 渠道差异收敛到两个点：构造时注入的 send 闭包（怎么把一条告警发出去）
// 与可选的 checkResp（部分 IM 平台用 HTTP 200 表示业务失败，如签名/
// 关键词不匹配）。构造函数统一返回 *imChannel：方法集挂在骨架上，
// 从而与 Notifier 一样"未启用返回 nil，nil 接收者调用安全，调用方无需判空"。

package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"zedr/internal/platform/redact"
	"zedr/internal/server/domain"
)

const (
	// imQueueSize 与 webhook/syslog 队列同容量：IM 推送同样是尽力而为的
	// 旁路，队列满宁可丢通知也不阻塞告警入库主链路。
	imQueueSize = 256

	// imSendTimeout 是 IM 渠道单次 HTTP 发送超时（1s 级）。
	// IM 机器人 API 正常延迟在几百毫秒内，3s 已覆盖 TLS 握手 + 一次往返；
	// 卡片晚到或没到不影响告警本身已落库，不值得为慢渠道长期占用 worker。
	imSendTimeout = 3 * time.Second

	// imDedupWindow 是同一指纹的静默窗口：窗口内的重复命中只发首张卡片，
	// 其余静默丢弃。爆发事件里同一条告警会反复命中（探针轮询口径），
	// 对值班手机是纯噪音——首张已足够引起注意。
	imDedupWindow = 5 * time.Minute

	// imRateWindow / imRateMax 是小时上限：固定 60 分钟窗口内最多 30 张。
	// critical 突发（如跨主机爆发）如果不设上限就是卡片轰炸，
	// 会把真正要看的头几张淹没在通知栏里。
	imRateWindow = time.Hour
	imRateMax    = 30
)

// Channel 是告警通知渠道的统一接收端，app.go 的订阅循环面向它分发。
type Channel interface {
	Ingest(domain.Alert)
	Stats() (sent, failed, dropped int64)
	Close()
}

// 编译期断言：既有渠道零改动即可被统一消费，新渠道遵循同一契约。
var (
	_ Channel = (*Notifier)(nil)
	_ Channel = (*SyslogNotifier)(nil)
	_ Channel = (*imChannel)(nil)
)

// imChannel 是飞书/钉钉/Slack/邮件四个新渠道的公共骨架：
// 队列 + 单 worker + 计数 + 两级防风暴，语义与 Notifier 完全一致。
// 防风暴实现在共享的 dispatch（见 loop），四个渠道零重复代码；
// 它是纯通知侧行为，线协议零变化，也不影响告警主链路。
type imChannel struct {
	client    *http.Client
	send      func(a domain.Alert)
	sendText  func(text string) error // 限流摘要卡（纯文本）发送；nil = 渠道不支持
	checkResp func(body []byte) error // nil = 只看 HTTP 状态码
	log       *slog.Logger

	queue chan domain.Alert
	abort chan struct{}

	sent    atomic.Int64
	failed  atomic.Int64
	dropped atomic.Int64
	stopped atomic.Bool

	// ---- 防风暴状态（指纹去重 + 小时上限，见 admit）----
	// 正常只有 worker goroutine 读写；暴露 stormMu 是为了让测试能白盒
	// 拨动窗口时间（模拟"窗口过期"），而非表示有第二个写者。
	stormMu       sync.Mutex
	dedup         map[string]time.Time // fingerprint → 最近一次实际发送时刻
	winStart      time.Time            // 当前限流窗口起点（零值 = 尚未开窗）
	winSent       int                  // 窗口内已发送张数
	winSuppressed int                  // 窗口内因超上限被抑制的张数（摘要口径）
	digestSent    bool                 // 本窗口摘要卡是否已发（每窗口至多一张）
}

// newIMChannel 只构建骨架，不启动 worker——send 闭包需要引用骨架自身
// （渠道构造函数里赋值），必须先建后启，否则队列非空时有竞态。
func newIMChannel(log *slog.Logger) *imChannel {
	return &imChannel{
		client: &http.Client{Timeout: imSendTimeout},
		log:    log,
		queue:  make(chan domain.Alert, imQueueSize),
		abort:  make(chan struct{}),
		dedup:  make(map[string]time.Time),
	}
}

// start 启动 worker（构造函数完成 send 注入后调用）。
func (c *imChannel) start() { go c.loop() }

// Ingest 非阻塞入队；nil 接收保护与 Notifier 一致，调用方无需判空。
func (c *imChannel) Ingest(a domain.Alert) {
	if c == nil || c.stopped.Load() {
		return
	}
	select {
	case c.queue <- a:
	default:
		c.dropped.Add(1)
	}
}

// Stats 返回 (已发送, 失败, 丢弃)。
func (c *imChannel) Stats() (sent, failed, dropped int64) {
	if c == nil {
		return 0, 0, 0
	}
	return c.sent.Load(), c.failed.Load(), c.dropped.Load()
}

// Close 停止 worker；未发出的通知直接放弃（与 Notifier 同语义：
// 告警本身已落库，停机场景下尽力清空反而拖慢关闭）。
func (c *imChannel) Close() {
	if c == nil {
		return
	}
	c.stopped.Store(true)
	close(c.abort)
}

func (c *imChannel) loop() {
	for {
		select {
		case <-c.abort:
			return
		case a := <-c.queue:
			c.dispatch(a)
		}
	}
}

// dispatch 消费单条告警：先过两级防风暴闸门（同指纹静默 → 小时上限），
// 放行才真正发送。闸门在共享骨架这一层做，飞书/钉钉/Slack/邮件四个渠道
// 自动全部生效（email 也是 imChannel，send 前同样过滤）。
func (c *imChannel) dispatch(a domain.Alert) {
	drop, wantDigest := c.admit(a, time.Now())
	if wantDigest {
		c.deliverDigest()
	}
	if drop {
		return
	}
	c.send(a)
}

// admit 防风暴闸门判定。返回 (drop, wantDigest)：
// drop=true 表示抑制该告警（调用方不得发送）；wantDigest=true 表示本窗口
// 首次因超上限抑制，需要补发一张限流摘要卡。
//
// 摘要卡触发语义：每窗口至多一张，在该窗口第一条被上限压掉的告警处立即
// 发出——让值班在通知流"戛然而止"的第一时间就知道还有告警被压在管理台里，
// 而不是傻等一个小时后的整点汇总；窗口内后续超限只累计 dropped 计数，
// 不再重复打扰。摘要本身不计入窗口上限（digestSent 与 winSent 分离）。
func (c *imChannel) admit(a domain.Alert, now time.Time) (drop, wantDigest bool) {
	c.stormMu.Lock()
	defer c.stormMu.Unlock()

	// 惰性滚动固定窗口：距窗口起点已超过 60 分钟即进入新窗口。
	// 用固定窗口而非滑动窗口：值班能理解"每小时最多 30 条"，
	// 滑动窗口的边界不可预测，反而显得限流时灵时不灵。
	if !c.winStart.IsZero() && now.Sub(c.winStart) >= imRateWindow {
		c.winStart, c.winSent, c.winSuppressed, c.digestSent = time.Time{}, 0, 0, false
	}

	// 一级：同指纹 5 分钟静默。空指纹不参与去重（不同告警可能都缺指纹，
	// 按空串去重会把它们误当成同一条）。
	if fp := a.Fingerprint; fp != "" {
		if last, ok := c.dedup[fp]; ok && now.Sub(last) < imDedupWindow {
			c.dropped.Add(1)
			return true, false
		}
	}

	// 二级：小时上限。超限静默丢弃并计数（复用 Stats 的 dropped 语义）。
	if !c.winStart.IsZero() && c.winSent >= imRateMax {
		c.winSuppressed++
		c.dropped.Add(1)
		if !c.digestSent {
			c.digestSent = true
			return true, true
		}
		return true, false
	}

	// 放行：登记指纹与窗口计数。
	if c.winStart.IsZero() {
		c.winStart = now
	}
	c.winSent++
	if fp := a.Fingerprint; fp != "" {
		c.dedup[fp] = now
		c.pruneDedupLocked(now)
	}
	return false, false
}

// deliverDigest 发送限流摘要卡（text）。摘要是一次真实外发，成功失败
// 都照常计入 sent/failed，但不占窗口的告警张数上限。
func (c *imChannel) deliverDigest() {
	if c.sendText == nil {
		return
	}
	c.stormMu.Lock()
	n := c.winSuppressed
	c.stormMu.Unlock()
	if err := c.sendText(imRateDigestText(n)); err != nil {
		c.failed.Add(1)
		if c.log != nil {
			c.log.Warn("im_notify_failed", "kind", "rate_digest", "suppressed", n, "err", err)
		}
		return
	}
	c.sent.Add(1)
}

// imRateDigestText 渲染限流摘要卡文案（四渠道共用同一句话）。
func imRateDigestText(suppressed int) string {
	return fmt.Sprintf("过去一小时 %d 条告警被抑制未逐条推送（上限 %d），请打开管理台查看",
		suppressed, imRateMax)
}

// pruneDedupLocked 清掉指纹表里已过静默窗口的条目，防止长尾累积。
// 调用方必须持有 stormMu。
func (c *imChannel) pruneDedupLocked(now time.Time) {
	for fp, last := range c.dedup {
		if now.Sub(last) >= imDedupWindow {
			delete(c.dedup, fp)
		}
	}
}

// postJSON 把 payload POST 到 url 并判定成功：
// HTTP >= 300 失败；配置了 checkResp 时再校验平台业务码。
// 响应体只读 4KB——业务码都在头部，防止异常大响应占内存。
func (c *imChannel) postJSON(url string, payload any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), imSendTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode >= 300 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	if c.checkResp != nil {
		return c.checkResp(respBody)
	}
	return nil
}

// reportFail 是渠道发送的统一失败出口：计数 + warn（渠道名 + 原因/状态码）。
// 单渠道失败只记日志，绝不影响其他渠道——订阅循环对每个渠道独立 Ingest。
func (c *imChannel) reportFail(channel string, a domain.Alert, err error) {
	c.failed.Add(1)
	if c.log != nil {
		c.log.Warn("im_notify_failed", "channel", channel, "alert_id", a.ID, "err", err)
	}
}

// ---------------------------------------------------------------- 告警投影

// alertView 是卡片/邮件共用的告警字段投影。
//
// 脱敏在这里做而不信任上游：IM 消息会被转发、截图、进手机通知栏，
// 是最容易被"顺手外传"的出口，文本在离开服务端前统一再过一遍
// platform/redact（与探针上报出口同一套规则），纵深防御。
type alertView struct {
	title      string
	severity   string
	hostname   string
	process    string
	score      string
	mitre      string
	summary    string
	alertID    string
	occurredAt time.Time
}

func viewOf(a domain.Alert) alertView {
	return alertView{
		// 标题来自规则名/检测引擎，只需截断防异常超长
		title:    redact.Text(a.Title),
		severity: strings.ToUpper(string(a.Severity)),
		hostname: redact.Text(a.Hostname),
		process:  redact.Text(a.ProcessName),
		score:    strconv.Itoa(a.Score),
		mitre:    strings.Join(a.MITRE, ", "),
		// 摘要可能引用命令行片段，按命令行口径脱敏（password=/token= 等打码）
		summary:    redact.CmdLine(a.Summary),
		alertID:    a.ID,
		occurredAt: a.CreatedAt,
	}
}

// cardTitle 是各渠道共用的标题格式：「[Z-EDR][严重度] 标题」。
func cardTitle(v alertView) string {
	return "[Z-EDR][" + v.severity + "] " + v.title
}

// orDash 空值占位：显示"-"明确是"无"，而不是"漏渲染"。
func orDash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "-"
	}
	return s
}

// viewTime 是展示用时间（本地时区：值班在手机上看的是自己的钟）。
func (v alertView) viewTime() string {
	return v.occurredAt.Format("2006-01-02 15:04:05")
}

// ---------------------------------------------------------------- 飞书

// NewFeishu 创建飞书渠道（自定义机器人接收 interactive 卡片）。
// url 为空返回 nil（未启用）。
func NewFeishu(url, consoleURL string, log *slog.Logger) *imChannel {
	if url == "" {
		return nil
	}
	c := newIMChannel(log)
	c.checkResp = feishuRespOK
	c.send = func(a domain.Alert) {
		if err := c.postJSON(url, buildFeishuCard(a, consoleURL)); err != nil {
			c.reportFail("feishu", a, err)
			return
		}
		c.sent.Add(1)
	}
	// 限流摘要卡：text 类型即可（值班只需要知道"被压了多少条"）
	c.sendText = func(text string) error {
		return c.postJSON(url, map[string]any{
			"msg_type": "text",
			"content":  map[string]any{"text": text},
		})
	}
	c.start()
	return c
}

// feishuRespOK 校验飞书业务码：自定义机器人在签名/关键词不匹配等场景
// 会返回 HTTP 200 + code!=0，只看状态码会把失败当成功。
func feishuRespOK(body []byte) error {
	var r struct {
		Code *int64 `json:"code"`
		Msg  string `json:"msg"`
	}
	if err := json.Unmarshal(body, &r); err != nil {
		return nil // 非 JSON 响应不深究：HTTP 2xx 已代表传输成功
	}
	if r.Code != nil && *r.Code != 0 {
		return fmt.Errorf("code %d: %s", *r.Code, r.Msg)
	}
	return nil
}

// feishuTemplateColor 把严重度映射为飞书卡片头模板色。
// 飞书只接受固定枚举（blue/green/orange/red/grey/...），不接受任意色值；
// critical 与 high 同为红：对值班手机而言，这两档的处置动作是一样的。
func feishuTemplateColor(severity string) string {
	switch severity {
	case "critical", "high":
		return "red"
	case "medium":
		return "orange"
	default:
		return "grey"
	}
}

// buildFeishuCard 构造 interactive 卡片。
// 字段：主机/进程/得分/MITRE/摘要，文本全部来自 alertView（已脱敏）。
func buildFeishuCard(a domain.Alert, consoleURL string) map[string]any {
	v := viewOf(a)
	elements := []any{
		map[string]any{
			"tag": "div",
			"fields": []any{
				larkMDField("主机", v.hostname),
				larkMDField("进程", v.process),
				larkMDField("得分", v.score),
				larkMDField("MITRE", orDash(v.mitre)),
			},
		},
		map[string]any{
			"tag":  "div",
			"text": map[string]any{"tag": "lark_md", "content": "**摘要**\n" + orDash(v.summary)},
		},
		map[string]any{"tag": "hr"},
	}
	// "前往处理"链接：URL 只来自运营配置（HG_SERVER_CONSOLE_URL），不硬编码。
	// 未配置时不伪造地址——落"告警 ID"占位，运维凭 ID 在管理台告警页检索。
	if consoleURL != "" {
		elements = append(elements, map[string]any{
			"tag": "action",
			"actions": []any{
				map[string]any{
					"tag":  "button",
					"text": map[string]any{"tag": "plain_text", "content": "前往处理"},
					"type": "primary",
					"url":  consoleURL,
				},
			},
		})
	}
	elements = append(elements, map[string]any{
		"tag": "note",
		"elements": []any{
			map[string]any{"tag": "plain_text",
				"content": "Z-EDR • 告警 ID " + v.alertID + " • " + v.viewTime()},
		},
	})
	return map[string]any{
		"msg_type": "interactive",
		"card": map[string]any{
			"config": map[string]any{"wide_screen_mode": true},
			"header": map[string]any{
				"template": feishuTemplateColor(string(a.Severity)),
				"title":    map[string]any{"tag": "plain_text", "content": cardTitle(v)},
			},
			"elements": elements,
		},
	}
}

func larkMDField(name, value string) map[string]any {
	return map[string]any{
		"is_short": true,
		"text":     map[string]any{"tag": "lark_md", "content": "**" + name + "**\n" + value},
	}
}
