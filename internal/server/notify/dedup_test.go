package notify

// 防风暴（两级限流）测试：指纹去重、小时上限、摘要卡、窗口过期恢复。
// 全部走真实 httptest 端点计数，断言落在 HTTP 请求与 Stats 计数两侧——
// 防风暴是共享 dispatch 的行为，拿飞书渠道验证即代表四渠道同语义。

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"hostguard/internal/server/domain"
)

// stormServer 是按消息类型计数的假飞书端点：interactive 告警卡与
// text 摘要卡分别计数，并保留最近一张摘要的请求体供文案断言。
func stormServer(t *testing.T) (srv *httptest.Server, cards, digests *atomic.Int64, lastDigest func() string) {
	t.Helper()
	var c, d atomic.Int64
	var body atomic.Value // 最近一张摘要卡的请求体
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		if strings.Contains(string(b), `"msg_type":"text"`) {
			d.Add(1)
			body.Store(string(b))
		} else {
			c.Add(1)
		}
		fmt.Fprint(w, `{"code":0,"msg":"success"}`)
	}))
	t.Cleanup(srv.Close)
	return srv, &c, &d, func() string {
		s, _ := body.Load().(string)
		return s
	}
}

// differentAlerts 造 n 条指纹互不相同的告警（上限测试用：
// 指纹不同才不会触发一级去重，保证压卡只来自小时上限）。
func differentAlerts(n int) []domain.Alert {
	alerts := make([]domain.Alert, 0, n)
	for i := 0; i < n; i++ {
		a := secretAlert()
		a.ID = fmt.Sprintf("a-%03d", i)
		a.Fingerprint = fmt.Sprintf("fp-%03d", i)
		alerts = append(alerts, a)
	}
	return alerts
}

// TestIMChannelFingerprintDedup 一级防风暴：同一指纹 5 分钟内 5 条
// 只发首张，其余静默丢弃计入 dropped；静默窗口过期后同指纹恢复发送。
func TestIMChannelFingerprintDedup(t *testing.T) {
	srv, cards, _, _ := stormServer(t)
	f := NewFeishu(srv.URL, "", testLogger())
	defer f.Close()

	a := secretAlert()
	a.Fingerprint = "fp-burst"
	for i := 0; i < 5; i++ {
		f.Ingest(a)
	}
	waitFor(t, func() bool { return cards.Load() == 1 }, "同指纹 5 条应只发首张卡片")
	time.Sleep(150 * time.Millisecond) // 留出"多余发送"暴露的窗口
	if cards.Load() != 1 {
		t.Fatalf("静默窗口内不得重复发送，实际发出 %d 张", cards.Load())
	}
	if s, _, d := f.Stats(); s != 1 || d != 4 {
		t.Fatalf("Stats = sent %d / dropped %d，期望 1/4", s, d)
	}

	// 窗口过期：白盒把该指纹的最近发送时刻拨回 6 分钟前 → 恢复发送
	f.stormMu.Lock()
	f.dedup["fp-burst"] = time.Now().Add(-6 * time.Minute)
	f.stormMu.Unlock()
	f.Ingest(a)
	waitFor(t, func() bool { return cards.Load() == 2 }, "静默窗口过期后同指纹应恢复发送")
}

// TestIMChannelHourlyCapDigest 二级防风暴：31 条不同告警 →
// 30 张告警卡 + 1 张摘要卡；被上限压掉的计入 dropped，
// 摘要计入 sent 但不占上限，文案含固定话术。
func TestIMChannelHourlyCapDigest(t *testing.T) {
	srv, cards, digests, lastDigest := stormServer(t)
	f := NewFeishu(srv.URL, "", testLogger())
	defer f.Close()

	for _, a := range differentAlerts(31) {
		f.Ingest(a)
	}
	waitFor(t, func() bool { return cards.Load() == 30 && digests.Load() == 1 },
		"应发 30 张告警卡 + 1 张摘要卡")
	time.Sleep(150 * time.Millisecond)
	if cards.Load() != 30 || digests.Load() != 1 {
		t.Fatalf("计数漂移：cards=%d digests=%d，期望 30/1", cards.Load(), digests.Load())
	}
	// sent = 30 卡 + 1 摘要；dropped = 首条被压掉的告警
	if s, _, d := f.Stats(); s != 31 || d != 1 {
		t.Fatalf("Stats = sent %d / dropped %d，期望 31/1", s, d)
	}
	// 摘要文案契约：说明被压数量与上限，引导去管理台
	if got := lastDigest(); !strings.Contains(got, "被抑制未逐条推送") ||
		!strings.Contains(got, "上限 30") || !strings.Contains(got, "管理台") {
		t.Fatalf("摘要卡文案不符合契约: %s", got)
	}
}

// TestIMChannelWindowExpiryResumes 限流窗口过期后恢复正常发送，
// 且不重复发摘要（每窗口至多一张）。
func TestIMChannelWindowExpiryResumes(t *testing.T) {
	srv, cards, digests, _ := stormServer(t)
	f := NewFeishu(srv.URL, "", testLogger())
	defer f.Close()

	for _, a := range differentAlerts(31) {
		f.Ingest(a)
	}
	waitFor(t, func() bool { return cards.Load() == 30 }, "前置：窗口内 30 张卡发满")

	// 白盒把窗口起点拨回 61 分钟前，模拟"窗口过期"
	f.stormMu.Lock()
	f.winStart = time.Now().Add(-61 * time.Minute)
	f.stormMu.Unlock()

	a := secretAlert()
	a.ID = "a-post-window"
	a.Fingerprint = "fp-post-window"
	f.Ingest(a)
	waitFor(t, func() bool { return cards.Load() == 31 }, "限流窗口过期后新告警应正常发送")
	if digests.Load() != 1 {
		t.Fatalf("窗口滚动不应重复发摘要，实际 %d 张", digests.Load())
	}
}
