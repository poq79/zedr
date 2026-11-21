package notify

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// SendText 是每日简报等非告警内容的推送通道：IM 渠道走纯文本端点，
// webhook/syslog 没有该能力（类型断言探测跳过）——契约用编译期断言 +
// 运行期断言双锁，防止未来有人把 TextSender 并进 Channel 破坏可选语义。
func TestIMChannelSendText(t *testing.T) {
	ch := make(chan []byte, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		ch <- b
		fmt.Fprint(w, `{"code":0,"msg":"success"}`)
	}))
	defer srv.Close()

	f := NewFeishu(srv.URL, "", testLogger())
	defer f.Close()

	ts, ok := any(f).(TextSender)
	if !ok {
		t.Fatal("imChannel 应实现 TextSender")
	}
	if err := ts.SendText("【Z-EDR 值班简报】测试"); err != nil {
		t.Fatalf("SendText = %v，期望 nil", err)
	}
	select {
	case body := <-ch:
		if len(body) == 0 {
			t.Fatal("文本请求体为空")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("未收到文本推送请求")
	}
}

func TestWebhookIsNotTextSender(t *testing.T) {
	// webhook 渠道没有"发一段话"的语义：断言它不实现 TextSender，
	// 简报推送调用方的类型断言会正确跳过它。
	if _, ok := any(&Notifier{}).(TextSender); ok {
		t.Fatal("webhook Notifier 不应实现 TextSender")
	}
	if _, ok := any(&SyslogNotifier{}).(TextSender); ok {
		t.Fatal("syslog 不应实现 TextSender")
	}
	// nil 接收者安全：未启用渠道返回 nil，简报推送循环无需判空
	var f *imChannel
	if _, ok := any(f).(TextSender); !ok {
		t.Fatal("nil *imChannel 类型仍应实现 TextSender")
	}
	if err := f.SendText("x"); err == nil {
		t.Fatal("nil 接收者 SendText 应返回错误而非静默成功")
	}
}
