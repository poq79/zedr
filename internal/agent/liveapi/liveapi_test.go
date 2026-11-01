package liveapi

// liveapi_test.go：/ping、/processes、/netstat 与真实 winapi 冒烟。
// fs* 端点测试见 fs_test.go。全部用 httptest 直打 New() handler。

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"runtime"
	"testing"
	"time"

	"zedr/internal/agent/state"
	"zedr/internal/agent/winapi"
)

// doGet 发请求并解析 JSON 响应体（含 httpx 的 {data}/{error} 包装）。
func doGet(t *testing.T, h http.Handler, target string) (int, map[string]any) {
	t.Helper()
	rec := doRaw(t, h, target)
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("响应不是 JSON: %v body=%s", err, rec.Body.String())
	}
	return rec.Code, body
}

// doRaw 发请求返回原始 recorder（fs/read 的字节流场景用）。
func doRaw(t *testing.T, h http.Handler, target string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, target, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// dataOf 取出 {data:} 包装内的载荷。
func dataOf(t *testing.T, body map[string]any) map[string]any {
	t.Helper()
	d, ok := body["data"].(map[string]any)
	if !ok {
		t.Fatalf("缺少 data 包装: %v", body)
	}
	return d
}

// errMsg 取出错误消息，用于断言 400 文案。
func errMsg(t *testing.T, body map[string]any) string {
	t.Helper()
	e, ok := body["error"].(map[string]any)
	if !ok {
		t.Fatalf("缺少 error 包装: %v", body)
	}
	m, _ := e["message"].(string)
	return m
}

func TestPing(t *testing.T) {
	h := New(Deps{
		Version:   "9.9.9",
		Hostname:  "box1",
		StartTime: time.Now().Add(-90 * time.Second),
	})
	code, body := doGet(t, h, "/ping")
	if code != http.StatusOK {
		t.Fatalf("期望 200 实得 %d body=%v", code, body)
	}
	d := dataOf(t, body)
	if d["ok"] != true {
		t.Errorf("ok 期望 true 实得 %v", d["ok"])
	}
	if d["version"] != "9.9.9" || d["hostname"] != "box1" {
		t.Errorf("version/hostname 不符: %v %v", d["version"], d["hostname"])
	}
	up, ok := d["uptime_sec"].(float64)
	if !ok || up < 89 || up > 120 {
		t.Errorf("uptime_sec 不在预期区间: %v", d["uptime_sec"])
	}
}

func TestProcesses(t *testing.T) {
	// Procs 未接线 → 501（与 404 区分：能力存在但未启用）
	h := New(Deps{StartTime: time.Now()})
	if code, _ := doGet(t, h, "/processes"); code != http.StatusNotImplemented {
		t.Fatalf("Procs==nil 期望 501 实得 %d", code)
	}

	gotLimit := -1
	h = New(Deps{
		StartTime: time.Now(),
		Procs: func(limit int) []state.ProcRow {
			gotLimit = limit
			return []state.ProcRow{{PID: 1, Name: "a.exe"}}
		},
	})
	code, body := doGet(t, h, "/processes?limit=99999")
	if code != http.StatusOK {
		t.Fatalf("期望 200 实得 %d", code)
	}
	if gotLimit != procMax {
		t.Fatalf("limit 钳制期望 %d 实得 %d", procMax, gotLimit)
	}
	items, ok := dataOf(t, body)["items"].([]any)
	if !ok || len(items) != 1 {
		t.Fatalf("items 结构不符: %v", body)
	}

	if _, body := doGet(t, h, "/processes"); gotLimit != procDefault {
		t.Fatalf("默认 limit 期望 %d 实得 %d body=%v", procDefault, gotLimit, body)
	}
}

func TestNetstatEnrichment(t *testing.T) {
	h := New(Deps{
		StartTime: time.Now(),
		Procs: func(limit int) []state.ProcRow {
			return []state.ProcRow{{PID: 100, Name: "foo.exe", Path: `C:\tools\foo.exe`}}
		},
		Netstat: func() []winapi.NetRow {
			return []winapi.NetRow{
				{Proto: "tcp", LocalIP: "127.0.0.1", LocalPort: 1234,
					RemoteIP: "1.2.3.4", RemotePort: 443, State: "ESTABLISHED", PID: 100},
				{Proto: "udp", LocalIP: "0.0.0.0", LocalPort: 5353,
					RemoteIP: "0.0.0.0", RemotePort: 0, PID: 999},
			}
		},
	})
	code, body := doGet(t, h, "/netstat")
	if code != http.StatusOK {
		t.Fatalf("期望 200 实得 %d", code)
	}
	raw, err := json.Marshal(dataOf(t, body)["items"])
	if err != nil {
		t.Fatal(err)
	}
	var items []struct {
		Proto      string `json:"proto"`
		LocalIP    string `json:"local_ip"`
		LocalPort  uint16 `json:"local_port"`
		RemoteIP   string `json:"remote_ip"`
		RemotePort uint16 `json:"remote_port"`
		State      string `json:"state"`
		PID        uint32 `json:"pid"`
		ProcName   string `json:"proc_name"`
		ProcPath   string `json:"proc_path"`
	}
	if err := json.Unmarshal(raw, &items); err != nil {
		t.Fatalf("items 反序列化失败: %v raw=%s", err, raw)
	}
	if len(items) != 2 {
		t.Fatalf("期望 2 行实得 %d", len(items))
	}
	// 行 1：pid 100 可富化
	if items[0].ProcName != "foo.exe" || items[0].ProcPath != `C:\tools\foo.exe` {
		t.Errorf("富化失败: %+v", items[0])
	}
	if items[0].Proto != "tcp" || items[0].LocalPort != 1234 ||
		items[0].RemoteIP != "1.2.3.4" || items[0].State != "ESTABLISHED" {
		t.Errorf("五元组不符: %+v", items[0])
	}
	// 行 2：pid 999 查不到 → 留空，不猜
	if items[1].ProcName != "" || items[1].ProcPath != "" {
		t.Errorf("查不到的 PID 应留空: %+v", items[1])
	}
}

func TestNetstatNotImplementedAndClamp(t *testing.T) {
	// Netstat 未接线 → 501
	h := New(Deps{StartTime: time.Now()})
	if code, _ := doGet(t, h, "/netstat"); code != http.StatusNotImplemented {
		t.Fatalf("Netstat==nil 期望 501 实得 %d", code)
	}

	// 超 2000 行钳制；Procs==nil 时仍可用（富化字段留空）
	h = New(Deps{
		StartTime: time.Now(),
		Netstat: func() []winapi.NetRow {
			rows := make([]winapi.NetRow, procMax+100)
			for i := range rows {
				rows[i] = winapi.NetRow{Proto: "tcp", PID: uint32(i)}
			}
			return rows
		},
	})
	code, body := doGet(t, h, "/netstat")
	if code != http.StatusOK {
		t.Fatalf("期望 200 实得 %d", code)
	}
	items := dataOf(t, body)["items"].([]any)
	if len(items) != procMax {
		t.Fatalf("钳制后期望 %d 行实得 %d", procMax, len(items))
	}
}

// TestGetNetstatRealSmoke 用真实 OS 连接表冒烟，验证 netstat.go 的
// 内存布局解析在本机成立（liveapi 侧唯一触达真实 sysctl 的用例）。
func TestGetNetstatRealSmoke(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("仅 Windows")
	}
	rows, err := winapi.GetNetstat()
	if err != nil {
		t.Fatalf("GetNetstat 失败: %v", err)
	}
	if len(rows) == 0 {
		t.Fatal("连接表为空，任何在网机器至少应有监听端点")
	}
	for _, r := range rows {
		if r.Proto == "" || r.LocalIP == "" {
			t.Fatalf("行字段缺失: %+v", r)
		}
		if r.Proto == "udp" && (r.RemoteIP != "0.0.0.0" || r.RemotePort != 0) {
			t.Fatalf("udp 远端应恒为 0.0.0.0:0: %+v", r)
		}
	}
	t.Logf("netstat rows=%d", len(rows))
}
