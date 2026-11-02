package liveapi

// peers_test.go：/peers 的聚合口径（桩连接表）+ 真机结构冒烟。

import (
	"fmt"
	"net/http"
	"runtime"
	"testing"
	"time"

	"zedr/internal/agent/state"
	"zedr/internal/agent/winapi"
)

func estRow(ip string, port uint16, pid uint32) winapi.NetRow {
	return winapi.NetRow{
		Proto: "tcp", RemoteIP: ip, RemotePort: port,
		State: "ESTABLISHED", PID: pid,
	}
}

func TestBuildPeersAggregation(t *testing.T) {
	rows := []winapi.NetRow{
		estRow("93.184.216.34", 443, 100),
		estRow("93.184.216.34", 443, 100),
		estRow("93.184.216.34", 80, 200),
		estRow("10.0.0.5", 445, 300),
		estRow("127.0.0.1", 8080, 300),
		// 非 ESTABLISHED 必须排除
		{Proto: "tcp", RemoteIP: "8.8.8.8", RemotePort: 53, State: "LISTEN", PID: 100},
	}
	snap := []state.ProcRow{
		{PID: 100, Name: "chrome.exe"},
		{PID: 200, Name: "chrome.exe"},
		{PID: 300, Path: `C:\Windows\System32\worker.exe`}, // Name 缺失时退回路径基名
	}

	res := buildPeersResult(rows, snap, time.Date(2026, 11, 2, 10, 0, 0, 0, time.UTC))
	if res.Truncated {
		t.Error("桩数据未超上限，truncated 应为 false")
	}
	if res.GeneratedAt != "2026-11-02T10:00:00Z" {
		t.Errorf("generated_at = %q", res.GeneratedAt)
	}
	if res.Counts.Established != 5 {
		t.Errorf("counts.established = %d，期望 5（LISTEN 不计）", res.Counts.Established)
	}
	if res.Counts.Public != 1 || res.Counts.Private != 1 {
		t.Errorf("counts public/private = %d/%d，期望 1/1（loopback 不计）",
			res.Counts.Public, res.Counts.Private)
	}
	if len(res.Peers) != 3 {
		t.Fatalf("peers 数 = %d，期望 3（按 IP 聚合）", len(res.Peers))
	}

	// 排序：连接数降序，93.184.216.34（3 条）在前
	top := res.Peers[0]
	if top.IP != "93.184.216.34" || top.Class != "public" || top.Conns != 3 {
		t.Fatalf("peers[0] 不符: %+v", top)
	}
	if len(top.Ports) != 2 || top.Ports[0].Port != 443 || top.Ports[0].Conns != 2 ||
		top.Ports[1].Port != 80 || top.Ports[1].Conns != 1 {
		t.Errorf("端口聚合/排序不符: %+v", top.Ports)
	}
	// 同一 PID 的两条连接只出现一次；按连接数降序
	if len(top.Procs) != 2 || top.Procs[0] != "chrome.exe(100)" || top.Procs[1] != "chrome.exe(200)" {
		t.Errorf("procs 去重/排序不符: %+v", top.Procs)
	}

	// 进程视图：pid 300 跟 2 个对端说话，排第一；名字来自路径基名
	if len(res.ByProcess) != 3 {
		t.Fatalf("by_process 数 = %d，期望 3", len(res.ByProcess))
	}
	if p := res.ByProcess[0]; p.PID != 300 || p.Name != "worker.exe" ||
		p.Conns != 2 || p.PeerCount != 2 {
		t.Errorf("by_process[0] 不符: %+v", p)
	}
	if p := res.ByProcess[1]; p.PID != 100 || p.Name != "chrome.exe" || p.Conns != 2 || p.PeerCount != 1 {
		t.Errorf("by_process[1] 不符: %+v", p)
	}
}

func TestBuildPeersClasses(t *testing.T) {
	rows := []winapi.NetRow{
		estRow("127.0.0.1", 1, 1),
		estRow("10.1.2.3", 2, 1),
		estRow("8.8.8.8", 3, 1),
		estRow("224.0.0.1", 4, 1),
		estRow("0.0.0.0", 5, 1),
		estRow("fe80::1", 6, 1),
		estRow("2606:4700:4700::1111", 7, 1),
	}
	res := buildPeersResult(rows, nil, time.Now())
	want := map[string]string{
		"127.0.0.1":            "loopback",
		"10.1.2.3":             "private",
		"8.8.8.8":              "public",
		"224.0.0.1":            "multicast",
		"0.0.0.0":              "reserved",
		"fe80::1":              "private",
		"2606:4700:4700::1111": "public",
	}
	for _, p := range res.Peers {
		if want[p.IP] != p.Class {
			t.Errorf("%s class = %q，期望 %q", p.IP, p.Class, want[p.IP])
		}
	}
	if res.Counts.Public != 2 || res.Counts.Private != 2 {
		t.Errorf("counts public/private = %d/%d，期望 2/2", res.Counts.Public, res.Counts.Private)
	}
	// 快照缺失时进程名必须显式标注，而不是留空
	if len(res.ByProcess) != 1 || res.ByProcess[0].Name != "(已退出)" {
		t.Errorf("快照缺失时 by_process 名不符: %+v", res.ByProcess)
	}
}

func TestBuildPeersTruncation(t *testing.T) {
	rows := make([]winapi.NetRow, 0, peersMax+5)
	for i := 0; i < peersMax+5; i++ {
		// 每个对端一个独立 PID：peers 与 by_process 同时超过上限
		rows = append(rows, estRow(fmt.Sprintf("203.0.113.%d", i+1), uint16(1000+i), uint32(i+1)))
	}
	res := buildPeersResult(rows, nil, time.Now())
	if !res.Truncated {
		t.Fatal("超过 peers/by_process 上限应置 truncated=true")
	}
	if len(res.Peers) != peersMax {
		t.Errorf("peers 长度 = %d，期望 %d", len(res.Peers), peersMax)
	}
	if len(res.ByProcess) != peersByProcessMax {
		t.Errorf("by_process 长度 = %d，期望 %d", len(res.ByProcess), peersByProcessMax)
	}
	// counts 是完整快照口径，不受数组截断影响
	if res.Counts.Established != peersMax+5 || res.Counts.Public != peersMax+5 {
		t.Errorf("counts 应反映完整快照: %+v", res.Counts)
	}

	// 边界：正好等于 peers 上限不应置 truncated。
	// 全部连接归同一个 PID，保证 by_process 不触发 50 条上限。
	boundary := make([]winapi.NetRow, 0, peersMax)
	for i := 0; i < peersMax; i++ {
		boundary = append(boundary, estRow(fmt.Sprintf("198.51.100.%d", i+1), 443, 1))
	}
	res = buildPeersResult(boundary, nil, time.Now())
	if res.Truncated {
		t.Error("正好等于上限不应截断")
	}
	if len(res.Peers) != peersMax {
		t.Errorf("边界 peers 长度 = %d", len(res.Peers))
	}
}

func TestPeersNotWired(t *testing.T) {
	h := New(Deps{StartTime: time.Now()})
	if code, _ := doGet(t, h, "/peers"); code != http.StatusNotImplemented {
		t.Fatalf("Netstat==nil 期望 501 实得 %d", code)
	}
}

// TestPeersRealMachine 真机结构冒烟：ESTABLISHED 可能为空（安静机器），
// 因此只断言结构与类型完整，不要求非空。
func TestPeersRealMachine(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("仅 Windows")
	}
	h := New(Deps{
		StartTime: time.Now(),
		Netstat: func() []winapi.NetRow {
			rows, err := winapi.GetNetstat()
			if err != nil {
				t.Logf("GetNetstat 失败: %v", err)
				return nil
			}
			return rows
		},
		Snapshot: func() []state.ProcRow { return nil },
	})
	code, body := doGet(t, h, "/peers")
	if code != http.StatusOK {
		t.Fatalf("期望 200 实得 %d body=%v", code, body)
	}
	d := dataOf(t, body)
	if _, err := time.Parse(time.RFC3339, d["generated_at"].(string)); err != nil {
		t.Errorf("generated_at 不是 RFC3339: %v", d["generated_at"])
	}
	if _, ok := d["truncated"].(bool); !ok {
		t.Errorf("truncated 不是布尔: %T", d["truncated"])
	}
	counts, ok := d["counts"].(map[string]any)
	if !ok {
		t.Fatalf("counts 不是对象: %T", d["counts"])
	}
	for _, k := range []string{"established", "public", "private"} {
		if _, ok := counts[k].(float64); !ok {
			t.Errorf("counts.%s 不是数字: %T", k, counts[k])
		}
	}
	peers, ok := d["peers"].([]any)
	if !ok {
		t.Fatalf("peers 不是数组: %T", d["peers"])
	}
	allowedClass := map[string]bool{
		"loopback": true, "private": true, "public": true,
		"multicast": true, "reserved": true, "": true,
	}
	for i, raw := range peers {
		p, ok := raw.(map[string]any)
		if !ok {
			t.Fatalf("peers[%d] 不是对象", i)
		}
		if ip, _ := p["ip"].(string); ip == "" {
			t.Errorf("peers[%d].ip 为空", i)
		}
		if class, _ := p["class"].(string); !allowedClass[class] {
			t.Errorf("peers[%d].class 非法: %q", i, class)
		}
		if _, ok := p["ports"].([]any); !ok {
			t.Errorf("peers[%d].ports 不是数组", i)
		}
		if _, ok := p["procs"].([]any); !ok {
			t.Errorf("peers[%d].procs 不是数组", i)
		}
	}
	procs, ok := d["by_process"].([]any)
	if !ok {
		t.Fatalf("by_process 不是数组: %T", d["by_process"])
	}
	for i, raw := range procs {
		p, ok := raw.(map[string]any)
		if !ok {
			t.Fatalf("by_process[%d] 不是对象", i)
		}
		for _, k := range []string{"pid", "conns", "peer_count"} {
			if _, ok := p[k].(float64); !ok {
				t.Errorf("by_process[%d].%s 不是数字: %T", i, k, p[k])
			}
		}
	}
	t.Logf("真机 peers: 已建立连接 %v，对端 %d，进程 %d",
		counts["established"], len(peers), len(procs))
}
