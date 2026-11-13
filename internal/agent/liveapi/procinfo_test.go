//go:build windows
// +build windows

package liveapi

// procinfo_test.go：/procinfo 与 netstat 富化（v2）。
// 假快照 + 假 Netstat + 假 Modules 断言富化/退出/内外网分类；
// 真机调用点（IsElevated/ProcessStartTime/VerifySignature）对假 PID/假
// 路径返回安全零值，不会放大成失败。

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"zedr/internal/agent/state"
	"zedr/internal/agent/winapi"
	"zedr/internal/model"
)

// unsignedProbePath 是 Modules 桩里的"未签名模块"探针路径：
// TestProcInfoFound 创建真实未签名文件后回填，供真机 VerifySignature 判定。
var unsignedProbePath string

func fakeDeps() Deps {
	return Deps{
		StartTime: time.Now(),
		Snapshot: func() []state.ProcRow {
			return []state.ProcRow{
				{
					PID: 100, PPID: 4, Name: "foo.exe", Path: `C:\tools\foo.exe`,
					CmdLine: `foo.exe --password=secret123 -token abc`, User: "alice",
					FirstSeen: time.Unix(1700000000, 0),
				},
			}
		},
		Netstat: func() []winapi.NetRow {
			return []winapi.NetRow{
				{Proto: "tcp", LocalIP: "0.0.0.0", LocalPort: 445,
					RemoteIP: "0.0.0.0", RemotePort: 0, State: "LISTEN", PID: 100},
				{Proto: "tcp", LocalIP: "10.1.1.2", LocalPort: 51000,
					RemoteIP: "1.2.3.4", RemotePort: 443, State: "ESTABLISHED", PID: 100},
				{Proto: "tcp", LocalIP: "127.0.0.1", LocalPort: 5000,
					RemoteIP: "127.0.0.1", RemotePort: 5001, State: "ESTABLISHED", PID: 999},
				{Proto: "tcp", LocalIP: "192.168.1.2", LocalPort: 51001,
					RemoteIP: "172.16.0.9", RemotePort: 80, State: "ESTABLISHED", PID: 999},
				{Proto: "udp", LocalIP: "0.0.0.0", LocalPort: 5353,
					RemoteIP: "0.0.0.0", RemotePort: 0, PID: 999},
				{Proto: "tcp", LocalIP: "0.0.0.0", LocalPort: 1,
					RemoteIP: "224.0.0.1", RemotePort: 1, State: "ESTABLISHED", PID: 100},
				{Proto: "tcp", LocalIP: "0.0.0.0", LocalPort: 2,
					RemoteIP: "240.0.0.9", RemotePort: 1, State: "ESTABLISHED", PID: 100},
			}
		},
		Modules: func(pid uint32) []model.ModuleInfo {
			if pid != 100 {
				return nil
			}
			// unsigned 计数的真机依赖：implant.exe 在测试内创建后注入路径
			//（不存在的路径 VerifySignature 返 error_* 状态，按设计不计入
			// unsigned——"未知 ≠ 未签名"）
			return []model.ModuleInfo{
				{Name: "kernel32.dll", Path: `C:\Windows\System32\kernel32.dll`},
				{Name: "implant.exe", Path: unsignedProbePath},
			}
		},
	}
}

func TestProcInfoFound(t *testing.T) {
	// Path 换成真实文件（临时文件，unsigned 是它的真实签名状态）
	dir := t.TempDir()
	realFile := filepath.Join(dir, "implant.exe")
	if err := os.WriteFile(realFile, []byte("MZfake"), 0o644); err != nil {
		t.Fatal(err)
	}
	unsignedProbePath = realFile
	defer func() { unsignedProbePath = "" }()
	d := fakeDeps()
	d.Snapshot = func() []state.ProcRow {
		return []state.ProcRow{{PID: 100, Name: "foo.exe", Path: realFile,
			CmdLine: `foo.exe --password=secret123`, User: "alice"}}
	}
	h := New(d)
	code, body := doGet(t, h, "/procinfo?pid=100")
	if code != http.StatusOK {
		t.Fatalf("期望 200 实得 %d body=%v", code, body)
	}
	out := dataOf(t, body)
	if out["exists"] != true || out["name"] != "foo.exe" {
		t.Fatalf("基本信息不符: %v", out)
	}
	// 命令行脱敏：值被 *** 替换
	cmd, _ := out["cmdline"].(string)
	if cmd == "" || contains(cmd, "secret123") {
		t.Errorf("cmdline 未脱敏: %q", cmd)
	}
	// connections 只含本 PID 的行
	conns, _ := json.Marshal(out["connections"])
	var items []struct {
		PID         uint32 `json:"pid"`
		RemoteIP    string `json:"remote_ip"`
		RemoteClass string `json:"remote_class"`
		Exited      bool   `json:"exited"`
	}
	if err := json.Unmarshal(conns, &items); err != nil {
		t.Fatalf("connections 结构不符: %v raw=%s", err, conns)
	}
	if len(items) != 4 {
		t.Fatalf("本 PID 连接期望 4 条实得 %d: %s", len(items), conns)
	}
	for _, c := range items {
		if c.PID != 100 {
			t.Errorf("混入他进程连接: %+v", c)
		}
	}
	// modules：真机 VerifySignature——真实临时文件 unsigned，系统文件 valid/证书库
	modsRaw, _ := json.Marshal(out["modules"])
	var mods []map[string]string
	if err := json.Unmarshal(modsRaw, &mods); err != nil {
		t.Fatalf("modules 结构不符: %v", err)
	}
	if len(mods) != 2 {
		t.Fatalf("modules 期望 2 个: %s", modsRaw)
	}
	uc, _ := out["unsigned_module_count"].(float64)
	if uc < 1 { // notreal.dll 必然 unsigned
		t.Errorf("unsigned_module_count 应 ≥1: %v (%v)", out["unsigned_module_count"], out)
	}
	if out["modules_truncated"] != false {
		t.Errorf("未超上限不应截断: %v", out["modules_truncated"])
	}
	// exec_info：存在 + 签名状态键存在
	exec, ok := out["exec_info"].(map[string]any)
	if !ok || exec["exists"] != true || exec["signed_state"] == "" {
		t.Fatalf("exec_info 不符: %v", out["exec_info"])
	}
	_ = uc
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func TestProcInfoNotFoundAndValidation(t *testing.T) {
	h := New(fakeDeps())
	// 不存在 → 200 exists:false
	code, body := doGet(t, h, "/procinfo?pid=888")
	if code != http.StatusOK {
		t.Fatalf("期望 200 实得 %d", code)
	}
	if d := dataOf(t, body); d["exists"] != false {
		t.Fatalf("exists 期望 false: %v", d)
	}
	// 非法/缺失 pid → 400
	for _, q := range []string{"", "?pid=0", "?pid=abc", "?pid=-1"} {
		if code, _ := doGet(t, h, "/procinfo"+q); code != http.StatusBadRequest {
			t.Fatalf("pid=%q 期望 400 实得 %d", q, code)
		}
	}
}

func TestProcInfoModulesTruncated(t *testing.T) {
	d := fakeDeps()
	d.Modules = func(pid uint32) []model.ModuleInfo {
		mods := make([]model.ModuleInfo, procModulesMax+10)
		for i := range mods {
			mods[i] = model.ModuleInfo{Name: "m.dll", Path: `C:\x\m.dll`}
		}
		return mods
	}
	h := New(d)
	_, body := doGet(t, h, "/procinfo?pid=100")
	out := dataOf(t, body)
	if out["modules_truncated"] != true {
		t.Fatalf("超上限应标注截断: %v", out)
	}
	if mods, ok := out["modules"].([]any); !ok || len(mods) != procModulesMax {
		t.Fatalf("模块应截到 %d 实得 %v", procModulesMax, out["modules"])
	}
}

func TestProcInfoModulesNilOmitted(t *testing.T) {
	d := fakeDeps()
	d.Modules = nil
	h := New(d)
	_, body := doGet(t, h, "/procinfo?pid=100")
	out := dataOf(t, body)
	// Modules 未接线：modules 块省略，端点其余功能照常（200）
	if _, ok := out["modules"]; ok {
		t.Fatalf("Modules==nil 时 modules 应省略: %v", out)
	}
	if out["connections"] == nil {
		t.Fatalf("connections 不应受影响")
	}
}

// TestProcInfoExitedEnrichment 交叉验证 netstat 富化的 exited/remote_class
// （同一 enrichNetRows 同时服务 /netstat 与 /procinfo）。
func TestProcInfoExitedEnrichment(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("仅 Windows（remote_class 之外的行不涉及，但保持环境一致）")
	}
	h := New(fakeDeps())
	_, body := doGet(t, h, "/procinfo?pid=100")
	out := dataOf(t, body)
	conns, _ := json.Marshal(out["connections"])
	var items []struct {
		RemoteIP    string `json:"remote_ip"`
		RemoteClass string `json:"remote_class"`
		Exited      bool   `json:"exited"`
		ProcUser    string `json:"proc_user"`
	}
	if err := json.Unmarshal(conns, &items); err != nil {
		t.Fatal(err)
	}
	for _, c := range items {
		if c.Exited {
			t.Errorf("快照内 PID 不应标退出: %+v", c)
		}
		if c.ProcUser != "alice" {
			t.Errorf("proc_user 应来自快照: %+v", c)
		}
	}
}

func TestNetstatV2Enrichment(t *testing.T) {
	h := New(fakeDeps())
	code, body := doGet(t, h, "/netstat")
	if code != http.StatusOK {
		t.Fatalf("期望 200 实得 %d", code)
	}
	raw, _ := json.Marshal(dataOf(t, body)["items"])
	var items []struct {
		PID          uint32 `json:"pid"`
		RemoteIP     string `json:"remote_ip"`
		RemoteClass  string `json:"remote_class"`
		ProcName     string `json:"proc_name"`
		ProcUser     string `json:"proc_user"`
		ProcCmdline  string `json:"proc_cmdline"`
		Exited       bool   `json:"exited"`
		ProcElevated bool   `json:"proc_elevated"`
	}
	if err := json.Unmarshal(raw, &items); err != nil {
		t.Fatalf("items 结构不符: %v", err)
	}
	if len(items) != 7 {
		t.Fatalf("期望 7 行实得 %d: %s", len(items), raw)
	}
	// remote_class 分类表（契约 §11.2）
	wantClass := map[string]string{
		"0.0.0.0":    "reserved", // UDP 端点远端恒 0.0.0.0
		"1.2.3.4":    "public",
		"127.0.0.1":  "loopback",
		"172.16.0.9": "private",
		"224.0.0.1":  "multicast",
		"240.0.0.9":  "reserved",
	}
	for _, it := range items {
		want, ok := wantClass[it.RemoteIP]
		if !ok {
			t.Fatalf("意外远端 %s", it.RemoteIP)
		}
		if it.RemoteClass != want {
			t.Errorf("remote_ip=%s remote_class 期望 %s 实得 %s", it.RemoteIP, want, it.RemoteClass)
		}
	}
	// 行 0（PID 100）：快照内 → 有用户与脱敏 cmdline，未退出
	if items[0].Exited || items[0].ProcName != "foo.exe" || items[0].ProcUser != "alice" {
		t.Errorf("快照内行富化不符: %+v", items[0])
	}
	if contains(items[0].ProcCmdline, "secret123") || items[0].ProcCmdline == "" {
		t.Errorf("proc_cmdline 应脱敏且非空: %q", items[0].ProcCmdline)
	}
	// 行 2（PID 999）：不在快照 → exited + "(已退出)"（单快照无法回溯历史名）
	if !items[2].Exited || items[2].ProcName != "(已退出)" {
		t.Errorf("快照外行应标退出: %+v", items[2])
	}
}

func TestClassifyRemote(t *testing.T) {
	cases := []struct{ ip, want string }{
		{"127.0.0.1", "loopback"},
		{"::1", "loopback"},
		{"10.0.0.1", "private"},
		{"172.16.5.5", "private"},
		{"192.168.0.1", "private"},
		{"169.254.1.1", "private"}, // 链路本地并入 private（契约口径）
		{"fe80::1", "private"},
		{"1.2.3.4", "public"},
		{"224.0.0.1", "multicast"},
		{"ff02::1", "multicast"},
		{"0.0.0.0", "reserved"},
		{"::", "reserved"},
		{"240.0.0.1", "reserved"},
		{"255.255.255.255", "reserved"},
		{"not-an-ip", ""},
	}
	for _, tc := range cases {
		if got := classifyRemote(tc.ip); got != tc.want {
			t.Errorf("classifyRemote(%q) = %q, want %q", tc.ip, got, tc.want)
		}
	}
}
