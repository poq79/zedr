//go:build windows
// +build windows

package hygiene

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"zedr/internal/agent/winapi"
)

func TestExeFromCommand(t *testing.T) {
	// 用本机真实存在的文件构造用例，保证 isFile 的存在性检查可判定
	probe := filepath.Join(t.TempDir(), "probe.exe")
	if err := os.WriteFile(probe, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	lower := strings.ToLower(probe)

	// 内核写法归一化用例：借用真实的 C:\Windows 文件，只在 Windows 上有语义
	sys := os.Getenv("SystemRoot")
	if sys == "" {
		sys = `C:\Windows`
	}
	notepad := sys + `\System32\notepad.exe`
	if _, err := os.Stat(notepad); err != nil {
		t.Skipf("本机缺少 %s，跳过内核路径用例", notepad)
	}

	cases := []struct {
		in  string
		out string
	}{
		{"", ""},
		{`"C:\Program Files\App\a.exe" -flag x`, `C:\Program Files\App\a.exe`}, // 引号形态：定位到引号即止，不依赖存在性
		{probe + " -k netsvcs", probe},                                         // 无引号带参数
		{probe, probe},                                                         // 纯路径
		{probe + ` /v /d`, probe},                                              // 斜杠参数
		{`"C:\no closing quote\b.exe`, ""},                                     // 引号未闭合：无法定位，诚实返回空
		{lower, strings.ToLower(probe)},                                        // Windows 路径大小写不敏感，Stat 本身兼容
		{`\SystemRoot\System32\notepad.exe`, notepad},                          // 服务镜像路径内核写法
		{`System32\notepad.exe`, notepad},                                      // 相对 %SystemRoot%
		{`%windir%\System32\notepad.exe`, notepad},                             // 环境变量写法
		{`\??\` + notepad, notepad},                                            // NT 设备路径前缀
	}
	for _, c := range cases {
		if got := exeFromCommand(c.in); got != c.out {
			t.Errorf("exeFromCommand(%q) = %q, want %q", c.in, got, c.out)
		}
	}
}

func TestListenerScope(t *testing.T) {
	cases := map[string]string{
		"0.0.0.0":     "any",
		"::":          "any",
		"127.0.0.1":   "loopback",
		"::1":         "loopback",
		"192.168.1.5": "lan",
		"10.0.0.2":    "lan",
	}
	for ip, want := range cases {
		if got := listenerScope(ip); got != want {
			t.Errorf("listenerScope(%q) = %q, want %q", ip, got, want)
		}
	}
}

func TestReadHostsFile(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "hosts")
	content := "# comment\n127.0.0.1 localhost\n::1 localhost\n" +
		"10.9.8.7 intranet.corp\n0.0.0.0 ads.example.com # block tool\n\n" +
		"1.2.3.4   multi.host.example extra.host.example\n"
	if err := os.WriteFile(good, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	rep := readHostsFile(good)
	if !rep.Readable {
		t.Fatal("可读文件不应标记 unreadable")
	}
	// localhost x2 + intranet + ads + multi = 5 条非注释条目
	if len(rep.Entries) != 5 {
		t.Fatalf("应解析出 5 条非注释条目，got %d: %+v", len(rep.Entries), rep.Entries)
	}
	// 行内注释应剥离；多主机行只取第一条主机名（UI 展示主映射即可）
	if rep.Entries[3].Hostname != "ads.example.com" || rep.Entries[3].IP != "0.0.0.0" {
		t.Errorf("行内注释剥离错误: %+v", rep.Entries[3])
	}

	missing := readHostsFile(filepath.Join(dir, "nope"))
	if missing.Readable || missing.Note == "" {
		t.Error("不可读文件应 unreadable 且带说明")
	}
}

func TestAuditFlags(t *testing.T) {
	base := PersistAudit{Key: "k", Kind: "registry_run", Command: "x", InBaseline: true, Enabled: true}

	if f := auditFlags(base); len(f) != 0 {
		t.Errorf("无 exe 路径时不应有 flags, got %v", f)
	}

	withFile := base
	withFile.ExePath = `C:\x\a.exe`
	withFile.File = fileMeta{Exists: true, Signed: true, SigState: "valid", Signer: "Trusted Co"}
	if f := auditFlags(withFile); len(f) != 0 {
		t.Errorf("已入基线 + 可信签名文件不应有 flags, got %v", f)
	}

	// 签名缺失探查字段（sig_state 空）等价于未知：按未签名处理
	unprobed := base
	unprobed.ExePath = `C:\x\a.exe`
	unprobed.File = fileMeta{Exists: true}
	if f := auditFlags(unprobed); len(f) != 1 || f[0] != FlagUnsigned {
		t.Errorf("存在但无签名状态应标 unsigned, got %v", f)
	}

	missing := base
	missing.ExePath = `C:\x\a.exe`
	missing.File = fileMeta{Exists: false}
	if f := auditFlags(missing); len(f) != 1 || f[0] != FlagFileMissing {
		t.Errorf("文件缺失应标 file_missing, got %v", f)
	}

	// 有签名但摘要不符 = 被篡改，走 unsigned 位
	tampered := base
	tampered.ExePath = `C:\x\a.exe`
	tampered.File = fileMeta{Exists: true, Signed: true, SigState: "bad_digest"}
	if f := auditFlags(tampered); len(f) != 1 || f[0] != FlagUnsigned {
		t.Errorf("bad_digest 应标 unsigned, got %v", f)
	}

	unsigned := base
	unsigned.ExePath = `C:\x\a.exe`
	unsigned.File = fileMeta{Exists: true, Signed: false, SigState: "unsigned"}
	if f := auditFlags(unsigned); len(f) != 1 || f[0] != FlagUnsigned {
		t.Errorf("未签名应标 unsigned, got %v", f)
	}

	// MSIX 包存放区的文件不做裸 Authenticode，"无签名"是采集盲区不是风险
	msix := base
	msix.ExePath = `C:\Program Files\WindowsApps\Microsoft.WSL_1.1.3.0_x64__8wekyb3d8bbwe\wslservice.exe`
	msix.File = fileMeta{Exists: true, Signed: false, SigState: "unsigned", Company: "Microsoft Corporation"}
	if f := auditFlags(msix); len(f) != 1 || f[0] != FlagNoInfo {
		t.Errorf("WindowsApps 路径应降级为 no_info, got %v", f)
	}

	newItem := base
	newItem.InBaseline = false
	if f := auditFlags(newItem); len(f) != 1 || f[0] != FlagNew {
		t.Errorf("基线外应标 new, got %v", f)
	}

	elevated := base
	elevated.Elevated = true
	if f := auditFlags(elevated); len(f) != 1 || f[0] != FlagElevated {
		t.Errorf("最高权限应标 elevated, got %v", f)
	}
}

func TestItoa(t *testing.T) {
	for n, want := range map[int64]string{0: "0", 5: "5", -42: "-42", 17179869184: "17179869184"} {
		if got := itoa(n); got != want {
			t.Errorf("itoa(%d) = %q, want %q", n, got, want)
		}
	}
}

// TestAuditLive 是真机冒烟：枚举应至少拿到系统服务（spoolsv 类），
// 且基线外条目的 flags 里能看到 new。容忍空集（CI 环境极端裁剪），
// 只保证不 panic、不出现未知 kind。
func TestAuditLive(t *testing.T) {
	a := NewAuditor()
	items := a.Audit(map[string]bool{"systemd|fake": true})
	for _, it := range items {
		switch it.Kind {
		case winapi.PersistRegistryRun, winapi.PersistRegistryRunOnce, winapi.PersistWinlogon,
			winapi.PersistStartupFolder, winapi.PersistService, winapi.PersistScheduledTask,
			winapi.PersistIFEO:
		default:
			t.Errorf("未知持久化类型 %q", it.Kind)
		}
		if it.Command == "" && it.Location == "" {
			t.Errorf("条目 %q 缺 command 与 location", it.Key)
		}
	}
}

func TestBrowserAuditLive(t *testing.T) {
	out := BrowserAudit()
	for _, e := range out.Extensions {
		if e.Browser == "" || e.Profile == "" || e.Name == "" {
			t.Errorf("扩展条目字段缺失: %+v", e)
		}
	}
}
