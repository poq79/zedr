package hygiene

// linuxparse_test.go — Linux 格式纯解析函数的单测（无构建标签，
// Windows 上即可跑全）。fixture 按内核文档与发行版惯例手写：
//   - /proc/net/tcp{,6} 口径：docs.kernel.org/networking/proc_net_tcp.html
//   - dpkg status：Debian policy 的 RFC822 段落格式
// 实机校准项（首日在 Linux 上复核）：tcp6 字节序还原、dpkg 魔改字段。

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseDpkgStatus(t *testing.T) {
	// 覆盖点：installed 段保留、deinstall 残留剔除、续行跳过、
	// Installed-Size 数值化、Maintainer 进 publisher
	data := []byte(`Package: curl
Status: install ok installed
Version: 7.88.1-10
Installed-Size: 1234
Maintainer: Debian Curl Team <pkg-curl-devel@x>

Package: zsh
Status: deinstall ok config-files
Version: 5.9-4

Package: nginx
Status: install ok half-installed
Version: 1.22.1-9

Package: openssh-server
Description: secure shell server
 continuation line here
Status: install ok installed
Version: 1:9.2p1-1
Installed-Size: 4321
Maintainer: Debian OpenSSH Maintainers <x>

`)
	got := parseDpkgStatus(data)
	if len(got) != 2 {
		t.Fatalf("应保留 2 条 installed，got %d: %+v", len(got), got)
	}
	if got[0].Name != "curl" || got[0].Version != "7.88.1-10" || got[0].SizeKB != 1234 {
		t.Errorf("curl 解析错误: %+v", got[0])
	}
	if got[0].Publisher != "Debian Curl Team <pkg-curl-devel@x>" {
		t.Errorf("publisher 解析错误: %+v", got[0])
	}
	if got[1].Name != "openssh-server" || got[1].SizeKB != 4321 {
		t.Errorf("openssh-server 解析错误: %+v", got[1])
	}
	if got[1].Source != "dpkg" {
		t.Errorf("source 应为 dpkg: %+v", got[1])
	}
}

func TestParseSshdEffective(t *testing.T) {
	data := []byte(`
# 注释行
Port 22
PermitRootLogin yes
PermitRootLogin no
PasswordAuthentication "no"
Match User backup
	PermitRootLogin yes
	PasswordAuthentication yes
AllowTcpForwarding no
`)
	m := parseSshdEffective(data)
	// sshd_config(5)：同一关键字第一次出现生效——这是本解析器的核心语义
	if m["permitrootlogin"] != "yes" {
		t.Errorf("permitrootlogin 应取第一次出现 yes，got %q", m["permitrootlogin"])
	}
	if m["passwordauthentication"] != "no" {
		t.Errorf("passwordauthentication 应去引号得 no，got %q", m["passwordauthentication"])
	}
	if _, ok := m["port"]; !ok {
		t.Error("port 应存在（小写键归一）")
	}
	// Match 块是按用户/来源的条件覆盖，不是全局值：全局口径止步于第一个
	// Match，块内键（AllowTcpForwarding）不应进入全局口径
	if _, ok := m["allowtcpforwarding"]; ok {
		t.Error("Match 块内的新键不应进入全局口径")
	}
}

func TestCountSudoNopasswd(t *testing.T) {
	lines := []string{
		"# commented NOPASSWD line",
		"root ALL=(ALL:ALL) ALL",
		"deploy ALL=(ALL) NOPASSWD: /usr/bin/systemctl restart app",
		"%ops ALL=(ALL) NOPASSWD: ALL # inline comment",
		"Cmnd_Alias REBOOT = /sbin/reboot, NOPASSWD: /sbin/shutdown",
		"",
	}
	if n := countSudoNopasswd(lines); n != 3 {
		t.Errorf("应计 3 条 NOPASSWD（注释行不计），got %d", n)
	}
}

func TestParseLoginDefs(t *testing.T) {
	data := []byte(`
PASS_MAX_DAYS	99999
# comment
PASS_MIN_DAYS 0
PASS_MAX_DAYS 90
`)
	m := parseLoginDefs(data)
	if m["PASS_MAX_DAYS"] != "90" {
		t.Errorf("后值应覆盖前值，got %q", m["PASS_MAX_DAYS"])
	}
	if m["PASS_MIN_DAYS"] != "0" {
		t.Errorf("PASS_MIN_DAYS 解析错误: %q", m["PASS_MIN_DAYS"])
	}
}

func TestParseProcNet(t *testing.T) {
	// /proc/net/tcp 真实形态（列分隔为变长空格）。local_address 是
	// 小端 u32 的 hex：127.0.0.1=0100007F、192.168.10.1=010AA8C0。
	// 127.0.0.1:8080 LISTEN（st 0A）+ 已建立连接（st 01）
	tcp := "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n" +
		"   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0\n" +
		"   1: 0100007F:1F90 010AA8C0:9C40 01 00000000:00000000 00:00000000 00000000  1000        0 12346 1 0000000000000000 24 4 30 10 -1\n"
	rows := parseProcNet("tcp", tcp)
	if len(rows) != 2 {
		t.Fatalf("应解析 2 行，got %d", len(rows))
	}
	if rows[0].LocalIP != "127.0.0.1" || rows[0].LocalPort != 8080 || rows[0].State != "0A" || rows[0].Inode != 12345 {
		t.Errorf("LISTEN 行解析错误: %+v", rows[0])
	}
	if rows[1].State != "01" || rows[1].Inode != 12346 {
		t.Errorf("ESTAB 行解析错误: %+v", rows[1])
	}
	if rows[0].Proto != "tcp" {
		t.Errorf("proto 应由调用方注入: %+v", rows[0])
	}

	udp := "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops\n" +
		"   12: 00000000:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 999 1 0000000000000000 0\n"
	udpRows := parseProcNet("udp", udp)
	if len(udpRows) != 1 || udpRows[0].LocalPort != 53 || udpRows[0].Inode != 999 {
		t.Errorf("udp 行解析错误: %+v", udpRows)
	}
}

func TestParseHexIPv4(t *testing.T) {
	cases := map[string]string{
		"0100007F": "127.0.0.1", // 小端：最低字节是第一段
		"00000000": "0.0.0.0",
		"010AA8C0": "192.168.10.1",
	}
	for in, want := range cases {
		got, ok := parseHexIPv4(in)
		if !ok || got != want {
			t.Errorf("parseHexIPv4(%q) = %q,%v want %q", in, got, ok, want)
		}
	}
	if _, ok := parseHexIPv4("123"); ok {
		t.Error("非法长度应失败")
	}
}

func TestParseHexIPv6(t *testing.T) {
	// 内核按 IP6_HEX_FMT 打印原生序 u32 字：小端机上每 8 hex 组内部
	// 字节反。::1 打印为 …01000000；2001:db8::1 打印为 B80D0120…01000000。
	cases := map[string]string{
		"00000000000000000000000000000000": "::",
		"00000000000000000000000001000000": "::1",
		"B80D0120000000000000000000000000": "2001:db8::",
		"B80D0120000000000000000000010000": "2001:db8::100",
	}
	for in, want := range cases {
		got, ok := parseHexIPv6(in)
		if !ok || got != want {
			t.Errorf("parseHexIPv6(%q) = %q,%v want %q", in, got, ok, want)
		}
	}
}

func TestParseHexSockaddr(t *testing.T) {
	ip, port, ok := parseHexSockaddr("0100007F:1F90")
	if !ok || ip != "127.0.0.1" || port != 8080 {
		t.Errorf("v4 sockaddr 解析错误: %q %d %v", ip, port, ok)
	}
	if _, _, ok := parseHexSockaddr("bogus"); ok {
		t.Error("非法 sockaddr 应失败")
	}
}

func TestParseRpmQA(t *testing.T) {
	data := []byte("bash\t5.2.15\t1234567\n\ncurl\t7.88.1\t999999\n")
	got := parseRpmQA(data)
	if len(got) != 2 {
		t.Fatalf("应 2 条，got %d", len(got))
	}
	if got[0].Name != "bash" || got[0].SizeKB != 1234567/1024 {
		t.Errorf("rpm size 换算错误: %+v", got[0])
	}
	if got[1].Source != "rpm" {
		t.Errorf("source 应为 rpm: %+v", got[1])
	}
}

func TestModeWorldWritable(t *testing.T) {
	if !modeWorldWritable(os.FileMode(0o666)) {
		t.Error("0666 应判世界可写")
	}
	if modeWorldWritable(os.FileMode(0o644)) {
		t.Error("0644 不应判世界可写")
	}
	// sticky 位（0o1000）不影响 o+w 判定——目录的 sticky 是缓解不是豁免，
	// 体检仍应列出（例如 1777 目录）
	if !modeWorldWritable(os.FileMode(0o1777)) {
		t.Error("1777 应判世界可写（sticky 不豁免）")
	}
}

func TestAuditSources(t *testing.T) {
	// 驻留画像注入路径：字段映射 + 排序。flags 的存在性断言依赖本机
	// 文件系统（/usr 路径在 Windows 上不存在），拆到 TestAuditLinuxFlags
	// 用纯数据断言，这里只测映射。
	a := NewAuditor()
	baseline := map[string]bool{"cron|/etc/cron.d/app|backup.sh": true}
	src := []PersistSource{
		{Key: "systemd_unit|/etc/systemd/system|x.service", Kind: "systemd_unit",
			Location: "/etc/systemd/system", Name: "x.service", Command: "/opt/x/bin/x", Enabled: true},
		{Key: "cron|/etc/cron.d/app|backup.sh", Kind: "cron", Location: "/etc/cron.d/app",
			Name: "backup.sh", Command: "/usr/local/bin/backup.sh", Enabled: true},
	}
	out := a.AuditSources(src, baseline)
	if len(out) != 2 {
		t.Fatalf("应 2 条画像，got %d", len(out))
	}
	// Key 升序排序（Windows Audit 同口径）
	if out[0].Key != "cron|/etc/cron.d/app|backup.sh" {
		t.Errorf("应按 Key 排序: %q", out[0].Key)
	}
	if out[0].Kind != "cron" || out[0].Command != "/usr/local/bin/backup.sh" || !out[0].Enabled {
		t.Errorf("字段映射错误: %+v", out[0])
	}
	if !out[0].InBaseline {
		t.Error("基线内条目应标 InBaseline")
	}
	if out[1].InBaseline {
		t.Error("基线外条目 InBaseline 应为 false")
	}
	if out[1].ExePath != "/opt/x/bin/x" {
		t.Errorf("ExePath 提取错误: %q", out[1].ExePath)
	}
}

func TestAuditLinuxFlags(t *testing.T) {
	// Linux 着色逻辑是纯函数（Windows 版的对应测试在 hygiene_test.go）。
	// 裁剪语义：unsigned/no_info 不标（无签名面），file_missing/new/elevated 保留。
	base := PersistAudit{Key: "k", Kind: "cron", Command: "x", InBaseline: true, Enabled: true}

	if f := auditLinuxFlags(base); len(f) != 0 {
		t.Errorf("无 ExePath 不应有 flags, got %v", f)
	}
	missing := base
	missing.ExePath = "/opt/x/bin/x"
	missing.File = fileMeta{Exists: false}
	if f := auditLinuxFlags(missing); len(f) != 1 || f[0] != FlagFileMissing {
		t.Errorf("文件缺失应标 file_missing, got %v", f)
	}
	exists := base
	exists.ExePath = "/usr/sbin/sshd"
	exists.File = fileMeta{Exists: true}
	if f := auditLinuxFlags(exists); len(f) != 0 {
		t.Errorf("文件存在且在基线内不应有 flags（Linux 不标 unsigned）, got %v", f)
	}
	newItem := base
	newItem.InBaseline = false
	if f := auditLinuxFlags(newItem); len(f) != 1 || f[0] != FlagNew {
		t.Errorf("基线外应标 new, got %v", f)
	}
	elevated := base
	elevated.Elevated = true
	if f := auditLinuxFlags(elevated); len(f) != 1 || f[0] != FlagElevated {
		t.Errorf("提权应标 elevated, got %v", f)
	}
}

func TestLinuxExePath(t *testing.T) {
	cases := []struct{ in, want string }{
		{"/usr/sbin/sshd -D", "/usr/sbin/sshd"},
		{"/usr/bin/env python3 app.py", "/usr/bin/env"},
		{"/opt/tool/bin/x", "/opt/tool/bin/x"},
		{`"/usr/sbin/x" --flag`, "/usr/sbin/x"},
		{"systemctl restart app", ""}, // 相对名不猜
		{"sh -c 'curl evil'", ""},     // shell 语法不猜
		{"", ""},
	}
	for _, c := range cases {
		if got := linuxExePath(c.in); got != c.want {
			t.Errorf("linuxExePath(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestReadHostsFileLinuxLayout(t *testing.T) {
	// readHostsFile 已是双平台共享；这里用 Linux hosts 语义补一条
	// 环境无关的冒烟（Windows 测试文件里已有等价用例）
	dir := t.TempDir()
	p := filepath.Join(dir, "hosts")
	content := "127.0.0.1 localhost\n# comment\n10.0.0.5 db.internal\n"
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	rep := readHostsFile(p)
	if !rep.Readable || len(rep.Entries) != 2 {
		t.Errorf("hosts 解析错误: %+v", rep)
	}
	if rep.Entries[1].IP != "10.0.0.5" || rep.Entries[1].Hostname != "db.internal" {
		t.Errorf("条目解析错误: %+v", rep.Entries[1])
	}
}
