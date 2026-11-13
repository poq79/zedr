package collect

// procfs 纯解析单测（neutral，Windows 上直接跑）。
//
// 本仓库没有 Linux 测试环境，Phase A1 的验证口径 = 交叉编译 + 纯逻辑
// 单测：这里只打 procfs 的"文本格式契约"，不碰真实 /proc。样例值全部
// 按 procfs 文档化格式构造（fs/proc/array.c 的 stat 字段序、
// net/ipv4/tcp_seq.c 的 %08X __be32 打印口径）；如实测发现口径出入，
// 以实机为准修正本文件与 parse_procdata.go。

import (
	"testing"
	"time"
)

// stat 最小完整样本：')' 后恰好 20 个字段（field 3..22），其中
// rest[19]（全文件 field 22）= starttime = 2500。
const procStatMinimal = "1234 (bash) S 1 1234 1234 0 -1 4194560 100 0 0 0 5 3 0 0 20 0 1 0 2500"

func TestParseProcStat(t *testing.T) {
	t.Run("plain", func(t *testing.T) {
		st, err := parseProcStat([]byte(procStatMinimal + "\n"))
		if err != nil {
			t.Fatal(err)
		}
		want := procStat{Comm: "bash", State: "S", PPID: 1, StartTimeTicks: 2500}
		if st != want {
			t.Fatalf("got %+v, want %+v", st, want)
		}
	})

	t.Run("multi-digit-pid-not-in-comm", func(t *testing.T) {
		// 回归锁（修复过的真实缺陷）：comm 必须锚定第一个 '(' 到最后
		// 一个 ')'。修复前的实现是"跳过首字符 + 去前缀括号"的近似，
		// PID 的剩余数字与 " (" 会混进进程名（如 "234 (bash"）。
		st, err := parseProcStat([]byte(procStatMinimal))
		if err != nil {
			t.Fatal(err)
		}
		if st.Comm != "bash" {
			t.Fatalf("comm = %q, want %q（PID 残余混进了进程名）", st.Comm, "bash")
		}
	})

	t.Run("comm-with-spaces-and-parens", func(t *testing.T) {
		// systemd 的 sd-pam 助手进程名就叫 "(sd-pam)"（字面带括号），
		// 内核线程名可含空格——只有最后一个 ')' 才是 comm 收尾。
		in := "812 ((sd-pam) worker 2) D 1 812 812 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 99\n"
		st, err := parseProcStat([]byte(in))
		if err != nil {
			t.Fatal(err)
		}
		if st.Comm != "(sd-pam) worker 2" || st.State != "D" || st.PPID != 1 || st.StartTimeTicks != 99 {
			t.Fatalf("got %+v", st)
		}
	})

	t.Run("extra-fields-tolerated", func(t *testing.T) {
		// 真实文件 field 22 之后还有 30 个字段，多余字段必须被忽略
		in := procStatMinimal + " 4194304 1234 0 0 18446744073709551615 0 0 0 17 0"
		st, err := parseProcStat([]byte(in))
		if err != nil {
			t.Fatal(err)
		}
		if st.StartTimeTicks != 2500 {
			t.Fatalf("StartTimeTicks = %d, want 2500", st.StartTimeTicks)
		}
	})

	t.Run("too-few-fields", func(t *testing.T) {
		// 恰好缺 starttime（19 个字段）——字段数下界是切分正确性的关键
		in := "1234 (bash) S 1 1234 1234 0 -1 4194560 100 0 0 0 5 3 0 0 20 0 1 0"
		if _, err := parseProcStat([]byte(in)); err == nil {
			t.Fatal("19 个字段应当报错")
		}
	})

	t.Run("bad-inputs", func(t *testing.T) {
		for _, in := range []string{
			"",                           // 空文件（读取竞态）
			"1234 bash S",                // 无括号
			"(bash) S 1 2",               // 缺 pid 前缀也要能拒绝——open>=l 不成立，但字段不足
			"1234 (unterminated S 1 2 3", // 只有左括号
		} {
			if _, err := parseProcStat([]byte(in)); err == nil {
				t.Fatalf("input %q 应当报错", in)
			}
		}
	})
}

func TestParseHexAddr(t *testing.T) {
	cases := []struct {
		in   string
		ip   string
		port uint16
		ok   bool
	}{
		// IPv4：8 字符整体小端（127.0.0.1 → 0100007F）
		{"0100007F:1F90", "127.0.0.1", 8080, true},
		{"6401A8C0:0035", "192.168.1.100", 53, true},
		{"00000000:0000", "0.0.0.0", 0, true},
		// IPv6：4 组 × 8 字符，组内小端、组间正序（::1 → …01000000）
		{"00000000000000000000000001000000:0035", "::1", 53, true},
		{"b80d0120000000000000000001000000:04D2", "2001:db8::1", 1234, true},
		// IPv4-mapped（tcp6 上可见）：::ffff:127.0.0.1 的网络序字节是
		// 00×10,FF,FF,7F,00,00,01 → 按字小端打印为 …FFFF0000 0100007F；
		// net.IP 展示口径是退回点分十进制
		{"0000000000000000FFFF00000100007F:1F90", "127.0.0.1", 8080, true},
		// 非法输入
		{"123:1F90", "", 0, false},      // 主机段长度既非 8 也非 32
		{"0100007F", "", 0, false},      // 缺冒号/端口
		{":1F90", "", 0, false},         // 主机段为空
		{"ZZ00007F:1F90", "", 0, false}, // 非 hex 字符
		{"0100007F:ZZZZ", "", 0, false}, // 端口非 hex
	}
	for _, c := range cases {
		ip, port, ok := parseHexAddr(c.in)
		if ok != c.ok {
			t.Errorf("%q: ok = %v, want %v", c.in, ok, c.ok)
			continue
		}
		if ok && (ip != c.ip || port != c.port) {
			t.Errorf("%q: got (%s,%d), want (%s,%d)", c.in, ip, port, c.ip, c.port)
		}
	}
}

// genTCPRow 构造一行 /proc/net/tcp 数据（不含表头）。
func genTCPRow(sl, local, remote, state, inode string) string {
	return "  " + sl + ": " + local + " " + remote + " " + state +
		" 00000000:00000000 00:00000000 00000000  1000        0 " + inode +
		" 1 0000000000000000 100 0 0 10 0\n"
}

const tcpHeader = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"

func TestParseNetTCP(t *testing.T) {
	t.Run("header-and-full-rows", func(t *testing.T) {
		// 0100A8C0 反转 = C0.A8.00.01 = 192.168.0.1（192.168.1.100 的
		// 打印是 6401A8C0，见 TestParseHexAddr）
		data := tcpHeader +
			genTCPRow("0", "0100007F:1F90", "0100A8C0:0035", "01", "12345") +
			genTCPRow("1", "0100007F:1F91", "0100007F:1F90", "06", "0") +
			genTCPRow("2", "00000000:0016", "00000000:0000", "0A", "12346")
		conns := parseNetTCP([]byte(data), "tcp")
		want := []struct {
			lip   string
			lport uint16
			rip   string
			rport uint16
			state string
		}{
			{"127.0.0.1", 8080, "192.168.0.1", 53, "ESTABLISHED"},
			{"127.0.0.1", 8081, "127.0.0.1", 8080, "TIME_WAIT"},
			{"0.0.0.0", 22, "0.0.0.0", 0, "LISTEN"},
		}
		if len(conns) != len(want) {
			t.Fatalf("len(conns) = %d, want %d: %+v", len(conns), len(want), conns)
		}
		for i, w := range want {
			c := conns[i]
			if c.Proto != "tcp" || c.LocalIP != w.lip || c.LocalPort != w.lport ||
				c.RemoteIP != w.rip || c.RemotePort != w.rport || c.State != w.state {
				t.Errorf("conn[%d] = %+v, want (%s:%d -> %s:%d %s)", i, c, w.lip, w.lport, w.rip, w.rport, w.state)
			}
		}
	})

	t.Run("skips-junk-lines", func(t *testing.T) {
		// 表头行 / 空行 / 短行（不足 inode 列）一律跳过，其余正常解析
		data := tcpHeader + "\n" +
			"   3: 0100007F:1F90\n" + // 只有 2 个字段
			"   4: 0100007F:1F90 0100007F:1F91 01 00000000:00000000 00:00000000 00000000  1000        0\n" + // 9 个字段，缺 inode
			genTCPRow("5", "0100007F:1F92", "00000000:0000", "08", "99999")
		conns := parseNetTCP([]byte(data), "tcp")
		if len(conns) != 1 || conns[0].State != "CLOSE_WAIT" {
			t.Fatalf("got %+v, want 仅保留 1 条 CLOSE_WAIT", conns)
		}
	})

	t.Run("no-header-still-parses", func(t *testing.T) {
		// 调用方掐了表头（或增量拼接）也应可解析：首列不以 ':' 结尾才跳过
		data := genTCPRow("0", "0100007F:1F90", "00000000:0000", "0A", "12345")
		if conns := parseNetTCP([]byte(data), "tcp"); len(conns) != 1 {
			t.Fatalf("got %+v, want 1 条", conns)
		}
	})

	t.Run("state-map-full-table", func(t *testing.T) {
		for code, want := range procTCPStateNames {
			data := genTCPRow("0", "0100007F:1F90", "00000000:0000", code, "1")
			conns := parseNetTCP([]byte(data), "tcp")
			if len(conns) != 1 || conns[0].State != want {
				t.Errorf("state %s: got %+v, want %s", code, conns, want)
			}
		}
		// 未知码保留原文而不是静默归桶；小写容错（内核恒大写）
		for code, want := range map[string]string{"0C": "UNKNOWN(0C)", "0a": "LISTEN"} {
			data := genTCPRow("0", "0100007F:1F90", "00000000:0000", code, "1")
			if conns := parseNetTCP([]byte(data), "tcp"); len(conns) != 1 || conns[0].State != want {
				t.Errorf("state %s: got %+v, want %s", code, conns, want)
			}
		}
	})

	t.Run("entries-inode", func(t *testing.T) {
		// 带 inode 的入口：正常行带 inode；inode 列非数字 → Inode=0（无法归属）
		data := genTCPRow("0", "0100007F:1F90", "00000000:0000", "01", "12345") +
			genTCPRow("1", "0100007F:1F91", "00000000:0000", "01", "N/A")
		entries := parseNetTCPEntries([]byte(data), "tcp")
		if len(entries) != 2 {
			t.Fatalf("len = %d, want 2", len(entries))
		}
		if entries[0].Inode != 12345 {
			t.Errorf("entries[0].Inode = %d, want 12345", entries[0].Inode)
		}
		if entries[1].Inode != 0 {
			t.Errorf("entries[1].Inode = %d, want 0（不可解析即无归属）", entries[1].Inode)
		}
	})

	t.Run("empty", func(t *testing.T) {
		if conns := parseNetTCP(nil, "tcp"); len(conns) != 0 {
			t.Fatalf("got %+v, want 空", conns)
		}
	})
}

func TestBootTicksToUnixNanosAt(t *testing.T) {
	if got := bootTicksToUnixNanosAt(0, 100, time.Now()); got != 0 {
		t.Fatalf("ticks=0 应返回零值哨兵，got %d", got)
	}
	now := time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)
	// ticks=2500（25s 进程龄）+ uptime 100s → 启动时刻 = now-75s
	if got, want := bootTicksToUnixNanosAt(2500, 100.0, now), now.Add(-75*time.Second).UnixNano(); got != want {
		t.Fatalf("got %d, want %d", got, want)
	}
	// uptime 带厘秒小数（/proc/uptime 恒两位小数）
	if got, want := bootTicksToUnixNanosAt(2500, 100.5, now), now.Add(-75500*time.Millisecond).UnixNano(); got != want {
		t.Fatalf("got %d, want %d", got, want)
	}
	// 大 uptime 不溢出 int64 纳秒（约 3 年 uptime 的量级）
	if got := bootTicksToUnixNanosAt(10_000_000_000, 100_000_000, now); got == 0 {
		t.Fatal("大 uptime 换算溢出为 0")
	}
}

func TestBootTicksToUnixNanosWrapper(t *testing.T) {
	// 薄包装用真实墙钟，只验证锚定方向与量级（±2s）；精确等值由
	// bootTicksToUnixNanosAt 的注入测试保证
	want := time.Now().Add(-75 * time.Second).UnixNano()
	got := bootTicksToUnixNanos(2500, 100.0)
	if d := got - want; d > int64(2*time.Second) || d < -int64(2*time.Second) {
		t.Fatalf("got %d, want ~%d（偏差超过 2s）", got, want)
	}
}

func TestParseUptime(t *testing.T) {
	cases := []struct {
		in    string
		want  float64
		valid bool
	}{
		{"12345.67 89012.34\n", 12345.67, true},
		{"0.00 0.00", 0, true},
		{"", 0, false},
		{"\n", 0, false},
		{"notanumber", 0, false},
	}
	for _, c := range cases {
		got, err := parseUptime([]byte(c.in))
		if c.valid != (err == nil) {
			t.Errorf("%q: err = %v, valid = %v", c.in, err, c.valid)
			continue
		}
		if c.valid && got != c.want {
			t.Errorf("%q: got %v, want %v", c.in, got, c.want)
		}
	}
}

func TestParseCmdline(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"sh\x00-c\x00ls\x00", "sh -c ls"}, // 正常 argv
		{"proc\x00", "proc"},               // 单参数
		{"\x00", ""},                       // 空参数（内核线程常见）
		{"", ""},                           // 空文件
		{"a\x00\x00b\x00", "a b"},          // 连续 NUL（zombie 残迹）
		{"python3\x00-c\x00print(1)\x00", "python3 -c print(1)"}, // 参数内空格会糊掉，已知损失
	}
	for _, c := range cases {
		if got := parseCmdline([]byte(c.in)); got != c.want {
			t.Errorf("%q: got %q, want %q", c.in, got, c.want)
		}
	}
}

func TestParseStatusUIDs(t *testing.T) {
	t.Run("normal", func(t *testing.T) {
		data := []byte("Name:\tsshd\nUid:\t1000\t1000\t1000\t1000\nGid:\t1000\t1000\t1000\t1000\n")
		uid, euid, ok := parseStatusUIDs(data)
		if !ok || uid != 1000 || euid != 1000 {
			t.Fatalf("got (%d,%d,%v), want (1000,1000,true)", uid, euid, ok)
		}
	})
	t.Run("root", func(t *testing.T) {
		data := []byte("Uid:\t0\t0\t0\t0\n")
		uid, euid, ok := parseStatusUIDs(data)
		if !ok || uid != 0 || euid != 0 {
			t.Fatalf("got (%d,%d,%v), want (0,0,true)", uid, euid, ok)
		}
	})
	t.Run("setuid-dropped-privilege", func(t *testing.T) {
		// real=1000 / effective=0：提权判定看 euid
		data := []byte("Uid:\t1000\t0\t1000\t1000\n")
		uid, euid, ok := parseStatusUIDs(data)
		if !ok || uid != 1000 || euid != 0 {
			t.Fatalf("got (%d,%d,%v), want (1000,0,true)", uid, euid, ok)
		}
	})
	t.Run("missing-or-malformed", func(t *testing.T) {
		if _, _, ok := parseStatusUIDs([]byte("Name:\tx\n")); ok {
			t.Fatal("缺 Uid 行应 ok=false")
		}
		if _, _, ok := parseStatusUIDs([]byte("Uid:\t1000\n")); ok {
			t.Fatal("只有 1 列应 ok=false")
		}
		if _, _, ok := parseStatusUIDs(nil); ok {
			t.Fatal("空输入应 ok=false")
		}
	})
}
