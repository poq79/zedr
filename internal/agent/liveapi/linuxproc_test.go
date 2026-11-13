// 本测试文件 NEUTRAL（无构建标签）：/proc 解析纯逻辑在 Windows 上跑
// （验证口径，见 linuxproc.go 头注释）。样例取自内核文档口径（tcp_seq.c
// 打印格式），与 collect/parse_procdata_test.go 的样例互为参照——两份解析
// 的口径一致性由两边各自的样例测试锁定。
package liveapi

import (
	"strings"
	"testing"
	"time"
)

func TestParseProcNetAddr(t *testing.T) {
	cases := []struct {
		in   string
		ip   string
		port uint16
		ok   bool
	}{
		{"0100007F:1F90", "127.0.0.1", 8080, true},                 // IPv4 小端还原
		{"00000000:0050", "0.0.0.0", 80, true},                     // 通配地址
		{"00000000000000000000000001000000:0016", "::1", 22, true}, // IPv6 ::1
		{"0000000000000000FFFF00001F00C0A8:01BB", "", 443, true},   // v4-mapped 形态（IP 交给 net.IP 展示）
		{"0100007F", "", 0, false},                                 // 缺端口
		{"XXXX:1F90", "", 0, false},                                // 非 hex
		{"0100007F:XXXX", "", 0, false},                            // 端口非 hex
		{"123:1F90", "", 0, false},                                 // 长度非法
	}
	for _, c := range cases {
		ip, port, ok := parseProcNetAddr(c.in)
		if ok != c.ok {
			t.Errorf("%s: ok 期望 %v 实得 %v", c.in, c.ok, ok)
			continue
		}
		if !ok {
			continue
		}
		if port != c.port {
			t.Errorf("%s: port 期望 %d 实得 %d", c.in, c.port, port)
		}
		if c.ip != "" && ip != c.ip {
			t.Errorf("%s: ip 期望 %q 实得 %q", c.in, c.ip, ip)
		}
	}
}

func TestParseProcNetRows(t *testing.T) {
	// 样例：表头 + LISTEN（inode 1234）+ ESTABLISHED（inode 5678）+
	// TIME_WAIT（inode 0，内核口径）+ 残行（字段不足）+ 地址残行。
	data := []byte(strings.Join([]string{
		"  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode",
		"   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1234 1 0000000000000000 100 0 0 10 0",
		"   1: 0100007F:1F91 0A00007F:01BB 01 00000000:00000000 02:00000A3C 00000000   100        0 5678 1 0000000000000000 24 4 30 10 -1",
		"   2: 00000000:0050 00000000:0000 06 00000000:00000000 00:00000000 00000000     0        0 0 1 0000000000000000 100 0 0 10 0",
		"   3: 0100007F:1F92残行",
		"   4: BADADDR:1F93 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 9999 1 0000000000000000 100 0 0 10 0",
		"",
	}, "\n"))

	rows := parseProcNetRows(data, "tcp")
	if len(rows) != 3 {
		t.Fatalf("期望 3 行（表头/残行/地址残行/空行跳过）实得 %d", len(rows))
	}
	if rows[0].Row.State != "LISTEN" || rows[0].Row.LocalIP != "127.0.0.1" ||
		rows[0].Row.LocalPort != 8080 || rows[0].Inode != 1234 {
		t.Errorf("第一行口径不符: %+v", rows[0])
	}
	if rows[1].Row.State != "ESTABLISHED" || rows[1].Row.RemoteIP != "127.0.0.10" ||
		rows[1].Row.RemotePort != 443 {
		t.Errorf("第二行口径不符: %+v", rows[1])
	}
	// TIME_WAIT：inode=0 → 无法归属 PID（保留行，PID 由投影层置 0）
	if rows[2].Row.State != "TIME_WAIT" || rows[2].Inode != 0 {
		t.Errorf("TIME_WAIT 行口径不符: %+v", rows[2])
	}
	// 未知状态码保留原文（可观测，不静默归桶）
	unknown := parseProcNetRows([]byte(
		"  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"+
			"   0: 0100007F:1F90 00000000:0000 0C 00000000:00000000 00:00000000 00000000 0 0 1 1 0000000000000000 100 0 0 10 0\n"), "tcp")
	if len(unknown) != 1 || unknown[0].Row.State != "UNKNOWN(0C)" {
		t.Errorf("未知状态码应保留原文: %+v", unknown)
	}
}

func TestProcNetStateNames(t *testing.T) {
	if procNetStateNames["0A"] != "LISTEN" || procNetStateNames["01"] != "ESTABLISHED" {
		t.Fatalf("状态码映射口径漂移（对照 tcp_states.h）")
	}
	if !strings.HasPrefix(procNetStateName("FF"), "UNKNOWN") {
		t.Errorf("未知码应带 UNKNOWN 前缀: %q", procNetStateName("FF"))
	}
}

func TestParseProcStatStarttime(t *testing.T) {
	// comm 含空格与括号的进程名（如 "tmux: server"），按最后一个 ')' 切分。
	// 剩余列序：state(0) ppid(1) pgrp(2) session(3) tty(4) tpgid(5) flags(6)
	// minflt(7) cminflt(8) majflt(9) cmajflt(10) utime(11) stime(12) cutime(13)
	// cstime(14) priority(15) nice(16) num_threads(17) itrealvalue(18)
	// starttime(19)——即第 22 列。
	line := "1234 (tmux: server) S 1 1234 1234 0 -1 4194560 123 0 0 0 10 5 0 0 20 0 1 0 " +
		"48765 10000000 200 18446744073709551615 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20\n"
	ticks, ok := parseProcStatStarttime([]byte(line))
	if !ok {
		t.Fatalf("样例行应解析成功")
	}
	if ticks != 48765 {
		t.Errorf("starttime 期望 48765 实得 %d", ticks)
	}
	// 字段不足 / 无括号 → 拒绝
	if _, ok := parseProcStatStarttime([]byte("1234 (x) S 1 2 3")); ok {
		t.Errorf("字段不足应拒绝")
	}
	if _, ok := parseProcStatStarttime([]byte("no parens here")); ok {
		t.Errorf("无 comm 括号应拒绝")
	}
}

func TestParseProcUptime(t *testing.T) {
	v, ok := parseProcUptime([]byte("12345.67 23456.78\n"))
	if !ok || v != 12345.67 {
		t.Errorf("uptime 口径不符: %v %v", v, ok)
	}
	if _, ok := parseProcUptime([]byte("")); ok {
		t.Errorf("空 uptime 应拒绝")
	}
}

func TestParseProcUidReal(t *testing.T) {
	uid, ok := parseProcUidReal([]byte("Name:\tsshd\nUid:\t0\t0\t0\t0\nGid:\t0\n"))
	if !ok || uid != 0 {
		t.Errorf("root uid 口径不符: %v %v", uid, ok)
	}
	uid, ok = parseProcUidReal([]byte("Name:\tnginx\nUid:\t998\t998\t998\t998\n"))
	if !ok || uid != 998 {
		t.Errorf("普通 uid 口径不符: %v %v", uid, ok)
	}
	if _, ok := parseProcUidReal([]byte("Name:\tx\n")); ok {
		t.Errorf("无 Uid 行应拒绝")
	}
}

func TestParseOSReleasePretty(t *testing.T) {
	got := parseOSReleasePretty([]byte("NAME=\"Ubuntu\"\nPRETTY_NAME=\"Ubuntu 24.04 LTS\"\nID=ubuntu\n"))
	if got != "Ubuntu 24.04 LTS" {
		t.Errorf("PRETTY_NAME 口径不符: %q", got)
	}
	if parseOSReleasePretty([]byte("ID=debian\n")) != "" {
		t.Errorf("缺 PRETTY_NAME 应返回空串（调用方回退）")
	}
}

func TestProcStarttimeUnixAnchoring(t *testing.T) {
	// 锚定逻辑不读文件的部分：ticks=0（boot 期进程）→ 恰为 boot 时刻。
	// 文件读取部分（/proc）在 Windows 上不存在，procStarttimeUnix 返回 0
	// ——这也是 IO 壳在非 Linux 平台"天然不执行"的佐证。
	if ts := procStarttimeUnix(1, time.Now()); ts != 0 {
		t.Errorf("Windows 上 /proc 不存在，应返回 0（诚实未知）: %d", ts)
	}
	if procIsRootEuid(1) {
		t.Errorf("Windows 上 /proc 不存在，root 判定应 false")
	}
	if owners := procInodeOwners(map[uint64]struct{}{1: {}}); len(owners) != 0 {
		t.Errorf("Windows 上 /proc 不存在，归属表应为空")
	}
}
