package recon

// linuxparse_test.go — procfs 纯解析单测（无构建标签，Windows 上跑）。
// fixture 按 proc(5) 手册页格式手写；实机校准项见 base_linux.go 头注。

import "testing"

func TestParseProcStatStarttime(t *testing.T) {
	// 真实形态（proc(5) 第 22 字段 = starttime）：comm 含空格与括号时
	// 必须从最后一个 ')' 之后切字段——这是本解析器的核心陷阱用例。
	cases := []struct {
		name string
		in   string
		want uint64
	}{
		{"普通进程",
			"1234 (sshd) S 1 1234 1234 0 -1 4194560 123 0 0 0 100 20 0 0 20 5 1 0 123456789 98765432 9999 18446744073709551615 1 1 0 0 0 0 0 0 0 0 0 0 17 4 0 0 0 0 0\n",
			123456789},
		{"comm 含空格与嵌套括号",
			"77 ((sd-pam)) S 999 77 77 0 -1 1077952768 0 0 0 0 0 0 0 0 20 0 1 0 77777777 123456 999 18446744073709551615 1 1 0 0 0 0 0 0 0 0 0 0 17 0 0 0 0 0 0\n",
			77777777},
	}
	for _, c := range cases {
		got, ok := parseProcStatStarttime([]byte(c.in))
		if !ok || got != c.want {
			t.Errorf("%s: parseProcStatStarttime = %d,%v want %d", c.name, got, ok, c.want)
		}
	}
	if _, ok := parseProcStatStarttime([]byte("garbage")); ok {
		t.Error("无右括号的脏数据应失败")
	}
	if _, ok := parseProcStatStarttime([]byte("12 (x) S 1 2")); ok {
		t.Error("字段不足应失败")
	}
}

func TestParseProcStatBtime(t *testing.T) {
	data := []byte("cpu  100 0 50 100000 0 0 0 0 0 0\ncpu0 10 0 5 10000 0 0 0 0 0 0\nintr 123\nbtime 1731412345\nprocs_running 3\n")
	v, ok := parseProcStatBtime(data)
	if !ok || v != 1731412345 {
		t.Errorf("btime 解析错误: %d %v", v, ok)
	}
	if _, ok := parseProcStatBtime([]byte("cpu 1 2 3\n")); ok {
		t.Error("缺 btime 行应失败")
	}
}

func TestProcStarttimeToUnix(t *testing.T) {
	// btime=1731412345, starttime=2500 ticks @USER_HZ=100 → +25s
	if got := procStarttimeToUnix(1731412345, 2500); got != 1731412370 {
		t.Errorf("tick 换算错误: %d", got)
	}
}
