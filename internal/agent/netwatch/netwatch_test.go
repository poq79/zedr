//go:build windows

// 测试夹具用 winapi.TCPConn 构造连接表（Windows 形态）；netwatch 的
// Linux 覆盖由 collect 的 parse_procdata_test.go（解析）与实机验收承担。
package netwatch

import (
	"fmt"
	"testing"
	"time"

	"zedr/internal/agent/winapi"
)

// t0 是测试时间线的原点；全部窗口/冷却计算只依赖 Tick.TakenAt。
var t0 = time.Date(2026, 11, 3, 10, 0, 0, 0, time.UTC)

func conn(ip string, port uint16, state string) winapi.TCPConn {
	return winapi.TCPConn{Proto: "TCP", LocalIP: "10.0.0.1", LocalPort: 40000,
		RemoteIP: ip, RemotePort: port, State: state, PID: 100}
}

// tickOf 构造一个快照；procs 为 nil 时由调用方按需补。
func tickOf(at time.Time, conns map[uint32][]winapi.TCPConn, procs map[uint32]ProcIdent) Tick {
	if procs == nil {
		procs = map[uint32]ProcIdent{}
	}
	return Tick{TakenAt: at, Conns: conns, Procs: procs}
}

func pid100(at time.Time) ProcIdent {
	return ProcIdent{PID: 100, Name: "scanner.exe", StartTime: at}
}

func ruleIDs(fs []Finding) map[string]bool {
	out := map[string]bool{}
	for _, f := range fs {
		out[f.RuleID] = true
	}
	return out
}

// prime 完成 pid 100 的"首次 sighting = 基线"：基线连接（良性 443）不计入
// 任何窗口，之后的连接才开始计数。除了 TestPIDReuse（自带可变身份）外，
// 所有场景测试都应先 prime，否则第一条连接会被当基线吞掉。
func prime(w *Watch, at time.Time, ident ProcIdent) {
	w.Observe(tickOf(at, map[uint32][]winapi.TCPConn{
		100: {conn("203.0.113.99", 443, "ESTABLISHED")},
	}, map[uint32]ProcIdent{100: ident}))
}

// 0) 首次 sighting 是基线：存量连接再大也不触发——这是启动风暴防护的核心。
func TestFirstSightIsBaseline(t *testing.T) {
	w := New(Config{}, 1)
	var conns []winapi.TCPConn
	for i := 0; i < 20; i++ {
		conns = append(conns, conn(fmt.Sprintf("203.0.113.%d", 20+i), 9999, "ESTABLISHED"))
	}
	fs := w.Observe(tickOf(t0.Add(time.Second), map[uint32][]winapi.TCPConn{100: conns},
		map[uint32]ProcIdent{100: pid100(t0)}))
	if len(fs) != 0 {
		t.Fatalf("首次 sighting 的存量连接不应触发任何规则: %v", ruleIDs(fs))
	}
	// 第二轮 20 个全新 IP：开始计数 → NW-002
	var conns2 []winapi.TCPConn
	for i := 0; i < 20; i++ {
		conns2 = append(conns2, conn(fmt.Sprintf("203.0.113.%d", 60+i), 9999, "ESTABLISHED"))
	}
	fs = w.Observe(tickOf(t0.Add(3*time.Second), map[uint32][]winapi.TCPConn{100: conns2},
		map[uint32]ProcIdent{100: pid100(t0)}))
	if !ruleIDs(fs)["NW-002"] {
		t.Fatalf("基线之后的新增扇出应触发 NW-002: %v", ruleIDs(fs))
	}
}

// 1) NW-001 端口扫描：逐步扇出 40 个端口触发（2026-11-14 阈值 12→40，
// 正常多端口应用防误报）；同端口反复连接不虚增计数。
func TestPortScanThresholdAndDedup(t *testing.T) {
	w := New(Config{}, 1)
	ident := pid100(t0)
	prime(w, t0, ident)
	at := t0.Add(time.Second)

	// 39 个端口：不触发
	for i := 0; i < 39; i++ {
		at = at.Add(5 * time.Second)
		fs := w.Observe(tickOf(at, map[uint32][]winapi.TCPConn{
			100: {conn("203.0.113.10", uint16(1000+i), "ESTABLISHED")},
		}, map[uint32]ProcIdent{100: ident}))
		if len(fs) != 0 {
			t.Fatalf("39 个端口不应触发，第 %d 个端口时触发: %v", i+1, ruleIDs(fs))
		}
	}
	// 同一批连接重复上报（长连接每轮都在表里）：计数不得虚增
	for i := 0; i < 5; i++ {
		at = at.Add(2 * time.Second)
		var conns []winapi.TCPConn
		for p := uint16(1000); p < 1039; p++ {
			conns = append(conns, conn("203.0.113.10", p, "ESTABLISHED"))
		}
		if fs := w.Observe(tickOf(at, map[uint32][]winapi.TCPConn{100: conns},
			map[uint32]ProcIdent{100: ident})); len(fs) != 0 {
			t.Fatalf("重复连接去重后仍只有 39 个端口，不应触发: %v", ruleIDs(fs))
		}
	}
	// 第 40 个端口：触发 NW-001
	at = at.Add(2 * time.Second)
	fs := w.Observe(tickOf(at, map[uint32][]winapi.TCPConn{
		100: {conn("203.0.113.10", 2000, "ESTABLISHED")},
	}, map[uint32]ProcIdent{100: ident}))
	ids := ruleIDs(fs)
	if !ids["NW-001"] {
		t.Fatalf("40 个端口应触发 NW-001，得到: %v", ids)
	}
	if fs[0].Severity != "high" || fs[0].Verdict != "suspicious" {
		t.Fatalf("NW-001 定级不符: %+v", fs[0])
	}
	// 冷却期内继续扫：不重复告警
	at = at.Add(2 * time.Second)
	fs = w.Observe(tickOf(at, map[uint32][]winapi.TCPConn{
		100: {conn("203.0.113.10", 2001, "ESTABLISHED")},
	}, map[uint32]ProcIdent{100: ident}))
	if len(fs) != 0 {
		t.Fatalf("冷却期内不应重复告警: %v", ruleIDs(fs))
	}
}

// 2) NW-002 主机扫探：非常见端口 IP 扇出触发；常见端口（443）不触发。
func TestHostSweepCommonPortsExempt(t *testing.T) {
	w := New(Config{}, 1)
	ident := pid100(t0)

	sweep := func(port uint16) []Finding {
		var conns []winapi.TCPConn
		for i := 0; i < 15; i++ {
			conns = append(conns, conn(fmt.Sprintf("203.0.113.%d", 20+i), port, "ESTABLISHED"))
		}
		return w.Observe(tickOf(t0.Add(time.Second), map[uint32][]winapi.TCPConn{100: conns},
			map[uint32]ProcIdent{100: ident}))
	}
	prime(w, t0, ident)
	if ids := ruleIDs(sweep(9999)); !ids["NW-002"] {
		t.Fatalf("15 台主机的非常见端口扇出应触发 NW-002: %v", ids)
	}
	// 新实例验证常见端口豁免（避免上一例的窗口残留干扰）
	w2 := New(Config{}, 1)
	prime(w2, t0, ident)
	if fs := w2.Observe(tickOf(t0.Add(time.Second), map[uint32][]winapi.TCPConn{100: mustConns(15, 443)},
		map[uint32]ProcIdent{100: ident})); len(fs) != 0 {
		t.Fatalf("443 扇出不应触发任何规则: %v", ruleIDs(fs))
	}
}

func mustConns(n int, port uint16) []winapi.TCPConn {
	var out []winapi.TCPConn
	for i := 0; i < n; i++ {
		out = append(out, conn(fmt.Sprintf("203.0.113.%d", 20+i), port, "ESTABLISHED"))
	}
	return out
}

// 3) NW-003 横向扫探：内网横向端口扇出，critical。
func TestLateralSweep(t *testing.T) {
	w := New(Config{}, 1)
	ident := pid100(t0)
	prime(w, t0, ident)
	var conns []winapi.TCPConn
	for i := 0; i < 8; i++ {
		conns = append(conns, conn(fmt.Sprintf("192.168.1.%d", 10+i), 445, "ESTABLISHED"))
	}
	fs := w.Observe(tickOf(t0.Add(time.Second), map[uint32][]winapi.TCPConn{100: conns},
		map[uint32]ProcIdent{100: ident}))
	ids := ruleIDs(fs)
	if !ids["NW-003"] {
		t.Fatalf("8 台内网主机 445 扇出应触发 NW-003: %v", ids)
	}
	for _, f := range fs {
		if f.RuleID == "NW-003" && (f.Severity != "critical" || f.Score != 70) {
			t.Fatalf("NW-003 定级应为 critical/70: %+v", f)
		}
	}
}

// 4) NW-004：SYN_SENT 消失 → 无响应；并发 SYN_SENT 超阈值 → 触发。
func TestNoResponseAndSynFlood(t *testing.T) {
	w := New(Config{}, 1)
	ident := pid100(t0)
	prime(w, t0, ident)
	// 16 对尝试（4 个 IP × 4 端口，避开 NW-001 的 12 端口/单 IP 与
	// NW-002 的 15 IP 扇出），全部 SYN_SENT
	var conns []winapi.TCPConn
	for ip := 0; ip < 4; ip++ {
		for p := 0; p < 4; p++ {
			conns = append(conns, conn(fmt.Sprintf("203.0.113.%d", 60+ip), uint16(5000+ip*10+p), "SYN_SENT"))
		}
	}
	if fs := w.Observe(tickOf(t0.Add(time.Second), map[uint32][]winapi.TCPConn{100: conns},
		map[uint32]ProcIdent{100: ident})); len(fs) != 0 {
		t.Fatalf("仅 SYN_SENT 存量不应立即触发: %v", ruleIDs(fs))
	}
	// 下一轮全部消失 → 16 次无响应，失败比 100% → NW-004
	fs := w.Observe(tickOf(t0.Add(3*time.Second), map[uint32][]winapi.TCPConn{100: nil},
		map[uint32]ProcIdent{100: ident}))
	if !ruleIDs(fs)["NW-004"] {
		t.Fatalf("无响应尝试应触发 NW-004: %v", ruleIDs(fs))
	}

	// 并发 SYN_SENT 洪流：56 个并发（跨 2 个 IP）
	w2 := New(Config{}, 1)
	ident2 := ProcIdent{PID: 100, Name: "flood.exe", StartTime: t0}
	prime(w2, t0, ident2)
	var flood []winapi.TCPConn
	for i := 0; i < 28; i++ {
		flood = append(flood, conn("203.0.113.90", uint16(7000+i), "SYN_SENT"))
		flood = append(flood, conn("203.0.113.91", uint16(7000+i), "SYN_SENT"))
	}
	fs = w2.Observe(tickOf(t0.Add(time.Second), map[uint32][]winapi.TCPConn{100: flood},
		map[uint32]ProcIdent{100: ident2}))
	if !ruleIDs(fs)["NW-004"] {
		t.Fatalf("并发 SYN_SENT ≥50 应触发 NW-004: %v", ruleIDs(fs))
	}
}

// 5) NW-005 连接速率异常：连续 3 个周期高速且非常见端口占比高。
func TestRateAnomalyStreak(t *testing.T) {
	w := New(Config{}, 1)
	ident := pid100(t0)
	prime(w, t0, ident)
	at := t0.Add(time.Second)
	fired := false
	for i := 0; i < 4; i++ {
		at = at.Add(3 * time.Second)
		var conns []winapi.TCPConn
		for j := 0; j < 65; j++ {
			// 端口随周期偏移：同 (ip,port) 会去重，必须每轮都是新连接
			conns = append(conns, conn(fmt.Sprintf("198.51.100.%d", j%250),
				uint16(9000+i*100+j), "ESTABLISHED"))
		}
		fs := w.Observe(tickOf(at, map[uint32][]winapi.TCPConn{100: conns},
			map[uint32]ProcIdent{100: ident}))
		if ruleIDs(fs)["NW-005"] {
			fired = true
			break
		}
	}
	if !fired {
		t.Fatal("连续高速非常见端口连接应触发 NW-005")
	}
}

// 6) 环回与本机地址排除。
func TestLoopbackAndOwnIPExcluded(t *testing.T) {
	w := New(Config{}, 1)
	// 注入本机地址表并冻结刷新（否则首次 Observe 会用真实网卡覆盖）
	w.ownIPs["203.0.113.156"] = true
	w.ownIPsAt = t0
	conns := []winapi.TCPConn{
		conn("127.0.0.1", 8080, "ESTABLISHED"),
		conn("203.0.113.156", 445, "ESTABLISHED"),
		conn("169.254.1.5", 445, "ESTABLISHED"),
		conn("::1", 8080, "ESTABLISHED"),
	}
	fs := w.Observe(tickOf(t0.Add(time.Second), map[uint32][]winapi.TCPConn{100: conns},
		map[uint32]ProcIdent{100: pid100(t0)}))
	if len(fs) != 0 {
		t.Fatalf("环回/本机/链路本地连接不应触发: %v", ruleIDs(fs))
	}
}

// 7) 可信进程阈值放大。
func TestTrustedScale(t *testing.T) {
	var conns []winapi.TCPConn
	for p := uint16(1000); p < 1040; p++ {
		conns = append(conns, conn("203.0.113.10", p, "ESTABLISHED"))
	}
	mk := func(trusted bool) ProcIdent {
		id := pid100(t0)
		id.Trusted = trusted
		id.Name = "svchost.exe"
		return id
	}
	w := New(Config{}, 1)
	prime(w, t0, mk(true))
	// 可信进程 40 个端口：阈值 ×3 = 120，不触发
	fs := w.Observe(tickOf(t0.Add(time.Second), map[uint32][]winapi.TCPConn{100: conns},
		map[uint32]ProcIdent{100: mk(true)}))
	if ruleIDs(fs)["NW-001"] {
		t.Fatal("可信进程 40 端口不应触发（阈值放大 3 倍）")
	}
	// 不可信进程同样规模：触发
	w2 := New(Config{}, 1)
	prime(w2, t0, mk(false))
	fs = w2.Observe(tickOf(t0.Add(time.Second), map[uint32][]winapi.TCPConn{100: conns},
		map[uint32]ProcIdent{100: mk(false)}))
	if !ruleIDs(fs)["NW-001"] {
		t.Fatalf("不可信进程 40 端口应触发: %v", ruleIDs(fs))
	}
}

// 8) PID 复用：创建时间变化必须清零行为窗口。
func TestPIDReuseResetsWindow(t *testing.T) {
	w := New(Config{}, 1)
	at := t0
	// base 是本轮端口起点：每轮用不同端口，避免 (ip,port) 去重把新事件吞掉
	add := func(n int, start time.Time, base uint16) []Finding {
		at = at.Add(3 * time.Second)
		var conns []winapi.TCPConn
		for p := base; p < base+uint16(n); p++ {
			conns = append(conns, conn("203.0.113.10", p, "ESTABLISHED"))
		}
		return w.Observe(tickOf(at, map[uint32][]winapi.TCPConn{100: conns},
			map[uint32]ProcIdent{100: {PID: 100, Name: "x.exe", StartTime: start}}))
	}
	// 首次 sighting：基线，不计
	if fs := add(20, t0, 1000); len(fs) != 0 {
		t.Fatalf("首次 sighting 是基线，20 端口不应触发: %v", ruleIDs(fs))
	}
	// 同 PID、创建时间不同 → 新进程，窗口清零且重新建基线
	if fs := add(20, t0.Add(time.Hour), 1000); len(fs) != 0 {
		t.Fatalf("PID 复用后旧窗口应清零，不应触发: %v", ruleIDs(fs))
	}
	// 新进程累计：+20 → 20，不触发
	if fs := add(20, t0.Add(time.Hour), 1020); len(fs) != 0 {
		t.Fatalf("新进程累计 20 端口不应触发: %v", ruleIDs(fs))
	}
	// 再 +20 → 40 → 触发
	fs := add(20, t0.Add(time.Hour), 1040)
	if !ruleIDs(fs)["NW-001"] {
		t.Fatalf("累计 40 端口应触发: %v", ruleIDs(fs))
	}
}

// 9) TIME_WAIT 残留也应计入连接证据（快速开合连接的唯一可采样形态）。
func TestTimeWaitCounted(t *testing.T) {
	w := New(Config{}, 1)
	ident := pid100(t0)
	prime(w, t0, ident)
	at := t0.Add(time.Second)
	for i := 0; i < 40; i++ {
		at = at.Add(3 * time.Second)
		fs := w.Observe(tickOf(at, map[uint32][]winapi.TCPConn{
			100: {conn("203.0.113.10", uint16(3000+i), "TIME_WAIT")},
		}, map[uint32]ProcIdent{100: ident}))
		if i < 39 && len(fs) != 0 {
			t.Fatalf("第 %d 个 TIME_WAIT 不应触发", i+1)
		}
		if i == 39 && !ruleIDs(fs)["NW-001"] {
			t.Fatalf("40 个 TIME_WAIT 端口应触发 NW-001: %v", ruleIDs(fs))
		}
	}
}

// 10) 探针自身进程跳过；无快照进程的窗口冻结（不误评估）。
func TestSelfPIDAndStaleEviction(t *testing.T) {
	w := New(Config{}, 100)
	var conns []winapi.TCPConn
	for p := uint16(1000); p < 1015; p++ {
		conns = append(conns, conn(fmt.Sprintf("203.0.113.%d", p), p, "ESTABLISHED"))
	}
	// 自身 PID 100 的"扫描"不应产生任何告警
	if fs := w.Observe(tickOf(t0.Add(time.Second), map[uint32][]winapi.TCPConn{100: conns}, nil)); len(fs) != 0 {
		t.Fatalf("探针自身进程应被跳过: %v", ruleIDs(fs))
	}
	// 普通进程正常跟踪（首现建基线也建状态）
	w.Observe(tickOf(t0.Add(2*time.Second), map[uint32][]winapi.TCPConn{200: conns},
		map[uint32]ProcIdent{200: {PID: 200, Name: "p.exe", StartTime: t0}}))
	if st := w.Stats(); st.TrackedProcs != 1 {
		t.Fatalf("应跟踪 1 个进程，实际 %d", st.TrackedProcs)
	}
	// 长时间无快照后状态应被淘汰
	at := t0.Add(20 * time.Minute)
	w.Observe(tickOf(at, map[uint32][]winapi.TCPConn{}, nil))
	if st := w.Stats(); st.TrackedProcs != 0 {
		t.Fatalf("过期进程状态应被淘汰，实际 %d", st.TrackedProcs)
	}
}

// 11) 进程中途消失：窗口冻结，rateStreak 不因中断而误续。
func TestRateStreakResetOnGap(t *testing.T) {
	w := New(Config{}, 1)
	ident := pid100(t0)
	prime(w, t0, ident)
	at := t0.Add(time.Second)
	busy := func(round int) []winapi.TCPConn {
		var conns []winapi.TCPConn
		for j := 0; j < 65; j++ {
			conns = append(conns, conn(fmt.Sprintf("198.51.100.%d", j%250),
				uint16(9000+round*100+j), "ESTABLISHED"))
		}
		return conns
	}
	// 两个达标周期
	for i := 0; i < 2; i++ {
		at = at.Add(3 * time.Second)
		w.Observe(tickOf(at, map[uint32][]winapi.TCPConn{100: busy(i)},
			map[uint32]ProcIdent{100: ident}))
	}
	// 中断 30 秒（进程无连接）→ streak 必须清零
	at = at.Add(30 * time.Second)
	w.Observe(tickOf(at, map[uint32][]winapi.TCPConn{}, map[uint32]ProcIdent{100: ident}))
	// 再一个达标周期：streak 应从 1 重新计起，不触发
	at = at.Add(3 * time.Second)
	fs := w.Observe(tickOf(at, map[uint32][]winapi.TCPConn{100: busy(9)},
		map[uint32]ProcIdent{100: ident}))
	if ruleIDs(fs)["NW-005"] {
		t.Fatal("中断后 streak 未清零，导致提前触发 NW-005")
	}
}

// NW-004 的非常见端口占比条件：DNS 故障/断网时全机失败集中在常用端口
// （53 等），形态与扫描正交——不应触发（v0.9.10 深化二轮误报收口）。
func TestNoResponseCommonPortExempt(t *testing.T) {
	w := New(Config{}, 1)
	ident := pid100(t0)
	prime(w, t0, ident)
	// 16 次全部打向 53 端口（4 个 IP × 4 次同端口重试——DNS 故障形态）
	var conns []winapi.TCPConn
	for ip := 0; ip < 4; ip++ {
		for p := 0; p < 4; p++ {
			conns = append(conns, conn(fmt.Sprintf("203.0.113.%d", 60+ip), 53, "SYN_SENT"))
		}
	}
	w.Observe(tickOf(t0.Add(time.Second), map[uint32][]winapi.TCPConn{100: conns},
		map[uint32]ProcIdent{100: ident}))
	fs := w.Observe(tickOf(t0.Add(3*time.Second), map[uint32][]winapi.TCPConn{100: nil},
		map[uint32]ProcIdent{100: ident}))
	for _, f := range fs {
		if f.RuleID == "NW-004" {
			t.Fatalf("常用端口的全量失败不应触发 NW-004: %+v", f)
		}
	}
}
