package chain

import (
	"math/rand"
	"strings"
	"sync"
	"testing"
	"time"

	"zedr/internal/agent/allow"
	"zedr/internal/model"
)

// newTestEngine 构造可注入时钟的引擎，返回引擎、找出的 findings 切片指针
// 与可控的 now。
func newTestEngine(alw *allow.List) (*Engine, *[]Finding, *time.Time) {
	base := time.Date(2026, 11, 6, 10, 0, 0, 0, time.Local)
	now := base
	var mu sync.Mutex
	findings := &[]Finding{}
	e := New(Options{
		OnFinding: func(f Finding) {
			mu.Lock()
			*findings = append(*findings, f)
			mu.Unlock()
		},
		Allow: alw,
		Now:   func() time.Time { return now },
	})
	return e, findings, &now
}

func lastFinding(t *testing.T, fs *[]Finding) Finding {
	t.Helper()
	got := *fs
	if len(got) == 0 {
		t.Fatalf("期望产出链告警，实际 0 条")
	}
	return got[len(got)-1]
}

func findingsCount(fs *[]Finding) int { return len(*fs) }

func advance(now *time.Time, d time.Duration) { *now = now.Add(d) }

// procStage 是链首进程阶段的样例构造（落地未签名）。
func procStage(pid uint32, path string, dropped, signed bool) Stage {
	return Stage{
		Kind: KindProc, PID: pid, StartTime: time.Unix(1000, 0),
		Name: "sample.exe", Path: path, Dropped: dropped, Signed: signed,
		When: time.Unix(1100, 0),
	}
}

func connStage(pid uint32, ip string) Stage {
	return Stage{
		Kind: KindConn, PID: pid, StartTime: time.Unix(1000, 0),
		PeerIP: ip, PeerPort: 443, When: time.Unix(1160, 0),
	}
}

func TestDropExecC2Fire(t *testing.T) {
	e, fs, now := newTestEngine(nil)
	e.Feed(procStage(4242, `C:\Users\pub\AppData\Local\evil.exe`, true, false))
	e.Feed(connStage(4242, "203.0.113.9"))

	f := lastFinding(t, fs)
	if f.RuleID != "CHAIN-DROP-EXEC-C2" {
		t.Fatalf("规则 ID = %s", f.RuleID)
	}
	if len(f.Stages) != 2 {
		t.Fatalf("阶段数 = %d", len(f.Stages))
	}
	if f.Root == nil || f.Root.PID != 4242 {
		t.Fatalf("根因进程 = %+v", f.Root)
	}
	for _, m := range f.MITRE {
		if m == "T1105" {
			return
		}
	}
	t.Fatalf("MITRE 缺 T1105: %v", f.MITRE)
	if !strings.Contains(f.Summary, "进程创建") || !strings.Contains(f.Summary, "主动外联") {
		t.Fatalf("摘要缺阶段叙事: %s", f.Summary)
	}
	_ = now
}

func TestDropExecC2SignedNoFire(t *testing.T) {
	e, fs, _ := newTestEngine(nil)
	// 签名有效：可写目录落地+执行是合法软件常态，不进链
	e.Feed(procStage(4242, `C:\Users\pub\AppData\Local\inst.exe`, true, true))
	e.Feed(connStage(4242, "203.0.113.9"))
	if findingsCount(fs) != 0 {
		t.Fatalf("签名进程不应成链")
	}
}

func TestDropExecC2LoopbackNoFire(t *testing.T) {
	e, fs, _ := newTestEngine(nil)
	e.Feed(procStage(4242, `C:\temp\evil.exe`, true, false))
	// 回环外联不算 C2 证据
	e.Feed(Stage{Kind: KindConn, PID: 4242, StartTime: time.Unix(1000, 0),
		PeerIP: "127.0.0.1", PeerPort: 8080, When: time.Unix(1160, 0)})
	if findingsCount(fs) != 0 {
		t.Fatalf("回环外联不应成链")
	}
}

func TestDropExecC2KeyMismatchNoFire(t *testing.T) {
	e, fs, _ := newTestEngine(nil)
	e.Feed(procStage(4242, `C:\temp\evil.exe`, true, false))
	// 另一进程的外联不能拼进这条链（实体约束）
	e.Feed(connStage(999, "203.0.113.9"))
	e.Feed(connStage(4243, "203.0.113.9"))
	if findingsCount(fs) != 0 {
		t.Fatalf("不同进程的阶段不应成链")
	}
}

func TestDropExecC2SpanExpiry(t *testing.T) {
	e, fs, now := newTestEngine(nil)
	e.Feed(Stage{Kind: KindProc, PID: 4242, StartTime: time.Unix(1000, 0),
		Name: "evil.exe", Path: `C:\temp\evil.exe`, Dropped: true, Signed: false, When: *now})
	advance(now, 16*time.Minute) // 超过 15min 链窗：既不推进也被惰性回收
	e.Feed(Stage{Kind: KindConn, PID: 4242, StartTime: time.Unix(1000, 0),
		PeerIP: "203.0.113.9", PeerPort: 443, When: *now})
	if findingsCount(fs) != 0 {
		t.Fatalf("超窗后不应成链")
	}
}

func TestBruteSuccessFire(t *testing.T) {
	e, fs, now := newTestEngine(nil)
	e.Feed(Stage{Kind: KindBrute, When: *now, FailCount: 14, SrcIP: "198.51.100.7", LoginUser: "admin"})
	advance(now, 2*time.Minute)
	e.Feed(Stage{Kind: KindLogonOK, When: *now, SrcIP: "198.51.100.7", LoginUser: "admin", LogonType: "10"})
	advance(now, time.Minute)
	e.Feed(Stage{Kind: KindProc, PID: 777, StartTime: time.Unix(2000, 0),
		Name: "tool.exe", Path: `C:\temp\tool.exe`, Dropped: true, Signed: false, When: *now})

	f := lastFinding(t, fs)
	if f.RuleID != "CHAIN-BRUTE-SUCCESS" {
		t.Fatalf("规则 ID = %s", f.RuleID)
	}
	if len(f.Stages) != 3 {
		t.Fatalf("阶段数 = %d", len(f.Stages))
	}
	if f.Root == nil || f.Root.PID != 777 {
		t.Fatalf("根因进程应为执行环节: %+v", f.Root)
	}
	joined := strings.Join(f.MITRE, ",")
	if !strings.Contains(joined, "T1110") || !strings.Contains(joined, "T1078") {
		t.Fatalf("MITRE = %v", f.MITRE)
	}
}

func TestBruteSuccessIPMismatchNoFire(t *testing.T) {
	e, fs, now := newTestEngine(nil)
	e.Feed(Stage{Kind: KindBrute, When: *now, FailCount: 14, SrcIP: "198.51.100.7"})
	advance(now, time.Minute)
	e.Feed(Stage{Kind: KindLogonOK, When: *now, SrcIP: "203.0.113.99"}) // 异源
	advance(now, time.Minute)
	e.Feed(Stage{Kind: KindProc, PID: 777, StartTime: time.Unix(2000, 0),
		Path: `C:\temp\t.exe`, Dropped: true, Signed: false, When: *now})
	if findingsCount(fs) != 0 {
		t.Fatalf("异源暴破+登录不应成链")
	}
}

func TestBruteSuccessSignedProcNoFire(t *testing.T) {
	e, fs, now := newTestEngine(nil)
	e.Feed(Stage{Kind: KindBrute, When: *now, FailCount: 14, SrcIP: "198.51.100.7"})
	advance(now, time.Minute)
	e.Feed(Stage{Kind: KindLogonOK, When: *now, SrcIP: "198.51.100.7"})
	// 签名进程执行（安装器时序）不成链
	e.Feed(Stage{Kind: KindProc, PID: 777, StartTime: time.Unix(2000, 0),
		Path: `C:\temp\setup.exe`, Dropped: true, Signed: true, When: *now})
	if findingsCount(fs) != 0 {
		t.Fatalf("签名执行环节不应成链")
	}
}

func TestBruteSuccessProcTooLate(t *testing.T) {
	e, fs, now := newTestEngine(nil)
	e.Feed(Stage{Kind: KindBrute, When: *now, FailCount: 14, SrcIP: "198.51.100.7"})
	advance(now, time.Minute)
	e.Feed(Stage{Kind: KindLogonOK, When: *now, SrcIP: "198.51.100.7"})
	advance(now, 5*time.Minute) // 超过 3min 执行窗口
	e.Feed(Stage{Kind: KindProc, PID: 777, StartTime: time.Unix(2000, 0),
		Path: `C:\temp\t.exe`, Dropped: true, Signed: false, When: *now})
	if findingsCount(fs) != 0 {
		t.Fatalf("登录后 3min 外的执行不应成链")
	}
}

func TestBruteSuccessWithoutBruteNoFire(t *testing.T) {
	e, fs, now := newTestEngine(nil)
	// 只有成功登录（EVT-BRUTE 未达阈值的场景）：没有链首，不成链
	e.Feed(Stage{Kind: KindLogonOK, When: *now, SrcIP: "198.51.100.7"})
	e.Feed(Stage{Kind: KindProc, PID: 777, StartTime: time.Unix(2000, 0),
		Path: `C:\temp\t.exe`, Dropped: true, Signed: false, When: *now})
	if findingsCount(fs) != 0 {
		t.Fatalf("缺链首不应成链")
	}
}

func TestPersistRunFire(t *testing.T) {
	e, fs, now := newTestEngine(nil)
	e.Feed(Stage{Kind: KindPersist, When: *now, ItemKind: "run", ItemName: "Updater",
		ItemPath: `C:\Users\pub\AppData\Roaming\upd\svc.exe`, MITRE: "T1547.001", RefRuleID: "P-001"})
	advance(now, 3*time.Minute)
	e.Feed(Stage{Kind: KindProc, PID: 555, StartTime: time.Unix(3000, 0),
		Name: "svc.exe", Path: `C:/Users/pub/AppData/Roaming/upd/SVC.EXE`, // 大小写与斜杠方向都归一
		Signed: false, When: *now})

	f := lastFinding(t, fs)
	if f.RuleID != "CHAIN-PERSIST-RUN" {
		t.Fatalf("规则 ID = %s", f.RuleID)
	}
	// MITRE 取链首持久化手段
	if len(f.MITRE) != 1 || f.MITRE[0] != "T1547.001" {
		t.Fatalf("MITRE = %v", f.MITRE)
	}
}

func TestPersistRunSignedProcNoFire(t *testing.T) {
	e, fs, now := newTestEngine(nil)
	e.Feed(Stage{Kind: KindSvcInst, When: *now, ItemName: "LegitSvc",
		ItemPath: `C:\Program Files\Legit\svc.exe`, MITRE: "T1543.003"})
	e.Feed(Stage{Kind: KindProc, PID: 555, StartTime: time.Unix(3000, 0),
		Path: `C:\Program Files\Legit\svc.exe`, Signed: true, When: *now})
	if findingsCount(fs) != 0 {
		t.Fatalf("签名软件安装时序不应成链")
	}
}

func TestPersistRunPathMismatchNoFire(t *testing.T) {
	e, fs, now := newTestEngine(nil)
	e.Feed(Stage{Kind: KindPersist, When: *now, ItemKind: "run",
		ItemPath: `C:\Users\pub\AppData\Roaming\upd\svc.exe`})
	e.Feed(Stage{Kind: KindProc, PID: 555, StartTime: time.Unix(3000, 0),
		Path: `C:\Windows\Other\svc.exe`, Signed: false, When: *now})
	if findingsCount(fs) != 0 {
		t.Fatalf("路径不匹配不应成链")
	}
}

func TestInjectOutFire(t *testing.T) {
	e, fs, now := newTestEngine(nil)
	e.Feed(Stage{Kind: KindMem, PID: 900, Name: "svchost.exe", When: *now,
		Path: `C:\Windows\Temp\fake.exe`, RefRuleID: "MEM-1055", RefScore: 60})
	advance(now, time.Minute)
	e.Feed(Stage{Kind: KindConn, PID: 900, PeerIP: "203.0.113.9", PeerPort: 443, When: *now})

	f := lastFinding(t, fs)
	if f.RuleID != "CHAIN-INJECT-OUT" {
		t.Fatalf("规则 ID = %s", f.RuleID)
	}
	if f.Severity != model.SeverityCritical {
		t.Fatalf("严重度 = %s", f.Severity)
	}
}

func TestInjectOutNetStageFire(t *testing.T) {
	e, fs, now := newTestEngine(nil)
	e.Feed(Stage{Kind: KindMem, PID: 900, Name: "p.exe", When: *now})
	// netwatch 命中同样算外联证据
	e.Feed(Stage{Kind: KindNet, PID: 900, PeerIP: "198.51.100.9", PeerPort: 445,
		RefRuleID: "NW-003", When: *now})
	if findingsCount(fs) != 1 {
		t.Fatalf("NW 命中应补全注入链")
	}
}

func TestFiredIgnoreWindow(t *testing.T) {
	e, fs, now := newTestEngine(nil)
	// 第一条链走完
	e.Feed(Stage{Kind: KindBrute, When: *now, FailCount: 14, SrcIP: "198.51.100.7"})
	e.Feed(Stage{Kind: KindLogonOK, When: *now, SrcIP: "198.51.100.7"})
	e.Feed(Stage{Kind: KindProc, PID: 777, StartTime: time.Unix(2000, 0),
		Path: `C:\temp\t.exe`, Dropped: true, Signed: false, When: *now})
	if findingsCount(fs) != 1 {
		t.Fatalf("第一条链应完成")
	}
	// 防洪窗口内同样的序列再来一遍：不起链
	e.Feed(Stage{Kind: KindBrute, When: *now, FailCount: 14, SrcIP: "198.51.100.7"})
	e.Feed(Stage{Kind: KindLogonOK, When: *now, SrcIP: "198.51.100.7"})
	e.Feed(Stage{Kind: KindProc, PID: 778, StartTime: time.Unix(2100, 0),
		Path: `C:\temp\t2.exe`, Dropped: true, Signed: false, When: *now})
	if findingsCount(fs) != 1 {
		t.Fatalf("防洪窗口内不应重复成链")
	}
	// 防洪过期后可以再成链
	advance(now, 2*firedIgnore)
	e.Feed(Stage{Kind: KindBrute, When: *now, FailCount: 14, SrcIP: "198.51.100.7"})
	e.Feed(Stage{Kind: KindLogonOK, When: *now, SrcIP: "198.51.100.7"})
	e.Feed(Stage{Kind: KindProc, PID: 779, StartTime: time.Unix(2200, 0),
		Path: `C:\temp\t3.exe`, Dropped: true, Signed: false, When: *now})
	if findingsCount(fs) != 2 {
		t.Fatalf("防洪过期后应再次成链，实际 %d", findingsCount(fs))
	}
}

func TestAllowSkipsStage(t *testing.T) {
	alw := allow.New("")
	if err := alw.AddLocal(allow.TypePath, `c:\temp\trusted.exe`, "test"); err != nil {
		t.Fatal(err)
	}
	e, fs, _ := newTestEngine(alw)
	// 链首实体被信任：整条链从源头不成立
	e.Feed(Stage{Kind: KindProc, PID: 42, StartTime: time.Unix(1000, 0),
		Path: `C:\Temp\Trusted.EXE`, Dropped: true, Signed: false, When: time.Unix(1100, 0)})
	e.Feed(Stage{Kind: KindConn, PID: 42, StartTime: time.Unix(1000, 0),
		PeerIP: "203.0.113.9", When: time.Unix(1160, 0)})
	if findingsCount(fs) != 0 {
		t.Fatalf("白名单实体不应成链")
	}
}

func TestMachineCapEviction(t *testing.T) {
	e, fs, _ := newTestEngine(nil)
	// 灌满链首（不同 PID 各一条 pending），验证上限内不丢、不崩
	for i := uint32(1); i <= maxMachines+50; i++ {
		e.Feed(Stage{Kind: KindProc, PID: i, StartTime: time.Unix(int64(i), 0),
			Path: `C:\temp\e.exe`, Dropped: true, Signed: false, When: time.Unix(1100, 0)})
	}
	st := e.Stats()
	if st.Active > maxMachines {
		t.Fatalf("活跃链超上限: %d", st.Active)
	}
	if st.Dropped == 0 {
		t.Fatalf("超限应有淘汰计数")
	}
	if findingsCount(fs) != 0 {
		t.Fatalf("链首阶段不应产出告警")
	}
}

func TestStatsFired(t *testing.T) {
	e, _, now := newTestEngine(nil)
	e.Feed(Stage{Kind: KindMem, PID: 900, Name: "p.exe", When: *now})
	e.Feed(Stage{Kind: KindConn, PID: 900, PeerIP: "203.0.113.9", When: *now})
	st := e.Stats()
	if st.Fired != 1 || st.Active != 0 {
		t.Fatalf("Stats = %+v", st)
	}
}

func TestConcurrentFeed(t *testing.T) {
	e, _, now := newTestEngine(nil)
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				pid := uint32(g*1000 + i%50 + 1)
				e.Feed(Stage{Kind: KindProc, PID: pid, StartTime: time.Unix(1000, 0),
					Path: `C:\temp\e.exe`, Dropped: true, Signed: false, When: *now})
				e.Feed(Stage{Kind: KindConn, PID: pid, StartTime: time.Unix(1000, 0),
					PeerIP: "203.0.113.9", When: *now})
				e.Feed(Stage{Kind: KindBrute, When: *now, FailCount: 20, SrcIP: "1.2.3.4"})
			}
		}(g)
	}
	wg.Wait()
	// 只验证不崩/不竞争（-race 下有竞争即失败），不验证具体条数
}

func TestNilEngineSafe(t *testing.T) {
	var e *Engine
	e.Feed(Stage{Kind: KindConn, PID: 1}) // 不应 panic
	if e.Stats().Fired != 0 {
		t.Fatalf("nil 引擎 Stats 应为零值")
	}
}

// ---------------------------------------------------------------- 补强测试

func TestStageTimeSkewTolerance(t *testing.T) {
	e, fs, now := newTestEngine(nil)
	// evtlog 事件时间可能略早于消费时刻（30s 轮询 + 采样粒度）——
	// 链内允许 ≤2min 的倒挂
	e.Feed(Stage{Kind: KindBrute, When: *now, FailCount: 14, SrcIP: "198.51.100.7"})
	e.Feed(Stage{Kind: KindLogonOK, When: now.Add(-90 * time.Second), SrcIP: "198.51.100.7"})
	e.Feed(Stage{Kind: KindProc, PID: 777, StartTime: time.Unix(2000, 0),
		Path: `C:\temp\t.exe`, Dropped: true, Signed: false, When: *now})
	if findingsCount(fs) != 1 {
		t.Fatalf("≤2min 事件时间倒挂应能推进链")
	}
}

func TestStageSkewBeyondToleranceNoFire(t *testing.T) {
	e, fs, now := newTestEngine(nil)
	e.Feed(Stage{Kind: KindBrute, When: *now, FailCount: 14, SrcIP: "198.51.100.7"})
	// 倒挂超过 2min 容忍：视为乱序噪声，不推进
	e.Feed(Stage{Kind: KindLogonOK, When: now.Add(-5 * time.Minute), SrcIP: "198.51.100.7"})
	e.Feed(Stage{Kind: KindProc, PID: 777, StartTime: time.Unix(2000, 0),
		Path: `C:\temp\t.exe`, Dropped: true, Signed: false, When: *now})
	if findingsCount(fs) != 0 {
		t.Fatalf("超容忍倒挂不应成链")
	}
}

func TestBruteProcExactlyAt3minBoundary(t *testing.T) {
	e, fs, now := newTestEngine(nil)
	e.Feed(Stage{Kind: KindBrute, When: *now, FailCount: 14, SrcIP: "1.2.3.4"})
	e.Feed(Stage{Kind: KindLogonOK, When: *now, SrcIP: "1.2.3.4"})
	advance(now, 3*time.Minute) // 恰好 3min：边界内（<=）应成链
	e.Feed(Stage{Kind: KindProc, PID: 777, StartTime: time.Unix(2000, 0),
		Path: `C:\temp\t.exe`, Dropped: true, Signed: false, When: *now})
	if findingsCount(fs) != 1 {
		t.Fatalf("恰好 3min 边界应成链")
	}
}

func TestRefFingerprintPassthrough(t *testing.T) {
	e, fs, now := newTestEngine(nil)
	e.Feed(Stage{Kind: KindMem, PID: 900, Name: "p.exe", When: *now,
		RefRuleID: "MEM-1055", RefScore: 60, RefFingerprint: "memwatch:900:1000"})
	e.Feed(Stage{Kind: KindConn, PID: 900, PeerIP: "203.0.113.9", When: *now})
	f := lastFinding(t, fs)
	if f.Stages[0].RefFingerprint != "memwatch:900:1000" {
		t.Fatalf("阶段指纹未透传: %q", f.Stages[0].RefFingerprint)
	}
}

func TestStatsByRule(t *testing.T) {
	e, _, now := newTestEngine(nil)
	// DROP-EXEC-C2 一条
	e.Feed(Stage{Kind: KindProc, PID: 1, StartTime: time.Unix(1000, 0),
		Path: `C:\temp\a.exe`, Dropped: true, Signed: false, When: *now})
	e.Feed(Stage{Kind: KindConn, PID: 1, StartTime: time.Unix(1000, 0),
		PeerIP: "203.0.113.9", When: *now})
	// INJECT-OUT 两条（不同 PID）
	for _, pid := range []uint32{2, 3} {
		e.Feed(Stage{Kind: KindMem, PID: pid, When: *now})
		e.Feed(Stage{Kind: KindConn, PID: pid, PeerIP: "203.0.113.9", When: *now})
	}
	st := e.Stats()
	if st.ByRule["CHAIN-DROP-EXEC-C2"] != 1 || st.ByRule["CHAIN-INJECT-OUT"] != 2 {
		t.Fatalf("ByRule = %v", st.ByRule)
	}
	if st.Fired != 3 {
		t.Fatalf("Fired = %d", st.Fired)
	}
}

func TestAllowPersistItemPath(t *testing.T) {
	alw := allow.New("")
	if err := alw.AddLocal(allow.TypePath, `c:\tools\kept.exe`, "test"); err != nil {
		t.Fatal(err)
	}
	e, fs, now := newTestEngine(alw)
	// 持久化项指向被信任路径：链首直接被拦
	e.Feed(Stage{Kind: KindPersist, When: *now, ItemKind: "run", ItemName: "K",
		ItemPath: `C:\Tools\Kept.EXE`})
	e.Feed(Stage{Kind: KindProc, PID: 5, StartTime: time.Unix(1000, 0),
		Path: `C:\tools\kept.exe`, Signed: false, When: *now})
	if findingsCount(fs) != 0 {
		t.Fatalf("白名单持久化项不应成链")
	}
}

// TestPropertyRandomStreams 用固定种子的随机阶段流做不变量校验：
// 不 panic、活跃链 ≤ 上限、完成的链阶段数与叙事行一一对应、MITRE 非空。
// 这是"生产可用"的最低韧性门槛——任何后续改动破坏了状态机不变量，
// 这里先炸。
func TestPropertyRandomStreams(t *testing.T) {
	rng := rand.New(rand.NewSource(20261106))
	kinds := []string{KindProc, KindConn, KindNet, KindBrute, KindLogonOK, KindSvcInst, KindPersist, KindMem}

	// 第一段：全种类乱序大流（±1h）——只校验不 panic 与容量不变量
	e := New(Options{Now: func() time.Time { return time.Unix(2000, 0) }, OnFinding: func(Finding) {}})
	for i := 0; i < 3000; i++ {
		e.Feed(Stage{
			Kind: kinds[rng.Intn(len(kinds))],
			When: time.Unix(2000, 0).Add(time.Duration(rng.Intn(7200)-3600) * time.Second),
			PID:  uint32(rng.Intn(64) + 1),
			Name: "p.exe", Path: `C:\temp\p.exe`,
			Dropped: rng.Intn(2) == 0, Signed: rng.Intn(2) == 0,
			PeerIP: "203.0.113.9", PeerPort: 443,
			FailCount: rng.Intn(20), SrcIP: "1.2.3.4",
			ItemPath: `C:\temp\p.exe`, ItemKind: "run", ItemName: "k",
		})
		if st := e.Stats(); st.Active > maxMachines {
			t.Fatalf("活跃链越界: %d", st.Active)
		}
	}

	// 第二段：高碰撞小键空间——逼出完成的链，校验结构不变量
	e2 := New(Options{
		Now: func() time.Time { return time.Unix(2000, 0) },
		OnFinding: func(f Finding) {
			if len(f.Stages) < 2 || len(f.Lines) != len(f.Stages) || len(f.MITRE) == 0 {
				t.Errorf("链结构不变量被破坏: stages=%d lines=%d mitre=%v",
					len(f.Stages), len(f.Lines), f.MITRE)
			}
		},
	})
	for i := 0; i < 3000; i++ {
		e2.Feed(Stage{Kind: kinds[rng.Intn(len(kinds))],
			When: time.Unix(2000, 0).Add(time.Duration(rng.Intn(120)-60) * time.Second),
			PID:  uint32(rng.Intn(8) + 1), Name: "p.exe", Path: `C:\temp\p.exe`,
			Dropped: true, Signed: false, PeerIP: "203.0.113.9",
			FailCount: 20, SrcIP: "1.2.3.4", ItemPath: `C:\temp\p.exe`,
			ItemKind: "run", ItemName: "k",
		})
	}
	t.Logf("不变量校验完成，完成链 %d 条", e2.Stats().Fired)
}

// BenchmarkFeedHot 量化热路径成本：512 条 pending 链 + 高频外联阶段
// （每轮 scan 对每个有连接的进程喂一次 conn 阶段，链 key 大多对不上）。
// 预算：单次 Feed ≤ 数微秒，否则 2s 扫描周期会被 Feed 拖垮。
func BenchmarkFeedHot(b *testing.B) {
	base := time.Unix(1000, 0)
	e := New(Options{Now: func() time.Time { return base.Add(time.Minute) }, OnFinding: func(Finding) {}})
	// 灌满链首
	for i := uint32(1); i <= maxMachines; i++ {
		e.Feed(Stage{Kind: KindProc, PID: i, StartTime: base,
			Path: `C:\temp\e.exe`, Dropped: true, Signed: false, When: base})
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pid := uint32(i%256 + 1)
		e.Feed(Stage{Kind: KindConn, PID: pid, StartTime: base,
			PeerIP: "203.0.113.9", PeerPort: 443, When: base.Add(time.Minute)})
	}
}

// TestPurgeAllowlisted 验证"加白即回收"链侧语义：白名单更新后，任何
// 环节命中白名单的进行中链整体作废（与服务端 AddAllowlist 回收语义对齐）。
func TestPurgeAllowlisted(t *testing.T) {
	alw := allow.New("")
	e, fs, _ := newTestEngine(alw)
	// 先在白名单为空时起链（proc 环节已收集进 machine）
	e.Feed(Stage{Kind: KindProc, PID: 42, StartTime: time.Unix(1000, 0),
		Path: `C:\Users\pub\Downloads\tool.exe`, Dropped: true, Signed: false,
		When: time.Unix(1100, 0)})
	if e.Stats().Active != 1 {
		t.Fatalf("链首应处于 pending")
	}
	// 运维随后加白该镜像：未完成的链必须立即作废
	if err := alw.AddLocal(allow.TypePath, `c:\users\pub\downloads\tool.exe`, "test"); err != nil {
		t.Fatal(err)
	}
	if n := e.PurgeAllowlisted(); n != 1 {
		t.Fatalf("应回收 1 条链，实际 %d", n)
	}
	if e.Stats().Active != 0 {
		t.Fatalf("回收后不应有活跃链")
	}
	// 被回收的链不再闭合：外联阶段来了也只当无主信号丢弃
	e.Feed(Stage{Kind: KindConn, PID: 42, StartTime: time.Unix(1000, 0),
		PeerIP: "203.0.113.9", When: time.Unix(1160, 0)})
	if findingsCount(fs) != 0 {
		t.Fatalf("已回收的链不应再产出告警")
	}
	// 新起的链首会被 Feed 时的白名单检查直接拦下（双保险）
	e.Feed(Stage{Kind: KindProc, PID: 43, StartTime: time.Unix(1000, 0),
		Path: `C:\Users\pub\Downloads\tool.exe`, Dropped: true, Signed: false,
		When: time.Unix(1200, 0)})
	if e.Stats().Active != 0 {
		t.Fatalf("白名单实体不应再起链")
	}
}
