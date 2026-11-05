package chain

import (
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
