//go:build windows
// +build windows

// memwatch 接线层：内存威胁巡检——把 /memscan 的人工单 PID 排查产品化
// 为周期性检测。
//
// 检测语义：进程注入（T1055）绕不过的物理痕迹是"注入后的匿名可执行内存
// 残留"——私有（MEM_PRIVATE）+ 可执行 + 无文件映射 + 起始 MZ 的区域。
// 内核回调域（CreateRemoteThread/ProcessAccess）用户态不可见，这是它的
// 最佳近似：看不见注入动作，但看得见注入结果。
//
// 诚实边界（不得对外宣传成"内存取证"）：
//   - 只有 VirtualQueryEx 元数据 + 每个可疑区域 2 字节 MZ 探测，
//     不读取/不缓存/不传输任何其他内存内容；
//   - 受保护进程（PPL）打不开，如实跳过；预算超限如实标 truncated；
//   - **误报源真实存在**：.NET JIT、打包程序（UPX 运行时解压）、Electron
//     类应用都有合法的私有可执行内存——所以输出是"证据链 + suspicious"，
//     不定 malicious，签名富化与白名单由上层处置；
//   - 选样只覆盖"引擎有信号或新进程"的集合，长驻低风险进程靠轮转慢慢
//     覆盖，不是全量内存扫描（那会烧掉探针 CPU 预算）。
package agentapp

import (
	"context"
	"fmt"
	"os"
	"sort"
	"time"

	"zedr/internal/agent/chain"
	"zedr/internal/agent/enrich"
	"zedr/internal/agent/state"
	"zedr/internal/agent/winapi"
	"zedr/internal/model"
)

// memWatchBudget 是单轮扫描的进程数上限：每轮 5min，10 个 × 单进程
// 元数据扫描（毫秒级~几十毫秒）——对探针 CPU 的贡献可忽略，同时保证
// 高风险集合的覆盖新鲜度（选样按分数排，最可疑的永远先扫）。
const memWatchBudget = 10

// memWatchCandidate 是巡检选样的一条候选（从本地进程视图投影）。
type memWatchCandidate struct {
	PID       uint32
	Name      string
	Path      string
	CmdLine   string
	StartTime time.Time
	Score     int
}

// selectMemCandidates 是巡检选样的纯函数（可单测）：
//   - 只选引擎有信号的进程（Score>0：白名单外、可写目录、外联、血缘
//     异常……任何一个检测层的信号都算——内存巡检是"对可疑者的深查"，
//     不做全量盲扫）；
//   - 分层：落地即执行关联（10min 窗口内）的进程优先——刚落地的 PE
//     最该深查；其余按分数降序、同级最新优先；
//   - 探针自身进程排除。
func selectMemCandidates(rows []state.ProcRow, selfPID uint32, budget int, landed map[uint32]time.Time) []memWatchCandidate {
	var tier1, tier2 []memWatchCandidate
	for _, r := range rows {
		if r.PID == 0 || r.PID == selfPID || r.Score <= 0 {
			continue
		}
		c := memWatchCandidate{
			PID: r.PID, Name: r.Name, Path: r.Path, CmdLine: r.CmdLine,
			StartTime: r.FirstSeen, Score: r.Score,
		}
		if lt, ok := landed[r.PID]; ok && time.Since(lt) <= 10*time.Minute {
			tier1 = append(tier1, c)
			continue
		}
		tier2 = append(tier2, c)
	}
	sort.Slice(tier1, func(i, j int) bool { return tier1[i].Score > tier1[j].Score })
	sort.Slice(tier2, func(i, j int) bool {
		if tier2[i].Score != tier2[j].Score {
			return tier2[i].Score > tier2[j].Score
		}
		return tier2[i].StartTime.After(tier2[j].StartTime)
	})
	out := append(tier1, tier2...)
	if len(out) > budget {
		out = out[:budget]
	}
	return out
}

// memHit 是单进程扫描后的聚合结论。
type memHit struct {
	Suspicious  int    // 私有可执行 ≥4KB 区域数
	MZConfirmed int    // 其中 PE 头确认为 MZ 的（ReadProcessMemory 失败的不计）
	TotalBytes  uint64 // MZ 确认区域的体积和
	Truncated   bool
}

// scoreMemHit 把扫描结果折算成告警定级。返回 nil 表示不值得告警。
// 评分口径：1 个 MZ 区域 = 证据成立（suspicious/45）；≥3 个或 ≥4MB =
// 注入载荷通常伴随多区域/大体积（high/60）。单看"有"不看"多"会把
// JIT/打包程序一棍打死，多区域是更强的非常态信号。
func scoreMemHit(hit memHit) *memFinding {
	if hit.MZConfirmed <= 0 {
		return nil
	}
	sev, score := model.SeverityMedium, 45
	if hit.MZConfirmed >= 3 || hit.TotalBytes >= 4<<20 {
		sev, score = model.SeverityHigh, 60
	}
	return &memFinding{Severity: sev, Score: score, Hit: hit}
}

// memFinding 是巡检产出（emit 前的中间结构）。
type memFinding struct {
	Severity model.Severity
	Score    int
	Hit      memHit
}

// memwatchLoop 是周期巡检循环（HG_AGENT_MEMWATCH 开关，默认 5min）。
func (a *Agent) memwatchLoop(ctx context.Context) {
	interval := a.cfg.MemWatchInterval
	if interval < time.Minute {
		interval = 5 * time.Minute
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			a.memwatchOnce()
		}
	}
}

// memwatchOnce 执行一轮选样+扫描+告警。单 goroutine 调用，无锁设计。
func (a *Agent) memwatchOnce() {
	rows := a.store.Procs(2000)
	// 落地优先名单：10 分钟内被"落地即执行"关联过的进程
	a.memLandedMu.Lock()
	landed := make(map[uint32]time.Time, len(a.memLanded))
	for pid, at := range a.memLanded {
		if time.Since(at) <= 10*time.Minute {
			landed[pid] = at
		} else {
			delete(a.memLanded, pid)
		}
	}
	a.memLandedMu.Unlock()

	scanned, hits := 0, 0
	for _, c := range selectMemCandidates(rows, uint32(os.Getpid()), memWatchBudget, landed) {
		res, err := winapi.ScanMemory(c.PID)
		if err != nil {
			// 受保护/已退出是正常调查结论，静默跳过（有计数）
			continue
		}
		scanned++
		hit := memHit{
			Suspicious: res.SuspiciousTotal,
			Truncated:  res.SuspiciousTruncated,
		}
		for _, s := range res.Suspicious {
			if s.PEHeader != nil && *s.PEHeader {
				hit.MZConfirmed++
				hit.TotalBytes += s.Size
			}
		}
		f := scoreMemHit(hit)
		if f == nil {
			continue
		}
		var meta enrich.Meta
		// 签名富化：系统目录内签名有效的进程几乎不会有异常私有可执行
		//（.NET JIT 的区域无 MZ 头，不会到这里）——命中即值得上报
		if c.Path != "" {
			meta = a.enr.Describe(c.Path)
			if meta.Signed && meta.SignatureOK && meta.InSystem {
				a.log.Debug("memwatch_signed_skip", "pid", c.PID, "path", c.Path)
				continue
			}
			if hit, _ := a.alw.Match(meta.Hash, c.Path, meta.Signer, "", c.Name, ""); hit {
				continue
			}
		}
		if a.eng.IsWarmup(time.Now()) {
			continue
		}
		a.emitMemFinding(c, *f, meta)
		hits++
	}
	if scanned > 0 {
		a.log.Debug("memwatch_round", "scanned", scanned, "hits", hits)
	}
	a.memScans.Store(int64(scanned))
	a.memHits.Store(int64(hits))
}

// emitMemFinding 组装 T1055 证据告警。
func (a *Agent) emitMemFinding(c memWatchCandidate, f memFinding, meta enrich.Meta) {
	// 指纹先算：链阶段的来源回指与告警本体同值
	fp := fmt.Sprintf("memwatch:%d:%d", c.PID, c.StartTime.Unix())

	// 攻击链馈送：MEM-1055 作为注入链首（INJECT-OUT）。白名单/签名
	// 护栏已在 memwatchOnce 过滤，这里无条件喂。
	if a.chainE != nil {
		a.chainE.Feed(chain.Stage{
			Kind: chain.KindMem, When: time.Now(),
			PID: c.PID, Name: c.Name, Path: c.Path, CmdLine: c.CmdLine,
			Hash: meta.Hash, Signer: meta.Signer, Signed: meta.Signed,
			RefRuleID: "MEM-1055", RefScore: f.Score, RefFingerprint: fp,
		})
	}

	size := fmt.Sprintf("%.1fMB", float64(f.Hit.TotalBytes)/(1<<20))
	summary := fmt.Sprintf(
		"进程 %s(PID %d) 的地址空间发现 %d 个私有可执行区域（%d 个带 PE 头，合计 %s）。"+
			"私有可执行内存中的 PE 头是进程注入（T1055）完成后的残留证据；"+
			"注意：打包程序（UPX 运行时解压）也可能呈现此形态，请结合签名与落地记录判断。",
		c.Name, c.PID, f.Hit.Suspicious, f.Hit.MZConfirmed, size)
	a.emitAlert(model.AlertEnvelope{
		Fingerprint: fp,
		Title: fmt.Sprintf("内存威胁：私有可执行内存含 PE 头（%d 区域 / %s）",
			f.Hit.MZConfirmed, size),
		Summary:     summary,
		Verdict:     model.VerdictSuspicious,
		Severity:    f.Severity,
		Score:       f.Score,
		PID:         c.PID,
		ProcessName: c.Name,
		ImagePath:   c.Path,
		ProcUser:    "SYSTEM/MEMWATCH",
		HashSHA256:  meta.Hash,
		Signer:      meta.Signer,
		Signed:      meta.Signed,
		RuleIDs:     []string{"MEM-1055"},
		MITRE:       []string{"T1055"},
		Evidence: model.Evidence{
			Process: model.ProcEvidence{
				PID: c.PID, Name: c.Name, Path: c.Path, CmdLine: c.CmdLine,
				StartTime:  c.StartTime,
				HashSHA256: meta.Hash, Signer: meta.Signer,
				Signed: meta.Signed, SignatureOK: meta.SignatureOK,
			},
			Signals: []model.Signal{{
				Layer: "memwatch", ID: "MEM-1055", Name: "私有可执行内存含 PE 头",
				Score: f.Score, Note: summary, MITRE: "T1055",
			}},
			Notes: []string{
				fmt.Sprintf("suspicious_regions=%d mz_confirmed=%d total_bytes=%d truncated=%v",
					f.Hit.Suspicious, f.Hit.MZConfirmed, f.Hit.TotalBytes, f.Hit.Truncated),
			},
		},
		OccurredAt: time.Now(),
	})
}
