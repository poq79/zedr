//go:build windows
// +build windows

// netwatch 接线层：把行为检测 Finding 转成统一 AlertEnvelope。
//
// 分工与 persist/inventory 同构：netwatch 包只负责"行为是否越阈值"（机制），
// 本文件负责"告警怎么富化、怎么定级、要不要发"（策略）——白名单优先、
// 富化签名证据、冷启动静默期与引擎同口径。
package agentapp

import (
	"fmt"
	"strings"
	"time"

	"zedr/internal/agent/chain"
	"zedr/internal/agent/collect"
	"zedr/internal/agent/enrich"
	"zedr/internal/agent/netwatch"
	"zedr/internal/agent/winapi"
	"zedr/internal/model"
)

// systemProcNames 是"系统进程名"启发式集合（netwatch 用它放大阈值抑制误报）。
//
// 诚实边界：进程名可伪造，这**不是**安全边界只是降噪——伪造系统名的进程
// 在两处必然露馅：① 这里触发告警时富化会发现镜像路径不在系统目录（加注
// 复核提示）；② 路径信誉/签名/血缘各层照常工作。集合只收"天然大量合法
// 扇出"的系统组件，而不是所有系统进程。
var systemProcNames = map[string]bool{
	"SVCHOST.EXE": true, "LSASS.EXE": true, "SERVICES.EXE": true,
	"WININIT.EXE": true, "WINLOGON.EXE": true, "CSRSS.EXE": true,
	"SMSS.EXE": true, "DLLHOST.EXE": true, "TASKHOSTW.EXE": true,
	"SPOOLSV.EXE": true, "MSMPENG.EXE": true, "CONHOST.EXE": true,
	"RUNTIMEBROKER.EXE": true, "SIHOST.EXE": true, "CTFMON.EXE": true,
}

// trustKey 是 trusted 抽查结果的缓存键（PID 复用靠启动时间区分）。
type trustKey struct {
	pid   uint32
	start int64
}

// trustEntry 是一次抽查结论与其新鲜度。
type trustEntry struct {
	trusted bool
	at      time.Time
}

// procTrusted 判定 netwatch 的"可信进程"（阈值放大 ×3 的依据）。
//
// 名字在系统进程名集合只是初筛——名字可伪造：svchost.exe 落在 TEMP 是
// 老把戏，放大会让伪装者的扫描阈值变成三倍（漏报方向）。对命中系统名
// 的进程抽查一次 ImagePath：镜像不在系统目录 → 不放大（宁可多告警也
// 不给伪装者降敏），且告警侧本就有"名像系统、路径不像"的伪装标注。
// 每 tick 只对 1-3 个 svchost 类进程发生，成本可忽略；结论按
// (pid, starttime) 缓存 60s，长驻进程不重复验路径。路径解析失败
// （进程刚退出）→ 不放大也不缓存，倾向更敏感的一侧。
func (a *Agent) procTrusted(pid uint32, name string, start time.Time) bool {
	if !systemProcNames[strings.ToUpper(name)] {
		return false
	}
	now := time.Now()
	key := trustKey{pid: pid, start: start.Unix()}
	a.trustMu.Lock()
	if e, ok := a.trustCache[key]; ok && now.Sub(e.at) < time.Minute {
		a.trustMu.Unlock()
		return e.trusted
	}
	a.trustMu.Unlock()

	path, err := winapi.ImagePath(pid)
	trusted := err == nil && path != "" && looksLikeSystemPath(path)
	a.trustMu.Lock()
	if len(a.trustCache) > 128 {
		a.trustCache = map[trustKey]trustEntry{} // 防无界：整体重建即可
	}
	a.trustCache[key] = trustEntry{trusted: trusted, at: now}
	a.trustMu.Unlock()
	if !trusted && err == nil {
		a.log.Warn("netwatch_name_disguise_suspect",
			"pid", pid, "name", name, "path", path,
			"note", "系统进程名、非系统目录镜像——不享受阈值放大")
	}
	return trusted
}

// netObserve 消费一轮采集快照，驱动网络行为检测并把命中转为告警。
func (a *Agent) netObserve(snap *collect.Snapshot) {
	now := time.Now()

	// 只为"本轮有连接"的进程构造标识（netwatch 只评估有连接的进程）；
	// 启动时间来自采集器最完整口径，用于 PID 复用清窗。
	procs := make(map[uint32]netwatch.ProcIdent, len(snap.Conns))
	for pid := range snap.Conns {
		name, start := a.coll.IdentOf(snap, pid)
		ppid := uint32(0)
		if p, ok := snap.Procs[pid]; ok {
			ppid = p.PPID
		}
		procs[pid] = netwatch.ProcIdent{
			PID: pid, PPID: ppid, Name: name, StartTime: start,
			Trusted: a.procTrusted(pid, name, start),
		}
	}

	findings := a.nw.Observe(netwatch.Tick{
		TakenAt: now,
		Conns:   snap.Conns,
		Procs:   procs,
	})
	if len(findings) == 0 {
		return
	}

	// 冷启动静默期与进程检测引擎同口径：窗口数据刚建立不久，
	// "第一分钟的扇出"既不完整也不可信，宁可漏这一窗。
	if a.eng.IsWarmup(now) {
		a.log.Debug("netwatch_warmup_suppressed", "findings", len(findings))
		return
	}
	for _, f := range findings {
		a.emitNetFinding(f, snap)
	}
}

// emitNetFinding 单条行为告警：白名单 → 富化 → 组装统一信封。
func (a *Agent) emitNetFinding(f netwatch.Finding, snap *collect.Snapshot) {
	// 镜像路径：进程已退出时 ImagePath 查不到，退回快照期记住的名字口径
	path, err := winapi.ImagePath(f.Ident.PID)
	if err != nil || path == "" {
		path = f.Ident.Path
	}
	var meta enrich.Meta
	haveMeta := false
	if path != "" {
		meta = a.enr.Describe(path)
		haveMeta = true
	}

	// 白名单优先：运维明确信任的镜像不产生行为告警
	if hit, _ := a.alw.Match(meta.Hash, path, meta.Signer, "", f.Ident.Name, ""); hit {
		a.log.Debug("netwatch_whitelisted", "pid", f.Ident.PID, "rule", f.RuleID)
		return
	}

	// 指纹先算：链阶段的来源回指与告警本体必须同值（AI 研判/事件叙事
	// 靠它把链阶段精确对账回原始告警）
	bucket := time.Now().Truncate(15 * time.Minute).Unix()
	fp := fmt.Sprintf("nw:%s:%d:%d:%d",
		f.RuleID, f.Ident.PID, f.Ident.StartTime.Unix(), bucket)

	// 攻击链馈送：NW 命中作为链的外联证据（DROP-EXEC-C2 / INJECT-OUT
	// 的第二环）。对端样例从同轮快照补齐。
	if a.chainE != nil {
		ip, port := chainSamplePeer(snap.Conns[f.Ident.PID])
		a.chainE.Feed(chain.Stage{
			Kind: chain.KindNet, When: time.Now(),
			PID: f.Ident.PID, StartTime: f.Ident.StartTime,
			Name: f.Ident.Name, Path: path,
			Hash: meta.Hash, Signer: meta.Signer, Signed: meta.Signed,
			PeerIP: ip, PeerPort: uint32(port),
			RefRuleID: f.RuleID, RefScore: f.Score, RefFingerprint: fp,
			MITRE: chainFirstMITRE(f.MITRE), Note: f.Summary,
		})
	}

	// "系统进程名 + 非系统目录镜像"是伪装强线索：阈值被放大过（可能压住
	// 更早的告警），必须在这里把疑点显式交给人工。
	summary := f.Summary
	if f.Ident.Trusted && haveMeta && !meta.InSystem && !looksLikeSystemPath(path) {
		summary += "；注意：进程名属于系统进程但镜像不在系统目录，存在伪装可能，请人工复核"
		a.log.Warn("netwatch_name_disguise_suspect",
			"pid", f.Ident.PID, "name", f.Ident.Name, "path", path)
	}

	// 运行身份：行为告警的证据面与进程告警对齐（AI 研判与运营视图都
	// 依赖"谁在跑"）；进程已退出时解析失败留空，不冒充 SYSTEM。
	procUser, _ := winapi.ProcessUser(f.Ident.PID)
	sessionID, _ := winapi.SessionID(f.Ident.PID)

	evidence := model.Evidence{
		Process: model.ProcEvidence{
			PID: f.Ident.PID, PPID: f.Ident.PPID, Name: f.Ident.Name, Path: path,
			User: procUser, SessionID: sessionID,
			StartTime:  f.Ident.StartTime,
			HashSHA256: meta.Hash, Signer: meta.Signer,
			Signed: meta.Signed, SignatureOK: meta.SignatureOK,
		},
		Signals: []model.Signal{{
			Layer: "netwatch", ID: f.RuleID, Name: "网络行为检测",
			Score: f.Score, Note: f.Summary, MITRE: strings.Join(f.MITRE, ","),
		}},
		Notes: f.Notes,
	}
	// 网络证据：该进程当前连接（钳制 20 条，防超大连接表撑爆告警体）
	if conns := snap.Conns[f.Ident.PID]; len(conns) > 0 {
		nc := make([]model.NetConn, 0, 20)
		for _, c := range conns {
			if len(nc) >= 20 {
				break
			}
			nc = append(nc, model.NetConn{
				Proto: c.Proto, LocalIP: c.LocalIP, LocalPort: uint32(c.LocalPort),
				RemoteIP: c.RemoteIP, RemotePort: uint32(c.RemotePort), State: c.State,
			})
		}
		evidence.Network = nc
	}

	// 指纹带 15 分钟桶：持续扫描按桶重复送达（证据会更新），
	// 同一桶内的重复命中交给服务端指纹去重吸收
	a.emitAlert(model.AlertEnvelope{
		Fingerprint: fp,
		Title:       f.Title,
		Summary:     summary,
		Verdict:     f.Verdict,
		Severity:    f.Severity,
		Score:       f.Score,
		PID:         f.Ident.PID,
		PPID:        f.Ident.PPID,
		ProcessName: f.Ident.Name,
		ImagePath:   path,
		ProcUser:    procUser,
		RuleIDs:     []string{f.RuleID},
		MITRE:       f.MITRE,
		Evidence:    evidence,
		OccurredAt:  time.Now(),
	})
}
