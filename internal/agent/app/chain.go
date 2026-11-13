//go:build windows
// +build windows

// chain 接线层：把多源信号喂给攻击链关联引擎，并把链告警转成统一信封。
//
// 分工与 netwatch/filedef 接线同构：chain 包只负责"阶段序列是否成链"
// （机制），本文件负责"喂什么、喂不喂"（策略）——探针自身安装产物排除、
// 阶段富化；白名单在引擎内单点判定，馈送方不重复。
package agentapp

import (
	"fmt"
	"hash/fnv"
	"os"
	"strings"
	"time"

	"zedr/internal/agent/chain"
	"zedr/internal/agent/collect"
	"zedr/internal/agent/detect"
	"zedr/internal/agent/winapi"
	"zedr/internal/model"
)

// chainSelfPath 是探针自身镜像的归一化路径：自安装（服务/Run 键指向
// zedr-agent.exe 后随即自启）是合法时序，PERSIST-RUN 链必须排除，
// 否则每次安装/升级都会凭空产出一条"持久化项被执行"的链告警。
var chainSelfPath = func() string {
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	return chainNormPath(exe)
}()

// chainNormPath 与 chain.normPath 同口径的路径归一化（键匹配两侧一致）。
func chainNormPath(p string) string {
	return strings.ToLower(strings.ReplaceAll(strings.TrimSpace(p), "/", "\\"))
}

// chainFeedProc 在 scan 循环喂进程创建阶段。
//
// 全量喂（含 below_threshold/warmup/duplicate 的 Result）：链消费的是
// "实体 + 时序"事实，不重复引擎的阈值决策；白名单豁免的 Result 没有信号
// 也没有完整证据，直接跳过（引擎内 allowlisted 还会再拦一道，双保险）。
func (a *Agent) chainFeedProc(pi collect.ProcessInfo, res *detect.Result) {
	if a.chainE == nil || res == nil || res.Suppressed == "whitelist" {
		return
	}
	dropped := false
	for _, sg := range res.Evidence.Signals {
		if sg.ID == "DROP-001" {
			dropped = true
			break
		}
	}
	a.chainE.Feed(chain.Stage{
		Kind: chain.KindProc, When: time.Now(),
		PID: pi.PID, StartTime: pi.StartTime,
		Name: pi.Name, Path: pi.Path, CmdLine: pi.CmdLine, User: pi.User,
		Hash:    res.Evidence.Process.HashSHA256,
		Signer:  res.Evidence.Process.Signer,
		Signed:  res.Evidence.Process.Signed,
		Dropped: dropped,
	})
}

// chainObserveConns 每轮扫描喂外联阶段（来自本轮已拉取的连接表，
// 零新增系统调用）。只喂"有非回环对端"的进程；引擎对没有 pending 链的
// key 是 O(1) 丢弃，不需要在这里预筛。探针自身进程跳过——它到服务端的
// 上报连接是常态，且自身永远不会成为链的任何环节。
func (a *Agent) chainObserveConns(snap *collect.Snapshot) {
	if a.chainE == nil {
		return
	}
	now := time.Now()
	self := uint32(os.Getpid())
	for pid, conns := range snap.Conns {
		if pid == self {
			continue
		}
		ip, port, ok := chainFirstOutbound(conns)
		if !ok {
			continue
		}
		name, start := a.coll.IdentOf(snap, pid)
		a.chainE.Feed(chain.Stage{
			Kind: chain.KindConn, When: now,
			PID: pid, StartTime: start, Name: name,
			PeerIP: ip, PeerPort: uint32(port),
		})
	}
}

// chainFirstOutbound 取连接表里第一条非回环外联对端。SYN_SENT 也算——
// 被丢弃的扫描与被墙的 C2 都到不了 ESTABLISHED，尝试本身就是行为证据。
func chainFirstOutbound(conns []winapi.TCPConn) (string, uint16, bool) {
	for _, c := range conns {
		if c.State == "LISTEN" {
			continue
		}
		if c.RemoteIP == "" || !isChainOutboundIP(c.RemoteIP) {
			continue
		}
		return c.RemoteIP, c.RemotePort, true
	}
	return "", 0, false
}

// isChainOutboundIP 排除回环与未指定地址（与 chain.outboundPeer 同口径）。
func isChainOutboundIP(ip string) bool {
	if ip == "0.0.0.0" || ip == "::" || ip == "::1" {
		return false
	}
	return !strings.HasPrefix(ip, "127.")
}

// chainSamplePeer 为 net 阶段取对端样例（netwatch Finding 不带对端结构，
// 从同轮快照的连接表补一条作为证据）。
func chainSamplePeer(conns []winapi.TCPConn) (string, uint16) {
	ip, port, ok := chainFirstOutbound(conns)
	if !ok {
		return "", 0
	}
	return ip, port
}

// chainNotSelf 判断持久化指向路径是否为探针自身镜像（自安装排除）。
func chainNotSelf(path string) bool {
	if chainSelfPath == "" || path == "" {
		return true
	}
	return chainNormPath(path) != chainSelfPath
}

// chainFirstMITRE 取技术映射首项。
func chainFirstMITRE(ms []string) string {
	if len(ms) == 0 {
		return ""
	}
	return ms[0]
}

// emitChainFinding 是 chain.OnFinding 回调：链告警转统一信封。
//
// 证据面：每阶段一条 Signal（Layer=chain）+ 阶段时间线 Notes；根因进程
// 上探到信封顶层（PID/镜像/命令行），管理台告警抽屉与 AI 研判按普通
// 告警消费，无需特殊处理。指纹 = 规则 + key 哈希 + 链起点：同链不同实例
// 指纹不同（每次完成都是一条新告警），防洪窗口负责防重复。
func (a *Agent) emitChainFinding(f chain.Finding) {
	env := model.AlertEnvelope{
		Fingerprint: fmt.Sprintf("chain:%s:%x:%d", f.RuleID, chainKeyHash(f.Key), f.Started.Unix()),
		Title:       f.Title,
		Summary:     f.Summary,
		Verdict:     f.Verdict,
		Severity:    f.Severity,
		Score:       f.Score,
		RuleIDs:     []string{f.RuleID},
		MITRE:       f.MITRE,
		ProcUser:    "SYSTEM/CHAIN",
		OccurredAt:  time.Now(),
	}

	if f.Root != nil {
		env.PID = f.Root.PID
		env.ProcessName = f.Root.Name
		env.ImagePath = f.Root.Path
		env.CmdLine = f.Root.CmdLine
		env.HashSHA256 = f.Root.Hash
		env.Signer = f.Root.Signer
		env.Signed = f.Root.Signed
		if f.Root.User != "" {
			env.ProcUser = f.Root.User
		}
	}

	sigs := make([]model.Signal, 0, len(f.Stages))
	notes := []string{
		"chain_rule=" + f.RuleID,
		"chain_key=" + f.Key,
		"chain_started=" + f.Started.Format(time.RFC3339),
		"confidence=high（全确定性环节）",
	}
	for i, st := range f.Stages {
		line := ""
		if i < len(f.Lines) {
			line = f.Lines[i]
		}
		sigs = append(sigs, model.Signal{
			Layer: "chain",
			ID:    fmt.Sprintf("%s#%d", f.RuleID, i+1),
			Name:  chain.KindLabel(st.Kind),
			Score: st.RefScore,
			Note:  line,
			MITRE: st.MITRE,
		})
		notes = append(notes, line)
		// 阶段回指来源告警：服务端事件叙事（A1..An）与 AI 研判引用
		// 靠它把链阶段对账回真实告警，不靠时间窗猜
		if st.RefFingerprint != "" {
			notes = append(notes, fmt.Sprintf("stage%d_ref=%s %s",
				i+1, st.RefRuleID, st.RefFingerprint))
		}
	}
	env.Evidence = model.Evidence{Signals: sigs, Notes: notes}
	if f.Root != nil {
		env.Evidence.Process = model.ProcEvidence{
			PID: f.Root.PID, Name: f.Root.Name, Path: f.Root.Path,
			CmdLine: f.Root.CmdLine, User: f.Root.User, StartTime: f.Root.StartTime,
			HashSHA256: f.Root.Hash, Signer: f.Root.Signer, Signed: f.Root.Signed,
		}
	}

	a.emitAlert(env)
}

// chainKeyHash 把链 key 压成短哈希（key 可能含完整路径，指纹不携带原文）。
func chainKeyHash(key string) uint64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(key))
	return h.Sum64()
}
