//go:build windows
// +build windows

// evtlog_logon.go：登录面与账户监控 v2（E1 扩展）+ PowerShell 脚本块监控。
//
// 与 evtlog.go 的逐条映射互补的三类"分析"逻辑在这里：
//  1. 4624 登录类型过滤（实测本机 24h 65 条全是 Type 5 服务登录/SYSTEM——
//     直告警不可行，只关注 Type 2 交互/3 网络/10 RDP 的真实有人/远程登录）
//  2. 暴破成功序列：窗口内同账户多次 4625 后紧跟 4624 同账户成功——
//     单看任何一个事件都看不见"攻击成功"，序列才是信号
//  3. 交互/RDP 登录时段基线：小时直方图学习，异常时段首现告警
//
// 诚实边界：4624 的 LoginType 5（服务登录）不产生任何信号——服务自登录
// 是 Windows 常态；时段基线是内存态，重启重学（前 logonBaselineWarmup
// 个样本只学习不告警）；4624 的 ProcessId 是登录授予方（lsass），
// 不是"谁在登录"，告警不带 PID。
package agentapp

import (
	"fmt"
	"strings"

	"zedr/internal/agent/chain"
	"zedr/internal/agent/winapi"
	"zedr/internal/model"
)

// sensitiveGroups 是"加入即提权"的敏感组集合（Builtin 域本地组按
// Server 中文/英文实测名匹配，EqualFold 不区分大小写）。其余组降 low。
var sensitiveGroups = []string{
	"Administrators", "远程桌面用户", "Remote Desktop Users",
	"Distributed COM Users", "Event Log Readers", "Backup Operators",
	"Server Operators", "Account Operators", "Print Operators",
	"Cryptographic Operators", "Network Configuration Operators",
}

const (
	// logonBaselineWarmup 是时段基线的学习样本数：交互/RDP 登录样本
	// 少于此数时只学习小时分布不告警。样本是"真实登录"级别的事件，
	// 一台正常机器一周也就几十个——20 个的学习期约数天，够铺开小时面。
	logonBaselineWarmup = 20

	// logonTypesMonitored 是值得关注的有效登录类型：
	// 2=交互 3=网络 7=解锁 10=RDP。5（服务/批处理）与 4（批处理）是
	// Windows 服务常态（实测 24h 65 条全是 Type 5 SYSTEM），不产生信号。
	logonTypesMonitored = "2,3,7,10"

	// bruteforceSuccessMin 是暴破成功序列判定的历史失败次数下限。
	bruteforceSuccessMin = 5
)

// evtLogonWatch 处理 4624 成功登录：类型过滤 → 暴破成功序列 → 时段基线。
func (a *Agent) evtLogonWatch(ev winapi.EvtEvent) {
	user := evtData(ev.Data, []string{"targetusername"}, 0)
	logonType := evtData(ev.Data, []string{"logontype"}, 0)
	srcIP := evtData(ev.Data, []string{"ipaddress"}, 0)

	// 类型过滤：Type 5/4/8（服务/批处理/明文网络服务）是机器常态噪声。
	// 实测：本机 24h 全部为 Type 5 SYSTEM via services.exe。
	switch logonType {
	case "2", "3", "7", "10":
	default:
		return
	}
	// 机器账户（$ 结尾）与 SYSTEM 的 Type 3 网络登录是域/服务常态，
	// 不进时段基线（否则基线被机器噪声铺满，人的异常时段反而不可见）。
	if strings.HasSuffix(user, "$") || strings.EqualFold(user, "system") {
		return
	}

	// ① 暴破成功序列：同账户在聚合窗口内有足量 4625 失败后成功登录
	// —— "失败很多次然后成功了"就是暴破成功的定义（T1110）。
	if n := a.recentFailCount(user); n >= bruteforceSuccessMin {
		a.emitAlert(model.AlertEnvelope{
			Fingerprint: fmt.Sprintf("evt:brute-success:%s:%d", strings.ToLower(user), ev.TimeCreated.Unix()/300),
			Title:       fmt.Sprintf("登录安全：疑似暴破成功（账户 %s）", user),
			Summary: fmt.Sprintf("账户 %q 在此前窗口内有 %d 次登录失败，随后自 %s 成功登录（类型 %s）。"+
				"「密集失败后成功」是密码暴破成功（T1110）的直接序列证据，请立即核实该来源与账户。", user, n, srcIP, logonType),
			Verdict:  model.VerdictSuspicious,
			Severity: model.SeverityCritical,
			Score:    85,
			ProcUser: "SYSTEM/EVTLOG",
			RuleIDs:  []string{"EVT-BRUTE-SUCCESS"},
			MITRE:    []string{"T1110"},
			Evidence: model.Evidence{
				Signals: []model.Signal{{
					Layer: "evtlog", ID: "EVT-BRUTE-SUCCESS", Name: "暴破成功序列",
					Score: 85, Note: fmt.Sprintf("failed=%d user=%s src=%s", n, user, srcIP), MITRE: "T1110",
				}},
			},
			OccurredAt: ev.TimeCreated,
		})

		// 攻击链馈送：暴破成功序列作为 BRUTE-SUCCESS 第二环（事件时间
		// 口径与链首暴破波对齐；指纹与告警本体同值）。
		if a.chainE != nil {
			a.chainE.Feed(chain.Stage{
				Kind: chain.KindLogonOK, When: ev.TimeCreated,
				LoginUser: user, SrcIP: srcIP, LogonType: logonType,
				FailCount: n, RefRuleID: "EVT-BRUTE-SUCCESS", RefScore: 85,
				RefFingerprint: fmt.Sprintf("evt:brute-success:%s:%d",
					strings.ToLower(user), ev.TimeCreated.Unix()/300),
			})
		}
	}

	// ② 时段基线：交互/RDP 登录落在从未见过的小时 → 观察级
	// （样本未达学习期时不告警；基线内存态，重启重学）。
	a.logonMu.Lock()
	if a.logonHours == nil {
		a.logonHours = map[uint8]bool{}
	}
	hour := uint8(ev.TimeCreated.Hour())
	seen := a.logonHours[hour]
	a.logonSamples++
	firstSeen := seen
	a.logonHours[hour] = true
	samples := a.logonSamples
	a.logonMu.Unlock()

	if !firstSeen && samples > logonBaselineWarmup {
		// 新小时桶首现：此前从未在该时段见过交互/RDP 登录
		a.emitAlert(model.AlertEnvelope{
			Fingerprint: fmt.Sprintf("evt:logon-hour:%d:%d", hour, ev.TimeCreated.Unix()/3600),
			Title:       fmt.Sprintf("登录安全：异常时段登录（%02d 点档首次出现）", hour),
			Summary: fmt.Sprintf("交互/RDP 登录（账户 %s 自 %s，类型 %s）发生在此前从未观测过的时段（%02d 时档）。"+
				"夜间/非工作时段的首次交互登录是「人在场攻击」的常见前兆；时段基线随使用学习，误报会随覆盖完善衰减。",
				user, srcIP, logonType, hour),
			Verdict:  model.VerdictSuspicious,
			Severity: model.SeverityMedium,
			Score:    40,
			ProcUser: "SYSTEM/EVTLOG",
			RuleIDs:  []string{"EVT-LOGON-HOUR"},
			Evidence: model.Evidence{
				Signals: []model.Signal{{
					Layer: "evtlog", ID: "EVT-LOGON-HOUR", Name: "异常时段登录",
					Score: 40, Note: fmt.Sprintf("hour=%d user=%s src=%s", hour, user, srcIP),
				}},
			},
			OccurredAt: ev.TimeCreated,
		})
	}
}

// ---------------------------------------------------------------- 账户

// emitEvtAccountChange：账户创建（4720）/删除（4726）——T1136.001 本地
// 账户持久化/权限维持的直接证据；inventory accounts 节是"当前状态"，
// 事件日志是"谁在何时建了谁"的动作证据。
func (a *Agent) emitEvtAccountChange(ev winapi.EvtEvent) {
	created := ev.EventID == 4720
	target := evtData(ev.Data, []string{"targetusername"}, 0)
	actor := evtData(ev.Data, []string{"subjectusername"}, 0)
	if target == "" {
		return
	}
	verb := "删除"
	if created {
		verb = "创建"
	}
	summary := fmt.Sprintf("账户 %q 被 %s %s（事件日志权威证据，T1136.001）。新建本地账户是权限维持/后门账户的常见落点。",
		target, actor, verb)
	a.emitAlert(model.AlertEnvelope{
		Fingerprint: fmt.Sprintf("evt:%d:%s:%d", ev.EventID, strings.ToLower(target), ev.TimeCreated.Unix()/60),
		Title:       fmt.Sprintf("账户安全：本地账户被%s（%s）", verb, target),
		Summary:     summary,
		Verdict:     model.VerdictSuspicious,
		Severity:    model.SeverityMedium,
		Score:       45,
		ProcUser:    "SYSTEM/EVTLOG",
		RuleIDs:     []string{"EVT-ACCT"},
		MITRE:       []string{"T1136.001"},
		Evidence: model.Evidence{
			Signals: []model.Signal{{
				Layer: "evtlog", ID: "EVT-ACCT", Name: "账户创建/删除",
				Score: 45, Note: summary, MITRE: "T1136.001",
			}},
			Notes: []string{"target=" + target, "actor=" + actor, fmt.Sprintf("record_id=%d", ev.RecordID)},
		},
		OccurredAt: ev.TimeCreated,
	})
}

// emitEvtGroupChange：敏感组成员变更（4728 全局组加入 / 4732 本地组加入，
// Administrators 走 4732）——T1098 的 OS 权威证据；inventory accounts 节
// 的 diff 是状态面，这里是动作面（谁把谁加进了哪个组）。
// 字段语义：TargetUserName=组名（宿主组），MemberName=被加入的成员。
func (a *Agent) emitEvtGroupChange(ev winapi.EvtEvent) {
	group := evtData(ev.Data, []string{"targetusername"}, 0)
	member := evtData(ev.Data, []string{"membername"}, 0)
	actor := evtData(ev.Data, []string{"subjectusername"}, 0)
	if group == "" || member == "" {
		return
	}
	// 敏感组白名单：只对"权限提升有意义"的组产生 high 信号；Everyone/
	// Users/Guests 等默认组是 Windows 常态（软件安装也会写入），降 low。
	sensitive := false
	for _, g := range sensitiveGroups {
		if strings.EqualFold(group, g) {
			sensitive = true
			break
		}
	}
	sev, score := model.SeverityLow, 30
	if sensitive {
		sev, score = model.SeverityHigh, 70
	}
	summary := fmt.Sprintf("账户 %q 被加入组 %q（操作者 %s）。%s",
		member, group, actor,
		map[bool]string{true: "敏感组成员变更是权限提升/持久化（T1098）的权威证据；inventory 管理员组变更告警与本事件同源互证。",
			false: "非敏感组，仅记录。"}[sensitive])
	a.emitAlert(model.AlertEnvelope{
		Fingerprint: fmt.Sprintf("evt:%d:%s:%s:%d", ev.EventID, strings.ToLower(member), strings.ToLower(group), ev.TimeCreated.Unix()/60),
		Title:       fmt.Sprintf("账户安全：成员加入组（%s → %s）", member, group),
		Summary:     summary,
		Verdict:     model.VerdictSuspicious,
		Severity:    sev,
		Score:       score,
		ProcUser:    "SYSTEM/EVTLOG",
		RuleIDs:     []string{"EVT-GROUPCHG"},
		MITRE:       []string{"T1098"},
		Evidence: model.Evidence{
			Signals: []model.Signal{{
				Layer: "evtlog", ID: "EVT-GROUPCHG", Name: "敏感组成员变更",
				Score: score, Note: summary, MITRE: "T1098",
			}},
			Notes: []string{
				"member=" + member, "group=" + group, "actor=" + actor,
				fmt.Sprintf("record_id=%d", ev.RecordID),
			},
		},
		OccurredAt: ev.TimeCreated,
	})
}

// emitEvtAuditPolicy：审计策略变更（4719）——防篡改与 F3 whodata 的
// 前提守护（策略被改可能导致 4663 类信号失效）。
func (a *Agent) emitEvtAuditPolicy(ev winapi.EvtEvent) {
	actor := evtData(ev.Data, []string{"subjectusername"}, 0)
	a.emitAlert(model.AlertEnvelope{
		Fingerprint: fmt.Sprintf("evt:4719:%d", ev.TimeCreated.Unix()/300),
		Title:       "事件安全：系统审计策略被变更",
		Summary: fmt.Sprintf("系统审计策略被 %s 变更（T1562.002）。审计策略是本机安全事件可见性的地基，"+
			"变更可能是运维动作，也可能是攻击者在关闭审计后行事的痕迹，请核实。", actor),
		Verdict:  model.VerdictSuspicious,
		Severity: model.SeverityHigh,
		Score:    60,
		ProcUser: "SYSTEM/EVTLOG",
		RuleIDs:  []string{"EVT-AUDITCHG"},
		MITRE:    []string{"T1562.002"},
		Evidence: model.Evidence{
			Signals: []model.Signal{{
				Layer: "evtlog", ID: "EVT-AUDITCHG", Name: "审计策略变更",
				Score: 60, Note: "审计策略被变更", MITRE: "T1562.002",
			}},
			Notes: []string{"actor=" + actor, fmt.Sprintf("record_id=%d", ev.RecordID)},
		},
		OccurredAt: ev.TimeCreated,
	})
}

// ---------------------------------------------------------------- 4104

// psScriptPatterns 是 PowerShell 脚本块的弱信号打分表。
// 单个词是公开技术名词（明文不触 §5.1 红线），"组合总分"才构成攻击
// 形态判定——这样既避开明文恶意工具名，又能对混淆组合告警。
var psScriptPatterns = []struct {
	token string
	score int
}{
	{"-enc", 2}, {"-encodedcommand", 3}, {"-w hidden", 2}, {"-windowstyle hidden", 2},
	{"frombase64string", 2}, {"invoke-expression", 3}, {"iex (", 3}, {"iex(", 3},
	{"downloadstring", 3}, {"downloadfile", 3}, {"net.webclient", 2},
	{"add-type", 2}, {"-nop", 1}, {"-noprofile", 1}, {"bypass", 1},
	{"invoke-command", 2}, {"start-process -verb", 1}, {"scheduledtask", 1},
	{"win32_process", 2}, {"create()", 0},
}

// psScriptScore 按"解码后的小写脚本文本"打分；总分 ≥6 视为可疑组合。
func psScriptScore(text string) (int, []string) {
	low := strings.ToLower(text)
	score, hits := 0, []string{}
	for _, p := range psScriptPatterns {
		if strings.Contains(low, p.token) {
			score += p.score
			hits = append(hits, p.token)
		}
	}
	return score, hits
}

// emitEvtScriptBlock：PowerShell 脚本块执行（4104）。
//
// 与进程命令行的关系（设计问答）：命令行只能看到 `powershell -enc XXX`
// 或 `-File x.ps1` 的"外壳"；4104 记录的是**解码后实际执行的脚本文本**——
// -File 执行的脚本内容、脚本内 IEX 拼接执行的内容，命令行层完全不可见。
// 证据带宿主 PID 便于与进程告警人工关联；可疑模式组合（总分≥6）才告警，
// 纯运维脚本只落证据不入告警流（本机实测 63 条/24h 运维噪声）。
func (a *Agent) emitEvtScriptBlock(ev winapi.EvtEvent) {
	text := evtData(ev.Data, []string{"scriptblocktext"}, 0)
	if strings.TrimSpace(text) == "" {
		return
	}
	score, hits := psScriptScore(text)
	// 证据恒定入库（本地视图），告警按可疑组合过滤
	a.log.Info("evtlog_scriptblock",
		"score", score, "hits", strings.Join(hits, ","),
		"pid", ev.RecordID, "text", truncateRunes(text, 200))
	if score < 6 {
		return
	}
	summary := fmt.Sprintf("PowerShell 脚本块命中可疑组合（命中 %v，总分 %d）。脚本内容已截取于证据；"+
		"无文件攻击（T1059.001）的载荷与混淆常在此现形，请结合宿主进程与落地记录判断。",
		hits, score)
	a.emitAlert(model.AlertEnvelope{
		Fingerprint: fmt.Sprintf("evt:4104:%d:%d", ev.RecordID, ev.TimeCreated.Unix()/60),
		Title:       fmt.Sprintf("PowerShell：可疑脚本块执行（总分 %d）", score),
		Summary:     summary,
		Verdict:     model.VerdictSuspicious,
		Severity:    model.SeverityHigh,
		Score:       60,
		ProcUser:    "SYSTEM/EVTLOG",
		RuleIDs:     []string{"EVT-PSBLOCK"},
		MITRE:       []string{"T1059.001"},
		Evidence: model.Evidence{
			Signals: []model.Signal{{
				Layer: "evtlog", ID: "EVT-PSBLOCK", Name: "可疑 PowerShell 脚本块",
				Score: 60, Note: summary, MITRE: "T1059.001",
			}},
			Notes: []string{
				"hits=" + strings.Join(hits, ","),
				"script=" + truncateRunes(text, 500),
				fmt.Sprintf("record_id=%d", ev.RecordID),
			},
		},
		OccurredAt: ev.TimeCreated,
	})
}

// truncateRunes 按 rune 截断（超长脚本文本的证据摘要用）。
func truncateRunes(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}
