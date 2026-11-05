// rules.go:攻击链规则表与链告警的叙事构建。
//
// 规则设计纪律（调研报告 §设计建议，2026-11-06 联网核实）：
//   - 只消费已有信号，不新增采集面；
//   - 全部环节确定性判定（签名/路径/事件类型），弱信号不独立成链
//    （ATLASv2 审计教训：词汇新颖性之外的时序泛化是误报放大器）；
//   - 首批 4 条覆盖最高价值链：落地→执行→C2、暴破→成功→执行工具、
//     持久化→执行、注入→外联。勒索链不在此重复——既有"critical 只能
//     由诱饵命中关联升级"的两级防线（FILE-RANSOM）已覆盖。
package chain

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"zedr/internal/model"
)

// rule 是一条链规则：阶段序列 + 实体口径 + 定级。
type rule struct {
	id       string
	title    string
	length   int // 阶段总数
	span     time.Duration
	score    int
	verdict  model.Verdict
	severity model.Severity
	// mitre 是默认技术序列；链首阶段自带 MITRE 时优先用阶段值
	// （PERSIST-RUN 的技术取决于持久化手段：Run 键/服务/计划任务）。
	mitre []string
	// guidance 拼在摘要尾部的人工指引
	guidance string
	// keyOf 从阶段提取链 key；返回 "" 表示该阶段与本规则无关
	keyOf func(Stage) string
	// match 判定第 idx 阶段（idx>0 时 m 非 nil，可引用已收集阶段做
	// same_field 约束与阶段间隔约束）
	match func(idx int, s Stage, m *machine) bool
}

// allRules 是链规则表（顺序即 Feed 时的评估顺序，无逻辑影响）。
var allRules = [...]rule{
	{
		id:  "CHAIN-DROP-EXEC-C2",
		title: "攻击链：落地程序执行后外联",
		length: 2, span: procChainMaxSpan,
		score: 75, verdict: model.VerdictSuspicious, severity: model.SeverityHigh,
		mitre: []string{"T1105"},
		guidance: "「刚落地的未签名程序 → 主动外联」是下载器/植入体的经典闭环（T1105）。" +
			"请核对镜像来源（MotW/落地路径）与外联对端是否预期；如非已知软件行为，建议隔离处置。",
		// 单进程链：进程 → 该进程的外联。同 key 约束天然把阶段绑在同一进程实体上。
		keyOf: procKey,
		match: func(idx int, s Stage, m *machine) bool {
			switch idx {
			case 0:
				// 链首：落地即执行 + 未签名。复用引擎 DROP-001 判定
				//（目录风险/窗口已在引擎算过），签名阈值在链侧收紧为
				// "无签名"——签名有效的可写目录解包是合法软件常态。
				return s.Kind == KindProc && s.Dropped && !s.Signed
			case 1:
				return (s.Kind == KindConn || s.Kind == KindNet) && outboundPeer(s.PeerIP)
			}
			return false
		},
	},
	{
		id:  "CHAIN-BRUTE-SUCCESS",
		title: "攻击链：暴破成功后执行落地程序",
		length: 3, span: hostChainMaxSpan,
		score: 85, verdict: model.VerdictSuspicious, severity: model.SeverityCritical,
		mitre: []string{"T1110", "T1078"},
		guidance: "「密集登录失败 → 成功登录 → 立即执行刚落地的未签名程序」是暴破入侵的完整闭环。 " +
			"请立即核实来源 IP 与账户，确认会话内执行过的程序；这与单条 EVT-BRUTE-SUCCESS 相比多了行为侧证据。",
		// 跨代链退化为 Wazuh if_matched 形态：单探针 = 单主机视野，
		// key 恒为 host；同源约束（same_field）在阶段判定里做。
		keyOf: func(Stage) string { return "host" },
		match: func(idx int, s Stage, m *machine) bool {
			switch idx {
			case 0:
				return s.Kind == KindBrute
			case 1:
				// 暴破 → 成功登录 ≤10min：暴破会话的收尾动作，拖更久的
				// "成功"与暴破波的因果性骤降（宁可漏这条慢尾巴）。
				if s.Kind != KindLogonOK || len(m.stages) == 0 {
					return false
				}
				if s.When.Sub(m.stages[0].When) > 10*time.Minute {
					return false
				}
				// same_source_ip：两侧都带 IP 时必须同源；审核配置缺失
				// 导致任一侧无 IP 时按主机内关联放行（4624/4625 的 IP
				// 字段依赖审核策略，缺失是常态不是异常）。
				src := m.stages[0].SrcIP
				return src == "" || s.SrcIP == "" || src == s.SrcIP
			case 2:
				// 成功登录 → 3min 内执行"刚落地的未签名程序"：
				// 攻击者的下一动作通常是传工具、跑工具；系统自启动的
				// 签名软件不算链（安装器/更新是合法的落地+执行）。
				if s.Kind != KindProc || !s.Dropped || s.Signed {
					return false
				}
				return s.When.Sub(m.stages[len(m.stages)-1].When) <= 3*time.Minute
			}
			return false
		},
	},
	{
		id:  "CHAIN-PERSIST-RUN",
		title: "攻击链：新增持久化项被执行",
		length: 2, span: hostChainMaxSpan,
		score: 72, verdict: model.VerdictSuspicious, severity: model.SeverityHigh,
		mitre: []string{"T1547.001"}, // 链首阶段自带 MITRE 时覆盖
		guidance: "「新增自启动/服务项 → 指向程序被执行」把持久化告警从'可能被滥用'升级为'确实在跑'。" +
			"若该程序非已知软件行为，建议终止并移除对应持久化项；软件安装的正常时序（签名）不会进链。",
		// 实体口径 = 持久化指向的可执行路径（归一化）；proc 阶段用自己的
		// 镜像路径对上同一个 key。路径解析失败的阶段（4698 无命令字段）
		// keyOf 返回空，诚实退出关联。
		keyOf: func(s Stage) string {
			switch s.Kind {
			case KindPersist, KindSvcInst:
				return normPath(s.ItemPath)
			case KindProc:
				return normPath(s.Path)
			}
			return ""
		},
		match: func(idx int, s Stage, m *machine) bool {
			switch idx {
			case 0:
				return (s.Kind == KindPersist || s.Kind == KindSvcInst) && s.ItemPath != ""
			case 1:
				// 执行环节仍要求未签名：签名软件"写 Run 键 → 立即自启"
				// 是安装器的标准时序，不构成链。
				return s.Kind == KindProc && !s.Signed
			}
			return false
		},
	},
	{
		id:  "CHAIN-INJECT-OUT",
		title: "攻击链：注入残留进程外联",
		length: 2, span: procChainMaxSpan,
		score: 85, verdict: model.VerdictSuspicious, severity: model.SeverityCritical,
		mitre: []string{"T1055", "T1071"},
		guidance: "「私有可执行内存含 PE 头 + 同进程主动外联」是注入载荷上线（T1055→T1071）的组合证据。" +
			"MEM-1055 单独看可能来自打包程序/JIT，叠加外联后建议直接终止进程并做全盘落地排查。",
		// PID 口径（见 pidKey 注释：两个信号源的 StartTime 不同源）。
		keyOf: pidKey,
		match: func(idx int, s Stage, m *machine) bool {
			switch idx {
			case 0:
				return s.Kind == KindMem && s.PID != 0
			case 1:
				return (s.Kind == KindConn || s.Kind == KindNet) && outboundPeer(s.PeerIP)
			}
			return false
		},
	},
}

// build 把一条走完的 machine 组装成 Finding（在引擎锁内调用，只读 machine）。
func (r *rule) build(m *machine) Finding {
	f := Finding{
		RuleID:   r.id,
		Title:    r.title,
		Verdict:  r.verdict,
		Severity: r.severity,
		Score:    r.score,
		Stages:   append([]Stage(nil), m.stages...),
		Key:      m.key,
		Started:  m.stages[0].When,
	}
	// MITRE：链首阶段自带技术（持久化手段决定 T1547/T1543/T1053）优先
	if first := m.stages[0].MITRE; first != "" {
		f.MITRE = []string{first}
	} else {
		f.MITRE = append([]string(nil), r.mitre...)
	}
	// 根因进程：优先真实 proc 阶段，其次任何带 PID 的阶段
	for i := range m.stages {
		if m.stages[i].Kind == KindProc {
			f.Root = &m.stages[i]
			break
		}
	}
	if f.Root == nil {
		for i := range m.stages {
			if m.stages[i].PID != 0 {
				f.Root = &m.stages[i]
				break
			}
		}
	}

	var b strings.Builder
	fmt.Fprintf(&b, "检测到 %d 阶段攻击链（规则 %s）：", len(m.stages), r.id)
	for i := range m.stages {
		f.Lines = append(f.Lines, stageLine(i, m.stages[i]))
		b.WriteString("\n")
		b.WriteString(f.Lines[i])
	}
	b.WriteString("\n")
	b.WriteString(r.guidance)
	f.Summary = b.String()
	return f
}

// stageLine 把一个阶段渲染成一行人话（事件页/AI 研判都会直接消费）。
func stageLine(i int, s Stage) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s [%s] %s", numCircles(i), s.When.Format("15:04:05"), KindLabel(s.Kind))
	switch s.Kind {
	case KindProc:
		fmt.Fprintf(&b, "：%s（PID %s）", s.Name, pidStr(s.PID))
		if s.Path != "" {
			b.WriteString("，镜像 " + s.Path)
		}
		if !s.Signed {
			b.WriteString("，未签名")
		}
		if s.Dropped {
			b.WriteString("，落地即执行")
		}
		if s.MotW {
			b.WriteString("，带互联网来源标记")
		}
		if s.CmdLine != "" {
			b.WriteString("，命令行 " + truncate(s.CmdLine, 120))
		}
	case KindConn:
		fmt.Fprintf(&b, "：%s:%d", s.PeerIP, s.PeerPort)
	case KindNet:
		if s.RefRuleID != "" {
			b.WriteString("（" + s.RefRuleID + "）")
		}
		if s.PeerIP != "" {
			fmt.Fprintf(&b, "：%s:%d", s.PeerIP, s.PeerPort)
		}
	case KindBrute:
		fmt.Fprintf(&b, "：%d 次（阈值 10/分钟）", s.FailCount)
		if s.SrcIP != "" {
			b.WriteString("，来源 " + s.SrcIP)
		}
	case KindLogonOK:
		fmt.Fprintf(&b, "：账户 %s", s.LoginUser)
		if s.LogonType != "" {
			b.WriteString("（登录类型 " + s.LogonType + "）")
		}
		if s.SrcIP != "" {
			b.WriteString("，来源 " + s.SrcIP)
		}
	case KindSvcInst:
		fmt.Fprintf(&b, "：服务 %s", s.ItemName)
		if s.ItemPath != "" {
			b.WriteString("，指向 " + s.ItemPath)
		}
	case KindPersist:
		fmt.Fprintf(&b, "：%s %s", s.ItemKind, s.ItemName)
		if s.ItemPath != "" {
			b.WriteString("，指向 " + s.ItemPath)
		}
	case KindMem:
		fmt.Fprintf(&b, "：%s（PID %s）", s.Name, pidStr(s.PID))
		if s.Path != "" {
			b.WriteString("，镜像 " + s.Path)
		}
	}
	if s.RefRuleID != "" && s.Kind != KindNet {
		b.WriteString("〔来源告警 " + s.RefRuleID + "〕")
	}
	return b.String()
}

// KindLabel 是阶段种类的中文标签（接线层组装证据 Signal 时复用）。
func KindLabel(kind string) string {
	switch kind {
	case KindProc:
		return "进程创建"
	case KindConn:
		return "主动外联"
	case KindNet:
		return "网络行为命中"
	case KindBrute:
		return "登录失败暴发"
	case KindLogonOK:
		return "暴破成功登录"
	case KindSvcInst:
		return "新服务安装"
	case KindPersist:
		return "持久化项变更"
	case KindMem:
		return "内存注入残留"
	}
	return kind
}

// numCircles 提供带圈序号（阶段少，1-3 足够；超出退化普通括号）。
func numCircles(i int) string {
	circles := "①②③④⑤⑥⑦⑧⑨⑩"
	if i < len(circles) {
		return string([]rune(circles)[i])
	}
	return "(" + strconv.Itoa(i+1) + ")"
}

func pidStr(pid uint32) string {
	if pid == 0 {
		return "?"
	}
	return strconv.FormatUint(uint64(pid), 10)
}

// truncate 按 rune 截断（命令行等长文本进摘要用）。
func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}
