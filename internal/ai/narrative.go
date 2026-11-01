// 事件级 AI 检测（L6）：跨告警攻击链重建与叙事。
//
// 这是"AI 原生 EDR"往上走的一层：单告警研判回答"这一条可不可疑"，
// 事件叙事回答"这串告警连起来是什么攻击、走到哪一步、下一步会怎样"。
//
// 三条硬约束与单告警研判同构：
//  1. 证据锚定：每个阶段必须引用真实存在的告警（A1..An → 真实 ID 映射），
//     编造引用直接剔除，无引用的阶段计入 Uncited；
//  2. 抗注入：告警的进程名/命令行/路径同样不可信，进提示词前隔离；
//  3. 确定性兜底：没有模型时用"战术阶段 + 证据层"的确定性重建产出
//     同结构叙事——隔离网里这条能力不能归零。
package ai

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"zedr/internal/attack"
)

// IncidentAlert 是事件时间线上的一条告警（叙事的最小证据单位）。
// 出去的时间线给界面直接渲染，进提示词的那份按 Redactions 隔离。
type IncidentAlert struct {
	ID          string    `json:"id"`
	Title       string    `json:"title"`
	ProcessName string    `json:"process_name"`
	ImagePath   string    `json:"image_path"`
	CmdLine     string    `json:"cmdline,omitempty"`
	User        string    `json:"user,omitempty"`
	Severity    string    `json:"severity"`
	Verdict     string    `json:"verdict"`
	Score       int       `json:"score"`
	Signed      bool      `json:"signed"`
	Signer      string    `json:"signer,omitempty"`
	MITRE       []string  `json:"mitre,omitempty"`
	RuleIDs     []string  `json:"rule_ids,omitempty"`
	// Layers 是该告警证据命中的层（static/keyword/rule/lineage/behavior/persist），
	// 确定性阶段推断用它补 MITRE 缺位的情况。
	Layers     []string  `json:"layers,omitempty"`
	OccurredAt time.Time `json:"occurred_at"`
}

// IncidentInput 是一次事件叙事的完整输入。
type IncidentInput struct {
	IncidentID   string          `json:"incident_id"`
	Hostname     string          `json:"hostname"`
	FirstSeen    time.Time       `json:"first_seen"`
	LastSeen     time.Time       `json:"last_seen"`
	PeakSeverity string          `json:"peak_severity"`
	MaxScore     int             `json:"max_score"`
	AlertTotal   int             `json:"alert_total"` // 事件全量告警数（可能大于 len(Alerts)）
	Alerts       []IncidentAlert `json:"alerts"`      // 按时间升序，最多 40 条
	Host         HostContext     `json:"host"`
	// Redactions 是送模型用的隔离副本（键：A1.cmdline 等）；与分析师的展示无关。
	Redactions map[string]string `json:"-"`
}

// NarrativePhase 是攻击链上的一个阶段。
type NarrativePhase struct {
	Name        string   `json:"name"`
	Tactic      string   `json:"tactic"`
	TacticID    string   `json:"tactic_id"`
	Alerts      []string `json:"alerts"` // 真实告警 ID（已由 A 编号映射回来）
	Description string   `json:"description"`
}

// sanitizeIncidentInput 对叙事输入做注入扫描与隔离（与单告警同口径）：
// 命中的字段只写入 Redactions 副本（送模型用），原始值保留给分析师。
func sanitizeIncidentInput(in *IncidentInput) (*IncidentInput, int) {
	cp := *in
	cp.Alerts = append([]IncidentAlert(nil), in.Alerts...)
	cp.Redactions = make(map[string]string, 4)
	ignored := 0
	scrub := func(ref, field, val string) {
		if val == "" {
			return
		}
		sc := Scan(val)
		if !sc.Flagged {
			return
		}
		ignored++
		cp.Redactions[ref+"."+field] = sc.Redacted
	}
	for i := range cp.Alerts {
		ref := alertRef(i)
		a := &cp.Alerts[i]
		scrub(ref, "process", a.ProcessName)
		scrub(ref, "path", a.ImagePath)
		scrub(ref, "cmdline", a.CmdLine)
		scrub(ref, "signer", a.Signer)
	}
	return &cp, ignored
}

// UntrustedIgnoredHintNarrative 返回叙事输入的隔离项数量（供提示词安全声明）。
func (in *IncidentInput) UntrustedIgnoredHintNarrative() int { return len(in.Redactions) }

// IncidentNarrative 是事件级结论（与 TriageResult 同构：建议不写回判定）。
type IncidentNarrative struct {
	Summary       string           `json:"summary"`
	RiskScore     int              `json:"risk_score"` // 0-100，事件级风险
	Phases        []NarrativePhase `json:"phases"`
	MissingPhases []string         `json:"missing_phases,omitempty"`
	Coverage      []string         `json:"coverage,omitempty"` // 已覆盖的战术名
	Actions       []Action         `json:"actions,omitempty"`

	Grounded         bool `json:"grounded"`
	Uncited          int  `json:"uncited"`
	UntrustedIgnored int  `json:"untrusted_ignored"`

	Model          string `json:"model"`
	Engine         string `json:"engine"` // llm / heuristic
	LatencyMs      int64  `json:"latency_ms"`
	Degraded       bool   `json:"degraded"`
	DegradedReason string `json:"degraded_reason,omitempty"`
}

// alertRef 返回某条告警在提示词里的引用编号（A1..An）。
func alertRef(idx int) string { return fmt.Sprintf("A%d", idx+1) }

// canonicalTactics 是可展示的战术顺序（来自共享 ATT&CK 目录）。
func canonicalTactics() []attack.Tactic { return attack.Tactics() }

// tacticOfAlert 推断一条告警所属战术：优先 MITRE 技术映射，缺位时按证据层兜底。
// 返回 tacticID（可能为空串 = 未分类）。
func tacticOfAlert(a IncidentAlert) (tacticID, tacticName string) {
	for _, t := range a.MITRE {
		if tech, ok := attack.LookupTechnique(attack.NormalizeTech(t)); ok {
			if tac, ok := attack.TacticName(tech.TacticID); ok {
				return tac.ID, tac.NameZh
			}
		}
	}
	// 无 MITRE 时按证据层兜底：这是启发式的"最小假设"，不是硬映射。
	layerTactic := map[string]string{
		"persist":  "TA0003", // 持久化
		"behavior": "TA0002", // 执行
		"keyword":  "TA0007", // 发现
		"lineage":  "TA0002",
		"rule":     "TA0040", // 影响（规则通常描述后果）
		"static":   "TA0005", // 防御规避（签名/哈希关联）
	}
	for _, l := range a.Layers {
		if tid, ok := layerTactic[l]; ok {
			if tac, ok := attack.TacticName(tid); ok {
				return tac.ID, tac.NameZh
			}
		}
	}
	if tac, ok := attack.TacticName(attack.UncategorizedTacticID); ok {
		return tac.ID, tac.NameZh
	}
	return "", "未分类"
}

// deterministicNarrative 是确定性事件重建：无模型/预算耗尽时的兜底。
//
// 它做三件真实的事：按时间线把告警归入战术阶段、给出风险分与
// 缺失阶段提示、生成带真实告警引用的阶段描述。它写不出"攻击者意图"
// 这类环境推理——那正是 LLM 模式的增量。
func deterministicNarrative(in *IncidentInput) *IncidentNarrative {
	type bucket struct {
		tacticID, tacticName string
		alerts               []string
		descs                []string
	}
	order := []string{}
	byTactic := map[string]*bucket{}
	rank := map[string]int{}
	for i, t := range canonicalTactics() {
		rank[t.ID] = i
	}

	for i, a := range in.Alerts {
		tid, tname := tacticOfAlert(a)
		b, ok := byTactic[tid]
		if !ok {
			b = &bucket{tacticID: tid, tacticName: tname}
			byTactic[tid] = b
			order = append(order, tid)
		}
		b.alerts = append(b.alerts, a.ID)
		desc := fmt.Sprintf("%s（%s，%d 分）", a.Title, a.Severity, a.Score)
		if a.ProcessName != "" {
			desc += " · 进程 " + a.ProcessName
		}
		if a.CmdLine != "" {
			desc += " · 命令行：" + truncate(a.CmdLine, 80)
		}
		if a.Signed == false && a.Signer != "" {
			desc += " · 签名者 " + a.Signer
		}
		if len(b.descs) < 3 {
			b.descs = append(b.descs, desc)
		}
		_ = i
	}

	sort.SliceStable(order, func(i, j int) bool {
		ri, rj := rank[byTactic[order[i]].tacticID], rank[byTactic[order[j]].tacticID]
		return ri < rj
	})

	n := &IncidentNarrative{Engine: "heuristic", Model: "heuristic-v1"}
	covered := map[string]bool{}
	for _, tid := range order {
		b := byTactic[tid]
		tacticID := b.tacticID
		if tacticID == "" {
			tacticID = attack.UncategorizedTacticID
		}
		phase := NarrativePhase{
			Name:     phaseNameFor(tacticID, b.tacticName),
			Tactic:   b.tacticName,
			TacticID: tacticID,
			Alerts:   b.alerts,
		}
		phase.Description = strings.Join(b.descs, "；")
		if len(b.alerts) > 3 {
			phase.Description += fmt.Sprintf("；另有 %d 条同阶段告警", len(b.alerts)-3)
		}
		n.Phases = append(n.Phases, phase)
		if tid != "" && tid != attack.UncategorizedTacticID {
			covered[tid] = true
			n.Coverage = append(n.Coverage, b.tacticName)
		}
	}

	// 缺失阶段提示：只提示"高价值且通常应能在主机侧观测到"的几个战术，
	// 不把完整 ATT&CK 全列一遍（那会对每个事件都刷一屏"缺失"）。
	for _, tid := range []string{"TA0001", "TA0002", "TA0003", "TA0005", "TA0004", "TA0040"} {
		if covered[tid] {
			continue
		}
		if tac, ok := attack.TacticName(tid); ok {
			n.MissingPhases = append(n.MissingPhases, tac.Name)
		}
	}

	n.RiskScore = incidentRisk(in)
	n.Summary = fmt.Sprintf("主机 %s 在 %s 至 %s 间产生 %d 条告警（峰值 %s / %d 分），按证据可归入 %d 个战术阶段：%s。",
		in.Hostname, in.FirstSeen.Format("01-02 15:04"), in.LastSeen.Format("01-02 15:04"),
		in.AlertTotal, in.PeakSeverity, in.MaxScore, len(n.Phases), strings.Join(n.Coverage, "、"))
	if len(n.Phases) > 0 {
		n.Summary += "建议优先从「" + n.Phases[0].Name + "」阶段的告警开始核对。"
	}
	n.Actions = incidentActions(in)
	// 确定性重建天然带真实引用：每个阶段都指向真实告警。
	n.Grounded = len(n.Phases) > 0
	n.Uncited = 0
	return n
}

// phaseNameFor 把战术 ID 映射成人读的阶段名（比战术名更贴调查动作）。
func phaseNameFor(tacticID, fallback string) string {
	switch tacticID {
	case "TA0001":
		return "初始访问"
	case "TA0002":
		return "执行"
	case "TA0003":
		return "持久化"
	case "TA0004":
		return "提权"
	case "TA0005":
		return "防御规避"
	case "TA0006":
		return "凭据访问"
	case "TA0007":
		return "发现"
	case "TA0008":
		return "横向移动"
	case "TA0009":
		return "收集"
	case "TA0011":
		return "命令与控制"
	case "TA0040":
		return "影响"
	}
	if fallback == "" || fallback == "未分类" {
		return "未分类行为"
	}
	return fallback
}

// incidentRisk 计算事件级风险分：峰值分 + 阶段广度加成，钳制 0-100。
func incidentRisk(in *IncidentInput) int {
	risk := in.MaxScore
	phases := map[string]bool{}
	for _, a := range in.Alerts {
		if tid, _ := tacticOfAlert(a); tid != "" {
			phases[tid] = true
		}
	}
	if len(phases) >= 3 {
		risk += 10
	}
	if in.AlertTotal >= 5 {
		risk += 5
	}
	if risk > 100 {
		risk = 100
	}
	if risk < 0 {
		risk = 0
	}
	return risk
}

// incidentActions 是事件级处置建议（全部强制人工确认，理由同单告警护栏）。
func incidentActions(in *IncidentInput) []Action {
	if in.MaxScore < 40 {
		return nil
	}
	acts := []Action{{
		Type:   "hunt",
		Target: in.Hostname,
		Detail: "在同网段检索相同进程/命令行，确认是否已横向扩散",
	}}
	if in.MaxScore >= 70 || in.PeakSeverity == "critical" {
		acts = append([]Action{{
			Type:   "isolate",
			Target: in.Hostname,
			Detail: "隔离主机网络，阻断可能的横向移动与外联",
		}}, acts...)
	}
	for i := range acts {
		acts[i].RequiresApproval = true
	}
	return acts
}

// ValidateNarrative 校验 LLM 叙事输出：引用映射（A1..An → 真实 ID）、
// 剔除编造引用、统计无引用阶段、钳制风险分、强制审批。
func ValidateNarrative(n *IncidentNarrative, in *IncidentInput) *IncidentNarrative {
	// 引用映射表：A1..An 与真实 ID 双向可用（模型可能直接写真实 ID）
	refToReal := make(map[string]string, len(in.Alerts)*2)
	valid := make(map[string]bool, len(in.Alerts))
	for i, a := range in.Alerts {
		refToReal[alertRef(i)] = a.ID
		refToReal[a.ID] = a.ID
		valid[a.ID] = true
	}

	uncited := 0
	phases := n.Phases[:0]
	for _, p := range n.Phases {
		kept := make([]string, 0, len(p.Alerts))
		seen := map[string]bool{}
		for _, c := range p.Alerts {
			real, ok := refToReal[strings.TrimSpace(c)]
			if !ok || seen[real] {
				continue
			}
			seen[real] = true
			kept = append(kept, real)
		}
		p.Alerts = kept
		if len(kept) == 0 {
			uncited++
		}
		if p.TacticID == "" {
			p.TacticID = attack.UncategorizedTacticID
		}
		if p.Name == "" {
			p.Name = phaseNameFor(p.TacticID, p.Tactic)
		}
		phases = append(phases, p)
	}
	n.Phases = phases
	n.Uncited = uncited
	n.Grounded = len(phases) > 0 && uncited == 0

	if n.RiskScore < 0 {
		n.RiskScore = 0
	}
	if n.RiskScore > 100 {
		n.RiskScore = 100
	}
	for i := range n.Actions {
		n.Actions[i].RequiresApproval = true
	}
	// Coverage 以校验后的阶段为准重算（模型自报的 coverage 可能不可信）
	cov := []string{}
	seen := map[string]bool{}
	for _, p := range n.Phases {
		if p.Tactic != "" && !seen[p.Tactic] {
			seen[p.Tactic] = true
			cov = append(cov, p.Tactic)
		}
	}
	n.Coverage = cov
	if strings.TrimSpace(n.Summary) == "" && len(n.Phases) > 0 {
		n.Summary = fmt.Sprintf("事件涉及 %d 个阶段，结论未给出摘要。", len(n.Phases))
	}
	return n
}
