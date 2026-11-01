// Package ai 把主机安全遥测提供给推理后端（大模型或确定性启发式）做分析与研判。
//
// 设计原则（这几条决定了它和"接个 LLM 聊天框"的本质区别）：
//
//  1. **证据锚定**：所有结论必须引用具体证据条目（E1/E2…），没有引用的结论
//     一律标记为未落地（ungrounded）。安全分析最怕"听起来很合理但无从核对"，
//     而大模型最擅长的恰恰是生成这种文本。
//  2. **不可信内容隔离**：命令行、文件路径、进程名都是攻击者可控的。
//     把 `ignore previous instructions` 写进进程名是完全可行的攻击手法，
//     因此这些内容进入推理前必须被隔离并声明为"数据而非指令"。
//  3. **确定性护栏**：AI 只能产出"建议"，不能改写检测引擎的判定分数与状态。
//     高风险动作（终止进程、加白）永远需要人确认。
//  4. **可降级**：没有可用模型时，用确定性启发式产出同结构结论，
//     界面与接口完全无差别。安全产品不能因为"AI 服务挂了"就变成瞎子。
package ai

import "time"

// ---------- 输入侧 ----------

// TrustLevel 标记一段内容的可信度。
// untrusted 表示内容由攻击者/外部输入决定，可能包含指令。
type TrustLevel string

const (
	Trusted   TrustLevel = "trusted"   // 系统产生：规则 ID、分数、签名校验结果
	Untrusted TrustLevel = "untrusted" // 攻击者可控：命令行、路径、进程名、文件名
)

// EvidenceItem 是喂给推理后端的一条证据。
//
// ID 是稳定且简短的（E1、E2…），因为它的唯一用途是被结论引用——
// 让分析师能逐条核对"AI 是凭什么这么说的"。
type EvidenceItem struct {
	ID     string     `json:"id"`
	Layer  string     `json:"layer"` // static / keyword / rule / lineage / behavior / persist
	Name   string     `json:"name"`
	Score  int        `json:"score"`
	Detail string     `json:"detail"`
	Trust  TrustLevel `json:"trust"`
	MITRE  string     `json:"mitre,omitempty"`
}

// AncestorItem 是进程血缘链上的一环。
type AncestorItem struct {
	PID  uint32 `json:"pid"`
	Name string `json:"name"`
	Path string `json:"path"`
}

// HostContext 是主机维度的上下文，帮助模型判断"这台机器上这事正不正常"。
type HostContext struct {
	Hostname string `json:"hostname"`
	OS       string `json:"os_version"`
	// BaselineSamples 是血缘基线已观测样本数：样本太少时，
	// "罕见父子组合"的证据强度要打折，这一点必须告诉模型。
	BaselineSamples int64 `json:"baseline_samples"`
	// RecentAlertCount 是该主机近 1 小时告警数，用于判断是否处于攻击风暴中。
	RecentAlertCount int `json:"recent_alert_count"`
}

// TriageInput 是一次研判的完整输入。
type TriageInput struct {
	AlertID     string         `json:"alert_id"`
	Title       string         `json:"title"`
	Summary     string         `json:"summary"`
	Score       int            `json:"score"`
	Verdict     string         `json:"verdict"`
	Severity    string         `json:"severity"`
	ProcessName string         `json:"process_name"`
	ImagePath   string         `json:"image_path"`
	CmdLine     string         `json:"cmdline"`
	User        string         `json:"user"`
	Hash        string         `json:"hash_sha256"`
	Signed      bool           `json:"signed"`
	Signer      string         `json:"signer"`
	RuleIDs     []string       `json:"rule_ids"`
	MITRE       []string       `json:"mitre"`
	Evidence    []EvidenceItem `json:"evidence"`
	Ancestry    []AncestorItem `json:"ancestry"`
	Host        HostContext    `json:"host"`
	OccurredAt  time.Time      `json:"occurred_at"`

	// Redactions 存"送模型用的隔离副本"，键为字段名（cmdline/image_path…）
	// 或证据 ID（E3）。
	//
	// 刻意与原始字段分开：分析师与最终结论必须看到攻击者写的原文，
	// 否则无法判断真实行为；只有提示词里的那份副本需要剥离指令。
	Redactions map[string]string `json:"-"`
}

// ---------- 输出侧 ----------

// Reason 是一条判定理由。
// Citations 是这条理由依据的证据 ID；为空说明模型在"凭空发挥"。
type Reason struct {
	Text      string   `json:"text"`
	Citations []string `json:"citations"`
}

// Action 是建议的处置动作。
type Action struct {
	Type   string `json:"type"` // isolate / terminate / allowlist / hunt / monitor
	Target string `json:"target"`
	Detail string `json:"detail"`
	// RequiresApproval 恒为 true 的动作不允许自动执行。
	RequiresApproval bool `json:"requires_approval"`
}

// TriageResult 是研判结论。
type TriageResult struct {
	Verdict     string   `json:"verdict"`    // malicious / suspicious / benign / inconclusive
	Confidence  float64  `json:"confidence"` // 0..1
	Reasoning   []Reason `json:"reasoning"`
	Actions     []Action `json:"actions"`
	// Narrative 是一段人读的事件叙述（不含证据编号，用于快速理解）。
	Narrative string `json:"narrative"`
	// AttackChain 是按时间/血缘顺序的假设攻击阶段，可为空。
	AttackChain []string `json:"attack_chain,omitempty"`
	// Grounded 表示所有理由都至少引用了一条存在的证据。
	Grounded bool `json:"grounded"`
	// Uncited 统计没有引用任何证据的理由条数，用于质量评估。
	Uncited int `json:"uncited"`
	// UntrustedIgnored 记录被隔离、未参与推理的可疑指令片段数量（注入防护的产出）。
	UntrustedIgnored int `json:"untrusted_ignored"`

	Model     string `json:"model"`
	Engine    string `json:"engine"` // llm / heuristic
	LatencyMs int64  `json:"latency_ms"`
	// Degraded 表示因预算/可用性降级到启发式引擎。
	Degraded bool   `json:"degraded"`
	DegradedReason string `json:"degraded_reason,omitempty"`
}

// UntrustedIgnoredHint 返回隔离项数量（供后端填写提示词中的安全提示）。
func (in *TriageInput) UntrustedIgnoredHint() int { return len(in.Redactions) }

// ValidVerdict 判断结论取值是否合法。
func ValidVerdict(v string) bool {
	switch v {
	case "malicious", "suspicious", "benign", "inconclusive":
		return true
	}
	return false
}

// ---------- 狩猎 ----------

// Filter 是查询条件中的一项。
type Filter struct {
	Field string `json:"field"`
	Op    string `json:"op"` // eq / ne / gt / lt / gte / lte / contains / prefix / in
	Value string `json:"value"`
	// Values 用于 in 操作符。
	Values []string `json:"values,omitempty"`
}

// Query 是受控查询 DSL。
//
// 刻意不让模型直接产出 SQL：模型生成 SQL 等于把注入面开到数据库层，
// 而且无法审计。DSL 的字段与操作符都是白名单，翻译成 SQL 由我们自己做。
type Query struct {
	Target   string   `json:"target"` // alerts / processes
	Filters  []Filter `json:"filters"`
	SinceSec int64    `json:"since_sec"`
	OrderBy  string   `json:"order_by"`
	Desc     bool     `json:"desc"`
	Limit    int      `json:"limit"`
	// Explain 是模型对这条查询的自然语言解释，供分析师确认意图是否被正确理解。
	Explain string `json:"explain"`
}
