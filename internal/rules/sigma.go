package rules

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Sigma 规则导入转换器（2026-11-21，可行性调研见 overview.md——
// Security Onion 默认子集策略、Wazuh 5.0 每 detector 100 条硬上限、
// tyrian DNF 展开 +15% 等先例均为本文件设计依据）。
//
// v1 诚实边界：
//   - 只收 logsource.category=process_creation（product=windows）——
//     引擎 Target 只有进程/网络/模块维度，registry/file/image_load 的
//     Sigma 字段没有对应遥测字段，硬转换只会产出"永远不命中"的假规则；
//   - 只收 status=stable/test 与 level != informational；
//   - condition 支持单 selection、显式 and/or/not 组合；通配（1 of x*）、
//     括号分组与部分取反不支持，报告原因；
//   - or / and 组合按 DNF 笛卡尔积展开为多条规则（tyrian 实测展开系数
//     约 +15%），总分支数上限防爆。
//
// 导入侧纪律：全部以 observe 模式入库（计数不告警），人工转正——
// 观察模式就是 Sigma 生态"status=test → stable"生命周期缺失的 bake 期
// （社区 SOP 口径：7 天观察 FP≤20% 方转产）。

// dnfBranchCap 是单条 Sigma 规则 DNF 展开后的分支总数上限：
// 超过说明该规则的选择器组合过于复杂，自动展开会成倍放大引擎求值成本
// （Wazuh 5.0 的 100/detector 硬上限是同类防线）。
const dnfBranchCap = 64

// sigmaRule 是 Sigma YAML 单文档的最小解析结构。
type sigmaRule struct {
	Title          string   `yaml:"title"`
	ID             string   `yaml:"id"`
	Status         string   `yaml:"status"`
	Description    string   `yaml:"description"`
	Level          string   `yaml:"level"`
	Tags           []string `yaml:"tags"`
	FalsePositives []string `yaml:"falsepositives"`
	Logsource      struct {
		Category string `yaml:"category"`
		Product  string `yaml:"product"`
		Service  string `yaml:"service"`
	} `yaml:"logsource"`
	Detection struct {
		Condition string         `yaml:"condition"`
		Blocks    map[string]any `yaml:",inline"` // 其余键均为 selection 块
	} `yaml:"detection"`
}

// SigmaDraft 是转换产出的一条候选规则（Definition 已序列化为 DSL JSON）。
type SigmaDraft struct {
	Title       string
	Description string
	Severity    string
	Score       int
	MITRE       []string
	Definition  string
	Source      string // Sigma ID/标题，审计与追溯用
}

// SigmaSkip 是一条被拒绝的规则及原因（三态报告的 skipped/failed 共用）。
type SigmaSkip struct {
	Title  string `json:"title"`
	Reason string `json:"reason"`
}

// sigmaAllowedCategory 是 v1 接受的遥测类别：引擎 Target 有完整字段
// 维度的只有进程创建类。其余类别（registry/file/image_load/云）的
// Sigma 字段没有对应 Target 字段，硬转换只会产出永远不命中的假规则
// ——按类别拒绝并报告（tyrian 教训：静默部署=永不命中）。
const sigmaAllowedCategory = "process_creation"

// sigmaFieldMap 是 Sigma 字段 → 本引擎字段的映射表。只收录 Target
// 真实存在的字段；映射不到的当场报错（与 Compile 严格校验同口径）。
var sigmaFieldMap = map[string]string{
	"image":            "process.path",
	"commandline":      "process.cmdline",
	"user":             "process.user",
	"parentimage":      "parent.path",
	"originalfilename": "process.name",
}

// sigmaSeverityMap 是 Sigma level → 本引擎严重度与建议分值。
var sigmaSeverityMap = map[string]struct {
	Sev   string
	Note  string
	Score int
}{
	"critical": {Sev: "critical", Score: 90},
	"high":     {Sev: "high", Score: 75},
	"medium":   {Sev: "medium", Note: "（medium 级建议观察期放宽阈值）", Score: 50},
	"low":      {Sev: "low", Note: "（low 级通常量大，务必观察后转正）", Score: 25},
}

// ConvertSigma 把单份 Sigma YAML 文档转成候选规则草稿。可能产出多条
//（or 分支与多值字段按 DNF 笛卡尔积展开）；被门禁拒绝时返回 skip 原因。
// 纯转换不做存储——入库与配额由调用方裁决。
func ConvertSigma(doc []byte) ([]SigmaDraft, SigmaSkip, error) {
	var r sigmaRule
	if err := yaml.Unmarshal(doc, &r); err != nil {
		return nil, SigmaSkip{}, fmt.Errorf("YAML 解析失败: %w", err)
	}
	title := firstNonEmptyStr(r.Title, r.ID, "(未命名 Sigma 规则)")
	skip := func(reason string) ([]SigmaDraft, SigmaSkip, error) {
		return nil, SigmaSkip{Title: title, Reason: reason}, nil
	}

	// ---- 门禁 1：状态分级（stable/test 才可上生产，规范原文口径）----
	switch strings.ToLower(r.Status) {
	case "stable", "test":
	case "experimental":
		return skip("status=experimental：规范明示可能产生误报或噪声，请人工改编后再导")
	case "deprecated", "unsupported":
		return skip("status=" + strings.ToLower(r.Status) + "：规则已被官方弃用")
	case "":
		return skip("缺少 status 字段（无法判断质量分级）")
	default:
		return skip("未知 status=" + r.Status)
	}

	// ---- 门禁 2：遥测类别（v1 只有进程创建）----
	cat := strings.ToLower(strings.TrimSpace(r.Logsource.Category))
	prod := strings.ToLower(strings.TrimSpace(r.Logsource.Product))
	if cat != sigmaAllowedCategory || (prod != "" && prod != "windows") {
		return skip(fmt.Sprintf("logsource %s/%s 暂无对应遥测维度（v1 仅支持 windows/process_creation）",
			orDashStr(prod), orDashStr(cat)))
	}

	// ---- 门禁 3：级别（informational 规范原文明确预期海量命中）----
	sev, ok := sigmaSeverityMap[strings.ToLower(r.Level)]
	if !ok {
		return skip("缺少 level 或级别不受支持（informational 预期海量命中，不进告警面）")
	}

	// ---- MITRE 技术编号提取（tags: attack.t1059.001 → T1059.001）----
	var mitre []string
	for _, t := range r.Tags {
		lt := strings.ToLower(t)
		if strings.HasPrefix(lt, "attack.t") {
			if up := strings.TrimPrefix(lt, "attack."); strings.HasPrefix(up, "t") {
				mitre = append(mitre, "T"+strings.ToUpper(strings.TrimPrefix(up, "t")))
			}
		}
	}

	// ---- condition 解析与 DNF 展开 ----
	cond := strings.TrimSpace(r.Detection.Condition)
	if cond == "" {
		return skip("detection.condition 为空")
	}
	if strings.Contains(cond, "(") {
		return skip("condition 含括号分组——不支持，请改写为显式 and/or 组合")
	}
	if strings.Contains(strings.ToLower(cond), " of ") {
		return skip("condition 使用通配引用（1 of x* / all of them）——不支持，请改写为显式 selection 名")
	}
	// and 优先级高于 or（Sigma 规范）：按 or 切分支，分支内按 and 拆
	var defs []Definition
	for _, part := range splitCond(cond, " or ") {
		bl, err := sigmaAndBranch(part, r.Detection.Blocks)
		if err != nil {
			return skip(fmt.Sprintf("%s：%v", title, err))
		}
		defs = append(defs, bl...)
		if len(defs) > dnfBranchCap {
			return skip(fmt.Sprintf("DNF 展开后规则数超过上限 %d——规则组合过于复杂，请拆分后导入", dnfBranchCap))
		}
	}
	if len(defs) == 0 {
		return skip("condition 未引用任何 selection")
	}

	drafts := make([]SigmaDraft, 0, len(defs))
	for bi, def := range defs {
		raw, err := json.Marshal(def)
		if err != nil {
			return skip(fmt.Sprintf("%s：%v", title, err))
		}
		if _, err := Compile(string(raw)); err != nil {
			return skip(fmt.Sprintf("%s：转换结果未通过编译校验：%v", title, err))
		}
		note := sigmaFPNote(r.FalsePositives)
		if sev.Note != "" {
			note += sev.Note
		}
		drafts = append(drafts, SigmaDraft{
			Title:       r.Title + orSuffix(len(defs), bi),
			Description: strings.TrimSpace(strings.TrimSpace(r.Description) + note),
			Severity:    sev.Sev,
			Score:       sev.Score,
			MITRE:       mitre,
			Definition:  string(raw),
			Source:      firstNonEmptyStr(r.ID, r.Title),
		})
	}
	return drafts, SigmaSkip{}, nil
}

// sigmaAndBranch 解析一个 and 连接的分支（术语可为 "not X"），返回该
// 分支展开后的规则定义列表：not 项进各定义的 None（取反语义），
// 非 not 项的多值 OR 按 DNF 笛卡尔积展开为多份 All。
func sigmaAndBranch(branch string, blocks map[string]any) ([]Definition, error) {
	cur := [][]Condition{{}}
	var noneConds []Condition
	for _, tok := range splitCond(branch, " and ") {
		tok = strings.TrimSpace(tok)
		negate := false
		if strings.HasPrefix(strings.ToLower(tok), "not ") {
			negate = true
			tok = strings.TrimSpace(strings.TrimPrefix(tok, "not "))
		}
		bd, err := sigmaBlockToDef(tok, blocks)
		if err != nil {
			return nil, err
		}
		if negate {
			// not X：X 的条件取反。仅支持单条件块与可否定操作符
			//（prefix/suffix/glob/regex 无否定形式——不支持并报告）；
			// 多条件块的取反需要 DNF 展开，v1 跳过
			if len(bd.Any) > 0 || len(bd.All) > 1 {
				return nil, fmt.Errorf("not 引用的 selection %q 含多条件/多值——其取反需要 DNF 展开，v1 不支持", tok)
			}
			if len(bd.All) != 1 {
				return nil, fmt.Errorf("not 引用的 selection %q 没有条件", tok)
			}
			nc, ok := negateCond(bd.All[0])
			if !ok {
				return nil, fmt.Errorf("not 引用的条件（%s %s）无可用的否定操作符", bd.All[0].Field, bd.All[0].Op)
			}
			noneConds = append(noneConds, nc)
			continue
		}
		// 非 not 块：Any 多值 = OR → 按分支展开（DNF）
		cur = dnfComb(cur, blockToBranches(bd))
		if len(cur) > dnfBranchCap {
			return nil, fmt.Errorf("and 组合的 DNF 展开超过上限 %d", dnfBranchCap)
		}
	}
	var out []Definition
	for _, conds := range cur {
		out = append(out, Definition{All: conds, None: noneConds})
	}
	return out, nil
}

// blockToBranches 把块定义转成 DNF 分支：
// All 部分必然 AND，Any 部分（多值 OR）每个条件各展开一个分支。
func blockToBranches(bd Definition) [][]Condition {
	if len(bd.Any) == 0 {
		return [][]Condition{bd.All}
	}
	var out [][]Condition
	for _, a := range bd.Any {
		branch := append(append([]Condition{}, bd.All...), a)
		out = append(out, branch)
	}
	return out
}

// dnfComb 对两组 DNF 分支做笛卡尔积合并（AND 语义）：
// (A1∨A2)∧(B1∨B2) = (A1∧B1)∨(A1∧B2)∨(A2∧B1)∨(A2∧B2)。
func dnfComb(a, b [][]Condition) [][]Condition {
	var out [][]Condition
	for _, aa := range a {
		for _, bb := range b {
			merged := append(append([]Condition{}, aa...), bb...)
			out = append(out, merged)
		}
	}
	return out
}

// negateCond 把单条件的操作符翻成否定形式。没有否定操作符的
//（prefix/suffix/glob/regex——引擎未提供 nprefix 等）返回 false，
// 调用方按"不支持"跳过。
func negateCond(c Condition) (Condition, bool) {
	switch c.Op {
	case "contains", "icontains":
		return Condition{Field: c.Field, Op: "ncontains", Value: c.Value}, true
	case "eq":
		return Condition{Field: c.Field, Op: "ne", Value: c.Value}, true
	case "ne":
		return Condition{Field: c.Field, Op: "eq", Value: c.Value}, true
	default:
		return c, false
	}
}

// sigmaBlockToDef 把一个 selection 块转成 Definition：
// 字段间 AND（进 All），同字段多值 OR（进 Any），|all 修饰符多值 AND。
func sigmaBlockToDef(name string, blocks map[string]any) (Definition, error) {
	raw, ok := blocks[name]
	if !ok {
		return Definition{}, fmt.Errorf("condition 引用的 selection %q 不存在", name)
	}
	fields, ok := raw.(map[string]any)
	if !ok {
		return Definition{}, fmt.Errorf("selection %q 不是字段映射", name)
	}
	keys := make([]string, 0, len(fields))
	for k := range fields {
		keys = append(keys, k)
	}
	sort.Strings(keys) // map 遍历无序：按字段名排序保证同输入同输出

	def := Definition{}
	for _, rawField := range keys {
		mods := strings.Split(strings.ToLower(rawField), "|")
		sigmaField := strings.TrimSpace(mods[0])
		target, ok := sigmaFieldMap[strings.ToLower(sigmaField)]
		if !ok {
			return Definition{}, fmt.Errorf("字段 %q 无映射（v1 不支持该遥测维度）", sigmaField)
		}
		values := sigmaValues(fields[rawField])
		if len(values) == 0 {
			return Definition{}, fmt.Errorf("字段 %q 的值为空", sigmaField)
		}
		op, allFlag, err := sigmaModifierToOp(mods[1:])
		if err != nil {
			return Definition{}, err
		}
		for _, v := range values {
			cond := Condition{Field: target, Op: op, Value: v}
			switch {
			case allFlag:
				def.All = append(def.All, cond) // |all：多值全部成立（AND）
			case len(values) > 1:
				def.Any = append(def.Any, cond) // 多值默认 OR
			default:
				def.All = append(def.All, cond) // 单值：与块内其他字段 AND
			}
		}
	}
	return def, nil
}

// sigmaModifierToOp 把 Sigma 值修饰符翻译成本引擎操作符。
// 返回 (op, 是否 |all, 错误)。不支持的修饰符显式报错——
// tyrian 教训："渲染成字面量的规则会部署且永不命中"。
// 大小写语义依据：Sigma 字符串匹配默认大小写不敏感（规范口径），
// 与本引擎 icontains/prefix/suffix/glob 的求值实现一致（均 lower 后比较）；
// |cased 时改用大小写敏感的 contains；|re 的语法（Sigma 规范明示
// Golang RE2）与本引擎 regexp 求值同源，语法级兼容。
func sigmaModifierToOp(mods []string) (string, bool, error) {
	cased := false
	all := false
	contains := false
	startsWith := false
	endsWith := false
	re := false
	for _, m := range mods {
		switch strings.TrimSpace(m) {
		case "contains":
			contains = true
		case "startswith":
			startsWith = true
		case "endswith":
			endsWith = true
		case "cased":
			cased = true
		case "all":
			all = true
		case "re":
			re = true
		default:
			return "", false, fmt.Errorf("值修饰符 %q 不支持（v1 支持 contains/startswith/endswith/re/cased/all）", m)
		}
	}
	switch {
	case re:
		return "regex", all, nil
	case contains && startsWith:
		return "", false, fmt.Errorf("修饰符组合 contains|startswith 暂不支持")
	case startsWith:
		return "prefix", all, nil
	case endsWith:
		return "suffix", all, nil
	case contains:
		if cased {
			return "contains", all, nil
		}
		return "icontains", all, nil
	default:
		return "glob", all, nil // 无修饰符 = wildcard 值（* 与 ?），glob 同为大小写不敏感
	}
}

// splitCond 按（小写化的）分隔符切分 condition，保留原始大小写。
func splitCond(cond, sep string) []string {
	lc := strings.ToLower(cond)
	lsep := strings.ToLower(sep)
	var out []string
	for {
		i := strings.Index(lc, lsep)
		if i < 0 {
			out = append(out, cond)
			return out
		}
		out = append(out, cond[:i])
		cond = cond[i+len(sep):]
		lc = lc[i+len(sep):]
	}
}

// sigmaValues 把 YAML 值归一成字符串列表（标量→单元素）。
func sigmaValues(v any) []string {
	switch t := v.(type) {
	case []any:
		out := make([]string, 0, len(t))
		for _, e := range t {
			out = append(out, fmt.Sprintf("%v", e))
		}
		return out
	case string:
		return []string{t}
	case nil:
		return nil
	default:
		return []string{fmt.Sprintf("%v", t)}
	}
}

func orSuffix(total, idx int) string {
	if total <= 1 {
		return ""
	}
	return fmt.Sprintf("（分支 %d/%d）", idx+1, total)
}

func sigmaFPNote(fps []string) string {
	if len(fps) == 0 {
		return ""
	}
	return "\n\n已知误报（来自 Sigma 规则，仅供加白参考，未自动加白）：" + strings.Join(fps, "、")
}

func firstNonEmptyStr(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func orDashStr(s string) string {
	if strings.TrimSpace(s) == "" {
		return "-"
	}
	return s
}
