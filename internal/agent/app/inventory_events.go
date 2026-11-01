// 本文件实现资产清单变更事件 → 告警的策略层：
// inventory.Diff 产出的 ChangeEvent 按节/动作富化定级，组装成 AlertEnvelope
// 走统一告警出口（本地视图 + 上报队列）。机制层（diff 本身）在 inventory 包，
// 这里只做"哪些变更值得告警、值多少分"的策略决定。
package agentapp

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"hostguard/internal/agent/enrich"
	"hostguard/internal/agent/inventory"
	"hostguard/internal/agent/winapi"
	"hostguard/internal/model"
)

// maxInventoryEventsPerRound 是单轮快照允许发射的资产变更告警上限。
// 服务/任务类条目在软件安装、组策略刷新时可能整批变动，不设上限的话
// 一次误判会把告警队列刷满，淹没真正的进程类高价值告警。
const maxInventoryEventsPerRound = 20

// inventoryFieldKey 生成条目主键提取函数：按给定字段顺序取值用 "|" 拼接
// （如 services 按 "name"、startup 按 "kind|location"）。
// 缺失字段取空串而不是 "<nil>"——缺字段是老版本 payload 的正常形态。
func inventoryFieldKey(fields ...string) func(map[string]any) string {
	return func(m map[string]any) string {
		parts := make([]string, 0, len(fields))
		for _, f := range fields {
			if v, ok := m[f]; ok && v != nil {
				parts = append(parts, fmt.Sprintf("%v", v))
			} else {
				parts = append(parts, "")
			}
		}
		return strings.Join(parts, "|")
	}
}

// emitInventoryEvents 把一轮 diff 产出的事件转成告警，带防风暴折叠：
// 超过单轮上限的事件丢弃，并汇总为一条 info 级提示（运维需要知道
// 有变更被折叠，否则资产页与告警流会对不上数）。
func (a *Agent) emitInventoryEvents(ctx context.Context, changes []inventory.ChangeEvent) {
	if len(changes) == 0 || ctx.Err() != nil {
		return
	}
	emitted := 0
	dropped := 0
	var droppedDescs []string
	for _, ev := range changes {
		if emitted >= maxInventoryEventsPerRound {
			dropped++
			if len(droppedDescs) < 10 {
				droppedDescs = append(droppedDescs, ev.Section+" "+ev.Kind+" "+ev.Key)
			}
			continue
		}
		if a.emitInventoryEvent(ev) {
			emitted++
		}
	}
	if dropped > 0 {
		a.emitInventoryStormNotice(len(changes), dropped, droppedDescs)
	}
}

// emitInventoryEvent 把单条变更事件转成告警；返回是否真的发射了
// （白名单命中的事件被跳过，不算发射也不算丢弃）。
func (a *Agent) emitInventoryEvent(ev inventory.ChangeEvent) bool {
	entry := ev.After
	if entry == nil {
		entry = ev.Before
	}
	path := inventoryEventPath(ev, entry)

	// 白名单优先：运维明确信任的对象（路径前缀）不再打扰
	if path != "" {
		if hit, _ := a.alw.Match("", path, "", "", "", ""); hit {
			a.log.Debug("inventory_whitelisted", "section", ev.Section, "kind", ev.Kind, "key", ev.Key)
			return false
		}
	}

	// 富化只对 added/changed 且有路径的做：removed 的文件往往已不在盘上，
	// 此时 Describe 只会得到"文件不存在"的噪声结论
	var meta enrich.Meta
	haveMeta := false
	if path != "" && ev.Kind != inventory.DiffRemoved {
		meta = a.enr.Describe(path)
		haveMeta = true
	}

	sev, score, mitre := classifyInventoryEvent(ev, path, meta, haveMeta)
	if mitre == nil {
		mitre = []string{}
	}

	detail := ev.Detail
	if detail == "" {
		detail = inventoryEntrySummary(entry)
	}

	// Summary = Detail + 签名结论（有富化结果时）
	summary := detail
	if note := inventorySigConclusion(haveMeta, meta); note != "" {
		summary = strings.TrimSpace(summary + "；" + note)
	}

	sigID := "INV-" + strings.ToUpper(ev.Section)
	env := model.AlertEnvelope{
		Fingerprint: invFingerprint(ev.Section, ev.Kind, ev.Key),
		Title: "资产变更：" + inventoryAction(ev.Kind) +
			inventorySectionLabel(ev.Section) + " " + ev.Key,
		Summary:  summary,
		Verdict:  inventoryVerdict(score),
		Severity: sev,
		Score:    score,
		// ProcessName 只在事件能关联到进程时非空（listeners 的 tcp 条目带进程名）
		ProcessName: strAny(entry, "process"),
		ImagePath:   path,
		RuleIDs:     []string{sigID},
		MITRE:       mitre,
		Evidence: model.Evidence{
			Signals: []model.Signal{{
				Layer: "inventory", ID: sigID, Name: "资产清单变更",
				Score: score, Note: detail, MITRE: strings.Join(mitre, ","),
			}},
			Notes: inventoryEvidenceNotes(ev),
		},
		OccurredAt: time.Now(),
	}
	a.emitAlert(env)
	a.log.Warn("inventory_change_alert",
		"section", ev.Section, "kind", ev.Kind, "key", ev.Key, "severity", sev)
	return true
}

// classifyInventoryEvent 是事件 → 定级的唯一映射点。
// 取舍：removed 一律 low（正常卸载远多于"攻击者清痕迹"，persist 侧同口径）；
// services/tasks/listeners 的 added 是持久化/驻留的高信号位置，给中高风险；
// adapters 变化（网卡增减、IP 变更）本身无攻击语义，只记录。
func classifyInventoryEvent(ev inventory.ChangeEvent, path string, meta enrich.Meta, haveMeta bool) (model.Severity, int, []string) {
	// signed 与 persist 包同口径：证书存在且校验通过才算"签名有效"
	signed := haveMeta && meta.Signed && meta.SignatureOK

	switch ev.Section {
	case "services":
		switch ev.Kind {
		case inventory.DiffAdded:
			// 新增服务：签名有效 → medium；签不出有效签名（含无路径可验）
			// → high。服务是最高价值的持久化位置，从严。
			if signed {
				return model.SeverityMedium, 45, []string{"T1543.003"}
			}
			return model.SeverityHigh, 60, []string{"T1543.003"}
		case inventory.DiffRemoved:
			return model.SeverityLow, 30, []string{"T1562.001"}
		default:
			return model.SeverityLow, 30, nil
		}
	case "tasks":
		if ev.Kind == inventory.DiffAdded {
			return model.SeverityMedium, 45, []string{"T1053.005"}
		}
		return model.SeverityLow, 30, nil
	case "listeners":
		if ev.Kind == inventory.DiffAdded {
			// 有进程路径且未签名才 high：system32 里的监听者是常态
			if path != "" && haveMeta && !signed {
				return model.SeverityHigh, 60, []string{"T1571"}
			}
			return model.SeverityLow, 30, nil
		}
		return model.SeverityLow, 30, nil
	case "startup":
		if ev.Kind == inventory.DiffAdded {
			// 自启动项没有签名语义，按"落点"定级：能解析出路径且不在
			// 系统目录（或路径文本不含 windows 目录痕迹）才 high
			if path != "" && haveMeta && !meta.InSystem && !looksLikeSystemPath(path) {
				return model.SeverityHigh, 60, []string{"T1547.001"}
			}
			return model.SeverityLow, 30, []string{"T1547.001"}
		}
		return model.SeverityLow, 30, nil
	case "defender":
		// 排除项是"给恶意软件开门"：新增排除 = critical；实时保护从 on
		// 变 off 同理。removed（取消排除）与一般 changed 属运营动作，low。
		switch ev.Kind {
		case inventory.DiffAdded:
			return model.SeverityCritical, 75, []string{"T1562.001"}
		case inventory.DiffChanged:
			// Detail 里带字段级差异；排除列表增长按 critical、其余按 low
			if strings.Contains(ev.Detail, "新增") || strings.Contains(ev.Detail, "exclusion") {
				return model.SeverityCritical, 75, []string{"T1562.001"}
			}
			return model.SeverityLow, 30, nil
		default:
			return model.SeverityLow, 30, []string{"T1562.001"}
		}
	case "firewall":
		// 配置档被关闭 = critical（T1562.004）；重新开启是恢复动作，medium
		if ev.Kind == inventory.DiffChanged && strings.Contains(ev.Detail, "disabled") {
			return model.SeverityCritical, 75, []string{"T1562.004"}
		}
		if ev.Kind == inventory.DiffChanged {
			return model.SeverityMedium, 45, []string{"T1562.004"}
		}
		return model.SeverityLow, 30, nil
	case "accounts":
		// 管理员组成员变化是最直接的权限提升证据（T1098）
		if ev.Kind == inventory.DiffAdded {
			return model.SeverityCritical, 80, []string{"T1098"}
		}
		if ev.Kind == inventory.DiffRemoved {
			return model.SeverityMedium, 45, []string{"T1098"}
		}
		return model.SeverityLow, 30, nil
	default:
		// adapters 及未来新增节：保守 low
		return model.SeverityLow, 30, nil
	}
}

// looksLikeSystemPath 兜底判断路径文本是否指向系统目录。
// enrich 的 InSystem 基于已解析路径的前缀判断，但自启动命令行里
// %windir% 这类引用不会被展开（os.ExpandEnv 不认 %VAR% 语法），
// 解析出的"字面路径"既不在系统目录也 stat 不到——不加这个兜底，
// Windows 自带的 %windir%\system32 自启动项会被误判为"非系统目录"。
func looksLikeSystemPath(path string) bool {
	low := strings.ToLower(path)
	return strings.Contains(low, `\windows\`) || strings.Contains(low, `\system32\`) ||
		strings.Contains(low, `\syswow64\`)
}

// inventoryEventPath 提取事件关联的可执行文件路径（供白名单与富化）。
// tasks 的 key 是任务路径（\Microsoft\...），不是磁盘文件路径，不参与。
func inventoryEventPath(ev inventory.ChangeEvent, entry map[string]any) string {
	switch ev.Section {
	case "services":
		// PathName 常带参数（"C:\...\svc.exe -k x"），解析出镜像路径
		return winapi.PersistCommandPath(strAny(entry, "path_name"))
	case "startup":
		return winapi.PersistCommandPath(strAny(entry, "value"))
	case "listeners":
		// 监听条目只有 PID，实时查镜像路径（监听进程存活，查询必成功；
		// 恰好退出的场景查不到返回空，按无路径定级 low）
		if pid := numAny(entry, "pid"); pid > 0 {
			if p, err := winapi.ImagePath(pid); err == nil {
				return p
			}
		}
	}
	return ""
}

// inventorySigConclusion 把富化结果转成一句签名结论（拼进 Summary）。
func inventorySigConclusion(haveMeta bool, meta enrich.Meta) string {
	if !haveMeta {
		return ""
	}
	switch {
	case meta.Signed && meta.SignatureOK:
		if meta.Signer != "" {
			return "签名：有效（" + meta.Signer + "）"
		}
		return "签名：有效"
	case meta.Signed:
		return "签名：无效（证书存在但校验未通过，文件可能被篡改）"
	default:
		return "签名：未签名"
	}
}

// inventoryAction 事件动作的中文名（用于标题）。
func inventoryAction(kind string) string {
	switch kind {
	case inventory.DiffAdded:
		return "新增"
	case inventory.DiffRemoved:
		return "移除"
	case inventory.DiffChanged:
		return "变更"
	default:
		return kind
	}
}

// inventorySectionLabel 节名的中文名（用于标题）。
func inventorySectionLabel(section string) string {
	switch section {
	case "services":
		return "服务 "
	case "tasks":
		return "计划任务 "
	case "listeners":
		return "监听端口 "
	case "adapters":
		return "网卡 "
	case "startup":
		return "自启动项 "
	default:
		return "清单项(" + section + ") "
	}
}

// inventoryVerdict 按分数给结论：与 persist 包阈值一致（38 分以上可疑）。
func inventoryVerdict(score int) model.Verdict {
	if score >= 38 {
		return model.VerdictSuspicious
	}
	return model.VerdictSafe
}

// invFingerprint 生成资产变更告警的指纹（section|kind|key 的 sha256 前 32 位）。
// 思路与 detect 包的 fingerprint 一致但独立实现：语义不同（进程事件指纹 vs
// 资产事件指纹），且 detect 的实现未导出、入参也绑定了进程证据结构。
func invFingerprint(section, kind, key string) string {
	sum := sha256.Sum256([]byte(strings.ToLower(section + "|" + kind + "|" + key)))
	return hex.EncodeToString(sum[:])[:32]
}

// inventoryEvidenceNotes 生成 before/after 摘要（附在 Evidence.Notes，
// 供服务端与 AI 研判还原"到底变了什么"）。
func inventoryEvidenceNotes(ev inventory.ChangeEvent) []string {
	notes := make([]string, 0, 2)
	if n := compactEntry("before", ev.Before); n != "" {
		notes = append(notes, n)
	}
	if n := compactEntry("after", ev.After); n != "" {
		notes = append(notes, n)
	}
	return notes
}

// compactEntry 把条目压成 "tag: {json}"（截断），只留概览不追求完整。
func compactEntry(tag string, m map[string]any) string {
	if len(m) == 0 {
		return ""
	}
	raw, err := json.Marshal(m)
	if err != nil {
		return ""
	}
	return tag + ": " + truncateStr(string(raw), 300)
}

// inventoryEntrySummary 给 added/removed 事件生成条目摘要（changed 事件的
// 字段级 Detail 由 Diff 生成）。字段按名排序取前几个，超长值截断。
func inventoryEntrySummary(entry map[string]any) string {
	keys := make([]string, 0, len(entry))
	for k := range entry {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for i, k := range keys {
		if i == 6 {
			parts = append(parts, fmt.Sprintf("…共 %d 个字段", len(keys)))
			break
		}
		parts = append(parts, k+": "+truncateStr(fmt.Sprintf("%v", entry[k]), 60))
	}
	return strings.Join(parts, "；")
}

// truncateStr 按 rune 截断。
func truncateStr(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}

// strAny 安全取字符串字段。
func strAny(m map[string]any, key string) string {
	if m == nil {
		return ""
	}
	s, _ := m[key].(string)
	return s
}

// numAny 安全取数值字段（JSON 反序列化后数字一律是 float64）。
func numAny(m map[string]any, key string) uint32 {
	if m == nil {
		return 0
	}
	f, ok := m[key].(float64)
	if !ok || f <= 0 {
		return 0
	}
	return uint32(f)
}

// emitInventoryStormNotice 折叠提示：一条 info 级告警，说明本轮有多少
// 变更被丢弃、样例是什么。指纹带时间戳——折叠提示每次都值得送达，
// 不该被服务端按指纹去重吞掉。
func (a *Agent) emitInventoryStormNotice(total, dropped int, descs []string) {
	summary := fmt.Sprintf("本轮共 %d 条资产变更，超过单轮 %d 条上限，%d 条已折叠。请到资产页核对完整清单。",
		total, maxInventoryEventsPerRound, dropped)
	if len(descs) > 0 {
		summary += " 折叠样例：" + strings.Join(descs, "；")
	}
	env := model.AlertEnvelope{
		Fingerprint: invFingerprint("inventory", "storm", time.Now().UTC().Format(time.RFC3339Nano)),
		Title:       "资产变更：变更风暴已折叠",
		Summary:     summary,
		Verdict:     model.VerdictSafe,
		Severity:    model.SeverityInfo,
		RuleIDs:     []string{"INV-STORM"},
		Evidence:    model.Evidence{Notes: descs},
		OccurredAt:  time.Now(),
	}
	a.emitAlert(env)
	a.log.Warn("inventory_change_alert",
		"section", "inventory", "kind", "storm", "key", "folded",
		"severity", env.Severity, "total", total, "dropped", dropped)
}
