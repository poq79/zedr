//go:build linux

// 资产清单循环（Linux）：linuxinv 八节离线盘点 + 差量上报 + 条目级
// diff → 告警管线，与 Windows 版 inventoryLoop 同构。差异只在分级
// 口径（classifyInventoryEventLinux）：Linux 无签名面，"新增服务"
// 的 signed 分支不存在，一律按未签名从严。
//
// 未在 Linux 实机验证。
package lapp

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"time"

	"zedr/internal/agent/inventory"
	"zedr/internal/agent/linuxinv"
	"zedr/internal/model"
)

// inventoryInterval 与 Windows 同参：清单变化频率远低于进程创建，
// 30s 足够及时；差量协议保证稳定态下每轮几乎零流量。
const inventoryInterval = 30 * time.Second

// inventoryLoop 周期采集资产清单快照并差量上报；变化节随后做条目级
// diff，把"新增了哪个服务/哪个 cron 项"转成告警。
func (a *Agent) inventoryLoop(ctx context.Context) {
	m := inventory.New(a.log)
	a.inv = m
	linuxinv.AgentVersion = a.cfg.Version

	// startup 节由 persist 基线提供（与 Windows invStartupSection 同语义）
	linuxinv.RegisterAll(m, a.log, a.invStartupSection)

	// 可 diff 节的条目主键（Linux 节形状对齐 Windows 线协议）
	keyFns := map[string]func(map[string]any) string{
		"services":  inventoryFieldKey("name"),
		"tasks":     inventoryFieldKey("path"),
		"listeners": inventoryFieldKey("proto", "port"),
		"startup":   inventoryFieldKey("kind", "location"),
		"users":     inventoryFieldKey("name"),
	}

	m.Run(ctx, inventoryInterval, func(sections []model.InventorySection) ([]string, error) {
		cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
		applied, err := a.up.PostInventory(cctx, sections)
		cancel()
		// 只在 post 成功后 diff：失败轮 Run 会回滚 payload 并在下一轮
		// 重试同一节，失败轮也发事件会把同一批变更重复告警。
		if err == nil {
			a.diffInventoryEvents(sections, keyFns)
		}
		return applied, err
	})
}

// invStartupSection 从 persist 基线投影 startup 节。
func (a *Agent) invStartupSection() (any, error) {
	items := a.pm.Items()
	type startupItem struct {
		Kind     string `json:"kind"`
		Location string `json:"location"`
		Name     string `json:"name"`
		Command  string `json:"command"`
	}
	out := make([]startupItem, 0, len(items))
	for _, it := range items {
		out = append(out, startupItem{
			Kind: it.Kind, Location: it.Location,
			Name: it.Key, Command: it.Value,
		})
	}
	return map[string]any{"items": out}, nil
}

// inventoryFieldKey 由指定字段拼条目主键（缺字段退化为整条 JSON）。
func inventoryFieldKey(fields ...string) func(map[string]any) string {
	return func(item map[string]any) string {
		parts := make([]string, 0, len(fields))
		for _, f := range fields {
			if v, ok := item[f]; ok {
				parts = append(parts, toStringKey(v))
			}
		}
		if len(parts) == 0 {
			return strings.TrimSpace(strings.Join(fields, "|")) + "|" + toStringKey(item)
		}
		return strings.Join(parts, "|")
	}
}

// toStringKey 把条目字段值转成 key 片段：字符串原样；数字统一整型口径
// （端口/计数不存在小数语义）；其余类型 JSON 序列化（兜底，不该出现）。
func toStringKey(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	case bool:
		if t {
			return "true"
		}
		return "false"
	default:
		if b, err := json.Marshal(v); err == nil {
			return string(b)
		}
		return ""
	}
}

// diffInventoryEvents 对本轮差量节做条目级 diff 并转告警。
// 首轮（invReady=false）只建基线不发事件。
func (a *Agent) diffInventoryEvents(sections []model.InventorySection, keyFns map[string]func(map[string]any) string) {
	wasReady := a.invReady
	a.invReady = true
	if !wasReady {
		return
	}
	for _, s := range sections {
		keyFn, ok := keyFns[s.Name]
		if !ok {
			continue
		}
		prev, ok := a.inv.LastPayload(s.Name)
		if !ok {
			continue
		}
		evs, err := inventory.Diff(prev, s.Payload, keyFn)
		if err != nil {
			a.log.Warn("inventory_diff_failed", "section", s.Name, "err", err)
			continue
		}
		for _, ev := range evs {
			sev, score, mitre := classifyInventoryEventLinux(ev)
			if sev == "" {
				continue
			}
			a.emitAlert(model.AlertEnvelope{
				Fingerprint: "inv:" + s.Name + ":" + ev.Key + ":" + string(ev.Kind),
				Title:       inventoryEventTitle(s.Name, ev),
				Summary:     ev.Detail,
				Verdict:     model.VerdictSuspicious,
				Severity:    sev,
				Score:       score,
				ProcUser:    "SYSTEM/INVENTORY",
				RuleIDs:     []string{"INV-" + strings.ToUpper(s.Name)},
				MITRE:       mitre,
				OccurredAt:  time.Now(),
			})
		}
	}
}

// classifyInventoryEventLinux 是 Linux 版分级口径（对齐 Windows 版的
// 组合思路，按 Linux 节语义裁剪）：无签名面 → 服务/自启动新增一律按
// 未签名从严；users 是 Linux 特有节（新增可登录账户=T1098 高价值）。
func classifyInventoryEventLinux(ev inventory.ChangeEvent) (model.Severity, int, []string) {
	switch ev.Section {
	case "services":
		if ev.Kind == inventory.DiffAdded {
			return model.SeverityHigh, 60, []string{"T1543.002"}
		}
		return model.SeverityLow, 30, []string{"T1562.001"}
	case "tasks":
		if ev.Kind == inventory.DiffAdded {
			return model.SeverityMedium, 45, []string{"T1053.003"}
		}
		return model.SeverityLow, 30, nil
	case "listeners":
		if ev.Kind == inventory.DiffAdded {
			// 新监听端口（非回环）是暴露面变化，从严
			return model.SeverityHigh, 60, []string{"T1571"}
		}
		return model.SeverityLow, 30, nil
	case "startup":
		if ev.Kind == inventory.DiffAdded {
			return model.SeverityHigh, 60, []string{"T1547"}
		}
		return model.SeverityLow, 30, []string{"T1547"}
	case "users":
		if ev.Kind == inventory.DiffAdded {
			return model.SeverityHigh, 60, []string{"T1098"}
		}
		return model.SeverityLow, 30, nil
	default:
		return "", 0, nil
	}
}

func inventoryEventTitle(section string, ev inventory.ChangeEvent) string {
	verb := "变更"
	switch ev.Kind {
	case inventory.DiffAdded:
		verb = "新增"
	case inventory.DiffRemoved:
		verb = "移除"
	}
	return "资产变更：" + section + " " + verb + "（" + ev.Key + "）"
}
