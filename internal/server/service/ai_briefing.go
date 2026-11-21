package service

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"zedr/internal/server/domain"
)

// ---------------------------------------------------------------- 今日值班简报（主动式 AI 第一步）
//
// 设计口径（2026-11-11 定向调研，来源见 overview.md）：Copilot Home/Today
// 的主动式命令中心形态 = 不等用户提问，先给"现在的盘子"。简报刻意做成
// **纯确定性聚合、零模型调用**——开总览页就拉一次，模型叙事会烧预算且
// 无模型时简报缺位；"让 AI 解读"作为一键动作把简报上下文喂给流式助手
// （作用域对话），token 花在人主动点击的那一刻。

// BriefAlert 是简报里的一条最近 critical 告警摘要。
type BriefAlert struct {
	ID          string    `json:"id"`
	Title       string    `json:"title"`
	Hostname    string    `json:"hostname"`
	Score       int       `json:"score"`
	ProcessName string    `json:"process_name,omitempty"`
	OccurredAt  time.Time `json:"occurred_at"`
}

// BriefRule 是窗口内一条高发规则。
type BriefRule struct {
	RuleID string `json:"rule_id"`
	Count  int    `json:"count"`
}

// DailyBriefing 是今日值班简报。
type DailyBriefing struct {
	WindowHours  int          `json:"window_hours"`
	GeneratedAt  time.Time    `json:"generated_at"`
	AlertsNew    int          `json:"alerts_new"`
	CriticalNew  int          `json:"critical_new"`
	EventsOpen   int          `json:"events_open"` // 窗口内新开的事件（incident）
	ChainHits    int          `json:"chain_hits"`  // 攻击链规则（CHAIN-*）新命中
	OpsPending   int          `json:"ops_pending"` // 值班队列待审
	HostsOffline int          `json:"hosts_offline"`
	TopRules     []BriefRule  `json:"top_rules"`
	RecentCrit   []BriefAlert `json:"recent_critical"`
	// Narrative 是 AI 态势叙述（narrative 槽位，30min 缓存）。仅当调用方
	// 显式请求且模型可用时非空——确定性骨架永远在，AI 只做解读层。
	Narrative string `json:"narrative,omitempty"`
	// NarrativeState: "ai"（成功）/ 降级原因（空串=未请求纯统计）。
	NarrativeState string `json:"narrative_state,omitempty"`
}

// DailyBriefing 聚合窗口内的值班盘子。全只读、全确定性——简报的可靠性
// 优先于聪明：AI 解读由用户显式点击"追问 AI"进入作用域对话。
func (s *AIService) DailyBriefing(ctx context.Context, hours int, wantNarrative bool) (*DailyBriefing, error) {
	if hours <= 0 || hours > 168 {
		hours = 24
	}
	b := &DailyBriefing{WindowHours: hours, GeneratedAt: time.Now()}
	cutoff := b.GeneratedAt.Add(-time.Duration(hours) * time.Hour)

	// 告警窗口统计：取最新 500 条再按时间过滤（告警无时间过滤参数，
	// 500 条对 24h 窗口是宽裕上界；更早的告警不参与简报）
	alerts, _, err := s.repos.Alerts.List(ctx, domain.AlertFilter{Page: 1, PageSize: 500})
	if err == nil {
		ruleCount := map[string]int{}
		for _, a := range alerts {
			if a.CreatedAt.Before(cutoff) {
				continue
			}
			b.AlertsNew++
			if a.Severity == domain.SeverityCritical {
				b.CriticalNew++
				if len(b.RecentCrit) < 3 {
					b.RecentCrit = append(b.RecentCrit, BriefAlert{
						ID: a.ID, Title: a.Title, Hostname: a.Hostname,
						Score: a.Score, ProcessName: a.ProcessName, OccurredAt: a.CreatedAt,
					})
				}
			}
			for _, id := range a.RuleIDs {
				if strings.HasPrefix(id, "CHAIN-") {
					b.ChainHits++
					continue
				}
				ruleCount[id]++
			}
		}
		for id, n := range ruleCount {
			b.TopRules = append(b.TopRules, BriefRule{RuleID: id, Count: n})
		}
		sort.Slice(b.TopRules, func(i, j int) bool { return b.TopRules[i].Count > b.TopRules[j].Count })
		if len(b.TopRules) > 3 {
			b.TopRules = b.TopRules[:3]
		}
	}

	// 事件（incident）窗口新开数
	if incs, _, err := s.repos.Incidents.List(ctx, "", 1, 200); err == nil {
		for _, in := range incs {
			if in.FirstSeen.After(cutoff) {
				b.EventsOpen++
			}
		}
	}

	// 值班队列待审
	if q, err := s.ListOpsQueue(ctx); err == nil {
		for _, it := range q {
			if it.Status == "pending" {
				b.OpsPending++
			}
		}
	}

	// 失联主机（在线率是简报的底色：防护面不全，其他数字都要打折）
	if agents, err := s.repos.Agents.List(ctx); err == nil {
		for _, a := range agents {
			if a.Status != domain.AgentOnline {
				b.HostsOffline++
			}
		}
	}

	// AI 态势叙述：数字聚合完成后才生成（叙述的事实源就是上面这些数字）。
	// 生成失败诚实降级为纯统计，State 里带原因——简报永远可用，AI 是加分项。
	if wantNarrative && s.eng != nil {
		var sb strings.Builder
		sb.WriteString(fmt.Sprintf("统计窗口 %d 小时：新增告警 %d（critical %d），新开事件 %d，攻击链命中 %d，",
			b.WindowHours, b.AlertsNew, b.CriticalNew, b.EventsOpen, b.ChainHits))
		sb.WriteString(fmt.Sprintf("值班队列待审 %d，失联主机 %d。", b.OpsPending, b.HostsOffline))
		if len(b.TopRules) > 0 {
			ids := make([]string, 0, len(b.TopRules))
			for _, r := range b.TopRules {
				ids = append(ids, fmt.Sprintf("%s×%d", r.RuleID, r.Count))
			}
			sb.WriteString("高发规则：" + strings.Join(ids, "、") + "。")
		}
		if text, state := s.eng.BriefNarrative(ctx, sb.String()); state == "ai" {
			b.Narrative = text
			b.NarrativeState = "ai"
		} else {
			b.NarrativeState = state
		}
	}
	return b, nil
}

// Text 把简报渲染成 IM 推送文本（每日 0800 定时推送用）。确定性、无模型、
// 零装饰——IM 卡片是"看一眼就知道今天要不要进控制台"，细节去管理台看。
func (b *DailyBriefing) Text() string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("【Z-EDR 值班简报 · 近 %dh】\n", b.WindowHours))
	sb.WriteString(fmt.Sprintf("新增告警 %d（critical %d）· 新开事件 %d · 攻击链命中 %d\n",
		b.AlertsNew, b.CriticalNew, b.EventsOpen, b.ChainHits))
	sb.WriteString(fmt.Sprintf("值班队列待审 %d · 失联主机 %d", b.OpsPending, b.HostsOffline))
	if len(b.TopRules) > 0 {
		ids := make([]string, 0, len(b.TopRules))
		for _, r := range b.TopRules {
			ids = append(ids, fmt.Sprintf("%s×%d", r.RuleID, r.Count))
		}
		sb.WriteString("\n高发规则：" + strings.Join(ids, "、"))
	}
	for _, a := range b.RecentCrit {
		sb.WriteString(fmt.Sprintf("\n• [%d] %s @ %s", a.Score, a.Title, a.Hostname))
	}
	if b.AlertsNew == 0 && b.OpsPending == 0 && b.HostsOffline == 0 {
		sb.WriteString("\n窗口内无新增告警、无待审、无失联——今天可以晚一点再看。")
	}
	return sb.String()
}
