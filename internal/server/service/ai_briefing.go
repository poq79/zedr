package service

import (
	"context"
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
}

// DailyBriefing 聚合窗口内的值班盘子。全只读、全确定性——简报的可靠性
// 优先于聪明：AI 解读由用户显式点击"追问 AI"进入作用域对话。
func (s *AIService) DailyBriefing(ctx context.Context, hours int) (*DailyBriefing, error) {
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
	return b, nil
}
