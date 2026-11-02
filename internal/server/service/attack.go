package service

import (
	"context"
	"sort"
	"time"

	"zedr/internal/attack"
	"zedr/internal/server/domain"
)

// AttackMatrix 构建战术×技术覆盖矩阵。
//
// 两个维度同图呈现：
//   - 告警命中（时间窗内）：有命中 = 该技术真实出现过；
//   - 规则覆盖（启用规则）：有覆盖无命中 = 安静态，是好事不是缺口。
//
// 只有命中没有覆盖的技术值得警惕——检出来自信号层兜底而非行为规则，
// 说明该链条还没有稳定的行为特征可依。
func (s *StatsService) AttackMatrix(ctx context.Context, windowDays int) (*domain.AttackMatrix, error) {
	if windowDays <= 0 {
		windowDays = 30
	}
	if windowDays > 365 {
		windowDays = 365
	}
	since := time.Now().Add(-time.Duration(windowDays) * 24 * time.Hour)

	agg, alertTotal, err := s.repos.Stats.MitreAgg(ctx, since)
	if err != nil {
		return nil, err
	}
	enabled, err := s.repos.Rules.ListEnabled(ctx)
	if err != nil {
		return nil, err
	}
	summary := domain.AttackSummary{TotalAlerts: alertTotal}

	// 启用规则 → 技术覆盖计数（规则的 MITRE 也是多值）
	ruleCount := map[string]int{}
	for _, r := range enabled {
		for _, m := range r.MITRE {
			if m = attack.NormalizeTech(m); m != "" {
				ruleCount[m]++
			}
		}
	}

	// 格子全集 = 目录技术 ∪ 告警中出现的技术 ∪ 有规则覆盖的技术。
	// 任何一路出现都不丢，保证矩阵与库内数据可对账。
	type cell struct {
		domain.AttackTechStat
		tacticID string
	}
	cells := map[string]*cell{}

	place := func(techID, name, nameZh, tacticID string) *cell {
		c, ok := cells[techID]
		if !ok {
			c = &cell{tacticID: tacticID}
			c.ID = techID
			c.Name = name
			c.NameZh = nameZh
			cells[techID] = c
		}
		return c
	}

	for _, tech := range attack.AllTechniques() {
		place(tech.ID, tech.Name, tech.NameZh, tech.TacticID)
	}
	for techID := range agg {
		techID = attack.NormalizeTech(techID)
		if tech, ok := attack.LookupTechnique(techID); ok {
			place(techID, tech.Name, tech.NameZh, tech.TacticID)
		} else {
			// 目录外编号（自定义规则新编号等）：归入未分类，不丢数据
			place(techID, techID, techID, attack.UncategorizedTacticID)
		}
	}
	for techID := range ruleCount {
		if tech, ok := attack.LookupTechnique(techID); ok {
			place(techID, tech.Name, tech.NameZh, tech.TacticID)
		} else {
			place(techID, techID, techID, attack.UncategorizedTacticID)
		}
	}

	// 填充聚合值与摘要（TotalAlerts 已由仓储单独统计，见上）
	for techID, c := range cells {
		if a, ok := agg[techID]; ok {
			c.AlertCount = a.Count
			c.OpenCount = a.Open
			c.CriticalCount = a.Critical
			if !a.LastSeen.IsZero() {
				c.LastSeen = a.LastSeen.Format(time.RFC3339)
			}
		}
		c.RuleCount = ruleCount[techID]
		if c.AlertCount > 0 {
			summary.TechniquesHit++
		}
		if c.RuleCount > 0 {
			summary.TechniquesCovered++
		}
		if c.tacticID == attack.UncategorizedTacticID {
			summary.Unmapped++
		}
	}

	// 按战术分组；战术内命中多的在前，其次按编号，保证渲染稳定
	grouped := map[string][]domain.AttackTechStat{}
	for _, c := range cells {
		grouped[c.tacticID] = append(grouped[c.tacticID], c.AttackTechStat)
	}
	out := &domain.AttackMatrix{
		WindowDays:  windowDays,
		GeneratedAt: time.Now(),
		Summary:     summary,
	}
	for _, tactic := range attack.Tactics() {
		cellsByTactic := grouped[tactic.ID]
		if cellsByTactic == nil {
			cellsByTactic = []domain.AttackTechStat{}
		}
		sort.Slice(cellsByTactic, func(i, j int) bool {
			if cellsByTactic[i].AlertCount != cellsByTactic[j].AlertCount {
				return cellsByTactic[i].AlertCount > cellsByTactic[j].AlertCount
			}
			return cellsByTactic[i].ID < cellsByTactic[j].ID
		})
		out.Tactics = append(out.Tactics, domain.AttackTactic{
			ID: tactic.ID, Name: tactic.Name, NameZh: tactic.NameZh, Techniques: cellsByTactic,
		})
	}
	return out, nil
}
