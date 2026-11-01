package api

import (
	"net/http"
	"testing"
	"time"

	"hostguard/internal/model"
)

// TestAttackMatrixAndDrillDown 端到端验证 ATT&CK 矩阵：
// 告警命中归位到正确战术、目录外编号进"未分类"、mitre 精确下钻
// 不会把父技术 T1059 与子技术 T1059.001 混在一起。
func TestAttackMatrixAndDrillDown(t *testing.T) {
	env := newTestEnv(t)
	agent := env.enrollAgent()
	env.agent = agent
	env.doAgentJSON(http.MethodPost, "/api/v1/agent/heartbeat",
		map[string]any{"hostname": "TEST-HOST", "proc_count": 10}, http.StatusOK)

	mk := func(fp string, mitre []string) model.AlertBatchRequest {
		return model.AlertBatchRequest{Alerts: []model.AlertEnvelope{{
			Fingerprint: fp,
			Title:       "ATT&CK 矩阵测试",
			Verdict:     model.VerdictSuspicious,
			Severity:    model.SeverityHigh,
			Score:       60,
			PID:         100,
			ProcessName: "powershell.exe",
			RuleIDs:     []string{"HG-003"},
			MITRE:       mitre,
			OccurredAt:  time.Now(),
		}}}
	}
	// 编号一：目录内（PowerShell 执行 → TA0002）；编号二：目录外
	env.doAgentJSON(http.MethodPost, "/api/v1/agent/alerts",
		mk("fp-matrix-1", []string{"T1059.001", "T9999"}), http.StatusOK)
	// 父技术 T1059 与子技术 T1059.001 是两个格子
	env.doAgentJSON(http.MethodPost, "/api/v1/agent/alerts",
		mk("fp-matrix-2", []string{"T1059"}), http.StatusOK)

	var m struct {
		Tactics []struct {
			ID         string `json:"id"`
			NameZh     string `json:"name_zh"`
			Techniques []struct {
				ID         string `json:"id"`
				AlertCount int    `json:"alert_count"`
				OpenCount  int    `json:"open_count"`
				RuleCount  int    `json:"rule_count"`
			} `json:"techniques"`
		} `json:"tactics"`
		WindowDays int `json:"window_days"`
		Summary    struct {
			TechniquesHit     int `json:"techniques_hit"`
			TechniquesCovered int `json:"techniques_covered"`
			TotalAlerts       int `json:"total_alerts"`
			Unmapped          int `json:"unmapped"`
		} `json:"summary"`
	}
	env.doJSON(http.MethodGet, "/api/v1/attack/matrix", nil, http.StatusOK, env.token, &m)

	if m.WindowDays != 30 {
		t.Fatalf("默认窗口应为 30 天，实际 %d", m.WindowDays)
	}
	if m.Summary.TotalAlerts != 2 || m.Summary.TechniquesHit != 3 {
		t.Fatalf("摘要不符: %+v", m.Summary)
	}
	if m.Summary.Unmapped != 1 {
		t.Fatalf("目录外编号应计 1 个，实际 %+v", m.Summary)
	}

	findCell := func(tacticID, techID string) (cell struct {
		ID         string `json:"id"`
		AlertCount int    `json:"alert_count"`
		OpenCount  int    `json:"open_count"`
		RuleCount  int    `json:"rule_count"`
	}, ok bool) {
		for _, tac := range m.Tactics {
			if tac.ID != tacticID {
				continue
			}
			for _, c := range tac.Techniques {
				if c.ID == techID {
					return c, true
				}
			}
		}
		return cell, false
	}
	// 已知技术进执行列，且内置规则覆盖计数 > 0
	cellT1059, ok := findCell("TA0002", "T1059.001")
	if !ok {
		t.Fatal("T1059.001 未出现在执行战术中")
	}
	if cellT1059.AlertCount != 1 || cellT1059.OpenCount != 1 || cellT1059.RuleCount == 0 {
		t.Fatalf("T1059.001 格子数据不符: %+v", cellT1059)
	}
	if _, ok := findCell("TA0002", "T1059"); !ok {
		t.Fatal("T1059 未出现在执行战术中")
	}
	// 目录外编号落在未分类
	if _, ok := findCell("uncategorized", "T9999"); !ok {
		t.Fatal("T9999 未归入未分类战术")
	}

	// ---- 精确下钻：mitre 过滤 ----
	var list struct {
		Total int `json:"total"`
	}
	env.doJSON(http.MethodGet, "/api/v1/alerts?mitre=T1059.001", nil, http.StatusOK, env.token, &list)
	if list.Total != 1 {
		t.Fatalf("T1059.001 精确下钻应命中 1 条，实际 %d", list.Total)
	}
	// 父技术编号不吞掉子技术告警
	env.doJSON(http.MethodGet, "/api/v1/alerts?mitre=T1059", nil, http.StatusOK, env.token, &list)
	if list.Total != 1 {
		t.Fatalf("T1059 精确下钻应命中 1 条（不含 T1059.001），实际 %d", list.Total)
	}
	// 小写容错
	env.doJSON(http.MethodGet, "/api/v1/alerts?mitre=t1059.001", nil, http.StatusOK, env.token, &list)
	if list.Total != 1 {
		t.Fatalf("小写编号应归一后命中，实际 %d", list.Total)
	}

	// 未授权访问被拒
	env.doJSON(http.MethodGet, "/api/v1/attack/matrix", nil, http.StatusUnauthorized, "", nil)
}
