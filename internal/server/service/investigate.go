package service

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"hostguard/internal/platform/apperr"
	"hostguard/internal/server/domain"
)

// InvestigationStep 是自动调查的一步：结论必须带证据引用。
// 与 AI 研判同一纪律——没有引用的 Finding 视为编造，宁写"无证据"。
type InvestigationStep struct {
	Name      string   `json:"name"`
	Finding   string   `json:"finding"`
	Citations []string `json:"citations"`
}

// RecommendedAction 是建议的处置动作。Available 反映服务端开关现状——
// 建议一个执行器没启用的动作，等于让分析员去撞墙。
type RecommendedAction struct {
	Action    string `json:"action"`
	Target    string `json:"target"`
	Available bool   `json:"available"`
	Reason    string `json:"reason"`
}

// Investigation 是一次完整的确定性调查报告。
type Investigation struct {
	AlertID            string               `json:"alert_id"`
	VerdictSuggestion  string               `json:"verdict_suggestion"`
	Confidence         float64              `json:"confidence"`
	Steps              []InvestigationStep  `json:"steps"`
	RecommendedActions []RecommendedAction  `json:"recommended_actions"`
	CreatedAt          time.Time            `json:"created_at"`
}

// investigationCacheTTL 是调查报告缓存的生存期。
// 每次 Investigate 都会重算并覆盖——缓存只是给 GET 复用，
// 不是"结果有效期"：证据随时会变（新告警、新清单），重算永远新鲜。
const investigationCacheTTL = 30 * time.Minute

// investigateScoreBase 是调查打分的基线分：一条触发调查的告警本身
// 已经值得怀疑，取证只会让它更清楚，不会凭空变干净。
const investigateScoreBase = 40

type investigateCacheEntry struct {
	inv     *Investigation
	created time.Time
}

var investigateMu sync.Mutex
var investigateCache = map[string]investigateCacheEntry{}

// Investigate 对一条告警执行确定性调查编排（不依赖 LLM）：
// 同哈希跨主机 → 同主机关联 → IOC 比对 → 持久化驻留 → 监听上下文。
// 每步独立容错：取不到数据就如实写"无数据"，绝不编造。
func (s *AIService) Investigate(ctx context.Context, alertID string) (*Investigation, error) {
	a, err := s.repos.Alerts.ByID(ctx, alertID)
	if err != nil {
		return nil, err
	}
	if a == nil {
		return nil, apperr.NotFound("告警不存在")
	}

	inv := &Investigation{AlertID: alertID, CreatedAt: time.Now()}
	score := investigateScoreBase

	// ---- 步骤 1：告警本体画像 ----
	// 主机级事件（资产变更等）没有进程上下文：画像按"事实是什么"呈现，
	// 不硬凑"进程 （）"这种空壳文案
	profile := sprintf("主机级事件，得分 %d，严重度 %s", a.Score, a.Severity)
	if a.ProcessName != "" {
		profile = sprintf("进程 %s（%s），得分 %d，严重度 %s，签名 %s",
			a.ProcessName, a.ImagePath, a.Score, a.Severity, signatureDesc(a.Signed, a.Signer))
	}
	inv.Steps = append(inv.Steps, InvestigationStep{
		Name:      "告警本体",
		Finding:   profile,
		Citations: []string{a.ID},
	})

	// ---- 步骤 2：同哈希跨主机 ----
	if a.HashSHA256 != "" {
		sameHash, _, err := s.repos.Alerts.List(ctx, domain.AlertFilter{
			Hash: a.HashSHA256, Page: 1, PageSize: 50, Sort: "oldest",
		})
		if err != nil {
			inv.Steps = append(inv.Steps, InvestigationStep{Name: "同哈希跨主机", Finding: "查询失败：" + err.Error()})
		} else {
			hosts := map[string]string{}
			for _, h := range sameHash {
				if h.Hostname != a.Hostname {
					hosts[h.Hostname] = h.ID
				}
			}
			if len(hosts) > 0 {
				score += 25
				ids := make([]string, 0, len(hosts))
				for hn, id := range hosts {
					ids = append(ids, hn+"("+id+")")
				}
				inv.Steps = append(inv.Steps, InvestigationStep{
					Name:      "同哈希跨主机",
					Finding:   sprintf("同一样本出现在另外 %d 台主机：%s——横向移动或投递链的强信号", len(hosts), strings.Join(ids, "、")),
					Citations: append([]string{a.HashSHA256[:16]}, ids...),
				})
			} else {
				inv.Steps = append(inv.Steps, InvestigationStep{
					Name:      "同哈希跨主机",
					Finding:   "其他主机未检出同一样本（单点事件）",
					Citations: []string{a.HashSHA256[:16]},
				})
			}
		}
	} else {
		inv.Steps = append(inv.Steps, InvestigationStep{Name: "同哈希跨主机", Finding: "告警无文件哈希，跳过"})
	}

	// ---- 步骤 3：同主机关联告警 ----
	related, _, err := s.repos.Alerts.List(ctx, domain.AlertFilter{
		AgentID: a.AgentID, Page: 1, PageSize: 50, Sort: "oldest",
	})
	relatedN := 0
	var relCit []string
	if err == nil {
		for _, ra := range related {
			if ra.ID == a.ID {
				continue
			}
			if !ra.CreatedAt.Add(-30 * time.Minute).After(a.CreatedAt) && !ra.CreatedAt.After(a.CreatedAt.Add(30*time.Minute)) {
				relatedN++
				if relatedN <= 5 {
					relCit = append(relCit, ra.ID+"("+ra.Title+")")
				}
			}
		}
	}
	if relatedN > 0 {
		score += 10
		inv.Steps = append(inv.Steps, InvestigationStep{
			Name:      "同主机关联告警",
			Finding:   sprintf("前后 30 分钟内同主机还有 %d 条相关告警", relatedN),
			Citations: relCit,
		})
	} else {
		// 无关联也如实成步：分析师需要知道"这一路查过了"而不是怀疑漏查
		inv.Steps = append(inv.Steps, InvestigationStep{
			Name:      "同主机关联告警",
			Finding:   "前后 30 分钟内同主机无其他相关告警",
			Citations: []string{a.AgentID},
		})
	}

	// ---- 步骤 4：IOC 比对 ----
	if a.HashSHA256 != "" {
		ioc, err := s.repos.IOCs.ByHash(ctx, strings.ToLower(a.HashSHA256))
		if err != nil {
			inv.Steps = append(inv.Steps, InvestigationStep{Name: "IOC 比对", Finding: "查询失败：" + err.Error()})
		} else if ioc != nil {
			score = 95
			inv.Steps = append(inv.Steps, InvestigationStep{
				Name:      "IOC 比对",
				Finding:   sprintf("样本哈希命中威胁情报库（%s），确认为已知恶意", ioc.Note),
				Citations: []string{"IOC:" + ioc.Hash[:16]},
			})
		} else {
			inv.Steps = append(inv.Steps, InvestigationStep{Name: "IOC 比对", Finding: "未命中威胁情报库", Citations: []string{a.HashSHA256[:16]}})
		}
	} else {
		// 主机级事件（资产变更等）没有文件哈希——显式成步而不是消失，
		// 让分析师知道"这一路查过了、查不到"和"根本没查"的区别
		inv.Steps = append(inv.Steps, InvestigationStep{Name: "IOC 比对", Finding: "告警无文件哈希（主机级事件），跳过", Citations: []string{a.ID}})
	}

	// ---- 步骤 5：持久化驻留 ----
	secs, err := s.repos.Inventory.ListByAgent(ctx, a.AgentID)
	if err != nil {
		inv.Steps = append(inv.Steps, InvestigationStep{Name: "持久化驻留", Finding: "资产清单不可用：" + err.Error()})
	} else {
		resident, cit := findResidence(secs, a.ImagePath, a.ProcessName)
		if resident {
			score += 20
			inv.Steps = append(inv.Steps, InvestigationStep{
				Name:      "持久化驻留",
				Finding:   "样本镜像或其父路径出现在自启动服务/计划任务/启动项中——具备驻留能力",
				Citations: cit,
			})
		} else {
			inv.Steps = append(inv.Steps, InvestigationStep{Name: "持久化驻留", Finding: "资产清单中未发现样本的持久化痕迹"})
		}
	}

	if score > 100 {
		score = 100
	}
	inv.Confidence = float64(score) / 100
	switch {
	case score >= 70:
		inv.VerdictSuggestion = "malicious"
	case score >= 45:
		inv.VerdictSuggestion = "suspicious"
	default:
		inv.VerdictSuggestion = "benign-需人工确认"
	}

	// 全步骤 Citations 归一为空数组（JSON null 会让前端 len() 崩）
	for i := range inv.Steps {
		if inv.Steps[i].Citations == nil {
			inv.Steps[i].Citations = []string{}
		}
	}

	// ---- 建议动作（Available 反映双层开关现状）----
	inv.RecommendedActions = []RecommendedAction{
		{Action: "quarantine_file", Target: a.ImagePath,
			Available: s.cfg.QuarantineEnabled,
			Reason:    "隔离样本镜像，阻断再次执行（需终端 HG_AGENT_QUARANTINE_ENABLED）"},
		{Action: "terminate", Target: sprintf("%s(pid=%d)", a.ProcessName, a.PID),
			Available: s.cfg.KillEnabled,
			Reason:    "终止进程，隔离前先终止避免文件锁（需终端 HG_AGENT_KILL_ENABLED）"},
	}

	investigateMu.Lock()
	investigateCache[alertID] = investigateCacheEntry{inv: inv, created: time.Now()}
	for id, e := range investigateCache {
		if time.Since(e.created) > investigationCacheTTL {
			delete(investigateCache, id)
		}
	}
	investigateMu.Unlock()

	s.log.InfoContext(ctx, "alert_investigated", "alert_id", alertID,
		"suggestion", inv.VerdictSuggestion, "confidence", inv.Confidence, "steps", len(inv.Steps))
	return inv, nil
}

// CachedInvestigation 返回缓存中的调查报告（GET 用；没有就 nil）。
func (s *AIService) CachedInvestigation(alertID string) *Investigation {
	investigateMu.Lock()
	defer investigateMu.Unlock()
	if e, ok := investigateCache[alertID]; ok && time.Since(e.created) <= investigationCacheTTL {
		return e.inv
	}
	return nil
}

// findResidence 在资产清单里找样本的驻留证据（服务二进制路径/启动项值）。
func findResidence(secs []domain.HostInventorySection, imagePath, procName string) (bool, []string) {
	lowImg := strings.ToLower(imagePath)
	lowName := strings.ToLower(procName)
	var cit []string
	for _, sec := range secs {
		if sec.Name != "services" && sec.Name != "tasks" && sec.Name != "startup" {
			continue
		}
		needle := lowImg
		if needle == "" {
			needle = lowName
		}
		if needle == "" {
			continue
		}
		if strings.Contains(strings.ToLower(sec.Payload), needle) {
			cit = append(cit, "inventory:"+sec.Name)
		}
	}
	return len(cit) > 0, cit
}

func signatureDesc(signed bool, signer string) string {
	if signed {
		return "已签名（" + signer + "）"
	}
	return "未签名"
}

func sprintf(format string, args ...any) string { return fmt.Sprintf(format, args...) }
