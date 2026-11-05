package service

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"zedr/internal/platform/apperr"
	"zedr/internal/server/domain"
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
	AlertID            string              `json:"alert_id"`
	VerdictSuggestion  string              `json:"verdict_suggestion"`
	Confidence         float64             `json:"confidence"`
	Steps              []InvestigationStep `json:"steps"`
	RecommendedActions []RecommendedAction `json:"recommended_actions"`
	CreatedAt          time.Time           `json:"created_at"`

	// 调查内部记账（不出 JSON）：减分项需要知道"加重证据是否出现"，
	// 而不是在每个步子里重复解析自己刚写的话。
	CrossHost    int
	HasResidence bool
}

// investigationCacheTTL 是调查报告缓存的生存期。
// 每次 Investigate 都会重算并覆盖——缓存只是给 GET 复用，
// 不是"结果有效期"：证据随时会变（新告警、新清单），重算永远新鲜。
const investigationCacheTTL = 30 * time.Minute

// investigateScoreBase 是调查打分的基线分。取 35 而不是更高：告警触发
// 只是"值得看一眼"，不是"半只脚踩实了恶意"——2026-11-06 复盘发现基线
// 40 时，任何 ±30 分钟内有同主机告警的条目都必然滑过 suspicious 线
// （40+10=50），值班队列于是清一色 suspicious，结论失去区分度。
const investigateScoreBase = 35

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
		// 默认排序（最新在前）取 50 条同哈希告警：跨主机判定看重最近的
		// 目击记录；超过 50 条的同哈希爆发按"已见主机"近似，是有界折衷
		sameHash, _, err := s.repos.Alerts.List(ctx, domain.AlertFilter{
			Hash: a.HashSHA256, Page: 1, PageSize: 50,
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
				inv.CrossHost = len(hosts)
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
	// 关联只统计**不同标题**的告警：同一规则对同一行为源的重复触发
	// （诱饵告警一次爆 3 条、清日志关键词每次 bash 会话都命中）不是
	// "别的坏事同时在发生"，把它算成关联证据等于同类爆发自己给自己
	// 加分——2026-11-06 复盘值班队列清一色 suspicious 的主因。
	related, _, err := s.repos.Alerts.List(ctx, domain.AlertFilter{
		// 默认排序（最新在前）：±30 分钟关联窗口找的是时间近邻，
		// 旧排序取"最早 50 条"会在告警量大时把真正的近邻挤出去
		AgentID: a.AgentID, Page: 1, PageSize: 50,
	})
	relatedN := 0
	burstN := 0
	var relCit []string
	seenTitles := map[string]bool{}
	if err == nil {
		for _, ra := range related {
			if ra.ID == a.ID {
				continue
			}
			if ra.CreatedAt.Add(-30*time.Minute).After(a.CreatedAt) || ra.CreatedAt.After(a.CreatedAt.Add(30*time.Minute)) {
				continue
			}
			if ra.Title == a.Title {
				burstN++
				continue
			}
			if seenTitles[ra.Title] {
				continue // 同一类告警多条只算一次，避免另一类爆发同样自我加分
			}
			seenTitles[ra.Title] = true
			relatedN++
			if relatedN <= 5 {
				relCit = append(relCit, ra.ID+"("+ra.Title+")")
			}
		}
	}
	if relatedN > 0 {
		score += 10
		note := sprintf("前后 30 分钟内同主机还有 %d 类不同告警", relatedN)
		if burstN > 0 {
			note += sprintf("；另有本规则同类爆发 %d 条，不计为关联证据", burstN)
		}
		inv.Steps = append(inv.Steps, InvestigationStep{
			Name:      "同主机关联告警",
			Finding:   note,
			Citations: relCit,
		})
	} else {
		// 无关联也如实成步：分析师需要知道"这一路查过了"而不是怀疑漏查
		note := "前后 30 分钟内同主机无其他不同类型告警"
		if burstN > 0 {
			note += sprintf("（本规则同类爆发 %d 条，不算关联）", burstN)
		}
		inv.Steps = append(inv.Steps, InvestigationStep{
			Name:      "同主机关联告警",
			Finding:   note,
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
			inv.HasResidence = true
			inv.Steps = append(inv.Steps, InvestigationStep{
				Name:      "持久化驻留",
				Finding:   "样本镜像或其父路径出现在自启动服务/计划任务/启动项中——具备驻留能力",
				Citations: cit,
			})
		} else {
			inv.Steps = append(inv.Steps, InvestigationStep{Name: "持久化驻留", Finding: "资产清单中未发现样本的持久化痕迹"})
		}
	}

	// ---- 步骤 6：减分项（诚实计分是双向的）----
	// 2026-11-06 复盘：此前只有加分没有减分，签名样本、主机级观察事件、
	// 五路排查全空的告警全都只能往 suspicious 方向走。减分不改变任何
	// 加分路径——真有 IOC/跨主机/驻留证据的条目不会被签名字段拉回来。
	hostLevel := a.ProcessName == "" && a.HashSHA256 == ""
	switch {
	case hostLevel:
		score -= 10
		inv.Steps = append(inv.Steps, InvestigationStep{
			Name:      "证据形态",
			Finding:   "主机级观察事件（无进程与文件上下文）：这类告警本身是观察哨，无法由本调查独立坐实恶意",
			Citations: []string{a.ID},
		})
	case a.Signed && a.Signer != "":
		score -= 12
		inv.Steps = append(inv.Steps, InvestigationStep{
			Name:      "证据形态",
			Finding:   sprintf("样本已签名（%s）：签名身份是可追责的真实主体，冒用签名的恶意样本成本远高于自签", a.Signer),
			Citations: []string{a.HashSHA256[:min16(len(a.HashSHA256))]},
		})
	}
	if a.HashSHA256 == "" {
		// 同哈希/IOC 两路对主机级事件天然不可用——已经在上面的步子里
		// 如实标注，这里不再重复减分
	} else if inv.CrossHost == 0 && !inv.HasResidence {
		score -= 10
		inv.Steps = append(inv.Steps, InvestigationStep{
			Name:      "证据形态",
			Finding:   "同哈希跨主机、IOC 比对、持久化驻留三路加重证据均缺——孤立事件",
			Citations: []string{a.HashSHA256[:min16(len(a.HashSHA256))]},
		})
	}

	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}
	inv.Confidence = float64(score) / 100
	inv.VerdictSuggestion = investigateVerdict(score)

	// 全步骤 Citations 归一为空数组（JSON null 会让前端 len() 崩）
	for i := range inv.Steps {
		if inv.Steps[i].Citations == nil {
			inv.Steps[i].Citations = []string{}
		}
	}

	// ---- 建议动作（Available 反映双层开关现状；只给"对象真实存在"的动作）----
	// 2026-11-06 复盘：主机级事件此前也会排出 quarantine_file:""（空路径）
	// 和 terminate:(pid=0)——建议一个不存在的对象，等于让值班人员去执行
	// 一次注定失败的处置，比不给建议更糟。
	if a.ImagePath != "" {
		inv.RecommendedActions = append(inv.RecommendedActions, RecommendedAction{
			Action: "quarantine_file", Target: a.ImagePath,
			Available: s.cfg.QuarantineEnabled,
			Reason:    "隔离样本镜像，阻断再次执行（需终端 HG_AGENT_QUARANTINE_ENABLED）",
		})
	}
	if a.PID > 0 {
		inv.RecommendedActions = append(inv.RecommendedActions, RecommendedAction{
			Action: "terminate", Target: sprintf("%s(pid=%d)", a.ProcessName, a.PID),
			Available: s.cfg.KillEnabled,
			Reason:    "终止进程，隔离前先终止避免文件锁（需终端 HG_AGENT_KILL_ENABLED）",
		})
	}
	if len(inv.RecommendedActions) == 0 {
		inv.RecommendedActions = append(inv.RecommendedActions, RecommendedAction{
			Action: "review_host", Target: a.Hostname,
			Available: true,
			Reason:    "主机级事件无进程/文件对象可处置：请到主机详情核查对应资产与事件上下文",
		})
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
	// 判定台账：确定性五步的结论同样进质量对账（source=heuristic）
	s.recordTriage(ctx, alertID, triageSourceHeuristic, inv.VerdictSuggestion, inv.Confidence, "heuristic")
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

// investigateVerdict 把调查总分映射成判定枚举。
// 枚举与 MCP 工具/研判引擎一致（malicious/suspicious/inconclusive/benign），
// 中文呈现由前端与队列摘要负责。阈值含义：
//
//	≥70 加重证据充分（IOC/跨主机/驻留叠加），可定性恶意；
//	≥45 有实质加重证据，标可疑；
//	≥30 基线分+少量上下文，证据不足以定性；
//	<30 只有基线分且带减分项，倾向误报。
func investigateVerdict(score int) string {
	switch {
	case score >= 70:
		return "malicious"
	case score >= 45:
		return "suspicious"
	case score >= 30:
		return "inconclusive"
	default:
		return "benign"
	}
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

// min16 限定哈希引用截取长度（引用里只放前 16 位，完整哈希在告警详情里）。
func min16(n int) int {
	if n < 16 {
		return n
	}
	return 16
}

func sprintf(format string, args ...any) string { return fmt.Sprintf(format, args...) }
