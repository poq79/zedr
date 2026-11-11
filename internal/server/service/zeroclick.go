package service

// Zero-click 自动调查（2026-11-10 用户裁决实施；对标 SentinelOne ASOC
// 的 zero-click investigation——critical 告警自动获得完整调查，分析员
// 醒来时证据链已就位）。
//
// 与旧 AutoOps 的关系：AutoOps 原口径是"确定性五步 + 入队"，注释明确
// 写着"刻意不用 LLM 自动调查：爆发时会烧穿预算"。本文件把这条裁决
// 升级为**带预算闸的 LLM 自动调查**：三道闸（指纹 30 分钟去重 / 每主机
// 每小时上限 / 引擎 token 预算）全过才跑 Agentic 循环（自带 host_live
// 实时取证与工具结果注入防线），任何一道不过回落确定性五步——原路径
// 一行未删，降级语义与"模型不可用"完全一致。
//
// 预算闸状态是进程内存态：server 重启后去重/计数归零。可接受——
// 重启窗口的重复调查有 AgentInvestigate 的 30 分钟结果缓存兜底，
// 而跨重启持久化计数会引入"重启即失去预算"的更差语义。

import (
	"context"
	"sync"
	"time"

	"zedr/internal/ai"
	"zedr/internal/platform/idgen"
	"zedr/internal/server/domain"
)

// zeroClickWindow 是同指纹去重窗口：同一条告警 30 分钟内不重复跑
// Agentic 调查（与 AgentInvestigate 的结果缓存 TTL 同口径）。
const zeroClickWindow = 30 * time.Minute

// zeroclickState 是预算闸的运行状态（进程内存态，见文件头注释）。
type zeroclickState struct {
	mu         sync.Mutex
	enabled    bool
	maxPerHost int
	fpLast     map[string]time.Time   // fingerprint → 最近一次 Agentic 调查
	hostHits   map[string][]time.Time // host → 本小时内的触发时刻
}

// SetZeroClick 注入开关与每主机每小时上限（app 装配期调用；上限
// 非正数回退默认 3——三个/h/主机对爆发场景够用且可预测）。
func (s *AIService) SetZeroClick(enabled bool, maxPerHost int) {
	if maxPerHost <= 0 {
		maxPerHost = 3
	}
	s.zc.mu.Lock()
	defer s.zc.mu.Unlock()
	s.zc.enabled = enabled
	s.zc.maxPerHost = maxPerHost
	s.zc.fpLast = map[string]time.Time{}
	s.zc.hostHits = map[string][]time.Time{}
}

// zeroClickGate 判定是否放行 Agentic 自动调查；返回 false 时给出
// 短理由（进日志，不给操作员看）。
func (s *AIService) zeroClickGate(a *domain.Alert) (bool, string) {
	s.zc.mu.Lock()
	defer s.zc.mu.Unlock()
	if !s.zc.enabled {
		return false, "disabled"
	}
	if a.Severity != domain.SeverityCritical || a.Verdict != domain.VerdictMalicious {
		return false, "not_critical_malicious"
	}
	now := time.Now()
	if last, ok := s.zc.fpLast[a.Fingerprint]; ok && now.Sub(last) < zeroClickWindow {
		return false, "fingerprint_dedup"
	}
	hits := s.zc.hostHits[a.Hostname]
	fresh := hits[:0]
	for _, t := range hits {
		if now.Sub(t) < time.Hour {
			fresh = append(fresh, t)
		}
	}
	if len(fresh) >= s.zc.maxPerHost {
		s.zc.hostHits[a.Hostname] = fresh
		return false, "host_hourly_cap"
	}
	// 放行即记账（先记后跑：失败也占额——调查失败重试最容易烧预算）
	s.zc.fpLast[a.Fingerprint] = now
	s.zc.hostHits[a.Hostname] = append(fresh, now)
	return true, ""
}

// zeroClickAgent 在闸门全开时执行 Agentic 自动调查并装配队列条目；
// 任何不满足（含模型降级/预算耗尽）返回 false，调用方走确定性原路径。
func (s *AIService) zeroClickAgent(ctx context.Context, a *domain.Alert) (*OpsItem, bool) {
	if ok, reason := s.zeroClickGate(a); !ok {
		if s.log != nil && reason != "not_critical_malicious" && reason != "disabled" {
			s.log.DebugContext(ctx, "ai_zeroclick_skip", "alert_id", a.ID, "reason", reason)
		}
		return nil, false
	}
	if !s.eng.AgentAvailable() {
		return nil, false
	}
	rep, err := s.AgentInvestigate(ctx, a.ID)
	if err != nil || rep == nil {
		return nil, false // 模型失败/预算耗尽：诚实回落确定性五步
	}
	if rep.Degraded {
		return nil, false
	}
	item := &OpsItem{
		ID: idgen.URLSafe(10), AlertID: a.ID, Title: a.Title, Hostname: a.Hostname,
		Severity: string(a.Severity), Score: a.Score,
		Engine: rep.Engine + "·" + rep.Model, CreatedAt: time.Now(), Status: "pending",
	}
	fillOpsFromAgentReport(item, rep)
	if s.log != nil {
		s.log.InfoContext(ctx, "ai_zeroclick_run", "alert_id", a.ID, "hostname", a.Hostname,
			"model", rep.Model, "tool_calls", rep.ToolCalls, "verdict", rep.Verdict,
			"latency_ms", rep.LatencyMs, "steps", len(rep.Steps))
	}
	return item, true
}

// fillOpsFromAgentReport 把 Agentic 报告装进队列条目（与
// fillOpsFromInvestigation 同口径：判定用中文 + 置信度 + 建议动作）。
// AgentReport 的 Findings/Actions 已带证据引用与审批标记，直通。
func fillOpsFromAgentReport(item *OpsItem, rep *ai.AgentReport) {
	item.Verdict = rep.Verdict
	item.Confidence = rep.Confidence
	item.Summary = rep.Summary
	item.Findings = rep.Findings
	item.Actions = rep.Actions
}
