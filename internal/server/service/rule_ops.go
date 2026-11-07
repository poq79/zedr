package service

import (
	"context"
	"time"

	"zedr/internal/platform/apperr"
	"zedr/internal/rules"
	"zedr/internal/server/domain"
)

// 本文件承载规则"运营面"能力：字段/模板参考、观察模式切换、
// 观察命中摄入与聚合。检测语义全部在探针引擎里，服务端只做
// 编排与台账（与 AI 研判的分层思路一致）。

// RuleMode 取值。
const (
	RuleModeActive  = "active"
	RuleModeObserve = "observe"
)

// Schema 返回规则 DSL 的字段/操作符参考与模板库（前端表单编辑器的
// 单一事实源，内容由 internal/rules 与引擎同包演进）。
func (s *RuleService) Schema() (any, error) {
	fields, ops := rules.Schema()
	return map[string]any{
		"fields":    fields,
		"ops":       ops,
		"templates": rules.Templates(),
	}, nil
}

// SetMode 切换规则执行模式（active=正常告警 / observe=观察）。
//
// 内置规则同样可切观察：内置 36 条里"理论上会误报"的那几条
// （如签名类、模块类），运营者可以先切观察跑几天再决定禁用还是
// 保留——这比"只能开/关"的二值选择精细得多，也是 Elastic
// "clone 后调分值"实践在单规则粒度上的替代。
func (s *RuleService) SetMode(ctx context.Context, id, mode, by string) (*domain.Rule, error) {
	if mode != RuleModeActive && mode != RuleModeObserve {
		return nil, apperr.Invalid("规则模式非法: %q（可选 active/observe）", mode)
	}
	r, err := s.repos.Rules.ByID(ctx, id)
	if err != nil {
		return nil, err
	}
	if r == nil {
		return nil, apperr.NotFound("规则")
	}
	ver, err := s.repos.Rules.MaxVersion(ctx)
	if err != nil {
		return nil, err
	}
	r.Mode = mode
	r.Version = ver + 1
	r.UpdatedAt = time.Now()
	if err := s.repos.Rules.Upsert(ctx, r); err != nil {
		return nil, err
	}
	s.log.InfoContext(ctx, "rule_mode_changed", "rule_id", id, "mode", mode, "by", by)
	return r, nil
}

// IngestObserve 摄入一台终端的观察命中快照（随心跳上报）。
// 整包替换语义：上报里没有的规则 ID 会被清理（转正/删除后残留
// 计数不虚高汇总）。失败只记日志——观察计数是辅助信号，
// 不值得让心跳因此失败。
func (s *RuleService) IngestObserve(ctx context.Context, agentID string, stats map[string]int64) {
	if stats == nil {
		return
	}
	if len(stats) > 128 {
		// 理论上观察规则不会超过这个量级；超限说明有异常，截断保护服务端
		trimmed := make(map[string]int64, 128)
		for id, hits := range stats {
			trimmed[id] = hits
			if len(trimmed) >= 128 {
				break
			}
		}
		stats = trimmed
	}
	if err := s.repos.RuleObserve.ReplaceForAgent(ctx, agentID, stats, time.Now()); err != nil {
		s.log.WarnContext(ctx, "observe_ingest_failed", "agent_id", agentID, "err", err)
	}
}

// IngestHitCounters 摄入一台终端的情报（hash/ip/path/keyword）与白名单
// 命中快照（随心跳上报，整包替换语义）。失败只记日志——计数是辅助
// 信号，不值得让心跳失败。
func (s *RuleService) IngestHitCounters(ctx context.Context, agentID string, iocHits, allowHits map[string]int64) {
	if iocHits != nil {
		if err := s.repos.IocObserve.ReplaceForAgent(ctx, agentID, iocHits, time.Now()); err != nil {
			s.log.WarnContext(ctx, "ioc_hits_ingest_failed", "agent_id", agentID, "err", err)
		}
	}
	if allowHits != nil {
		if err := s.repos.AllowObserve.ReplaceForAgent(ctx, agentID, allowHits, time.Now()); err != nil {
			s.log.WarnContext(ctx, "allow_hits_ingest_failed", "agent_id", agentID, "err", err)
		}
	}
}

// IntelVersion 当前情报版本（心跳响应用它对齐规则包版本口径：
// Bundle.Version = max(rules, intel)，心跳回传的版本必须是同一个值，
// 否则探针在情报变更后永远看不到版本推进、不重拉）。
func (s *RuleService) IntelVersion(ctx context.Context) (int, error) {
	return s.repos.Intel.Version(ctx)
}

// ListWithObserve 列出规则并附加全终端观察命中汇总。
// 汇总只对 observe 模式的规则展示：计数行是探针运行期快照，
// 规则转正/删除后残留在表里的旧行（等下一次心跳清理）没有展示意义。
func (s *RuleService) ListWithObserve(ctx context.Context) ([]domain.Rule, error) {
	items, err := s.repos.Rules.List(ctx)
	if err != nil {
		return nil, err
	}
	sums, err := s.repos.RuleObserve.SumByKey(ctx)
	if err != nil {
		// 汇总失败不阻塞列表（老库迁移前/表损坏都可能是原因），只置空
		s.log.WarnContext(ctx, "observe_sum_failed", "err", err)
		sums = nil
	}
	for i := range items {
		if items[i].Mode != RuleModeObserve {
			continue
		}
		if h, ok := sums[items[i].ID]; ok && h > 0 {
			items[i].ObservedHits = h
		}
	}
	return items, nil
}

// normalizeRuleMode 归一 mode 字段：空值=active，非法值报错。
func normalizeRuleMode(mode string) (string, error) {
	switch mode {
	case "", RuleModeActive:
		return RuleModeActive, nil
	case RuleModeObserve:
		return RuleModeObserve, nil
	default:
		return "", apperr.Invalid("规则模式非法: %q（可选 active/observe）", mode)
	}
}
