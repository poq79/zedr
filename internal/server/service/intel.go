package service

import (
	"context"
	"net"
	"strings"
	"time"

	"zedr/internal/model"
	"zedr/internal/platform/apperr"
	"zedr/internal/platform/idgen"
	"zedr/internal/server/domain"
)

// 非哈希威胁情报（ip/path/keyword）的运营面。
// hash 类在 ioc.go（独立 IOC 包管线，老探针兼容）；本文件三类随规则包
// 下发（RuleBundle.Intel，v2 签名覆盖）。

// intelMaxEntries 是非哈希情报的容量上限（与 IOC 库同量级护栏）。
const intelMaxEntries = 5000

// ListIntel 列出情报（typ 空=全部），并附加全终端命中汇总。
func (s *RuleService) ListIntel(ctx context.Context, typ string) ([]domain.IntelItem, error) {
	items, err := s.repos.Intel.List(ctx, typ)
	if err != nil {
		return nil, err
	}
	sums, err := s.repos.IocObserve.SumByKey(ctx)
	if err != nil {
		s.log.WarnContext(ctx, "intel_hits_sum_failed", "err", err)
		sums = nil
	}
	for i := range items {
		if h, ok := sums[items[i].Type+":"+items[i].Value]; ok && h > 0 {
			items[i].Hits = h
		}
	}
	return items, nil
}

// AddIntel 新增/更新一条情报（同 type+value 幂等覆盖），变更即递增
// 情报版本推动探针重拉规则包。
func (s *RuleService) AddIntel(ctx context.Context, typ, value string, score int, name, note, mitre, by string) (*domain.IntelItem, error) {
	value = strings.TrimSpace(value)
	switch typ {
	case domain.IntelIP:
		if net.ParseIP(value) == nil {
			return nil, apperr.Invalid("ip 不是合法 IP 地址: %q", value)
		}
		score = 0 // ip/path 命中走固定情报加成，分数由引擎统一
	case domain.IntelPath:
		if value == "" {
			return nil, apperr.Invalid("path 不能为空")
		}
		value = strings.ToLower(value)
		score = 0
	case domain.IntelKeyword:
		if value == "" || len(value) > 128 {
			return nil, apperr.Invalid("keyword 需要非空且不超过 128 字符")
		}
		value = strings.ToLower(value)
		if score == 0 {
			score = 25
		}
		if score < 5 || score > 40 {
			return nil, apperr.Invalid("keyword 分值需在 5-40（关键词层与内置共享 40 分帽，超配无意义）")
		}
		if name == "" {
			name = value
		}
	default:
		return nil, apperr.Invalid("情报类型非法，可选 ip/path/keyword")
	}

	existing, err := s.repos.Intel.ByValue(ctx, typ, value)
	if err != nil {
		return nil, err
	}
	if existing == nil {
		n, err := s.repos.Intel.Count(ctx)
		if err != nil {
			return nil, err
		}
		if n >= intelMaxEntries {
			return nil, apperr.Invalid("情报库已达上限（%d 条），请清理后重试", intelMaxEntries)
		}
	}

	e := &domain.IntelItem{
		ID:        idgen.Hex(10),
		Type:      typ,
		Value:     value,
		Score:     score,
		Name:      truncate(name, 120),
		Note:      truncate(note, 500),
		MITRE:     strings.TrimSpace(mitre),
		CreatedBy: by,
		CreatedAt: time.Now(),
	}
	if err := s.repos.Intel.Add(ctx, e); err != nil {
		return nil, err
	}
	if err := s.bumpIntelVersion(ctx); err != nil {
		s.log.WarnContext(ctx, "intel_version_bump_failed", "err", err)
	}
	s.log.InfoContext(ctx, "intel_added", "type", typ, "value_prefix", truncate(value, 60), "by", by)
	return e, nil
}

// DeleteIntel 删除一条情报。
func (s *RuleService) DeleteIntel(ctx context.Context, id, by string) error {
	if err := s.repos.Intel.Delete(ctx, id); err != nil {
		return apperr.NotFound("威胁情报")
	}
	if err := s.bumpIntelVersion(ctx); err != nil {
		s.log.WarnContext(ctx, "intel_version_bump_failed", "err", err)
	}
	s.log.InfoContext(ctx, "intel_deleted", "id", id, "by", by)
	return nil
}

// intelOf 组装规则包的非哈希情报列表（ip/path/keyword）。
// 空时必须返回 nil 而不是空切片：Intel 带 omitempty，空切片在 wire 上
// 被省略，探针解码得到 nil；v2 签名若按服务端内存值序列化出 "[]"、
// 探针按解码值序列化出 "null"，验签必然失败（实测踩过）。
func (s *RuleService) intelOf(ctx context.Context) []model.IntelDTO {
	items, err := s.repos.Intel.List(ctx, "")
	if err != nil {
		s.log.WarnContext(ctx, "intel_bundle_failed", "err", err)
		return nil
	}
	if len(items) == 0 {
		return nil
	}
	out := make([]model.IntelDTO, 0, len(items))
	for _, e := range items {
		out = append(out, model.IntelDTO{
			Type: e.Type, Value: e.Value, Score: e.Score,
			Name: e.Name, Note: e.Note, MITRE: e.MITRE,
		})
	}
	return out
}

// bumpIntelVersion 递增情报版本，并以当前规则 MaxVersion 为下限——
// 规则包版本取两者 max，情报版本不越过规则版本时探针的 ETag 永远
// 不变（实测：加完情报探针仍拉 intel=0 的旧包）。
func (s *RuleService) bumpIntelVersion(ctx context.Context) error {
	floor, err := s.repos.Rules.MaxVersion(ctx)
	if err != nil {
		return err
	}
	_, err = s.repos.Intel.BumpVersion(ctx, floor)
	return err
}
