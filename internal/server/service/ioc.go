package service

import (
	"context"
	"strings"
	"time"

	"zedr/internal/model"
	"zedr/internal/platform/apperr"
	"zedr/internal/platform/idgen"
	"zedr/internal/server/domain"
)

// iocMaxEntries 是 IOC 库的容量上限。
// 整包下发 + 终端全量驻内存，必须钉死规模；超过上限应走 MISP
// 等外部情报源做按需查询（RESEARCH.md R2），而不是无限堆哈希。
const iocMaxEntries = 10000

// ListIOCs 列出全部威胁指标。
func (s *RuleService) ListIOCs(ctx context.Context) ([]domain.IOC, error) {
	return s.repos.IOCs.List(ctx)
}

// AddIOC 新增一条 SHA256 指标。命中表随规则包节奏整包下发终端。
func (s *RuleService) AddIOC(ctx context.Context, hash, note, by string) (*domain.IOC, error) {
	hash = strings.ToLower(strings.TrimSpace(hash))
	if len(hash) != 64 || !isHex(hash) {
		return nil, apperr.Invalid("hash 必须是 64 位十六进制 SHA256")
	}
	if existing, err := s.repos.IOCs.ByHash(ctx, hash); err != nil {
		return nil, err
	} else if existing != nil {
		return nil, apperr.Conflict("该哈希已在 IOC 库中")
	}
	n, err := s.repos.IOCs.Count(ctx)
	if err != nil {
		return nil, err
	}
	if n >= iocMaxEntries {
		return nil, apperr.Invalid("IOC 库已达上限（%d 条），请清理后重试", iocMaxEntries)
	}

	e := &domain.IOC{
		ID:        idgen.Hex(10),
		Hash:      hash,
		Note:      truncate(note, 500),
		CreatedBy: by,
		CreatedAt: time.Now(),
	}
	if err := s.repos.IOCs.Add(ctx, e); err != nil {
		return nil, err
	}
	if _, err := s.repos.IOCs.BumpVersion(ctx); err != nil {
		// 指标已入库，版本没递增只影响下发及时性，记日志不回滚
		s.log.WarnContext(ctx, "ioc_version_bump_failed", "err", err)
	}
	s.log.InfoContext(ctx, "ioc_added", "hash_prefix", hash[:12], "by", by)
	return e, nil
}

// DeleteIOC 删除一条指标。
func (s *RuleService) DeleteIOC(ctx context.Context, id, by string) error {
	if err := s.repos.IOCs.Delete(ctx, id); err != nil {
		return apperr.NotFound("威胁指标")
	}
	if _, err := s.repos.IOCs.BumpVersion(ctx); err != nil {
		s.log.WarnContext(ctx, "ioc_version_bump_failed", "err", err)
	}
	s.log.InfoContext(ctx, "ioc_deleted", "id", id, "by", by)
	return nil
}

// IOCBundle 生成下发给终端的指标整包（含版本号，供 ETag 与单调校验）。
func (s *RuleService) IOCBundle(ctx context.Context) (*model.IOCBundle, int, error) {
	items, err := s.repos.IOCs.List(ctx)
	if err != nil {
		return nil, 0, err
	}
	ver, err := s.repos.IOCs.Version(ctx)
	if err != nil {
		return nil, 0, err
	}
	b := &model.IOCBundle{
		Version:     ver,
		GeneratedAt: time.Now().UTC(),
		IOCs:        make([]model.IOCDTO, 0, len(items)),
	}
	for _, e := range items {
		b.IOCs = append(b.IOCs, model.IOCDTO{Hash: e.Hash, Note: e.Note})
	}
	return b, len(b.IOCs), nil
}
