package service

import (
	"context"
	"log/slog"
	"strings"
	"time"

	"zedr/internal/model"
	"zedr/internal/platform/apperr"
	"zedr/internal/platform/idgen"
	"zedr/internal/rules"
	"zedr/internal/server/domain"
	"zedr/internal/server/repository"
)

// RuleService 负责规则库的播种、下发与自定义规则管理。
type RuleService struct {
	repos       repository.Repos
	log         *slog.Logger
	agentPolicy *model.AgentPolicy
}

// SeedBuiltins 将内置规则同步到数据库。
//
// 幂等：以 ID 为主键 upsert；只有条件体变化时才递增 version，
// 避免每次启动都把全量终端拉一遍规则。
func (s *RuleService) SeedBuiltins(ctx context.Context) (int, error) {
	builtins := rules.Builtins()
	curVersion, err := s.repos.Rules.MaxVersion(ctx)
	if err != nil {
		return 0, err
	}
	// 规则内容版本：首次播种使用 1，之后每次内容变更 +1
	baseVersion := curVersion
	if baseVersion < 1 {
		baseVersion = 0
	}

	changed := 0
	for _, b := range builtins {
		existing, err := s.repos.Rules.ByID(ctx, b.ID)
		if err != nil {
			return 0, err
		}
		def := b.JSON()

		if existing != nil && existing.Definition == def &&
			existing.Name == b.Name && string(existing.Severity) == string(b.Severity) &&
			existing.Score == b.Score {
			continue
		}

		baseVersion++
		r := &domain.Rule{
			ID:          b.ID,
			Name:        b.Name,
			Description: b.Description,
			Severity:    b.Severity,
			MITRE:       b.MITRE,
			Score:       b.Score,
			Enabled:     true,
			Builtin:     true,
			Definition:  def,
			Version:     baseVersion,
			UpdatedAt:   time.Now(),
		}
		if existing != nil {
			// 保留运营层面的启用/禁用与观察模式决定（内置规则被切到
			// 观察后，不应随升级被悄悄拉回告警模式）
			r.Enabled = existing.Enabled
			r.Mode = existing.Mode
		}
		if err := s.repos.Rules.Upsert(ctx, r); err != nil {
			return 0, err
		}
		changed++
	}

	if changed > 0 {
		s.log.InfoContext(ctx, "rules_seeded", "changed", changed, "total", len(builtins), "version", baseVersion)
	}
	return changed, nil
}

// List 列出全部规则。
func (s *RuleService) List(ctx context.Context) ([]domain.Rule, error) {
	return s.repos.Rules.List(ctx)
}

// Upsert 新增或更新一条自定义规则。
func (s *RuleService) Upsert(ctx context.Context, in *domain.Rule, by string) (*domain.Rule, error) {
	if in.ID == "" {
		in.ID = "HG-C-" + idgen.Hex(4)
	}
	if in.Name == "" {
		return nil, apperr.Invalid("规则名称不能为空")
	}
	if !in.Severity.Valid() {
		return nil, apperr.Invalid("严重度非法")
	}
	if in.Score <= 0 || in.Score > 100 {
		return nil, apperr.Invalid("分值必须在 1-100 之间")
	}
	mode, err := normalizeRuleMode(in.Mode)
	if err != nil {
		return nil, err
	}
	in.Mode = mode
	// 干跑校验：解析失败直接拒绝，避免下发到终端后解析报错
	if _, err := rules.Compile(in.Definition); err != nil {
		return nil, apperr.Invalid("规则定义非法: %v", err)
	}

	existing, err := s.repos.Rules.ByID(ctx, in.ID)
	if err != nil {
		return nil, err
	}
	ver, err := s.repos.Rules.MaxVersion(ctx)
	if err != nil {
		return nil, err
	}
	in.Version = ver + 1
	in.UpdatedAt = time.Now()
	in.Builtin = false
	if existing != nil {
		in.Builtin = existing.Builtin
	}
	if err := s.repos.Rules.Upsert(ctx, in); err != nil {
		return nil, err
	}
	s.log.InfoContext(ctx, "rule_upserted", "rule_id", in.ID, "by", by, "version", in.Version)
	return in, nil
}

// SetEnabled 启用/禁用规则。
func (s *RuleService) SetEnabled(ctx context.Context, id string, enabled bool, by string) (*domain.Rule, error) {
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
	r.Enabled = enabled
	r.Version = ver + 1
	r.UpdatedAt = time.Now()
	if err := s.repos.Rules.Upsert(ctx, r); err != nil {
		return nil, err
	}
	s.log.InfoContext(ctx, "rule_toggled", "rule_id", id, "enabled", enabled, "by", by)
	return r, nil
}

// Delete 删除自定义规则（内置规则不可删）。
func (s *RuleService) Delete(ctx context.Context, id, by string) error {
	if err := s.repos.Rules.Delete(ctx, id); err != nil {
		return apperr.Conflict("内置规则不可删除，可改为禁用")
	}
	s.log.InfoContext(ctx, "rule_deleted", "rule_id", id, "by", by)
	return nil
}

// Bundle 生成下发给终端的规则+白名单+非哈希情报整包。
// 版本取 max(rules, intel)：情报增删必须推动探针重拉（ETag/单调校验
// 都比较这个版本号），否则情报变更会在"规则没变"的终端上静默失效。
func (s *RuleService) Bundle(ctx context.Context, sinceVersion int) (*model.RuleBundle, error) {
	enabled, err := s.repos.Rules.ListEnabled(ctx)
	if err != nil {
		return nil, err
	}
	allow, err := s.repos.Allowlist.List(ctx)
	if err != nil {
		return nil, err
	}
	maxVer, err := s.repos.Rules.MaxVersion(ctx)
	if err != nil {
		return nil, err
	}
	intelVer, err := s.repos.Intel.Version(ctx)
	if err != nil {
		return nil, err
	}
	if intelVer > maxVer {
		maxVer = intelVer
	}

	bundle := &model.RuleBundle{
		Version:     maxVer,
		GeneratedAt: time.Now().UTC(),
		Rules:       make([]model.RuleDTO, 0, len(enabled)),
		Allowlist:   make([]model.AllowDTO, 0, len(allow)),
		Intel:       s.intelOf(ctx),
		AgentPolicy: s.agentPolicyOf(),
	}
	for _, r := range enabled {
		bundle.Rules = append(bundle.Rules, model.RuleDTO{
			ID: r.ID, Name: r.Name, Description: r.Description, Severity: r.Severity,
			MITRE: r.MITRE, Score: r.Score, Enabled: r.Enabled, Mode: r.Mode,
			Definition: r.Definition, Version: r.Version,
		})
	}
	for _, a := range allow {
		bundle.Allowlist = append(bundle.Allowlist, model.AllowDTO{Type: a.Type, Value: a.Value})
	}
	_ = sinceVersion // 版本号随包返回，终端自行比对决定是否应用
	return bundle, nil
}

// ---------------------------------------------------------------- 白名单

// ListAllowlist 列出白名单（附加全终端命中汇总，按 type:value 求和）。
func (s *RuleService) ListAllowlist(ctx context.Context) ([]domain.AllowlistEntry, error) {
	items, err := s.repos.Allowlist.List(ctx)
	if err != nil {
		return nil, err
	}
	sums, err := s.repos.AllowObserve.SumByKey(ctx)
	if err != nil {
		s.log.WarnContext(ctx, "allow_hits_sum_failed", "err", err)
		sums = nil
	}
	for i := range items {
		if h, ok := sums[items[i].Type+":"+items[i].Value]; ok && h > 0 {
			items[i].Hits = int(h)
			if h > 1<<31 { // 防御性钳制：int 在 32 位构建下溢出
				items[i].Hits = 1 << 31
			}
		}
	}
	return items, nil
}

// AddAllowlist 添加白名单项，并校验类型与取值。
//
// 同时执行"加白回收"：把已经触发过、且与这条白名单匹配的未处置告警
// 标记为误报，返回回收条数。这是降噪闭环里最容易漏掉的一环——
// 只加白不回收，历史告警仍会堆在队列里等人处理。
func (s *RuleService) AddAllowlist(ctx context.Context, typ, value, note, by string) (*domain.AllowlistEntry, int64, error) {
	switch typ {
	case "hash":
		if len(value) != 64 || !isHex(value) {
			return nil, 0, apperr.Invalid("hash 类型需要 64 位十六进制 SHA256")
		}
		value = strings.ToLower(value)
	case "path":
		if value == "" {
			return nil, 0, apperr.Invalid("path 不能为空")
		}
		value = strings.ToLower(value)
	case "signer":
		if value == "" {
			return nil, 0, apperr.Invalid("signer 不能为空")
		}
	case "pair":
		// 父子进程对，格式 parent.exe>child.exe
		if !strings.Contains(string(value), ">") {
			return nil, 0, apperr.Invalid("pair 格式应为 parent.exe>child.exe")
		}
		value = strings.ToLower(value)
	case "cmdline":
		if value == "" {
			return nil, 0, apperr.Invalid("cmdline 不能为空")
		}
	default:
		return nil, 0, apperr.Invalid("白名单类型非法，可选 hash/path/signer/pair/cmdline")
	}

	e := &domain.AllowlistEntry{
		ID:        idgen.Hex(10),
		Type:      typ,
		Value:     value,
		Note:      truncate(note, 500),
		CreatedBy: by,
		CreatedAt: time.Now(),
	}
	if err := s.repos.Allowlist.Add(ctx, e); err != nil {
		return nil, 0, err
	}

	recycled, err := s.repos.Alerts.RecycleForAllow(ctx, typ, value, by, time.Now())
	if err != nil {
		// 回收失败不影响加白本身，只记录
		s.log.WarnContext(ctx, "allowlist_recycle_failed", "err", err)
		recycled = 0
	}

	s.log.InfoContext(ctx, "allowlist_added",
		"type", typ, "value", truncate(value, 120), "by", by, "recycled", recycled)
	return e, recycled, nil
}

// DeleteAllowlist 删除白名单项。
func (s *RuleService) DeleteAllowlist(ctx context.Context, id, by string) error {
	if err := s.repos.Allowlist.Delete(ctx, id); err != nil {
		return apperr.NotFound("白名单项")
	}
	s.log.InfoContext(ctx, "allowlist_deleted", "id", id, "by", by)
	return nil
}

// ---------------------------------------------------------------- 审计

// AuditService 记录后台操作。
type AuditService struct{ repos repository.Repos }

// Record 写入一条审计日志（失败不影响主流程，只记日志）。
func (s *AuditService) Record(ctx context.Context, userID, username, action, target, detail, ip string) {
	_ = s.repos.Audit.Add(ctx, &domain.AuditLog{
		UserID:    userID,
		Username:  username,
		Action:    action,
		Target:    target,
		Detail:    truncate(detail, 2000),
		IP:        ip,
		CreatedAt: time.Now(),
	})
}

// List 查询审计日志。
func (s *AuditService) List(ctx context.Context, limit int) ([]domain.AuditLog, error) {
	return s.repos.Audit.List(ctx, limit)
}

// Verify 校验审计防篡改链。管理台校验端点与每日自检共用。
func (s *AuditService) Verify(ctx context.Context) (domain.AuditChainReport, error) {
	return s.repos.Audit.VerifyChain(ctx)
}

// ---------------------------------------------------------------- 统计

// StatsService 提供仪表盘聚合。
type StatsService struct{ repos repository.Repos }

// SetAgentPolicy 配置随规则包下发的终端运行策略（nil = 不干预）。
// 由 app 装配层在启动时注入，策略来源是服务端自己的环境变量——
// 企业里"所有终端统一扫描间隔"应该是平台配置，不是逐台手改。
func (s *RuleService) SetAgentPolicy(p *model.AgentPolicy) { s.agentPolicy = p }

// AgentPolicyOf 返回当前策略（可空）。供 GetBundle 填包。
func (s *RuleService) agentPolicyOf() *model.AgentPolicy { return s.agentPolicy }

// Dashboard 返回首页聚合数据（默认 24 小时窗口、1 小时粒度）。
func (s *StatsService) Dashboard(ctx context.Context, window time.Duration, bucket time.Duration) (*domain.DashboardSummary, error) {
	if window <= 0 {
		window = 24 * time.Hour
	}
	if bucket <= 0 {
		bucket = time.Hour
	}
	return s.repos.Stats.Dashboard(ctx, time.Now().Add(-window), int(bucket.Minutes()))
}

// ---------------------------------------------------------------- utils

func isHex(s string) bool {
	for _, r := range s {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')) {
			return false
		}
	}
	return true
}
