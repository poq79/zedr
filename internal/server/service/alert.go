package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"strings"
	"sync"
	"time"

	"hostguard/internal/model"
	"hostguard/internal/platform/apperr"
	"hostguard/internal/platform/idgen"
	"hostguard/internal/server/domain"
	"hostguard/internal/server/repository"
)

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// ---------------------------------------------------------------- 实时总线

// AlertBus 是极简的告警实时推送总线（SSE 使用）。
// 采用"每订阅者有界缓冲 + 丢弃最旧"策略，保证慢消费者不会拖垮服务端。
type AlertBus struct {
	mu   sync.RWMutex
	subs map[int]chan domain.Alert
	next int
}

// NewAlertBus 创建总线。
func NewAlertBus() *AlertBus {
	return &AlertBus{subs: make(map[int]chan domain.Alert)}
}

// Subscribe 订阅告警流。
func (b *AlertBus) Subscribe() (int, <-chan domain.Alert) {
	ch := make(chan domain.Alert, 64)
	b.mu.Lock()
	id := b.next
	b.next++
	b.subs[id] = ch
	b.mu.Unlock()
	return id, ch
}

// Unsubscribe 取消订阅。
func (b *AlertBus) Unsubscribe(id int) {
	b.mu.Lock()
	if ch, ok := b.subs[id]; ok {
		delete(b.subs, id)
		close(ch)
	}
	b.mu.Unlock()
}

// Publish 广播一条告警（非阻塞）。
func (b *AlertBus) Publish(a domain.Alert) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	for _, ch := range b.subs {
		select {
		case ch <- a:
		default:
			// 缓冲满则丢弃本条，避免阻塞上报主链路
		}
	}
}

// ---------------------------------------------------------------- 告警服务

// AlertService 负责告警入库、聚合降噪、查询与处置。
type AlertService struct {
	repos repository.Repos
	cfg   Config
	log   *slog.Logger
	bus   *AlertBus
}

// Ingest 批量接收终端上报的告警。
//
// 聚合策略（对应报告的"第二级降噪"）：同一 agent + 同一 fingerprint 在
// DupWindow 内重复出现时，不新增记录，而是给原告警的 duplicate 计数 +1，
// 这样"同一个恶意样本反复尝试执行 500 次"只会产生 1 条告警。
func (s *AlertService) Ingest(ctx context.Context, agent *domain.Agent, req model.AlertBatchRequest) (*model.AlertBatchResponse, error) {
	if len(req.Alerts) == 0 {
		return &model.AlertBatchResponse{}, nil
	}
	if len(req.Alerts) > 500 {
		return nil, apperr.Invalid("单批告警数不能超过 500 条")
	}

	resp := &model.AlertBatchResponse{}
	now := time.Now()
	since := now.Add(-s.cfg.DupWindow)

	for _, in := range req.Alerts {
		if !in.Verdict.Valid() || !in.Severity.Valid() {
			resp.Rejected++
			continue
		}
		if strings.TrimSpace(in.Title) == "" || strings.TrimSpace(in.ProcessName) == "" {
			resp.Rejected++
			continue
		}

		fp := in.Fingerprint
		if fp == "" {
			fp = deriveFingerprint(in)
		}

		dup, err := s.repos.Alerts.FindDuplicate(ctx, fp, agent.ID, since)
		if err != nil {
			return nil, err
		}
		if dup != nil {
			if err := s.repos.Alerts.BumpDuplicate(ctx, dup.ID, now); err != nil {
				return nil, err
			}
			resp.Duplicates++
			continue
		}

		occurred := in.OccurredAt
		if occurred.IsZero() || occurred.After(now.Add(time.Minute)) {
			occurred = now
		}

		a := &domain.Alert{
			ID:          idgen.Hex(12),
			AgentID:     agent.ID,
			Hostname:    agent.Hostname,
			Fingerprint: fp,
			Title:       truncate(in.Title, 200),
			Summary:     truncate(in.Summary, 2000),
			Verdict:     in.Verdict,
			Severity:    in.Severity,
			Score:       clampInt(in.Score, 0, 100),
			PID:         in.PID,
			PPID:        in.PPID,
			ProcessName: truncate(in.ProcessName, 260),
			ImagePath:   truncate(in.ImagePath, 1024),
			CmdLine:     truncate(in.CmdLine, 4096),
			ProcUser:    truncate(in.ProcUser, 160),
			HashSHA256:  truncate(in.HashSHA256, 64),
			Signer:      truncate(in.Signer, 200),
			Signed:      in.Signed,
			RuleIDs:     limitSlice(in.RuleIDs, 20),
			MITRE:       limitSlice(in.MITRE, 20),
			Evidence:    in.Evidence,
			Status:      domain.StatusOpen,
			OccurredAt:  occurred,
			CreatedAt:   now,
			HostCount:   1,
		}
		if err := s.repos.Alerts.Create(ctx, a); err != nil {
			return nil, err
		}
		resp.Accepted++

		if s.bus != nil {
			s.bus.Publish(*a)
		}
	}

	if resp.Accepted > 0 || resp.Duplicates > 0 {
		s.log.InfoContext(ctx, "alerts_ingested",
			"agent_id", agent.ID, "host", agent.Hostname,
			"accepted", resp.Accepted, "duplicates", resp.Duplicates, "rejected", resp.Rejected)
	}
	return resp, nil
}

// List 查询告警列表。
func (s *AlertService) List(ctx context.Context, f domain.AlertFilter) ([]domain.Alert, int, error) {
	return s.repos.Alerts.List(ctx, f)
}

// Get 查询单条告警。
func (s *AlertService) Get(ctx context.Context, id string) (*domain.Alert, error) {
	a, err := s.repos.Alerts.ByID(ctx, id)
	if err != nil {
		return nil, err
	}
	if a == nil {
		return nil, apperr.NotFound("告警")
	}
	return a, nil
}

// UpdateStatus 处置告警。
func (s *AlertService) UpdateStatus(ctx context.Context, id string, status domain.AlertStatus, by, note string) error {
	if !status.Valid() {
		return apperr.Invalid("状态非法，可选 open/acknowledged/resolved/false_positive")
	}
	if err := s.repos.Alerts.UpdateStatus(ctx, id, status, by, truncate(note, 1000), time.Now()); err != nil {
		return apperr.NotFound("告警")
	}
	s.log.InfoContext(ctx, "alert_status_changed", "alert_id", id, "status", status, "by", by)
	return nil
}

// Purge 清理已处置的历史告警。
func (s *AlertService) Purge(ctx context.Context, before time.Time) (int64, error) {
	return s.repos.Alerts.PurgeBefore(ctx, before)
}

func deriveFingerprint(in model.AlertEnvelope) string {
	key := strings.ToLower(strings.Join([]string{
		in.ProcessName, in.HashSHA256, strings.Join(in.RuleIDs, ","), string(in.Severity),
	}, "|"))
	return sha256Hex(key)[:32]
}

func clampInt(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func limitSlice(s []string, n int) []string {
	out := make([]string, 0, n)
	for _, v := range s {
		if v = strings.TrimSpace(v); v == "" {
			continue
		}
		out = append(out, v)
		if len(out) >= n {
			break
		}
	}
	return out
}
