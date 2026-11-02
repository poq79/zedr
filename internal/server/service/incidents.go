package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"strings"
	"sync"
	"time"

	"zedr/internal/model"
	"zedr/internal/platform/apperr"
	"zedr/internal/server/domain"
	"zedr/internal/server/repository"
)

// incidentSyncInterval 是事件聚类的节流下限：列表查询触发懒同步时，
// 距上次同步不足该间隔就直接读库（聚类本身要拉 200 条告警，不能每查必算）。
const incidentSyncInterval = 30 * time.Second

// incidentSyncPageSize 是单次懒同步的翻页页宽（仓储层钳制上界即 200）。
const incidentSyncPageSize = 200

// incidentSyncMaxAlerts 是单次懒同步翻页拉取的硬上界：open+acknowledged 超过
// 该值时，本轮只聚类最老的 5000 条，其余等待下一轮追赶——事件表是持久化的，
// 不会丢，只是聚类有延迟；没有上界的话，堆积中的库每次查询都要翻几十页。
const incidentSyncMaxAlerts = 5000

// IncidentService 承载事件的持久化、状态机与主机变更事件查询。
type IncidentService struct {
	repos repository.Repos
	cfg   Config
	log   *slog.Logger

	mu       sync.Mutex
	lastSync time.Time
}

// EnsureSynced 懒同步：距上次同步超过间隔才真正聚类一次。
// 挂在列表查询前，替代旧方案"后台 janitor 定时跑"——少一条装配线，
// 且语义更好：有人看才需要新鲜数据，没人看就不白算。
func (s *IncidentService) EnsureSynced(ctx context.Context) error {
	s.mu.Lock()
	if time.Since(s.lastSync) < incidentSyncInterval {
		s.mu.Unlock()
		return nil
	}
	s.lastSync = time.Now()
	s.mu.Unlock()
	if _, err := s.Sync(ctx); err != nil {
		// 同步失败不阻断查询：读库给旧数据 + 记日志
		s.log.WarnContext(ctx, "incident_sync_failed", "err", err)
	}
	return nil
}

// Sync 把未处置告警聚类成事件并持久化（Upsert 保护人工处置）。
// 顺带执行超期 open 告警归档（OpenAlertTTL>0 时启用）。
//
// 翻页拉全量：聚类输入必须覆盖全部未处置告警，否则 open+acknowledged 超
// 200 条时事件计数永远缺尾巴（规模债）。Sort=oldest 是 created_at 升序的
// 稳定分页，逐页拼接即全局有序，clusterByGap 可直接消费、无需重排。
func (s *IncidentService) Sync(ctx context.Context) (int, error) {
	var alerts []domain.Alert
	for page := 1; len(alerts) < incidentSyncMaxAlerts; page++ {
		batch, _, err := s.repos.Alerts.List(ctx, domain.AlertFilter{
			Status:   []domain.AlertStatus{model.StatusOpen, model.StatusAcknowledged},
			Page:     page,
			PageSize: incidentSyncPageSize,
			Sort:     "oldest",
		})
		if err != nil {
			return 0, err
		}
		alerts = append(alerts, batch...)
		if len(batch) < incidentSyncPageSize {
			break // 取空了：不足一页即到尾
		}
	}

	byHost := map[string][]domain.Alert{}
	order := []string{}
	for _, a := range alerts {
		if _, ok := byHost[a.Hostname]; !ok {
			order = append(order, a.Hostname)
		}
		byHost[a.Hostname] = append(byHost[a.Hostname], a)
	}

	now := time.Now()
	items := make([]domain.Incident, 0, len(order))
	for _, host := range order {
		groups := clusterByGap(byHost[host], incidentGap)
		for _, g := range groups {
			inc := s.toDomainIncident(host, g, now)
			items = append(items, inc)
		}
	}
	if err := s.repos.Incidents.UpsertBatch(ctx, items); err != nil {
		return 0, err
	}

	s.applyOpenAlertTTL(ctx, now)
	return len(items), nil
}

// toDomainIncident 把内存聚类视图转成持久化实体。
// ID 锚定「主机 + 簇内最老告警 ID」：同簇加新告警不换 ID，簇断开才新建。
func (s *IncidentService) toDomainIncident(host string, group []domain.Alert, now time.Time) domain.Incident {
	view := buildIncident(host, group)
	sum := sha256.Sum256([]byte(host + "|" + group[0].ID))
	agentID := ""
	for _, a := range group {
		if a.AgentID != "" {
			agentID = a.AgentID
			break
		}
	}
	title := "疑似活动（" + host + "）"
	if len(view.Processes) > 0 {
		n := 2
		if len(view.Processes) < n {
			n = len(view.Processes)
		}
		title = "疑似活动：" + strings.Join(view.Processes[:n], "、")
	}
	return domain.Incident{
		ID:           hex.EncodeToString(sum[:])[:16],
		AgentID:      agentID,
		Hostname:     host,
		Title:        title,
		PeakSeverity: view.PeakSeverity,
		MaxScore:     view.MaxScore,
		AlertCount:   view.AlertCount,
		OpenCount:    view.OpenCount,
		Status:       domain.IncidentOpen,
		Processes:    view.Processes,
		RuleIDs:      view.RuleIDs,
		MITRE:        view.MITRE,
		FirstSeen:    view.StartedAt,
		LastSeen:     view.LastAt,
		UpdatedAt:    now,
	}
}

// applyOpenAlertTTL 超期 open 告警自动归档。
// 默认禁用（TTL=0）：自动动运营数据必须显式打开——宁可脏列表，
// 不可悄悄替值班的人做"这告警不重要"的决定。
func (s *IncidentService) applyOpenAlertTTL(ctx context.Context, now time.Time) {
	if s.cfg.OpenAlertTTL <= 0 {
		return
	}
	cutoff := now.Add(-s.cfg.OpenAlertTTL)
	n, _, err := s.repos.Alerts.List(ctx, domain.AlertFilter{
		Status:        []domain.AlertStatus{model.StatusOpen},
		CreatedBefore: cutoff,
		Page:          1,
		PageSize:      200,
	})
	if err != nil {
		s.log.WarnContext(ctx, "open_alert_ttl_scan_failed", "err", err)
		return
	}
	for _, a := range n {
		if err := s.repos.Alerts.UpdateStatus(ctx, a.ID, model.StatusAcknowledged,
			"system", "超期自动归档（超过 OpenAlertTTL 未处置）", now); err != nil {
			s.log.WarnContext(ctx, "open_alert_ttl_archive_failed", "alert_id", a.ID, "err", err)
		}
	}
	if len(n) > 0 {
		s.log.InfoContext(ctx, "open_alert_ttl_archived", "count", len(n))
	}
}

// ListIncidents 读持久化事件（先懒同步），分页 + 可选状态过滤。
func (s *IncidentService) ListIncidents(ctx context.Context, status string, page, pageSize int) ([]domain.Incident, int, error) {
	if err := s.EnsureSynced(ctx); err != nil {
		return nil, 0, err
	}
	if status != "" && !domain.IncidentStatus(status).Valid() {
		return nil, 0, apperr.Invalid("非法的事件状态: %s", status)
	}
	return s.repos.Incidents.List(ctx, status, page, pageSize)
}

// TransitionIncident 推进事件状态机（只前进），审计由 API 层记录。
func (s *IncidentService) TransitionIncident(ctx context.Context, id string, next domain.IncidentStatus, note, by string) (*domain.Incident, error) {
	inc, err := s.repos.Incidents.ByID(ctx, id)
	if err != nil {
		return nil, err
	}
	if inc == nil {
		return nil, apperr.NotFound("事件")
	}
	if !domain.IncidentStatus(next).Valid() {
		return nil, apperr.Invalid("非法的事件状态: %s", next)
	}
	if !inc.Status.CanTransTo(next) {
		return nil, apperr.Invalid("事件状态不允许从 %s 迁移到 %s", inc.Status, next)
	}
	if err := s.repos.Incidents.UpdateStatus(ctx, id, next, note, time.Now()); err != nil {
		return nil, err
	}
	s.log.InfoContext(ctx, "incident_transition", "incident_id", id,
		"from", inc.Status, "to", next, "by", by)
	return s.repos.Incidents.ByID(ctx, id)
}

// CountByStatus 事件状态分布（/metrics 消费）。
func (s *IncidentService) CountByStatus(ctx context.Context) (map[string]int, error) {
	return s.repos.Incidents.CountByStatus(ctx)
}

// AvgFirstActionMinutes 事件 MTTA 平均分钟数（/metrics 消费，7 天窗口）。
func (s *IncidentService) AvgFirstActionMinutes(ctx context.Context, since time.Time) (float64, error) {
	return s.repos.Incidents.AvgFirstActionMinutes(ctx, since)
}

// GetHostChanges 返回主机资产变更事件（可选按节过滤）。
func (s *IncidentService) GetHostChanges(ctx context.Context, agentID, section string, limit int) ([]domain.Alert, error) {
	a, err := s.repos.Agents.ByID(ctx, agentID)
	if err != nil {
		return nil, err
	}
	if a == nil {
		return nil, apperr.NotFound("终端")
	}
	if limit <= 0 || limit > 200 {
		limit = 100
	}
	// 节名与清单查询同一白名单：拼错节名静默返回空会让分析师误读
	if section != "" {
		if _, ok := inventorySectionNames[section]; !ok {
			return nil, apperr.Invalid("非法的清单节名: %s", section)
		}
	}
	items, err := s.repos.Alerts.ListInventoryChanges(ctx, agentID, limit)
	if err != nil {
		return nil, err
	}
	if section == "" {
		return items, nil
	}
	want := "INV-" + strings.ToUpper(section)
	out := make([]domain.Alert, 0, len(items))
	for _, it := range items {
		for _, sig := range it.Evidence.Signals {
			if sig.ID == want {
				out = append(out, it)
				break
			}
		}
	}
	return out, nil
}
