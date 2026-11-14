package service

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"zedr/internal/platform/idgen"
	"zedr/internal/server/domain"
	"zedr/internal/server/repository"
)

// RuleIDSensorOffline 是服务端自产的"传感器失联"告警规则 ID。
// 只在服务端产生：探针死了就无法上报"我死了"，唯一可靠的信息源是心跳流
// 的消失（维护循环 3 分钟阈值翻转离线时建告警，恢复心跳自动结案）。
// 不进探针规则包，也不参与规则签名/版本体系。
const RuleIDSensorOffline = "SEN-OFFLINE"

// SensorWatchService 把"终端在线状态转变"转成告警闭环：
// online→offline 建告警（周期内去重），offline→online 自动结案。
//
// 去重不走 ingest 的指纹窗口——失联是"状态"不是"事件流"，一轮失联周期
// 只该有一条告警：建前查该终端是否已有未终态的 SEN-OFFLINE，恢复时统一
// 结案，下次失联是新周期新告警（指纹带最后心跳时间，保证历史可区分）。
type SensorWatchService struct {
	repos repository.Repos
	bus   *AlertBus
	cfg   Config
	log   *slog.Logger
}

// RaiseForTransitions 在维护循环标记离线后调用，每个转变终端至多产生一条
// 告警。返回新建条数；总开关关闭时直接返回 0。
func (s *SensorWatchService) RaiseForTransitions(ctx context.Context, agents []domain.Agent) (int, error) {
	if !s.cfg.SensorOfflineAlerts || len(agents) == 0 {
		return 0, nil
	}
	created := 0
	for i := range agents {
		open, err := s.repos.Alerts.FindOpenByRule(ctx, agents[i].ID, RuleIDSensorOffline)
		if err != nil {
			return created, err
		}
		if len(open) > 0 {
			// 本轮失联周期已有一条未结案告警（上一次告警后主机始终没回来）
			continue
		}
		a := s.buildOfflineAlert(&agents[i])
		if err := s.repos.Alerts.Create(ctx, a); err != nil {
			return created, fmt.Errorf("写入失联告警失败: %w", err)
		}
		if s.bus != nil {
			s.bus.Publish(*a)
		}
		created++
	}
	if created > 0 && s.log != nil {
		s.log.InfoContext(ctx, "sensor_offline_alerts_raised", "count", created)
	}
	return created, nil
}

// ResolveOnBackOnline 主机恢复心跳时自动结案其全部未终态失联告警。
// by=system：这是系统闭环动作而非人工处置，审计口径与 BulkUpdateStatus
// 的"谁在什么时候处置"区分开。
func (s *SensorWatchService) ResolveOnBackOnline(ctx context.Context, agentID string) (int, error) {
	open, err := s.repos.Alerts.FindOpenByRule(ctx, agentID, RuleIDSensorOffline)
	if err != nil {
		return 0, err
	}
	resolved := 0
	for i := range open {
		note := "主机恢复心跳，自动结案（sensor_back_online）"
		if err := s.repos.Alerts.UpdateStatus(ctx, open[i].ID, domain.StatusResolved,
			"system", note, time.Now()); err != nil {
			return resolved, err
		}
		resolved++
	}
	if resolved > 0 && s.log != nil {
		s.log.InfoContext(ctx, "sensor_back_online_resolved",
			"agent_id", agentID, "resolved", resolved)
	}
	return resolved, nil
}

// buildOfflineAlert 组装失联告警。
//   - Verdict 取 suspicious 而非 safe：探针静默既可能是关机断网，也可能是
//     攻击者杀死 EDR 的对抗行为（T1562 同类手法），服务端无法区分——
//     三值口径里"分不清"就归 suspicious，结合主机近期告警人工判断；
//   - MITRE 留空：没有证据支撑具体战术映射，宁可空不硬凑（诚实边界）；
//   - Score 40 只是展示分位（medium 档），不是检测融合分；
//   - OccurredAt 用最后心跳时刻而非发现时刻——时间线归因以事实为准。
func (s *SensorWatchService) buildOfflineAlert(a *domain.Agent) *domain.Alert {
	now := time.Now()
	silent := now.Sub(a.LastSeenAt)
	lastSeen := a.LastSeenAt
	if lastSeen.IsZero() {
		lastSeen = now
		silent = 0
	}
	minutes := int(silent.Minutes())
	if minutes < 1 {
		minutes = 1
	}
	sev := domain.Severity(s.cfg.SensorOfflineSeverity)
	if !sev.Valid() {
		sev = domain.SeverityMedium
	}
	return &domain.Alert{
		ID:          idgen.Hex(12),
		AgentID:     a.ID,
		Hostname:    a.Hostname,
		Fingerprint: fmt.Sprintf("sen-offline:%s:%d", a.ID, lastSeen.Unix()),
		Title:       fmt.Sprintf("终端失联：%s", a.Hostname),
		Summary: fmt.Sprintf("探针已 %d 分钟无心跳（阈值 3 分钟）。可能原因：主机关机/断网、"+
			"探针服务被停止或卸载、网络故障。探针静默也可能是对抗方终止 EDR 的信号，"+
			"请结合该主机近期告警与变更判断。", minutes),
		Verdict:  domain.VerdictSuspicious,
		Severity: sev,
		Score:    40,
		RuleIDs:  []string{RuleIDSensorOffline},
		Evidence: domain.Evidence{
			Notes: []string{
				fmt.Sprintf("last_seen_at=%s", lastSeen.UTC().Format(time.RFC3339)),
				fmt.Sprintf("silent_minutes=%d", minutes),
				fmt.Sprintf("agent_version=%s", a.Version),
				fmt.Sprintf("last_ip=%s", a.IP),
			},
		},
		Status:     domain.StatusOpen,
		OccurredAt: lastSeen,
		CreatedAt:  now,
		HostCount:  1,
	}
}
