package service

import (
	"context"
	"crypto/subtle"
	"log/slog"
	"strings"
	"sync"
	"time"

	"zedr/internal/model"
	"zedr/internal/platform/apperr"
	"zedr/internal/platform/idgen"
	"zedr/internal/server/domain"
	"zedr/internal/server/repository"
)

// AgentService 负责终端注册、心跳、指令下发。
type AgentService struct {
	skewMu   sync.RWMutex
	skewData map[string]time.Duration
	dropMu   sync.RWMutex
	dropData map[string]int64
	repos    repository.Repos
	cfg      Config
	log      *slog.Logger
}

// Enroll 处理终端注册。同一 machine_id 重复注册会轮转凭证（重装/迁移场景）。
func (s *AgentService) Enroll(ctx context.Context, req model.EnrollRequest, ip string) (*model.EnrollResponse, error) {
	if s.cfg.EnrollToken == "" {
		return nil, apperr.Unavailable("服务端未配置注册令牌，已拒绝注册")
	}
	if req.EnrollToken != s.cfg.EnrollToken {
		s.log.WarnContext(ctx, "enroll_rejected", "reason", "bad_token", "ip", ip, "host", req.Hostname)
		return nil, apperr.Unauthenticated("注册令牌无效")
	}
	if strings.TrimSpace(req.Hostname) == "" || strings.TrimSpace(req.MachineID) == "" {
		return nil, apperr.Invalid("hostname 与 machine_id 不能为空")
	}

	now := time.Now()
	secret := idgen.URLSafe(32)
	secretHash := hashSecret(secret)

	var agentID string
	existing, err := s.repos.Agents.ByMachineID(ctx, req.MachineID)
	if err != nil {
		return nil, err
	}
	if existing != nil {
		agentID = existing.ID
	} else {
		agentID = idgen.Hex(10)
	}

	a := &domain.Agent{
		ID:          agentID,
		Hostname:    truncate(req.Hostname, 128),
		OSVersion:   truncate(req.OSVersion, 128),
		Arch:        truncate(req.Arch, 32),
		Username:    truncate(req.Username, 96),
		IP:          ip,
		Tags:        sanitizeTags(req.Tags),
		Version:     truncate(req.Version, 32),
		MachineID:   truncate(req.MachineID, 64),
		SecretHash:  secretHash,
		Status:      domain.AgentOnline,
		EnrolledAt:  now,
		LastSeenAt:  now,
		RuleVersion: 0,
	}
	if err := s.repos.Agents.Upsert(ctx, a); err != nil {
		return nil, err
	}

	maxVer, err := s.repos.Rules.MaxVersion(ctx)
	if err != nil {
		return nil, err
	}

	s.log.InfoContext(ctx, "agent_enrolled",
		"agent_id", agentID, "host", a.Hostname, "ip", ip, "new", existing == nil)

	return &model.EnrollResponse{
		AgentID:              agentID,
		AgentSecret:          secret,
		ServerTime:           now.Unix(),
		HeartbeatIntervalSec: int(s.cfg.HeartbeatInterval.Seconds()),
		RuleVersion:          maxVer,
		ScanIntervalSec:      int(s.cfg.ScanInterval.Seconds()),
		KillEnabled:          s.cfg.KillEnabled,
	}, nil
}

// Authenticate 校验终端凭证，返回终端实体。
func (s *AgentService) Authenticate(ctx context.Context, agentID string) (*domain.Agent, error) {
	if agentID == "" {
		return nil, apperr.Unauthenticated("缺少终端标识")
	}
	a, err := s.repos.Agents.ByID(ctx, agentID)
	if err != nil {
		return nil, err
	}
	if a == nil {
		return nil, apperr.Unauthenticated("终端未注册或已被删除")
	}
	return a, nil
}

// CheckSecret 校验终端密钥。
func (s *AgentService) CheckSecret(a *domain.Agent, secret string) error {
	if secret == "" || a.SecretHash == "" {
		return apperr.Unauthenticated("终端密钥校验失败")
	}
	got := hashSecret(secret)
	// 恒定时间比较：避免通过响应时间差推断密钥前缀
	if subtle.ConstantTimeCompare([]byte(got), []byte(a.SecretHash)) != 1 {
		return apperr.Unauthenticated("终端密钥校验失败")
	}
	return nil
}

// recordSkew / SkewMap 维护各终端的时钟偏移（进程内，心跳即刷新）。
func (s *AgentService) recordSkew(agentID string, d time.Duration) {
	s.skewMu.Lock()
	defer s.skewMu.Unlock()
	if s.skewData == nil {
		s.skewData = make(map[string]time.Duration, 32)
	}
	s.skewData[agentID] = d
}

// SkewMap 返回各终端时钟偏移（毫秒）。终端 24h 无心跳后由 hosts 接口
// 自然不再展示（离线主机本就不参与时间线分析）。
// DroppedMap 返回各终端的告警队列丢弃计数。
func (s *AgentService) DroppedMap() map[string]int64 {
	s.dropMu.RLock()
	defer s.dropMu.RUnlock()
	out := make(map[string]int64, len(s.dropData))
	for id, n := range s.dropData {
		out[id] = n
	}
	return out
}

func (s *AgentService) SkewMap() map[string]int64 {
	s.skewMu.RLock()
	defer s.skewMu.RUnlock()
	out := make(map[string]int64, len(s.skewData))
	for id, d := range s.skewData {
		out[id] = d.Milliseconds()
	}
	return out
}

// Heartbeat 处理心跳并返回待下发指令。
func (s *AgentService) Heartbeat(ctx context.Context, agentID string, req model.HeartbeatRequest, ip string) (*model.HeartbeatResponse, error) {
	now := time.Now()

	// 时钟偏移 = 服务端收到时刻 - 探针发出时刻（含网络单程延迟，量级在毫秒，
	// 对"偏移几十秒"级别的判定完全够用）。只在内存记录，心跳即刷新。
	// 队列丢弃数随心跳上报：>0 的终端说明存在告警黑洞，
	// 通常意味着离线时间过长或队列太小，运营要能看到
	if req.QueueDropped > 0 {
		s.dropMu.Lock()
		if s.dropData == nil {
			s.dropData = make(map[string]int64, 16)
		}
		s.dropData[agentID] = req.QueueDropped
		s.dropMu.Unlock()
	}

	if !req.AgentTime.IsZero() {
		skew := now.Sub(req.AgentTime)
		if skew < -time.Hour || skew > time.Hour {
			// 超过 1 小时的偏移更可能是时钟源完全错乱，直接钳到告警阈值以上
			skew = time.Hour
		}
		s.recordSkew(agentID, skew)
		if skew > 10*time.Second {
			s.log.WarnContext(ctx, "clock_skew_detected", "agent_id", agentID,
				"skew_sec", int(skew.Seconds()), "hint", "事件时间线可能失真，请检查终端 NTP")
		}
	}
	if err := s.repos.Agents.UpdateHeartbeat(ctx, agentID, now,
		req.ProcCount, req.CPUPercent, req.MemMB, req.RuleVersion, ip, req.Version); err != nil {
		return nil, err
	}

	cmds, err := s.repos.Commands.PendingForAgent(ctx, agentID, 10)
	if err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(cmds))
	out := make([]model.Command, 0, len(cmds))
	for _, c := range cmds {
		ids = append(ids, c.ID)
		out = append(out, model.Command{ID: c.ID, Type: c.Type, Payload: c.Payload})
	}
	if len(ids) > 0 {
		if err := s.repos.Commands.MarkDelivered(ctx, ids, now); err != nil {
			return nil, err
		}
	}

	maxVer, err := s.repos.Rules.MaxVersion(ctx)
	if err != nil {
		return nil, err
	}

	return &model.HeartbeatResponse{
		ServerTime:  now.Unix(),
		RuleVersion: maxVer,
		AckCommand:  ids,
		Commands:    out,
		ScanSeconds: int(s.cfg.ScanInterval.Seconds()),
	}, nil
}

// List 列出所有终端，并附加未处置告警数。
func (s *AgentService) List(ctx context.Context) ([]domain.Agent, error) {
	agents, err := s.repos.Agents.List(ctx)
	if err != nil {
		return nil, err
	}
	counts, err := s.repos.Alerts.CountOpenByAgent(ctx)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	for i := range agents {
		agents[i].OpenAlerts = counts[agents[i].ID]
		// 90 秒无心跳视为离线（前端展示用，落库状态由维护任务刷新）
		if now.Sub(agents[i].LastSeenAt) > 90*time.Second && agents[i].Status == domain.AgentOnline {
			agents[i].Status = domain.AgentOffline
		}
	}
	return agents, nil
}

// Get 查询单个终端。
func (s *AgentService) Get(ctx context.Context, id string) (*domain.Agent, error) {
	a, err := s.repos.Agents.ByID(ctx, id)
	if err != nil {
		return nil, err
	}
	if a == nil {
		return nil, apperr.NotFound("终端")
	}
	counts, err := s.repos.Alerts.CountOpenByAgent(ctx)
	if err == nil {
		a.OpenAlerts = counts[a.ID]
	}
	return a, nil
}

// Delete 删除终端。
func (s *AgentService) Delete(ctx context.Context, id string) error {
	// 先清资产清单（孤儿数据）。清理失败只记日志不阻断：主机删除本身
	// 必须成功，残留的清单行不该反过来卡住主流程
	if err := s.repos.Inventory.DeleteByAgent(ctx, id); err != nil {
		s.log.WarnContext(ctx, "inventory_cleanup_failed", "agent_id", id, "err", err)
	}
	return s.repos.Agents.Delete(ctx, id)
}

// EnqueueCommand 下发指令（terminate/quarantine_file/quarantine_restore/rescan/sync_rules/collect）。
// 处置类指令走双层开关：服务端在这里拦一道，终端侧再各自配置确认——
// 单侧误开不会让破坏性动作真正生效。
func (s *AgentService) EnqueueCommand(ctx context.Context, agentID, typ, payload, by string) (*domain.AgentCommand, error) {
	a, err := s.repos.Agents.ByID(ctx, agentID)
	if err != nil {
		return nil, err
	}
	if a == nil {
		return nil, apperr.NotFound("终端")
	}
	switch typ {
	case "terminate":
		if !s.cfg.KillEnabled {
			return nil, apperr.Forbidden("服务端未启用主动处置能力（HG_SERVER_KILL_ENABLED）")
		}
	case "quarantine_file", "quarantine_restore":
		if !s.cfg.QuarantineEnabled {
			return nil, apperr.Forbidden("服务端未启用文件隔离能力（HG_SERVER_QUARANTINE_ENABLED）")
		}
	case "drill":
		// 演练会让探针在目标机器执行受控自测（自造样本），与处置类同纪律：
		// 服务端总开关 + 终端本地开关双层闸门，默认双侧关闭。
		if !s.cfg.DrillEnabled {
			return nil, apperr.Forbidden("服务端未启用检测演练（HG_SERVER_DRILL_ENABLED）")
		}
	case "rescan", "sync_rules", "collect":
		// 只读类动作始终允许
	default:
		return nil, apperr.Invalid("不支持的指令类型: %s", typ)
	}

	c := &domain.AgentCommand{
		ID:        idgen.Hex(10),
		AgentID:   agentID,
		Type:      typ,
		Payload:   payload,
		Status:    "pending",
		CreatedBy: by,
		CreatedAt: time.Now(),
	}
	if err := s.repos.Commands.Create(ctx, c); err != nil {
		return nil, err
	}
	s.log.InfoContext(ctx, "command_enqueued", "agent_id", agentID, "type", typ, "by", by)
	return c, nil
}

// commandResultMaxLen 是指令回执的入库上限。普通回执一句话足够，
// 检测演练的回执是整份 JSON 报告（逐步结果+告警引用），500 字节会被
// 拦腰截断成半截 JSON；列本身是 TEXT 无长度约束，上限纯粹是卫生闸。
const commandResultMaxLen = 4096

// CompleteCommand 处理终端回执。
func (s *AgentService) CompleteCommand(ctx context.Context, agentID string, results []model.CommandResult) error {
	now := time.Now()
	for _, r := range results {
		status := "done"
		if r.Status == "failed" {
			status = "failed"
		}
		if err := s.repos.Commands.Complete(ctx, r.CommandID, status, truncate(r.Result, commandResultMaxLen), now); err != nil {
			return err
		}
	}
	return nil
}

// MarkOffline 供维护任务调用：把长时间无心跳的终端标记为离线。
func (s *AgentService) MarkOffline(ctx context.Context, threshold time.Duration) (int64, error) {
	return s.repos.Agents.MarkOfflineBefore(ctx, time.Now().Add(-threshold))
}

// ListCommands 查询最近的指令下发记录。
func (s *AgentService) ListCommands(ctx context.Context, limit int) ([]domain.AgentCommand, error) {
	return s.repos.Commands.ListRecent(ctx, limit)
}

// ListCommandsByType 按终端+类型分页查询指令（检测演练报告走 type=drill
// 过滤，复用指令管线，不建新表）。
func (s *AgentService) ListCommandsByType(ctx context.Context, agentID, typ string, page, pageSize int) ([]domain.AgentCommand, int, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 200 {
		pageSize = 20
	}
	return s.repos.Commands.ListByAgentType(ctx, agentID, typ, (page-1)*pageSize, pageSize)
}

func hashSecret(s string) string {
	// 终端密钥与刷新令牌使用同一套 SHA-256 摘要策略（密钥本身是高熵随机串）
	return sha256Hex(s)
}

func sanitizeTags(tags []string) []string {
	out := make([]string, 0, len(tags))
	for _, t := range tags {
		t = strings.TrimSpace(t)
		if t == "" || len(t) > 32 {
			continue
		}
		out = append(out, t)
		if len(out) >= 10 {
			break
		}
	}
	return out
}
