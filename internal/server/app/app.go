package app

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"time"

	"zedr/internal/ai"
	"zedr/internal/mcp"
	"zedr/internal/model"
	"zedr/internal/platform/apperr"
	"zedr/internal/platform/httpx"
	"zedr/internal/platform/idgen"
	"zedr/internal/platform/logx"
	"zedr/internal/platform/rulehash"
	"zedr/internal/platform/settingseal"
	"zedr/internal/server/api"
	"zedr/internal/server/auth"
	"zedr/internal/server/ingestguard"
	"zedr/internal/server/livetunnel"
	"zedr/internal/server/notify"
	"zedr/internal/server/repository/sqlite"
	"zedr/internal/server/service"
	"zedr/internal/server/web"
)

// App 是已装配完成的服务端实例。
type App struct {
	Cfg      *Config
	Log      *slog.Logger
	Server   *httpx.Server
	store    *sqlite.Store
	services *service.Services
	// notifiers 是全部告警通知渠道（webhook/syslog/飞书/钉钉/Slack/邮件），
	// 统一以 notify.Channel 消费；启停与订阅循环见 New / Close。
	notifiers []notify.Channel
	// notifyWatch 轮询各渠道 Stats 增量判定连续失败（见 notify.Watchdog），
	// 状态经 /api/v1/notify/health 与 /metrics 暴露。
	notifyWatch *notify.Watchdog
	stop        chan struct{}

	// janitorTicks 是 janitor 循环的执行轮数（每轮 60s），用于触发每日备份
	janitorTicks int
}

// Version 由构建脚本注入（-ldflags -X）。
var Version = "dev"

// New 装配全部依赖。任一步失败都返回错误而不带病启动。
func New() (*App, error) {
	cfg, err := LoadConfig()
	if err != nil {
		return nil, err
	}

	log := logx.New(logx.Options{Level: cfg.LogLevel, Format: cfg.LogFormat})
	log.Info("server_starting", "env", cfg.Env, "version", Version, "addr", cfg.Addr)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	store, repos, err := sqlite.Open(ctx, cfg.DBPath)
	if err != nil {
		return nil, err
	}

	// 审计防篡改链密钥：显式配置优先，未配置从 JWTSecret 派生专用子密钥。
	// 启动即启用并回填历史行——回填发生在对外服务之前，避免链中途换语义。
	auditKey := []byte(cfg.AuditSealKey)
	if cfg.AuditSealKey == "" {
		auditKey = rulehash.DeriveKey([]byte(cfg.JWTSecret), "audit-seal")
	}
	if n, err := repos.Audit.EnableSeal(ctx, auditKey); err != nil {
		_ = store.Close()
		return nil, fmt.Errorf("启用审计防篡改链失败: %w", err)
	} else if n > 0 {
		log.Info("audit_seal_backfilled", "rows", n)
	}

	tokens, err := auth.NewManager(cfg.JWTSecret, cfg.AccessTTL, cfg.RefreshTTL)
	if err != nil {
		_ = store.Close()
		return nil, err
	}

	// 注册令牌缺失时自动生成并打印一次，避免"部署了但连不上"
	if cfg.EnrollToken == "" {
		cfg.EnrollToken = idgen.URLSafe(24)
		log.Warn("enroll_token_generated",
			"enroll_token", cfg.EnrollToken,
			"hint", "请把该值配置到终端 HG_AGENT_ENROLL_TOKEN，并写入服务端 HG_SERVER_ENROLL_TOKEN 以便重启后保持")
	}

	// aiCfg 同时喂给引擎（启动生效）与服务层（配置中心的回退基线与展示）
	aiCfg := ai.Config{
		Provider:          cfg.AIProvider,
		BaseURL:           cfg.AIBaseURL,
		APIKey:            cfg.AIAPIKey,
		Model:             cfg.AIModel,
		Timeout:           cfg.AITimeout,
		HourlyTokenBudget: cfg.AITokenBudget,
		AgentMaxSteps:     cfg.AIAgentMaxSteps,
		AgentToolTimeout:  cfg.AIAgentToolTimeout,
	}
	aiEngine := ai.NewEngine(aiCfg, log)

	// 后台 AI 配置的敏感字段加密密钥：显式配置优先，未配置从 JWTSecret 派生
	encKey, err := settingseal.Key(cfg.SettingEncKey, cfg.JWTSecret)
	if err != nil {
		_ = store.Close()
		return nil, fmt.Errorf("解析后台配置加密密钥失败: %w", err)
	}

	svc := service.New(repos, tokens, service.Config{
		EnrollToken:           cfg.EnrollToken,
		KillEnabled:           cfg.KillEnabled,
		QuarantineEnabled:     cfg.QuarantineEnabled,
		DrillEnabled:          cfg.DrillEnabled,
		SensorOfflineAlerts:   cfg.SensorOfflineAlerts,
		SensorOfflineSeverity: cfg.SensorOfflineSeverity,
		HeartbeatInterval:     time.Duration(cfg.HeartbeatSec) * time.Second,
		ScanInterval:          time.Duration(cfg.ScanSec) * time.Second,
		RetentionDays:         cfg.RetentionDays,
		DupWindow:             cfg.DupWindow,
		OpenAlertTTL:          cfg.OpenAlertTTL,
		AIBootstrap:           aiCfg,
		SettingEncKey:         encKey,
	}, log, aiEngine)

	// 后台 AI 配置中心的 DB 配置在启动时应用一次：
	// DB 有配置则以配置中心为准（热更新同一套逻辑），否则引擎保持 env 引导配置。
	// 失败只降级不阻断启动（LoadStoredConfig 内部处理）。
	svc.AI.LoadStoredConfig(ctx)

	// 终端运行策略：服务端一处配置，随规则包签名下发到所有探针。
	// 两项都未配置时不下发（agentPolicy=nil），完全尊重终端本地配置。
	var policy *model.AgentPolicy
	if cfg.AgentPolicyScanInterval > 0 || cfg.AgentPolicyCollector != "" {
		policy = &model.AgentPolicy{
			ScanIntervalSec: int(cfg.AgentPolicyScanInterval.Seconds()),
			Collector:       cfg.AgentPolicyCollector,
		}
		log.Info("agent_policy_active",
			"scan_interval_sec", policy.ScanIntervalSec, "collector", policy.Collector)
	}
	svc.Rule.SetAgentPolicy(policy)

	// 播种内置规则 + 初始管理员
	if _, err := svc.Rule.SeedBuiltins(ctx); err != nil {
		_ = store.Close()
		return nil, fmt.Errorf("播种内置规则失败: %w", err)
	}
	username, genPwd, err := svc.Auth.BootstrapAdmin(ctx, cfg.BootstrapUser, cfg.BootstrapPass)
	if err != nil {
		_ = store.Close()
		return nil, fmt.Errorf("创建初始管理员失败: %w", err)
	}
	if genPwd != "" {
		log.Warn("bootstrap_admin_created",
			"username", username, "password", genPwd,
			"hint", "这是唯一一次打印，请立即登录并修改密码")
	}

	// 告警外发通知：订阅总线，尽力外发（旁路，不影响主链路）。
	//
	// 严重度过滤是治理"通知风暴"的关键：告警入库是全量的，但推给
	// 值班手机/SIEM 的应该只是需要人看的部分——低分告警进系统留档即可，
	// 推送一条可疑的"接近阈值"事件只会消耗值班注意力（那是最贵的资源）。
	// 门槛统一取 HG_SERVER_WEBHOOK_MIN_SEVERITY，对全部渠道生效；
	// 渠道自身不重复实现过滤（见 notify.Channel）。
	minSev := severityRank(cfg.WebhookMinSeverity)

	notifier := notify.New(cfg.WebhookURL, cfg.WebhookSecret, cfg.WebhookTimeout, log)
	syslogger := notify.NewSyslog(cfg.SyslogAddr, log)

	// channels 是启用的渠道清单：每条达到门槛的告警逐渠道 Ingest，
	// 渠道之间互不影响（各自有独立队列与 worker，失败只记 warn）。
	channels := []notify.Channel{}
	if notifier != nil {
		channels = append(channels, notifier)
		log.Info("webhook_notifier_enabled", "url", cfg.WebhookURL,
			"min_severity", cfg.WebhookMinSeverity)
	}
	if syslogger != nil {
		channels = append(channels, syslogger)
		log.Info("syslog_notifier_enabled", "addr", cfg.SyslogAddr, "format", "CEF/UDP")
	}

	// IM 卡片渠道：与 webhook/syslog 同一条总线、同一个门槛，只多一路出方向消费
	feishu := notify.NewFeishu(cfg.FeishuWebhookURL, cfg.ConsoleURL, log)
	if feishu != nil {
		channels = append(channels, feishu)
		log.Info("feishu_notifier_enabled", "min_severity", cfg.WebhookMinSeverity)
	}
	dingtalk := notify.NewDingTalk(cfg.DingTalkWebhookURL, cfg.DingTalkSecret, cfg.ConsoleURL, log)
	if dingtalk != nil {
		channels = append(channels, dingtalk)
		log.Info("dingtalk_notifier_enabled", "sign", cfg.DingTalkSecret != "",
			"min_severity", cfg.WebhookMinSeverity)
	}
	slack := notify.NewSlack(cfg.SlackWebhookURL, cfg.ConsoleURL, log)
	if slack != nil {
		channels = append(channels, slack)
		log.Info("slack_notifier_enabled", "min_severity", cfg.WebhookMinSeverity)
	}
	mailer := notify.NewEmail(notify.EmailConfig{
		Host: cfg.SMTPHost,
		Port: cfg.SMTPPort,
		User: cfg.SMTPUser,
		Pass: cfg.SMTPPass,
		From: cfg.SMTPFrom,
		To:   cfg.AlertEmailTo,
	}, log)
	if mailer != nil {
		channels = append(channels, mailer)
		log.Info("email_notifier_enabled", "host", cfg.SMTPHost, "port", cfg.SMTPPort,
			"recipients", len(cfg.AlertEmailTo), "min_severity", cfg.WebhookMinSeverity)
	}

	// 通知看门狗：渠道名只能在装配点绑定（Channel 接口没有 Name），
	// 与 channels 一一对应。判定窗口数默认 3（≈3 分钟连续失败才报
	// degraded，排除单次网络抖动），可经 HG_SERVER_NOTIFY_FAIL_WINDOWS 调整。
	named := make([]notify.NamedChannel, 0, len(channels))
	if notifier != nil {
		named = append(named, notify.NamedChannel{Name: "webhook", Channel: notifier})
	}
	if syslogger != nil {
		named = append(named, notify.NamedChannel{Name: "syslog", Channel: syslogger})
	}
	if feishu != nil {
		named = append(named, notify.NamedChannel{Name: "feishu", Channel: feishu})
	}
	if dingtalk != nil {
		named = append(named, notify.NamedChannel{Name: "dingtalk", Channel: dingtalk})
	}
	if slack != nil {
		named = append(named, notify.NamedChannel{Name: "slack", Channel: slack})
	}
	if mailer != nil {
		named = append(named, notify.NamedChannel{Name: "email", Channel: mailer})
	}
	notifyWatch := notify.NewWatchdog(named, cfg.NotifyFailWindows)

	if len(channels) > 0 {
		if _, ch := svc.Bus.Subscribe(); ch != nil {
			go func() {
				for alert := range ch {
					// 只外发未处置的、达到严重度门槛的告警
					if alert.Status != model.StatusOpen ||
						severityRank(string(alert.Severity)) < minSev {
						continue
					}
					for _, out := range channels {
						out.Ingest(alert)
					}
				}
			}()
		}
	}

	// critical 告警自动触发确定性调查（v1 编排的自动触发器，LLM 叙事层后续接入）。
	//
	// Investigate 原本只能手动 POST 触发——critical 意味着"正在发生"，
	// 等值班点按钮就慢了一拍。这里另起一个总线订阅（Bus.Subscribe 支持
	// 多订阅者，与通知互不干扰）：critical 一到就异步调查，结果自动写入
	// investigateCache，前端 GET 同一端点即得，无感于触发方式。
	// 纪律：纯旁路——调查失败只记 warn，绝不影响告警入库与通知主链路；
	// 装配顺序已保证 svc.AI 先于本订阅构造（service.New 在前）。
	if _, ch := svc.Bus.Subscribe(); ch != nil {
		// 并发闸：最多同时 2 个调查。Investigate 是纯 DB 查询编排，
		// 但爆发事件会瞬间产生几十条 critical，不设闸会挤占共享 SQLite。
		const (
			autoInvConcurrency = 2
			// 防重集合容量上界：告警 ID 唯一且只发布一次，集合只增不减，
			// 触顶整表清空防止长尾泄漏（清空后同 ID 若再广播也只会多查一次）。
			autoInvDedupCap = 4096
		)
		sem := make(chan struct{}, autoInvConcurrency)
		seen := make(map[string]bool)
		go func() {
			for alert := range ch {
				if alert.Severity != model.SeverityCritical {
					continue
				}
				// 防重：同 ID 只调查一次（去重聚合/重放可能重复发布同一 ID）
				if seen[alert.ID] {
					continue
				}
				if len(seen) >= autoInvDedupCap {
					seen = make(map[string]bool)
				}
				seen[alert.ID] = true
				go func(id string) {
					sem <- struct{}{}
					defer func() { <-sem }()
					ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
					defer cancel()
					// AutoOps = 确定性调查 + 值班队列入队（方向 C）；
					// 刻意不用 LLM 自动调查：critical 爆发时每条都跑 agent 循环会烧穿预算。
					svc.AI.AutoOps(ctx, id)
				}(alert.ID)
			}
		}()
	}

	// 实时隧道会话注册表：探针反连建立会话后在此登记，
	// 管理端实时查询代理（api/live.go）据此寻址。
	// 总开关关闭时不创建（Router 对 nil 跳过端点挂载），探针侧按
	// "对端不支持"进每小时静默重试，与老服务端兼容矩阵同路径。
	var tunnelReg *livetunnel.Registry
	if cfg.LiveQueryEnabled {
		tunnelReg = livetunnel.NewRegistry(log)
	}

	// 实时查询业务核心：管理台代理与 MCP host_live 工具共用同一执法点
	//（白名单/预算/审计唯一事实源，service/livequery.go）。AI 服务的
	// Agentic 调查也借此在主机在线时取实时证据。
	liveSvc := service.NewLiveQueryService(tunnelReg, cfg.LiveQueryEnabled,
		cfg.LiveQueryFileRead, cfg.LiveQueryCollect, svc.Audit)
	svc.AI.SetLiveQuery(liveSvc)
	svc.AI.SetZeroClick(cfg.AIZeroClick, cfg.AIZeroClickMaxPerHost)

	// MCP 对外工具服务（只读）：独立 Token 鉴权、每工具调用进审计流。
	// 默认关闭；SDK 转正前协议子集自研（internal/mcp，TRADEOFFS §3.14）。
	var mcpSrv *mcp.Server
	if cfg.MCPEnabled && cfg.MCPToken != "" {
		mcpSrv = &mcp.Server{
			Name: "zedr-edr", Version: Version,
			Tools: service.MCPTools(),
			Ex:    service.NewMCPExecutor(svc.AI, liveSvc),
		}
		mcpSrv.OnCall = func(name string, callErr error) {
			detail := "tool=" + name
			if callErr != nil {
				detail += " err=" + callErr.Error()
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			svc.Audit.Record(ctx, "", "mcp", "mcp.tool.call", name, detail, "")
		}
		log.Info("mcp_server_enabled", "tools", len(mcpSrv.Tools))
	}

	router := api.Router(api.Deps{
		Services:       svc,
		Tokens:         tokens,
		Log:            log,
		WebFS:          web.FS(),
		AllowOrigins:   cfg.CORSOrigins,
		RateRPS:        cfg.RateRPS,
		LoginRPS:       cfg.LoginRPS,
		LoginBurst:     cfg.LoginBurst,
		RateBurst:      cfg.RateBurst,
		Ready:          readyCheck(store),
		RuleSignKey:    ruleSignKey(cfg),
		Version:        Version,
		StartedAt:      time.Now(),
		CookieSecure:   cfg.CookieSecure,
		Bus:            svc.Bus,
		Notifier:       notifier,
		NotifyReport:   notifyWatch.Report,
		UpgradeFile:    cfg.UpgradeFile,
		UpgradeVersion: cfg.UpgradeVersion,
		DeployPackage:  cfg.DeployPackage,
		DeployVersion:  cfg.DeployVersion,
		EnrollToken:    cfg.EnrollToken,
		Tunnel:         tunnelReg,
		Live:           liveSvc,
		Ingest:         ingestguard.New(cfg.IngestAlertRPS, cfg.IngestAlertBurst, cfg.IngestMaxInflight),
		MCP:            mcpSrv,
		MCPToken:       cfg.MCPToken,
	})

	srv := httpx.NewServer(httpx.ServerConfig{
		Addr:            cfg.Addr,
		Handler:         router,
		Logger:          log,
		ShutdownTimeout: cfg.ShutdownTimeout,
	})
	if err := srv.Listen(); err != nil {
		_ = store.Close()
		return nil, apperr.Unavailable(fmt.Sprintf("端口 %s 无法监听: %v", cfg.Addr, err))
	}

	return &App{
		Cfg:         cfg,
		Log:         log,
		Server:      srv,
		store:       store,
		services:    svc,
		notifiers:   channels,
		notifyWatch: notifyWatch,
		stop:        make(chan struct{}),
	}, nil
}

// Run 启动 HTTP 服务与后台维护任务，阻塞直到 ctx 取消。
func (a *App) Run(ctx context.Context) error {
	errCh := make(chan error, 1)
	go func() {
		a.Log.Info("server_listening", "addr", a.Server.Addr())
		errCh <- a.Server.Serve()
	}()

	go a.maintenanceLoop(ctx)

	select {
	case <-ctx.Done():
		a.Log.Info("server_stop_signal_received")
	case err := <-errCh:
		if err != nil {
			a.Log.Error("server_serve_failed", "err", err)
			_ = a.store.Close()
			return err
		}
	}

	shutCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := a.Server.Shutdown(shutCtx); err != nil {
		a.Log.Error("server_shutdown_error", "err", err)
	}
	if err := a.store.Close(); err != nil {
		a.Log.Error("db_close_error", "err", err)
	}
	a.Log.Info("server_stopped")
	return nil
}

// maintenanceLoop 周期性执行：终端离线标记、令牌清理、历史告警清理。
func (a *App) maintenanceLoop(ctx context.Context) {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-a.stop:
			return
		case <-ticker.C:
			if stale, err := a.services.Agent.MarkOffline(ctx, 3*time.Minute); err != nil {
				a.Log.Warn("mark_offline_failed", "err", err)
			} else if len(stale) > 0 {
				a.Log.Info("agents_marked_offline", "count", len(stale))
				// 失联告警与状态翻转同 tick 完成：转变事实只在翻转瞬间存在，
				// 拆到下一个 tick 就要另存"未消费的转变"状态，不值得。
				// 建告警条数由服务内部记日志（sensor_offline_alerts_raised）。
				if _, err := a.services.Sensor.RaiseForTransitions(ctx, stale); err != nil {
					a.Log.Warn("sensor_offline_alert_failed", "err", err)
				}
			}

			if n, err := a.store.DB().ExecContext(ctx,
				`DELETE FROM refresh_tokens WHERE expires_at < ?`, time.Now().UnixMilli()); err != nil {
				a.Log.Warn("token_gc_failed", "err", err)
			} else if rows, _ := n.RowsAffected(); rows > 0 {
				a.Log.Debug("tokens_gc", "rows", rows)
			}

			retention := time.Duration(a.Cfg.RetentionDays) * 24 * time.Hour
			if n, err := a.services.Alert.Purge(ctx, time.Now().Add(-retention)); err != nil {
				a.Log.Warn("alert_purge_failed", "err", err)
			} else if n > 0 {
				a.Log.Info("alerts_purged", "count", n)
			}

			// 通知看门狗观测：每窗推进一次连续失败判定，翻转即打日志。
			// degraded 用 Error 级——"告警在发但没人收到"比看起来更危险；
			// 恢复用 Info。状态本身走 /notify/health 与 /metrics 持续可见。
			for _, tr := range a.notifyWatch.Observe() {
				if tr.To == "degraded" {
					a.Log.Error("notify_watchdog_degraded", "channel", tr.Channel,
						"hint", "通知渠道连续失败，告警可能没有送达；详情见 GET /api/v1/notify/health")
				} else {
					a.Log.Info("notify_watchdog_recovered", "channel", tr.Channel)
				}
			}

			// 每轮 janitor 计数，累计 24 轮（≈24 小时）做一次数据库备份。
			// SQLite 单文件架构下"没有备份"等于"数据随时归零"：
			// 磁盘损坏、误删、迁移手滑，任何一样都会让全部告警与审计凭空消失。
			// VACUUM INTO 生成紧凑的一致性快照，在线执行不阻塞业务。
			// 告警完整性链：每天归档昨日摘要（幂等）。放 janitor 而不是
			// 独立协程——它必须与备份/清理同序执行，避免与 retention 竞态。
			if err := a.services.Stats.EnsureIntegrity(ctx, time.Now().Add(-24*time.Hour)); err != nil {
				a.Log.Warn("integrity_ensure_failed", "err", err)
			}

			a.janitorTicks++
			if a.janitorTicks%24 == 0 {
				if n, err := a.backupDB(ctx); err != nil {
					a.Log.Warn("db_backup_failed", "err", err)
				} else {
					a.Log.Info("db_backup_done", "file", n)
				}
				// 审计链每日自检与备份同批：断链（篡改/误删）是必须立即
				// 可见的安全事件，日志用 Error 级别；管理台 /audit/verify
				// 可随时手动全量校验。
				if rep, err := a.services.Audit.Verify(ctx); err != nil {
					a.Log.Warn("audit_verify_failed", "err", err)
				} else if !rep.OK {
					a.Log.Error("audit_chain_broken", "seq", rep.BrokenAt, "reason", rep.Reason)
				}
			}
		}
	}
}

// Close 停止后台任务。
func (a *App) Close() {
	select {
	case <-a.stop:
	default:
		close(a.stop)
	}
	// 逐渠道停止：队列中未发出的通知按渠道语义直接放弃
	//（告警本身已落库，停机时不再为旁路发送拖延退出）。
	for _, ch := range a.notifiers {
		ch.Close()
	}
}

// readyCheck 是 /ready 的判定逻辑。
//
// 只检查 Ping 是不够的：数据库能连上但不可写、或迁移没跑完时，
// 服务仍然会被判定为就绪并开始接流量，问题要到写入失败才暴露。
// 这里额外验证"可读 + 可写 + 迁移完整"三件事。
func readyCheck(store *sqlite.Store) func() error {
	return func() error {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()

		db := store.DB()
		if err := db.PingContext(ctx); err != nil {
			return fmt.Errorf("数据库不可达: %w", err)
		}
		// 只读查询：确认 schema 已就绪
		var n int
		if err := db.QueryRowContext(ctx, `SELECT COUNT(1) FROM schema_migrations`).Scan(&n); err != nil {
			return fmt.Errorf("迁移表不可读: %w", err)
		}
		// 写入探测：在事务里写后立即回滚，不留下任何副作用
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return fmt.Errorf("数据库不可写: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `CREATE TEMP TABLE IF NOT EXISTS _ready_probe(x INTEGER)`); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("数据库写入探测失败: %w", err)
		}
		return tx.Rollback()
	}
}

// ruleSignKey 解析规则包签名密钥。
//
// 显式配置优先；未配置时从 JWT secret 派生一个专用子密钥，
// 保证"开箱即可用"（终端侧仍需自行配置同一个值才能强制验签）。
func ruleSignKey(cfg *Config) []byte {
	if cfg.RuleSignKey != "" {
		return []byte(cfg.RuleSignKey)
	}
	return rulehash.DeriveKey([]byte(cfg.JWTSecret), "rule-signing")
}

// backupDB 用 VACUUM INTO 把数据库快照到 <db 目录>/backup/，
// 文件名带时间戳，保留最近 7 份。返回备份文件路径。
func (a *App) backupDB(ctx context.Context) (string, error) {
	src := a.Cfg.DBPath
	dir := filepath.Join(filepath.Dir(src), "backup")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	dst := filepath.Join(dir, fmt.Sprintf("zedr-server-%s.db", time.Now().Format("20060102-1504")))
	if _, err := a.store.DB().ExecContext(ctx, `VACUUM INTO ?`, dst); err != nil {
		return "", fmt.Errorf("VACUUM INTO 失败: %w", err)
	}

	// 只保留最近 7 份：备份本身就是要占用与源库同量级的磁盘空间，
	// 无上限的增长最终会变成新的故障源
	matches, _ := filepath.Glob(filepath.Join(dir, "zedr-server-*.db"))
	sort.Strings(matches)
	for len(matches) > 7 {
		if err := os.Remove(matches[0]); err != nil {
			return dst, err
		}
		matches = matches[1:]
	}
	return dst, nil
}

// severityRank 把严重度转成可比较的数值。
func severityRank(s string) int {
	switch s {
	case "critical":
		return 3
	case "high":
		return 2
	case "medium":
		return 1
	default:
		return 0
	}
}
