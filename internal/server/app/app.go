package app

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"time"

	"hostguard/internal/platform/apperr"
	"hostguard/internal/platform/httpx"
	"hostguard/internal/ai"
	"hostguard/internal/model"
	"hostguard/internal/server/notify"
	"hostguard/internal/platform/rulehash"
	"hostguard/internal/platform/idgen"
	"hostguard/internal/platform/logx"
	"hostguard/internal/server/api"
	"hostguard/internal/server/auth"
	"hostguard/internal/server/repository/sqlite"
	"hostguard/internal/server/service"
	"hostguard/internal/server/web"
)

// App 是已装配完成的服务端实例。
type App struct {
	Cfg      *Config
	Log      *slog.Logger
	Server   *httpx.Server
	store    *sqlite.Store
	services *service.Services
	notifier *notify.Notifier
	stop     chan struct{}

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

	aiEngine := ai.NewEngine(ai.Config{
		Provider:          cfg.AIProvider,
		BaseURL:           cfg.AIBaseURL,
		APIKey:            cfg.AIAPIKey,
		Model:             cfg.AIModel,
		Timeout:           cfg.AITimeout,
		HourlyTokenBudget: cfg.AITokenBudget,
	}, log)

	svc := service.New(repos, tokens, service.Config{
		EnrollToken:       cfg.EnrollToken,
		KillEnabled:       cfg.KillEnabled,
		HeartbeatInterval: time.Duration(cfg.HeartbeatSec) * time.Second,
		ScanInterval:      time.Duration(cfg.ScanSec) * time.Second,
		RetentionDays:     cfg.RetentionDays,
		DupWindow:         cfg.DupWindow,
	}, log, aiEngine)

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
	minSev := severityRank(cfg.WebhookMinSeverity)

	notifier := notify.New(cfg.WebhookURL, cfg.WebhookSecret, cfg.WebhookTimeout, log)
	syslogger := notify.NewSyslog(cfg.SyslogAddr, log)
	if notifier != nil || syslogger != nil {
		if _, ch := svc.Bus.Subscribe(); ch != nil {
			go func() {
				for alert := range ch {
					// 只外发未处置的、达到严重度门槛的告警
					if alert.Status != model.StatusOpen ||
						severityRank(string(alert.Severity)) < minSev {
						continue
					}
					notifier.Ingest(alert)
					syslogger.Ingest(alert)
				}
			}()
		}
	}
	if notifier != nil {
		log.Info("webhook_notifier_enabled", "url", cfg.WebhookURL,
			"min_severity", cfg.WebhookMinSeverity)
	}
	if syslogger != nil {
		log.Info("syslog_notifier_enabled", "addr", cfg.SyslogAddr, "format", "CEF/UDP")
	}

	router := api.Router(api.Deps{
		Services:     svc,
		Tokens:       tokens,
		Log:          log,
		WebFS:        web.FS(),
		AllowOrigins: cfg.CORSOrigins,
		RateRPS:      cfg.RateRPS,
		LoginRPS:     cfg.LoginRPS,
		LoginBurst:   cfg.LoginBurst,
		RateBurst:    cfg.RateBurst,
		Ready:  readyCheck(store),
		RuleSignKey: ruleSignKey(cfg),
		Version:      Version,
		StartedAt:    time.Now(),
		CookieSecure: cfg.CookieSecure,
		Bus:          svc.Bus,
		Notifier:     notifier,
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
		Cfg:      cfg,
		Log:      log,
		Server:   srv,
		store:    store,
		services: svc,
		stop:     make(chan struct{}),
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
			if n, err := a.services.Agent.MarkOffline(ctx, 3*time.Minute); err != nil {
				a.Log.Warn("mark_offline_failed", "err", err)
			} else if n > 0 {
				a.Log.Info("agents_marked_offline", "count", n)
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
	a.notifier.Close()
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
	dst := filepath.Join(dir, fmt.Sprintf("secserver-%s.db", time.Now().Format("20060102-1504")))
	if _, err := a.store.DB().ExecContext(ctx, `VACUUM INTO ?`, dst); err != nil {
		return "", fmt.Errorf("VACUUM INTO 失败: %w", err)
	}

	// 只保留最近 7 份：备份本身就是要占用与源库同量级的磁盘空间，
	// 无上限的增长最终会变成新的故障源
	matches, _ := filepath.Glob(filepath.Join(dir, "secserver-*.db"))
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
