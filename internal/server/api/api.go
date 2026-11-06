// Package api 是 HTTP 控制器层：解析请求、调用服务层、格式化响应。
//
// 本层严格不写业务逻辑：所有分支判断都下沉到 service，控制器只做
// 参数绑定 → 调用 → 序列化，保证业务规则可被直接单测。
package api

import (
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"zedr/internal/mcp"
	"zedr/internal/platform/apperr"
	"zedr/internal/platform/httpx"
	"zedr/internal/server/auth"
	"zedr/internal/server/ingestguard"
	"zedr/internal/server/livetunnel"
	"zedr/internal/server/notify"
	"zedr/internal/server/service"
)

// Deps 是控制器的依赖集合。
type Deps struct {
	Services     *service.Services
	Tokens       *auth.Manager
	Log          *slog.Logger
	WebFS        fs.FS       // 管理台静态资源（go:embed）
	AllowOrigins []string
	RateRPS      float64
	RateBurst    float64
	// 登录接口独立配额：全站配额为了正常使用必须放宽，登录需要更紧的闸
	LoginRPS     float64
	LoginBurst   float64
	Ready        func() error // /ready 探针
	Version      string
	StartedAt    time.Time
	CookieSecure bool // 生产环境走 HTTPS 时必须为 true
	Bus          *service.AlertBus
	Tickets      *ticketStore
	// RuleSignKey 是规则包签名密钥（由主密钥派生，见 rulehash.DeriveKey）
	RuleSignKey []byte
	// Notifier 是 webhook 告警通知器（nil 表示未启用），/metrics 读取其统计
	Notifier *notify.Notifier
	// UpgradeFile/UpgradeVersion 是探针自升级包（新版本 agent exe）的
	// 服务端配置；任一为空 = 升级端点按"未启用"返回 503
	UpgradeFile    string
	UpgradeVersion string
	// DeployPackage/DeployVersion 是"接入新主机"部署包（zip，管理台下载）；
	// 空 = 部署端点按"未启用"返回 503，管理台据此隐藏下载入口。
	// EnrollToken 是终端注册预共享令牌（接入引导展示用，adminOnly + 审计）；
	// 经 Deps 透传而非让 api 层直接摸 service 配置。
	DeployPackage string
	DeployVersion string
	EnrollToken   string

	// MCP 是对外 MCP Server（nil = 未启用，端点不注册）；
	// MCPToken 是独立 Bearer Token（与 JWT 分离，只读访问）。
	MCP      *mcp.Server
	MCPToken string

	// Tunnel 是实时隧道会话注册表（docs/LIVE-TUNNEL.md）；nil = 隧道端点
	// 与实时查询代理不注册（老部署平滑升级路径）。
	Tunnel *livetunnel.Registry
	// Ingest 是终端告警上报的背压闸（每终端限速 + 在途批次上限）。
	// nil = 不限制，兼容测试与老部署的默认行为。
	Ingest *ingestguard.Guard
	// LiveQueryEnabled/FileRead 对应 HG_SERVER_LIVEQUERY_ENABLED/FILEREAD，
	// 执法逻辑见 api/live.go。
	LiveQueryEnabled  bool
	LiveQueryFileRead bool

	// sseActive 是当前活跃的实时流连接数。
	// 用指针而非值：Deps 是按值传递的，而 atomic.Int64 内含 noCopy，
	// 放进结构体再拷贝会触发 vet 的 copylocks 检查（也确实是隐患）。
	sseActive *atomic.Int64
}

// Router 构建完整路由。
// maxSSEConns 是实时流的最大并发连接数。
// 管理台通常只有个位数标签页；给到 64 已足够宽裕，
// 同时把最坏情况下的资源占用钉死。
const maxSSEConns = 64

// acquireSSE 尝试占用一个实时流名额。
func (d *Deps) acquireSSE() bool {
	if d.sseActive == nil {
		return true
	}
	for {
		cur := d.sseActive.Load()
		if cur >= maxSSEConns {
			return false
		}
		if d.sseActive.CompareAndSwap(cur, cur+1) {
			return true
		}
	}
}

// releaseSSE 释放名额。
func (d *Deps) releaseSSE() {
	if d.sseActive != nil {
		d.sseActive.Add(-1)
	}
}

func Router(d Deps) http.Handler {
	d.sseActive = new(atomic.Int64)

	mux := http.NewServeMux()
	d.Tickets = newTicketStore(60 * time.Second)

	// ---------------- 健康检查（无鉴权、无日志噪音） ----------------
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		httpx.WriteRaw(w, r, http.StatusOK, map[string]any{
			"status":  "ok",
			"version": d.Version,
			"uptime":  int64(time.Since(d.StartedAt).Seconds()),
		})
	})
	mux.HandleFunc("GET /ready", func(w http.ResponseWriter, r *http.Request) {
		if d.Ready != nil {
			if err := d.Ready(); err != nil {
				httpx.WriteRaw(w, r, http.StatusServiceUnavailable, map[string]any{
					"status": "not_ready", "error": "依赖未就绪",
				})
				return
			}
		}
		httpx.WriteRaw(w, r, http.StatusOK, map[string]any{"status": "ready"})
	})

	// ---------------- 公开认证接口 ----------------
	authH := &authHandler{deps: d}
	// 登录单独限流：与普通接口共用一个桶时，暴力破解只受"全站配额"约束，
	// 而全站配额为了正常使用又必须放得比较宽。这里给登录再加一道更紧的闸。
	loginLimiter := httpx.NewTokenBucket(d.LoginRPS, d.LoginBurst)
	loginKey := func(r *http.Request) string { return httpx.ClientIP(r) }
	mux.Handle("POST /api/v1/auth/login",
		httpx.RateLimitMiddleware(loginLimiter, loginKey)(http.HandlerFunc(authH.login)))
	mux.HandleFunc("POST /api/v1/auth/refresh", authH.refresh)
	mux.HandleFunc("POST /api/v1/auth/logout", authH.logout)

	// ---------------- 终端注册（预共享令牌） ----------------
	agentH := &agentHandler{deps: d}
	mux.HandleFunc("POST /api/v1/agents/enroll", agentH.enroll)

	// ---------------- 终端带凭证接口 ----------------
	agentAuth := func(h http.HandlerFunc) http.Handler {
		return agentAuthMiddleware(d, h)
	}
	mux.Handle("POST /api/v1/agent/heartbeat", agentAuth(agentH.heartbeat))
	mux.Handle("POST /api/v1/agent/alerts", agentAuth(agentH.reportAlerts))
	mux.Handle("GET /api/v1/agent/rules", agentAuth(agentH.rules))
	mux.Handle("GET /api/v1/agent/iocs", agentAuth(agentH.agentIOCs))
	mux.Handle("GET /api/v1/agent/upgrade/manifest", agentAuth(agentH.upgradeManifest))
	mux.Handle("GET /api/v1/agent/upgrade/binary", agentAuth(agentH.upgradeBinary))
	mux.Handle("POST /api/v1/agent/commands/result", agentAuth(agentH.commandResult))
	mux.Handle("POST /api/v1/agent/inventory", agentAuth(agentH.saveInventory))
	// 实时隧道升级端点：鉴权在 livetunnel.UpgradeHandler 内经回调完成
	// （101 劫持前必须用规范 JSON 应答失败，与普通中间件的包装语义不同，
	// 故不走 agentAuth 包装）
	if d.Tunnel != nil {
		mux.Handle("GET /api/v1/agent/tunnel", http.HandlerFunc(agentH.tunnelUpgrade))
	}

	// ---------------- 管理台接口（JWT + RBAC） ----------------
	adminH := &adminHandler{deps: d}
	viewer := func(h http.HandlerFunc) http.Handler {
		return jwtMiddleware(d, nil, h)
	}
	writer := func(h http.HandlerFunc) http.Handler {
		return jwtMiddleware(d, []string{"admin", "analyst"}, h)
	}
	adminOnly := func(h http.HandlerFunc) http.Handler {
		return jwtMiddleware(d, []string{"admin"}, h)
	}

	mux.Handle("POST /api/v1/auth/change-password", viewer(authH.changePassword))
	mux.Handle("GET /api/v1/me", viewer(adminH.me))
	mux.Handle("GET /api/v1/dashboard", viewer(adminH.dashboard))

	mux.Handle("GET /api/v1/alerts", viewer(adminH.listAlerts))
	mux.Handle("GET /api/v1/alerts/{id}", viewer(adminH.getAlert))
	mux.Handle("POST /api/v1/alerts/{id}/status", writer(adminH.updateAlertStatus))
	mux.Handle("POST /api/v1/alerts/bulk-status", viewer(adminH.bulkUpdateStatus))

	// AI 分析能力：研判 / 自然语言检索 / 引擎状态
	mux.Handle("POST /api/v1/alerts/{id}/triage", viewer(adminH.triageAlert))
	mux.Handle("POST /api/v1/ai/hunt", viewer(adminH.hunt))
	mux.Handle("GET /api/v1/ai/stats", viewer(adminH.aiStats))

	// AI 配置中心（admin-only）：模型槽位 / 连通性测试 / 提示词模板 / 技能包。
	// 配置影响全局成本与判定行为，analyst 角色不开放写。
	mux.Handle("GET /api/v1/ai/config", adminOnly(adminH.aiGetConfig))
	mux.Handle("PUT /api/v1/ai/config", adminOnly(adminH.aiPutConfig))
	mux.Handle("POST /api/v1/ai/config/test", adminOnly(adminH.aiTestConfig))
	mux.Handle("GET /api/v1/ai/prompts", adminOnly(adminH.aiGetPrompts))
	mux.Handle("PUT /api/v1/ai/prompts/{task}", adminOnly(adminH.aiPutPrompt))
	mux.Handle("POST /api/v1/ai/prompts/{task}/rollback", adminOnly(adminH.aiRollbackPrompt))
	mux.Handle("GET /api/v1/ai/skills", adminOnly(adminH.aiListSkills))
	mux.Handle("POST /api/v1/ai/skills", adminOnly(adminH.aiUpsertSkill))
	mux.Handle("PUT /api/v1/ai/skills/{id}", adminOnly(adminH.aiUpsertSkill))
	mux.Handle("DELETE /api/v1/ai/skills/{id}", adminOnly(adminH.aiDeleteSkill))
	// AI 质量评测（admin-only）：heuristic 结构自检零成本；llm 模式消耗真实 token
	mux.Handle("POST /api/v1/ai/eval/run", adminOnly(adminH.aiRunEval))
	mux.Handle("GET /api/v1/ai/eval/last", adminOnly(adminH.aiLastEval))
	// 网页内 AI 助手（方向 B）与 AI 值班队列（方向 C）
	mux.Handle("POST /api/v1/ai/chat", viewer(adminH.aiChat))
	mux.Handle("GET /api/v1/ai/ops/queue", viewer(adminH.aiOpsQueue))
	mux.Handle("GET /api/v1/ai/quality/report", viewer(adminH.aiQualityReport))
	mux.Handle("POST /api/v1/ai/ops/bulk-review", writer(adminH.aiOpsBulkReview))
	mux.Handle("POST /api/v1/ai/ops/{id}/review", writer(adminH.aiOpsReview))
	mux.Handle("POST /api/v1/ai/ops/{id}/reevaluate", writer(adminH.aiOpsReevaluate))

	mux.Handle("GET /api/v1/hosts", viewer(adminH.listHosts))
	mux.Handle("GET /api/v1/hosts/{id}", viewer(adminH.getHost))
	mux.Handle("DELETE /api/v1/hosts/{id}", adminOnly(adminH.deleteHost))
	mux.Handle("POST /api/v1/hosts/{id}/commands", writer(adminH.sendCommand))
	// 检测演练：发起（analyst+，服务端总开关 HG_SERVER_DRILL_ENABLED 把门）
	// 与报告列表（viewer 可读，复盘/验收场景常需要只读角色能看到结果）
	mux.Handle("POST /api/v1/hosts/{id}/drill", writer(adminH.startDrill))
	mux.Handle("GET /api/v1/hosts/{id}/drills", viewer(adminH.listDrills))
	mux.Handle("GET /api/v1/hosts/{id}/inventory", viewer(adminH.getHostInventory))
	mux.Handle("GET /api/v1/commands", viewer(adminH.listCommands))
	// 接入新主机部署引导（adminOnly + 审计，见 api/deploy.go）
	mux.Handle("GET /api/v1/deploy/enroll-config", adminOnly(adminH.deployEnrollConfig))
	mux.Handle("GET /api/v1/deploy/agent-package", adminOnly(adminH.deployAgentPackage))

	mux.Handle("GET /api/v1/rules", viewer(adminH.listRules))
	mux.Handle("GET /api/v1/rules/schema", viewer(adminH.ruleSchema))
	mux.Handle("POST /api/v1/rules", writer(adminH.upsertRule))
	mux.Handle("POST /api/v1/rules/{id}/toggle", writer(adminH.toggleRule))
	mux.Handle("POST /api/v1/rules/{id}/mode", writer(adminH.setRuleMode))
	mux.Handle("DELETE /api/v1/rules/{id}", adminOnly(adminH.deleteRule))

	mux.Handle("GET /api/v1/allowlist", viewer(adminH.listAllowlist))
	mux.Handle("POST /api/v1/allowlist", writer(adminH.addAllowlist))
	mux.Handle("DELETE /api/v1/allowlist/{id}", writer(adminH.deleteAllowlist))
	mux.Handle("GET /api/v1/allowlist/export", adminOnly(adminH.exportAllowlist))
	mux.Handle("POST /api/v1/allowlist/import", adminOnly(adminH.importAllowlist))

	// 威胁指标库：查看所有角色可读；增删需要写权限
	mux.Handle("GET /api/v1/iocs", viewer(adminH.listIOCs))
	mux.Handle("POST /api/v1/iocs", writer(adminH.addIOC))
	mux.Handle("DELETE /api/v1/iocs/{id}", writer(adminH.deleteIOC))

	mux.Handle("GET /api/v1/incidents", viewer(adminH.listIncidents))
	mux.Handle("POST /api/v1/incidents/{id}/status", writer(adminH.transitionIncident))
	// 事件级 AI 检测（跨告警攻击链叙事）：与单告警研判同口径，viewer 可触发
	mux.Handle("POST /api/v1/incidents/{id}/narrate", viewer(adminH.narrateIncident))
	mux.Handle("GET /api/v1/incidents/{id}/narrative", viewer(adminH.getIncidentNarrative))
	mux.Handle("GET /api/v1/hosts/{id}/changes", viewer(adminH.getHostChanges))
	mux.Handle("POST /api/v1/alerts/{id}/investigate", viewer(adminH.investigateAlert))
	// Agentic 调查 v2：模型调用只读工具自主调查（未配置模型自动回退确定性五步）
	mux.Handle("POST /api/v1/alerts/{id}/investigate/agent", viewer(adminH.agentInvestigate))
	mux.Handle("GET /api/v1/alerts/{id}/agent-investigation", viewer(adminH.getAgentInvestigation))
	// 实时查询（只读调查面）：ping 是探活所以 viewer 可用；
	// 其余走 analyst+（writer 包装）——文件浏览/进程/连接的实时面
	// 比静态告警敏感，viewer 不放开
	mux.Handle("GET /api/v1/hosts/{id}/live/ping", viewer(adminH.livePing))
	mux.Handle("GET /api/v1/hosts/{id}/live/{rest...}", writer(adminH.liveQuery))
	mux.Handle("GET /api/v1/report/weekly", viewer(adminH.weeklyReport))
	mux.Handle("GET /api/v1/integrity", viewer(adminH.integrityReport))
	mux.Handle("GET /api/v1/attack/matrix", viewer(adminH.attackMatrix))
	mux.Handle("GET /api/v1/alerts/export", viewer(adminH.exportCSV))
	mux.HandleFunc("GET /metrics", adminH.metrics)

	mux.Handle("GET /api/v1/audit", viewer(adminH.listAudit))
	mux.Handle("GET /api/v1/users", adminOnly(adminH.listUsers))
	mux.Handle("POST /api/v1/users", adminOnly(adminH.createUser))

	// SSE：EventSource 无法带 Authorization 头，改用一次性短时效票据
	mux.Handle("POST /api/v1/stream/ticket", viewer(adminH.issueStreamTicket))
	mux.HandleFunc("GET /api/v1/stream/alerts", adminH.streamAlerts)

	// ---------------- MCP 对外端点（独立 Token，只读） ----------------
	if d.MCP != nil {
		mux.HandleFunc("POST /mcp", mcpPost(d))
		mux.HandleFunc("GET /mcp/skill.md", mcpSkill(d))
	}

	// ---------------- 管理台静态资源 ----------------
	if d.WebFS != nil {
		mux.Handle("GET /", spaHandler(d.WebFS))
	}
	// 中间件顺序（由外到内）：
	// request-id → 安全头 → 恢复 → 访问日志 → CORS → 限流 → 路由
	limiter := httpx.NewTokenBucket(d.RateRPS, d.RateBurst)
	skipLog := func(r *http.Request) bool {
		return r.URL.Path == "/health" || r.URL.Path == "/ready"
	}

	h := httpx.Chain(mux,
		httpx.RequestIDMiddleware,
		httpx.SecurityHeaders,
		httpx.RecoverMiddleware(d.Log),
		httpx.AccessLogMiddleware(d.Log, skipLog),
		httpx.CORS(d.AllowOrigins, true),
		httpx.RateLimitMiddleware(limiter, func(r *http.Request) string {
			return httpx.ClientIP(r)
		}),
	)
	return h
}

// spaHandler 提供单页应用：找不到具体文件时回落到 index.html。
func spaHandler(webFS fs.FS) http.Handler {
	fileServer := http.FileServer(http.FS(webFS))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clean := strings.TrimPrefix(r.URL.Path, "/")
		if clean == "" {
			clean = "index.html"
		}
		if f, err := webFS.Open(clean); err == nil {
			_ = f.Close()
			// 静态资源缓存：index.html 不缓存，带 hash 的资源长缓存
			if clean == "index.html" {
				w.Header().Set("Cache-Control", "no-cache")
			} else {
				w.Header().Set("Cache-Control", "public, max-age=3600")
			}
			fileServer.ServeHTTP(w, r)
			return
		}
		// 未知路径统一返回 index.html（前端路由接管）
		idx, err := webFS.Open("index.html")
		if err != nil {
			http.NotFound(w, r)
			return
		}
		defer idx.Close()
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache")
		_, _ = io.Copy(w, idx)
	})
}

// ---------------------------------------------------------------- 鉴权中间件

// agentAuthMiddleware 校验终端凭证。
//
// 采用 API-Key 模式：数据库只保存密钥的 SHA-256 摘要，终端每次请求携带
// `X-Agent-Id` + `Authorization: Bearer <agent_secret>`。这样即便数据库泄露，
// 也无法直接冒用终端身份（对比 HMAC 方案需要服务端持有明文密钥）。
func agentAuthMiddleware(d Deps, next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		agentID := r.Header.Get("X-Agent-Id")
		secret := bearerToken(r)
		if agentID == "" || secret == "" {
			httpx.WriteError(w, r, apperr.Unauthenticated("缺少终端身份凭证"))
			return
		}

		agent, err := d.Services.Agent.Authenticate(r.Context(), agentID)
		if err != nil {
			httpx.WriteError(w, r, err)
			return
		}
		if err := d.Services.Agent.CheckSecret(agent, secret); err != nil {
			d.Log.WarnContext(r.Context(), "agent_auth_rejected",
				"agent_id", agentID, "ip", httpx.ClientIP(r))
			httpx.WriteError(w, r, err)
			return
		}

		ctx := withAgent(r.Context(), agent)
		next(w, r.WithContext(ctx))
	})
}

// jwtMiddleware 校验访问令牌并做角色检查。
func jwtMiddleware(d Deps, roles []string, next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw := bearerToken(r)
		if raw == "" {
			httpx.WriteError(w, r, apperr.Unauthenticated("缺少访问令牌"))
			return
		}
		claims, err := d.Tokens.ParseAccess(raw)
		if err != nil {
			httpx.WriteError(w, r, err)
			return
		}
		// 令牌有效不代表账号可用：禁用/删除要立刻生效
		u, err := d.Services.Auth.Me(r.Context(), claims.UserID)
		if err != nil || u == nil || u.Disabled {
			httpx.WriteError(w, r, apperr.Unauthenticated("账号不可用，请重新登录"))
			return
		}

		p := &auth.Principal{UserID: u.ID, Username: u.Username, Role: u.Role}
		if len(roles) > 0 {
			allowed := false
			for _, role := range roles {
				if string(u.Role) == role {
					allowed = true
					break
				}
			}
			if !allowed {
				httpx.WriteError(w, r, apperr.Forbidden(""))
				return
			}
		}
		next(w, r.WithContext(auth.WithPrincipal(r.Context(), p)))
	})
}

func bearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if h == "" {
		return ""
	}
	parts := strings.SplitN(h, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return ""
	}
	return strings.TrimSpace(parts[1])
}
