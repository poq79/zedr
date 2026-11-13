//go:build windows
// +build windows

// Package localapi 为桌面 UI 提供本机只读（含少量本地处置）HTTP 接口。
//
// 安全模型：仅绑定回环地址 + 拒绝带 Origin 的跨站请求（防止网页脚本
// 通过浏览器访问本地端口）。因此不需要额外令牌，也不会与后台管理台混淆。
package localapi

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"

	"zedr/internal/agent/allow"
	"zedr/internal/agent/hygiene"
	"zedr/internal/agent/persist"
	"zedr/internal/agent/quarantine"
	"zedr/internal/agent/state"
	"zedr/internal/platform/apperr"
	"zedr/internal/platform/httpx"
)

// Backend 是本地 API 依赖的能力集合（由 agent 实现）。
type Backend interface {
	Runtime() state.RuntimeInfo
	Procs(limit int) []state.ProcRow
	Alerts(limit int) []*state.Alert
	AlertByID(id string) *state.Alert
	Rescan()
	AllowHash(hash, note string) error
	AllowPath(path, note string) error
	Allowlist() []allow.Entry
	RemoveAllow(typ, value string) error
	WhitelistSize() map[string]int
	// PersistItems 返回持久化基线（自启动）全部条目；供桌面端"驻留"视图。
	PersistItems() []persist.Item
	// QuarantineEntries 返回隔离区当前记录；处置能力默认关闭，多数时候为空。
	QuarantineEntries() []quarantine.Entry

	// ---- 泛安全体检（按需采集，全部只读；见 internal/agent/hygiene）----

	// Apps 返回已安装软件清单（Win32 卸载表 + Store 应用）。
	Apps() []hygiene.InstalledApp
	// Posture 返回安全配置姿势体检（UAC/RDP/SMBv1/补丁/隐私设置等）。
	Posture() []hygiene.Check
	// Exposure 返回网络暴露面（监听端点归属 + hosts + 系统代理）。
	Exposure() hygiene.ExposureReport
	// BrowserAudit 返回浏览器扩展清单与策略劫持面。
	BrowserAudit() hygiene.BrowserReport
	// PersistAudit 返回自启动项现场画像（签名/文件缺失/基线外）。
	PersistAudit() []hygiene.PersistAudit
}

// Deps 是构造参数。
type Deps struct {
	Backend Backend
	Log     *slog.Logger
	Addr    string
	// Token 是本地接口的访问令牌；为空表示不做令牌校验（仅保留 Origin 防护）。
	Token string
}

// Server 是本地 API 服务。
type Server struct {
	deps Deps
	srv  *httpx.Server
}

// New 创建服务。
func New(d Deps) *Server {
	return &Server{deps: d}
}

// Start 启动监听。
func (s *Server) Start() error {
	handler := s.routes()
	srv := httpx.NewServer(httpx.ServerConfig{
		Addr:    s.deps.Addr,
		Handler: handler,
		Logger:  s.deps.Log,
	})
	if err := srv.Listen(); err != nil {
		return err
	}
	s.srv = srv
	go func() {
		if err := srv.Serve(); err != nil && s.deps.Log != nil {
			s.deps.Log.Error("local_api_stopped", "err", err)
		}
	}()
	if s.deps.Log != nil {
		s.deps.Log.Info("local_api_listening", "addr", srv.Addr())
	}
	return nil
}

// Addr 返回实际监听地址。
func (s *Server) Addr() string {
	if s.srv == nil {
		return ""
	}
	return s.srv.Addr()
}

// Shutdown 优雅停机。
func (s *Server) Shutdown(ctx context.Context) error {
	if s.srv == nil {
		return nil
	}
	return s.srv.Shutdown(ctx)
}

func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()

	// api 给需要保护的接口统一套上访问控制。
	// 集中在一个地方注册，避免以后新增接口时忘记加防护——
	// 这类"漏掉一个就全盘失效"的保护，靠人记是记不住的。
	api := func(pattern string, h http.HandlerFunc) {
		mux.Handle(pattern, s.guard(h))
	}

	// /health 放行：桌面端与运维探活需要在没有令牌时也能判断进程是否活着
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		httpx.WriteRaw(w, r, http.StatusOK, map[string]any{"status": "ok"})
	})

	api("GET /api/local/status", func(w http.ResponseWriter, r *http.Request) {
		httpx.WriteJSON(w, r, http.StatusOK, s.deps.Backend.Runtime())
	})

	// 隐私透明端点：被装机器的用户有权一键知道"这个软件采集我什么、
	// 不采集什么、怎么脱敏"。知情权是安全产品与间谍软件的分界线。
	api("GET /api/local/privacy", func(w http.ResponseWriter, r *http.Request) {
		httpx.WriteJSON(w, r, http.StatusOK, map[string]any{
			"collected": []map[string]string{
				{"item": "进程清单", "detail": "进程名、路径、命令行、启动账号、PID/PPID 血缘"},
				{"item": "文件指纹", "detail": "可执行文件的 SHA256 哈希与数字签名状态（不上传文件内容）"},
				{"item": "网络连接", "detail": "进程的 TCP 连接远端地址（不抓包、不记录流量内容）"},
				{"item": "加载模块", "detail": "进程加载的 DLL 列表（仅路径）"},
				{"item": "自启动项", "detail": "注册表 Run/计划任务/服务等配置项的名称与命令"},
				{"item": "管理端实时查询", "detail": "安全管理员可经服务端实时查看本机进程/连接/文件目录；文件内容预览需现场显式开启且逐次留审计（谁在何时查了什么）"},
			},
			"not_collected": []string{
				"屏幕内容 / 键盘输入 / 剪贴板",
				"文档、图片等个人文件的内容",
				"浏览器历史、Cookie、密码",
				"网络流量的具体内容（仅记录连接元数据）",
			},
			"redaction": "命令行中的密码/令牌类参数（--password= 等 8 类）在离开本机前会被替换为占位符",
			"storage":   "告警与证据仅存于本机数据目录与你的总控服务端，无任何第三方上传通道",
		})
	})

	api("GET /api/local/processes", func(w http.ResponseWriter, r *http.Request) {
		limit := intParam(r, "limit", 300)
		httpx.WriteJSON(w, r, http.StatusOK, map[string]any{
			"items": s.deps.Backend.Procs(limit),
		})
	})

	api("GET /api/local/alerts", func(w http.ResponseWriter, r *http.Request) {
		limit := intParam(r, "limit", 200)
		httpx.WriteJSON(w, r, http.StatusOK, map[string]any{
			"items": s.deps.Backend.Alerts(limit),
		})
	})

	api("GET /api/local/alerts/{id}", func(w http.ResponseWriter, r *http.Request) {
		a := s.deps.Backend.AlertByID(r.PathValue("id"))
		if a == nil {
			httpx.WriteError(w, r, apperr.NotFound("告警"))
			return
		}
		httpx.WriteJSON(w, r, http.StatusOK, a)
	})

	api("GET /api/local/allowlist", func(w http.ResponseWriter, r *http.Request) {
		httpx.WriteJSON(w, r, http.StatusOK, map[string]any{
			"items": s.deps.Backend.Allowlist(),
			"size":  s.deps.Backend.WhitelistSize(),
		})
	})

	api("POST /api/local/allowlist", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Type  string `json:"type"`
			Value string `json:"value"`
			Note  string `json:"note"`
		}
		if err := httpx.DecodeJSON(r, &req); err != nil {
			httpx.WriteError(w, r, err)
			return
		}
		var err error
		switch req.Type {
		case allow.TypeHash:
			err = s.deps.Backend.AllowHash(req.Value, req.Note)
		case allow.TypePath:
			err = s.deps.Backend.AllowPath(req.Value, req.Note)
		default:
			err = apperr.Invalid("本地仅支持 hash / path 两种白名单类型")
		}
		if err != nil {
			httpx.WriteError(w, r, apperr.Invalid("%s", err.Error()))
			return
		}
		httpx.WriteNoContent(w)
	})

	api("DELETE /api/local/allowlist", func(w http.ResponseWriter, r *http.Request) {
		typ := r.URL.Query().Get("type")
		value := r.URL.Query().Get("value")
		if err := s.deps.Backend.RemoveAllow(typ, value); err != nil {
			httpx.WriteError(w, r, apperr.NotFound("白名单项"))
			return
		}
		httpx.WriteNoContent(w)
	})

	api("POST /api/local/rescan", func(w http.ResponseWriter, r *http.Request) {
		s.deps.Backend.Rescan()
		httpx.WriteNoContent(w)
	})

	// 驻留视图：持久化基线（7 类自启动位置）全部条目。
	// 只读快照（内存 map 拷贝），成本与条目数线性；桌面端 15s 轮询可承受。
	api("GET /api/local/persist", func(w http.ResponseWriter, r *http.Request) {
		httpx.WriteJSON(w, r, http.StatusOK, map[string]any{
			"items": s.deps.Backend.PersistItems(),
		})
	})

	// 隔离区当前记录。terminate/quarantine 双层开关默认关闭，
	// 这里多数时候是空列表——空是正常态，不是错误。
	api("GET /api/local/quarantine", func(w http.ResponseWriter, r *http.Request) {
		httpx.WriteJSON(w, r, http.StatusOK, map[string]any{
			"items": s.deps.Backend.QuarantineEntries(),
		})
	})

	// ---- 泛安全体检：按需采集（打开对应视图才调用），全部只读 ----

	api("GET /api/local/apps", func(w http.ResponseWriter, r *http.Request) {
		httpx.WriteJSON(w, r, http.StatusOK, map[string]any{
			"items": s.deps.Backend.Apps(),
		})
	})

	api("GET /api/local/posture", func(w http.ResponseWriter, r *http.Request) {
		httpx.WriteJSON(w, r, http.StatusOK, map[string]any{
			"checks": s.deps.Backend.Posture(),
		})
	})

	api("GET /api/local/exposure", func(w http.ResponseWriter, r *http.Request) {
		httpx.WriteJSON(w, r, http.StatusOK, s.deps.Backend.Exposure())
	})

	api("GET /api/local/browser", func(w http.ResponseWriter, r *http.Request) {
		httpx.WriteJSON(w, r, http.StatusOK, s.deps.Backend.BrowserAudit())
	})

	// 自启动项现场画像（与 /api/local/persist 的基线快照互补）。
	// 首次调用要逐文件验签，可能花一两秒——这是 Autoruns 的固有成本，
	// Agent 侧有 (path,size,mtime) 缓存，二次打开近零成本。
	api("GET /api/local/persist/audit", func(w http.ResponseWriter, r *http.Request) {
		httpx.WriteJSON(w, r, http.StatusOK, map[string]any{
			"items": s.deps.Backend.PersistAudit(),
		})
	})

	if fsys := FS(); fsys != nil {
		mux.Handle("GET /", http.FileServer(http.FS(fsys)))
	}

	return httpx.Chain(mux,
		httpx.RequestIDMiddleware,
		httpx.RecoverMiddleware(s.deps.Log),
		loopbackOnly,
		sameOriginOnly,
		httpx.SecurityHeaders,
	)
}

// loopbackOnly 只允许来自本机的请求。
func loopbackOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			host = r.RemoteAddr
		}
		if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// sameOriginOnly 拒绝浏览器跨站发起的请求（带 Origin 且与监听地址不符）。
func sameOriginOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if origin := r.Header.Get("Origin"); origin != "" {
			host := r.Host
			if !strings.Contains(origin, "://"+host) {
				http.Error(w, "cross-origin forbidden", http.StatusForbidden)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func intParam(r *http.Request, key string, def int) int {
	raw := r.URL.Query().Get(key)
	if raw == "" {
		return def
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n <= 0 {
		return def
	}
	if n > 2000 {
		return 2000
	}
	return n
}
