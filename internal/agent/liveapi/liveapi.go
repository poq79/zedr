// Package liveapi 提供实时隧道内的只读调查接口（LiveFS，
// 路径/字段/上限契约见 docs/LIVE-TUNNEL.md §5.2）。
//
// 安全模型：本包的 mux 不监听任何端口，只挂载在探针反连隧道（yamux 流）
// 上——能到达这里的连接物理上只有探针自己拨出的那条，因此不做每请求
// 鉴权（身份信任在隧道握手时一次性完成）。只读铁律靠两层保证：
//  1. 只注册 GET handler，无任何写语义端点；
//  2. FSys 抽象只暴露 List/Stat/Open 三个读操作，OSFS 底层用 os.Open（只读）。
//
// 本包由 W2 波次接线：app.Agent 组装 Deps 后把 New(d) 的返回值交给隧道
// http.Server；本包自身不拉起任何 goroutine、不持有任何监听面。
package liveapi

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"strconv"
	"time"

	"zedr/internal/agent/state"
	"zedr/internal/agent/winapi"
	"zedr/internal/livecatalog"
	"zedr/internal/model"
	"zedr/internal/platform/apperr"
	"zedr/internal/platform/httpx"
)

// Deps 是 liveapi 的构造依赖，由 app.Agent 在接线时拼装（见包注释）。
// 全部为值/函数字段，无锁无原子，按值传递安全。
type Deps struct {
	Version   string
	Hostname  string
	StartTime time.Time

	// Procs 返回实时进程表（通常包一层 state.Store.Procs）；nil 表示未接线，
	// /processes 返回 501，/netstat 的富化随之降级（proc_name/proc_path 留空）。
	Procs func(limit int) []state.ProcRow

	// Netstat 返回带 PID 的连接表（winapi.GetNetstat 的直通引用）；nil → 501。
	Netstat func() []winapi.NetRow

	// FS 文件系统抽象；nil 时用 OSFS（单测注入内存/桩实现）。
	FS FSys

	// ---- v2（契约 §11.1/§11.2）：三个新依赖全部 nil-able，向后兼容 ----

	// Modules 返回指定进程的模块列表（collector.Modules 直通引用，按需
	// 高成本接口）；nil 时 /procinfo 省略 modules/unsigned_module_count
	// 块，端点其余功能照常。
	Modules func(pid uint32) []model.ModuleInfo

	// Snapshot 返回采集层进程快照（通常包一层 state.Store.Procs(2000)）；
	// nil 时退回用 Procs(procMax)。/netstat 与 /procinfo 的富化共用。
	Snapshot func() []state.ProcRow

	// Runtime 返回探针运行时状态（state.Store.Runtime 直通引用）；nil →
	// /info 返回 501。
	Runtime func() state.RuntimeInfo
}

// 各端点参数上限（契约 §5.2"双侧钳制"的探针侧；中心代理侧还有一道）。
const (
	fsListMax     = 500
	fsListDefault = 200

	fsReadMax     = 512 << 10 // 512KB
	fsReadDefault = 64 << 10  // 64KB

	procMax     = 2000
	procDefault = 300

	hashMaxBytes = 2 << 30   // 2GB，/fs/hash 上限
	hashBufSize  = 256 << 10 // 流式哈希缓冲
	sniffLen     = 512       // http.DetectContentType 规定的嗅探窗口
)

// server 持有依赖的 handler 集合。
type server struct {
	d Deps
}

// New 构建只读调查 mux，返回的 http.Handler 直接交给隧道的 http.Server
// （Go 1.27 方法+路径 pattern 路由，风格与 localapi 一致）。
//
// 路由由 livecatalog 驱动构建（单一事实源，2026-11-09 起）：catalog 里的
// 每个端点必须有对应 handler，反之 handler 必须登记进 catalog——任何一侧
// 漂移在探针启动时立即 panic（宁可起不来也不能静默 404/漏注册）。
func New(d Deps) http.Handler {
	if d.FS == nil {
		d.FS = OSFS{}
	}
	s := &server{d: d}
	// handlers 显式登记：key 必须 == livecatalog.Endpoint.Name。
	// baseline/accounts/persistence 三个是包级构造函数（不依赖 Deps），
	// 其余是 *server 方法。
	handlers := map[string]http.HandlerFunc{
		"ping":         s.handlePing,
		"info":         s.handleInfo,
		"_catalog":     s.handleCatalog,
		"fs":           s.handleFSList,
		"fs/stat":      s.handleFSStat,
		"fs/read":      s.handleFSRead,
		"fs/hash":      s.handleFSHash,
		"fs/search":    s.handleFSSearch,
		"fs/grep":      s.handleFSGrep,
		"ads":          s.handleADS,
		"analyze":      s.handleAnalyze,
		"collect":      s.handleCollect,
		"processes":    s.handleProcesses,
		"procinfo":     s.handleProcInfo,
		"handles":      s.handleHandles,
		"handleowners": s.handleHandleOwners,
		"threads":      s.handleThreads,
		"memscan":      s.handleMemScan,
		"netstat":      s.handleNetstat,
		"peers":        s.handlePeers,
		"netinfo":      s.handleNetinfo,
		"registry":     s.handleRegistry,
		"evtlog":       s.handleEvtLog,
		"tasks":        s.handleTasks,
		"services":     s.handleServices,
		"drivers":      s.handleDrivers,
		"sessions":     s.handleSessions,
		"usn":          s.handleUSN,
		"baseline":     HandleBaseline(),
		"accounts":     HandleAccounts(),
		"persistence":  HandlePersistence(),
		"recon":        s.handleRecon,
	}
	mux := http.NewServeMux()
	for _, ep := range livecatalog.All() {
		h, ok := handlers[ep.Name]
		if !ok {
			panic(fmt.Sprintf("liveapi: catalog 端点 %q 没有对应 handler（实现与注册表漂移）", ep.Name))
		}
		mux.HandleFunc("GET /"+ep.Name, h)
		delete(handlers, ep.Name)
	}
	if len(handlers) > 0 {
		names := make([]string, 0, len(handlers))
		for n := range handlers {
			names = append(names, n)
		}
		sort.Strings(names)
		panic(fmt.Sprintf("liveapi: handler 未登记进 livecatalog（AI/服务端看不见这些端点）: %v", names))
	}
	return recoverWrap(mux)
}

// handleCatalog 是能力清单自描述端点（livecatalog 的运行时投影）：
// AI/服务端按主机版本拿参数契约——老版本探针的 catalog 自然少端点，
// 调用方据此做能力探测而不是猜端点存不存在。
func (s *server) handleCatalog(w http.ResponseWriter, r *http.Request) {
	httpx.WriteJSON(w, r, http.StatusOK, map[string]any{
		"agent_version": s.d.Version,
		"hostname":      s.d.Hostname,
		"generated_at":  time.Now().Unix(),
		"endpoints":     livecatalog.All(),
	})
}

func (s *server) handlePing(w http.ResponseWriter, r *http.Request) {
	httpx.WriteJSON(w, r, http.StatusOK, map[string]any{
		"ok":         true,
		"version":    s.d.Version,
		"uptime_sec": int64(time.Since(s.d.StartTime).Seconds()),
		"hostname":   s.d.Hostname,
	})
}

// errNotImplemented：能力存在但未接线（Deps 函数为 nil）。用 501 而非 404，
// 让中心端/前端能区分"端点不存在"与"探针未启用该能力"。
func errNotImplemented(what string) error {
	return &apperr.Error{
		Code:    apperr.Code("not_implemented"),
		Message: what + " 未在此探针启用",
		Status:  http.StatusNotImplemented,
	}
}

func (s *server) handleProcesses(w http.ResponseWriter, r *http.Request) {
	if s.d.Procs == nil {
		httpx.WriteError(w, r, errNotImplemented("进程表"))
		return
	}
	limit := queryInt(r, "limit", procDefault, 1, procMax)
	httpx.WriteJSON(w, r, http.StatusOK, map[string]any{
		"items": s.d.Procs(limit),
	})
}

// snapshotRows 取当前进程快照：优先 Snapshot（全量口径），未接线时退回
// Procs(procMax)，两者都 nil 才返回 nil。/netstat 与 /procinfo 共用。
func (s *server) snapshotRows() []state.ProcRow {
	if s.d.Snapshot != nil {
		return s.d.Snapshot()
	}
	if s.d.Procs != nil {
		return s.d.Procs(procMax)
	}
	return nil
}

// queryInt 解析整数 query 参数：缺省/非法回退 def，并钳制到 [min,max]。
func queryInt(r *http.Request, key string, def, min, max int) int {
	raw := r.URL.Query().Get(key)
	if raw == "" {
		return def
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		return def
	}
	if n < min {
		return min
	}
	if n > max {
		return max
	}
	return n
}

// queryInt64 同 queryInt，用于 offset/limit 这类可能超出 int 的值；
// n<=0 回退 def（offset 的 def 恒为 0，显式传 0 结果相同）。
func queryInt64(r *http.Request, key string, def, max int64) int64 {
	raw := r.URL.Query().Get(key)
	if raw == "" {
		return def
	}
	n, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || n <= 0 {
		return def
	}
	if n > max {
		return max
	}
	return n
}

// recoverWrap 兜底 panic → 规范 500。不接住的话 panic 会拆掉整条隧道流
// （而不只是本请求），前端的表象是"隧道闪断"且服务端难以归因。
func recoverWrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				slog.Error("liveapi_panic_recovered", "panic", fmt.Sprint(rec), "path", r.URL.Path)
				httpx.WriteError(w, r, apperr.Internal(errors.New(fmt.Sprint(rec))))
			}
		}()
		next.ServeHTTP(w, r)
	})
}
