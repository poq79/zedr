package service

// LiveQueryService：实时查询隧道代理的业务核心——白名单、超时预算、
// 双层子开关、审计的唯一事实源。两个消费方：
//   - api/live.go（管理台 JWT 面，RBAC 由路由包装保证）；
//   - MCP host_live 工具（AI 调查面，独立 Bearer Token）。
// 两面共用同一张预算表与同一条审计路径，杜绝"AI 面绕过执法点"。
//
// 2026-11-09 从 api/live.go 迁入：原实现把转发核心写在 api 层，
// MCP 要复用时只剩"复制一份"一条路——两份白名单必然漂移，故按分层
// 纪律（控制器不写业务）上收服务层。

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"zedr/internal/platform/apperr"
	"zedr/internal/platform/logx"
	"zedr/internal/platform/redact"
	"zedr/internal/server/livetunnel"
)

// LiveEndpoint 描述一个隧道内只读端点的转发预算与开关要求。
type LiveEndpoint struct {
	Timeout  time.Duration
	FileRead bool // 需要 HG_SERVER_LIVEQUERY_FILEREAD 子开关把门（内容预览）
	Collect  bool // 需要 HG_SERVER_LIVEQUERY_COLLECT 子开关把门（取证打包）
}

// LiveEndpoints 白名单预算表（原 api/live.go 口径 + 2026-11-09 调查面
// 扩展九端点）。fs/hash 与 analyze 要扫全文件所以最长；fs/search、
// evtlog、usn 探针侧自带 15s 内部预算，代理放宽让 truncated 语义有机会
// 送达而不是被代理先掐；collect 是 128MB zip 流式传输给 120s。
// 只读：消费方不得修改本表。
var LiveEndpoints = map[string]LiveEndpoint{
	"ping":      {Timeout: 5 * time.Second},
	"fs":        {Timeout: 15 * time.Second},
	"fs/stat":   {Timeout: 10 * time.Second},
	"fs/read":   {Timeout: 20 * time.Second, FileRead: true},
	"fs/hash":   {Timeout: 30 * time.Second},
	"processes": {Timeout: 10 * time.Second},
	"netstat":   {Timeout: 10 * time.Second},
	"analyze":   {Timeout: 30 * time.Second},
	"ads":       {Timeout: 10 * time.Second},
	"fs/search": {Timeout: 35 * time.Second},
	"procinfo":  {Timeout: 10 * time.Second},
	"info":      {Timeout: 5 * time.Second},
	// recon 含回环探测（40 次 × 2s 上限 + 30s 内部预算），代理给 40s：
	// 比探针内部预算宽，保证探针的 truncated 语义能送达而不是被代理先掐
	"recon":    {Timeout: 40 * time.Second},
	"baseline": {Timeout: 10 * time.Second},
	"accounts": {Timeout: 10 * time.Second},
	// 进程取证：句柄/线程枚举是内存级操作给 5s；占用者扫描与内存区域
	// 遍历更重（全系统句柄 + VirtualQueryEx 循环）给 10s，探针侧仍自带
	// 5s/2s 内部预算，超时返回 truncated
	"handles":      {Timeout: 5 * time.Second},
	"handleowners": {Timeout: 10 * time.Second},
	"threads":      {Timeout: 5 * time.Second},
	"memscan":      {Timeout: 10 * time.Second},
	// 持久化总览聚合三套枚举（服务+任务XML+启动项），15s 留足余量；
	// 外联对端是 Netstat 纯聚合，5s 足够
	"persistence": {Timeout: 15 * time.Second},
	"peers":       {Timeout: 5 * time.Second},

	// ---- 2026-11-09 调查面扩展（AI 取证对接基座）----
	// evtlog/usn 探针侧 15s 内部预算，代理给 20s 保 truncated 语义；
	// drivers 默认不验签 <1s，verify=1 实测 50 驱动 5.7s 给 15s；
	// tasks 实测 186 任务 0.5s、services 238 条 0.2s，均给足余量
	"registry": {Timeout: 10 * time.Second},
	"evtlog":   {Timeout: 20 * time.Second},
	"tasks":    {Timeout: 15 * time.Second},
	"services": {Timeout: 10 * time.Second},
	"drivers":  {Timeout: 15 * time.Second},
	"sessions": {Timeout: 10 * time.Second},
	"netinfo":  {Timeout: 10 * time.Second},
	"usn":      {Timeout: 20 * time.Second},
	// 取证打包：128MB zip 流式 + 探针 110s 软预算，代理给 120s；
	// Collect 子开关默认关（信息暴露面最大的端点，对齐 fs/read 纪律）
	"collect": {Timeout: 120 * time.Second, Collect: true},
}

// errTunnelNotConnected 是前端据以渲染"隧道未连接"状态条的错误码。
// 探针离线、老版本探针、主机 ID 不存在三种情况都归入此码：
// 对操作员而言行动指引相同（检查探针在线状态/版本）。
func errTunnelNotConnected(msg string) *apperr.Error {
	return &apperr.Error{
		Code:    apperr.Code("tunnel_not_connected"),
		Message: msg,
		Status:  http.StatusServiceUnavailable,
		Public:  true, // 状态描述即行动指引，不属于需要脱敏的内部错误
	}
}

// LiveTunnelClient 是隧道会话的最小接口（livetunnel.Client 的子集）。
type LiveTunnelClient interface {
	Acquire(ctx context.Context) error
	Release()
	HTTP() *http.Client
}

// LiveTunnelRegistry 按主机 ID 寻址隧道会话。
type LiveTunnelRegistry interface {
	Get(agentID string) (LiveTunnelClient, bool)
}

// tunnelAdapter 适配 *livetunnel.Registry：Get 返回具体类型无法直接
// 满足返回接口类型的 Go 接口规则，包一层做协变。
type tunnelAdapter struct{ r *livetunnel.Registry }

func (a tunnelAdapter) Get(agentID string) (LiveTunnelClient, bool) {
	c, ok := a.r.Get(agentID)
	if !ok || c == nil {
		return nil, false
	}
	return c, true
}

// LiveQueryService 实时查询业务核心（见文件头注释）。
type LiveQueryService struct {
	Tunnel   LiveTunnelRegistry
	Enabled  bool // HG_SERVER_LIVEQUERY_ENABLED 总开关
	FileRead bool // HG_SERVER_LIVEQUERY_FILEREAD 内容预览子开关
	Collect  bool // HG_SERVER_LIVEQUERY_COLLECT 取证打包子开关
	Audit    *AuditService
}

// NewLiveQueryService 组装服务；registry 为 nil（总开关关闭）时仅登记
// 开关状态，所有 Open 调用按未启用拒绝。
func NewLiveQueryService(registry *livetunnel.Registry, enabled, fileRead, collect bool, audit *AuditService) *LiveQueryService {
	s := &LiveQueryService{Enabled: enabled, FileRead: fileRead, Collect: collect, Audit: audit}
	if registry != nil {
		s.Tunnel = tunnelAdapter{r: registry}
	}
	return s
}

// LiveConn 是一次实时查询的响应连接：api 层负责头透传与流式拷贝，
// MCP 侧负责按上限读全——Body 的消费方式由调用方决定。
type LiveConn struct {
	Status int
	Header http.Header
	Body   io.ReadCloser
}

// Close 释放响应体（幂等）。
func (c *LiveConn) Close() error {
	if c.Body == nil {
		return nil
	}
	return c.Body.Close()
}

// Open 执行一次白名单内的实时查询：开关校验 → 白名单校验 → 隧道寻址
// → 并发闸 → 超时预算 → 审计（成功与失败都记）。operator 身份随
// X-ZEDR-Operator 头透传给探针侧审计（"谁在查"跟着请求走）。
func (s *LiveQueryService) Open(ctx context.Context, agentID, endpoint string, query url.Values, userID, operator, ip string) (*LiveConn, error) {
	if !s.Enabled {
		return nil, apperr.Forbidden("实时查询未启用（HG_SERVER_LIVEQUERY_ENABLED）")
	}
	ep, ok := LiveEndpoints[endpoint]
	if !ok {
		return nil, apperr.NotFound("实时查询端点")
	}
	// 内容出站类端点单独把门：这是该体系信息暴露面最大的两面，
	// 与处置类同纪律（默认关、现场显式开），不用总开关一并放过
	if ep.FileRead && !s.FileRead {
		return nil, apperr.Forbidden("文件内容预览未启用（HG_SERVER_LIVEQUERY_FILEREAD）")
	}
	if ep.Collect && !s.Collect {
		return nil, apperr.Forbidden("文件取证打包未启用（HG_SERVER_LIVEQUERY_COLLECT）")
	}
	if s.Tunnel == nil {
		return nil, errTunnelNotConnected("探针隧道未连接（探针离线或版本不支持实时查询）")
	}
	cli, ok := s.Tunnel.Get(agentID)
	if !ok {
		return nil, errTunnelNotConnected("探针隧道未连接（探针离线或版本不支持实时查询）")
	}
	// 超限立即拒绝而非排队：交互式操作排队只会让操作员以为界面卡死
	if err := cli.Acquire(ctx); err != nil {
		return nil, err
	}
	defer cli.Release()

	cctx, cancel := context.WithTimeout(ctx, ep.Timeout)
	defer cancel()

	// 隧道内 URL 的 host 段无意义（拨号恒指向本会话），约定 "http://tunnel/"
	treq, err := http.NewRequestWithContext(cctx, http.MethodGet,
		"http://tunnel/"+endpoint+"?"+query.Encode(), nil)
	if err != nil {
		return nil, apperr.Invalid("实时查询请求构造失败")
	}
	treq.Header.Set("X-ZEDR-Operator", operator)
	if rid := logx.RequestID(ctx); rid != "" {
		treq.Header.Set("X-ZEDR-Request-Id", rid)
	}

	started := time.Now()
	resp, err := cli.HTTP().Do(treq)
	ms := time.Since(started).Milliseconds()
	if err != nil {
		s.audit(ctx, userID, operator, agentID, fmt.Sprintf("%s transport_error %dms", endpoint, ms), ip)
		if cctx.Err() != nil {
			return nil, apperr.Unavailable(fmt.Sprintf("探针响应超时（预算 %s）", ep.Timeout))
		}
		return nil, errTunnelNotConnected("探针隧道已断开，请稍后重试")
	}

	// 审计口径与 sendCommand 一致：记"发生了什么"（端点+查询参数+结果+耗时）。
	// 带查询参数——事后能回答"当时看了哪个目录/注册表键"，追责链完整；
	// 路径类参数非敏感但可能很长，过 redact 截断。
	s.audit(ctx, userID, operator, agentID,
		fmt.Sprintf("%s %d %dms %s", endpoint, resp.StatusCode, ms, liveQueryDetail(query)), ip)

	return &LiveConn{Status: resp.StatusCode, Header: resp.Header, Body: resp.Body}, nil
}

func (s *LiveQueryService) audit(ctx context.Context, userID, operator, agentID, detail, ip string) {
	if s.Audit == nil {
		return // 单测注入最小依赖时不强求审计
	}
	s.Audit.Record(ctx, userID, operator, "host.live_query", agentID, detail, ip)
}

// liveQueryDetail 把查询参数整理成可读审计串（k=v 空格分隔，值过 redact）。
// 为什么不用 RawQuery 原文：URL 编码后的 C%3A%5C 在审计里不可读，
// 排查的人还要手动解码；逐值截断防超长路径撑爆 detail 字段。
func liveQueryDetail(q url.Values) string {
	keys := make([]string, 0, len(q))
	for k := range q {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for i, k := range keys {
		if i > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(redact.Path(q.Get(k)))
	}
	return b.String()
}
