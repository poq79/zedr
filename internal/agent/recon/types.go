// Package recon 实现资产侦查 v1（docs/LIVE-TUNNEL.md §12）：回答
// "这台机器上跑着什么资产、暴露成什么样"。
//
// 六类检测共用一份基础关联数据（进程表 + 端口表 join），各类 detector
// 只读本地系统事实；主动探测被独立的 probe 客户端收口，严格限制在
// 回环目标（127.0.0.1/::1）、GET only、2s 超时、≤64KB 读取、总次数 ≤40。
//
// 设计纪律：
//   - 单类失败不影响其他类：每类 detector 由 Run 包了 recover；
//   - 整体 30s 预算：超时返回已收集结果并置 truncated=true；
//   - 探测失败静默：资产仍以被动信息列出，auth_state/exposure 为 unknown；
//   - 不提交任何凭据：产品默认口令只作为文献级提示文本出现在 details。
package recon

import "encoding/json"

// 暴露等级（契约 §12.2/§12.4；unknown 表示"探测未能判定"，不冒充安全）。
const (
	LevelInfo     = "info"
	LevelLow      = "low"
	LevelMedium   = "medium"
	LevelHigh     = "high"
	LevelCritical = "critical"
	LevelUnknown  = "unknown"
)

// 认证状态（契约 §12.3 ai 类口径）。
const (
	AuthOpen     = "open"
	AuthRequired = "auth_required"
	AuthUnknown  = "unknown"
)

// 六类固定顺序：前端分组按此顺序渲染，探测结果也按此顺序返回。
var categoryOrder = []struct {
	Key   string
	Title string
}{
	{"web", "Web 服务"},
	{"ai", "AI Agent Harness"},
	{"db", "数据库与中间件"},
	{"remote", "远程管理面"},
	{"dev", "开发自动化"},
	{"virt", "容器与虚拟化"},
}

// Categories 返回全部类目 key（顺序稳定）。
func Categories() []string {
	out := make([]string, 0, len(categoryOrder))
	for _, c := range categoryOrder {
		out = append(out, c.Key)
	}
	return out
}

// CategoryTitle 返回类目展示名；未知 key 原样返回，避免空标题。
func CategoryTitle(key string) string {
	for _, c := range categoryOrder {
		if c.Key == key {
			return c.Title
		}
	}
	return key
}

// Result 是一次侦查的完整结果（契约 §12.2 ReconResult）。
// generated_at 用 RFC3339：与全站时间字段（occurred_at 等）一致，
// 前端可直接 new Date()，不需要区分秒/毫秒。
type Result struct {
	GeneratedAt string     `json:"generated_at"`
	DurationMS  int64      `json:"duration_ms"`
	Probed      bool       `json:"probed"`
	Truncated   bool       `json:"truncated"`
	Categories  []Category `json:"categories"`
}

// Category 是一类资产的分组。
type Category struct {
	Key      string      `json:"key"`
	Title    string      `json:"title"`
	Items    []AssetItem `json:"items"`
	Findings []Finding   `json:"findings"`
	// AgentFace 是端侧 AI 面清点子对象（agentface.go，2026-11-12 新增，
	// 对标 SentinelOne Singularity ADR 的 Agent and MCP inventory）。
	// 只挂在 ai 类：其他类目恒 nil，omitempty 下线协议完全向后兼容
	// （只增不改——不认识该键的消费端自然忽略）。
	AgentFace *AgentFace `json:"agent_face,omitempty"`
	// Error 是该类侦查失败/超时的说明（前端 ReconCategory.error 可直接渲染）；
	// 正常类目省略。单类失败不影响其他类。
	Error string `json:"error,omitempty"`
}

// AssetItem 是一个资产条目。process/listens 为空时省略/空数组，
// 前端不需要判 null（listens 恒输出 []）。
type AssetItem struct {
	ID       string         `json:"id"`
	Category string         `json:"category"`
	Kind     string         `json:"kind"`
	Title    string         `json:"title"`
	Process  *Process       `json:"process,omitempty"`
	Listens  []Listen       `json:"listens"`
	Endpoint string         `json:"endpoint,omitempty"`
	Exposure Exposure       `json:"exposure"`
	Details  map[string]any `json:"details"`
	Findings []string       `json:"findings"`
}

// Process 是资产归属进程的展示视图。cmdline 已过 platform/redact：
// 资产页与告警库同级泄露风险（Jupyter token、--password 等）。
// started_at 是进程真实启动时刻（RFC3339），取不到时退回探针首次观测
// 时间；两者语义不同，但都比如实留空更利于交叉排查。
type Process struct {
	PID       uint32 `json:"pid"`
	Name      string `json:"name"`
	Path      string `json:"path,omitempty"`
	User      string `json:"user,omitempty"`
	Cmdline   string `json:"cmdline,omitempty"`
	StartedAt string `json:"started_at,omitempty"`
}

// Listen 是资产监听端点。addr 保留原始本地地址（0.0.0.0/:: 表示全接口），
// 暴露面判定依赖它，不能提前归一化成 127.0.0.1。
type Listen struct {
	Proto string `json:"proto"`
	Addr  string `json:"addr"`
	Port  uint16 `json:"port"`
}

// Exposure 是暴露面结论 + 证据链。evidence 每条都应能让分析员复核
// （监听地址、HTTP 状态码、注册表值、配置路径）。
type Exposure struct {
	Level    string   `json:"level"`
	Evidence []string `json:"evidence"`
}

// Finding 是类目级问题条目。AssetItem.findings 是给人看的一句话列表，
// Finding 是结构化版本（带等级与资产关联），供前端筛选/统计。
//
// 字段兼容：F4 前端 normalizeFinding 同时接受 level/severity 与
// detail/advice 两套键名。契约只写了 [Finding]，这里在 MarshalJSON
// 里同时输出 level+severity、detail+advice，避免并行开发时字段对不上
// 导致页面空一块（不改变 Go 侧字段，只影响线协议）。
type Finding struct {
	AssetID string `json:"asset_id,omitempty"`
	Level   string `json:"level"`
	Title   string `json:"title"`
	Detail  string `json:"detail,omitempty"`
}

// MarshalJSON 输出前端两套键名兼容的 Finding。
func (f Finding) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		AssetID  string `json:"asset_id,omitempty"`
		Level    string `json:"level"`
		Severity string `json:"severity"`
		Title    string `json:"title"`
		Detail   string `json:"detail,omitempty"`
		Advice   string `json:"advice,omitempty"`
	}{
		AssetID:  f.AssetID,
		Level:    f.Level,
		Severity: f.Level,
		Title:    f.Title,
		Detail:   f.Detail,
		Advice:   f.Detail,
	})
}

// newCategory 构造空类目；items/findings 显式空切片，JSON 输出 [] 而非 null。
func newCategory(key, title string) Category {
	return Category{
		Key:      key,
		Title:    title,
		Items:    []AssetItem{},
		Findings: []Finding{},
	}
}

// errorCategory 把单类失败转换成可展示的类目（不中断其他类）。
func errorCategory(key, msg string) Category {
	cat := newCategory(key, CategoryTitle(key))
	cat.Error = msg
	cat.Findings = append(cat.Findings, Finding{
		Level:  LevelInfo,
		Title:  CategoryTitle(key) + " 侦查未完成",
		Detail: msg,
	})
	return cat
}
