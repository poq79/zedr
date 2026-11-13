//go:build linux

// localapi_linux.go：localapi 的 Linux 侧——视图类型 + Backend 默认实现。
//
// 未在 Linux 实机验证（本机无 Linux 测试环境）；验证口径 = GOOS=linux
// 交叉编译 + Windows 上运行的中性单测（本包无 Linux 专属纯逻辑，视图为
// 数据形状定义）。
//
// 视图类型：与 hygiene_types.go 的同名字段逐字对齐（json tag 一致），
// 字段形状漂移时以 hygiene 为准修这里。不 import hygiene 的原因见
// api.go 头注释（hygiene 正被另一会话并行改造，Linux 构建不耦合其
// 变化窗口）；Windows 侧用类型别名天然跟随，Linux 侧这份复制是对该
// 取舍的已知代价。
//
// LinuxBackend：lapp 集成接线前的默认 Backend——核心数据面（运行时/
// 进程/告警/白名单/驻留基线/隔离区）通过函数钩子由组合根注入，注入点
// 缺省时诚实返回空值；泛安全体检五方法在 hygiene 的 Linux 采集面完成
// 集成前返回诚实空值 + note（不伪造数据，集成后由组合根替换实现）。
package localapi

// localapi_linux.go：Linux 视图类型与默认 Backend。

import (
	"zedr/internal/agent/allow"
	"zedr/internal/agent/persist"
	"zedr/internal/agent/quarantine"
	"zedr/internal/agent/state"
)

// linuxHygieneNote 是体检面未接线时的统一诚实说明。
const linuxHygieneNote = "hygiene 泛安全体检的 Linux 采集面尚未接入（v1 诚实空值，集成后由组合根替换）"

// ---- 视图类型（与 hygiene_types.go 字段逐字对齐；服务端/前端零分叉）----

// linuxFileMeta 是 PersistAuditView.File 的形状（hygiene 的 fileMeta 未
// 导出，Linux 侧按同形状复制；v1 只填 Exists）。
type linuxFileMeta struct {
	Exists      bool   `json:"exists"`
	Signed      bool   `json:"signed"`
	SigState    string `json:"sig_state"`
	Signer      string `json:"signer,omitempty"`
	Company     string `json:"company,omitempty"`
	Description string `json:"description,omitempty"`
}

type InstalledAppView struct {
	Name        string `json:"name"`
	Version     string `json:"version,omitempty"`
	Publisher   string `json:"publisher,omitempty"`
	InstallDate string `json:"install_date,omitempty"`
	SizeKB      uint64 `json:"size_kb,omitempty"`
	Location    string `json:"location,omitempty"`
	// Source: win32 | store | dpkg | rpm | dir
	Source   string `json:"source"`
	Hidden   bool   `json:"hidden"`
	NoRemove bool   `json:"no_remove"`
	// Note 是 Linux 侧扩展字段：数据面说明（诚实空值场景下的"为什么"）。
	Note string `json:"note,omitempty"`
}

type CheckView struct {
	ID     string `json:"id"`
	Group  string `json:"group"` // config | update | privacy
	Title  string `json:"title"`
	State  string `json:"state"` // ok | warn | err | info
	Value  string `json:"value"`
	Why    string `json:"why"`
	Advice string `json:"advice,omitempty"`
	Note   string `json:"note,omitempty"` // Linux 侧扩展（同上）
}

type PersistAuditView struct {
	Key        string        `json:"key"`
	Kind       string        `json:"kind"`
	Location   string        `json:"location"`
	Name       string        `json:"name,omitempty"`
	Command    string        `json:"command"`
	Enabled    bool          `json:"enabled"`
	RunAs      string        `json:"run_as,omitempty"`
	Elevated   bool          `json:"elevated"`
	Trigger    string        `json:"trigger,omitempty"`
	ExePath    string        `json:"exe_path,omitempty"`
	File       linuxFileMeta `json:"file"`
	InBaseline bool          `json:"in_baseline"`
	Flags      []string      `json:"flags,omitempty"`
}

type linuxListener struct {
	Proto   string `json:"proto"`
	Addr    string `json:"addr"`
	Port    uint16 `json:"port"`
	Scope   string `json:"scope"` // loopback | lan | any
	Process string `json:"process,omitempty"`
}

type linuxHostEntry struct {
	IP       string `json:"ip"`
	Hostname string `json:"hostname"`
}

type linuxHostsReport struct {
	Entries  []linuxHostEntry `json:"entries"`
	Readable bool             `json:"readable"`
	Note     string           `json:"note,omitempty"`
}

type linuxProxyReport struct {
	Enabled       bool   `json:"enabled"`
	Server        string `json:"server,omitempty"`
	AutoConfigURL string `json:"auto_config_url,omitempty"`
	Override      string `json:"override,omitempty"`
}

type ExposureView struct {
	Listeners []linuxListener  `json:"listeners"`
	Hosts     linuxHostsReport `json:"hosts"`
	Proxy     linuxProxyReport `json:"proxy"`
	Note      string           `json:"note,omitempty"` // Linux 侧扩展（同上）
}

type linuxBrowserExt struct {
	Browser    string   `json:"browser"` // chrome | edge | chromium | firefox
	Profile    string   `json:"profile"`
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	Version    string   `json:"version,omitempty"`
	HostWide   bool     `json:"host_wide"`
	RiskyPerms []string `json:"risky_perms,omitempty"`
}

type linuxBrowserPolicy struct {
	Browser string `json:"browser"`
	Key     string `json:"key"`
	Detail  string `json:"detail"`
	Count   int    `json:"count"`
}

type BrowserView struct {
	Extensions []linuxBrowserExt    `json:"extensions"`
	Policies   []linuxBrowserPolicy `json:"policies"`
	Scanned    []string             `json:"scanned"`
	Note       string               `json:"note,omitempty"` // Linux 侧扩展（同上）
}

// ---- 导出视图字段类型别名 ----
// 视图结构体的字段类型原本非导出，跨包 Backend 实现（组合根）无法构造；
// 别名让形状与 JSON 线协议零变化，只放宽可构造性。

type (
	// LinuxListener 等 = 同名小写类型的导出别名（逐字段一致）。
	LinuxListener       = linuxListener
	LinuxHostEntry      = linuxHostEntry
	LinuxHostsReport    = linuxHostsReport
	LinuxProxyReport    = linuxProxyReport
	LinuxBrowserExt     = linuxBrowserExt
	LinuxBrowserPolicy  = linuxBrowserPolicy
	LinuxFileMeta       = linuxFileMeta
)

// ---- LinuxBackend：默认 Backend（钩子注入 + 诚实空值）----

// LinuxBackend 是 localapi.Backend 的 Linux 默认实现。核心数据面全部是
// 可选函数钩子（组合根按自己的 store/allow/quarantine 适配）；钩子为 nil
// 时返回诚实空值。体检面（Apps/Posture/Exposure/BrowserAudit/PersistAudit）
// 在 hygiene Linux 采集面集成前固定返回空值 + note。
//
// 并发纪律：钩子由组合根在 Start 前一次性赋值，之后只读；Backend 的
// 调用方是本包 routes（HTTP handler），无额外加锁。
type LinuxBackend struct {
	// Runtime/Procs/Alerts 是本地状态面（通常包一层 state.Store）。
	RuntimeFn func() state.RuntimeInfo
	ProcsFn   func(limit int) []state.ProcRow
	AlertsFn  func(limit int) []*state.Alert
	// AlertByIDFn 单条告警查询；nil 时恒 nil（404）。
	AlertByIDFn func(id string) *state.Alert
	// RescanFn 触发全量重扫；nil 时空操作（按钮点了没反应比 panic 好）。
	RescanFn func()
	// 白名单面（与 Windows Backend 同语义）。
	AllowHashFn   func(hash, note string) error
	AllowPathFn   func(path, note string) error
	AllowlistFn   func() []allow.Entry
	RemoveAllowFn func(typ, value string) error
	WhitelistFn   func() map[string]int
	// 驻留基线与隔离区。
	PersistItemsFn func() []persist.Item
	QuarantineFn   func() []quarantine.Entry
}

// compile 期锁接口：LinuxBackend 必须满足 Backend。
var _ Backend = (*LinuxBackend)(nil)

func (b *LinuxBackend) Runtime() state.RuntimeInfo {
	if b.RuntimeFn == nil {
		return state.RuntimeInfo{}
	}
	return b.RuntimeFn()
}

func (b *LinuxBackend) Procs(limit int) []state.ProcRow {
	if b.ProcsFn == nil {
		return []state.ProcRow{}
	}
	return b.ProcsFn(limit)
}

func (b *LinuxBackend) Alerts(limit int) []*state.Alert {
	if b.AlertsFn == nil {
		return []*state.Alert{}
	}
	return b.AlertsFn(limit)
}

func (b *LinuxBackend) AlertByID(id string) *state.Alert {
	if b.AlertByIDFn == nil {
		return nil
	}
	return b.AlertByIDFn(id)
}

func (b *LinuxBackend) Rescan() {
	if b.RescanFn != nil {
		b.RescanFn()
	}
}

func (b *LinuxBackend) AllowHash(hash, note string) error {
	if b.AllowHashFn == nil {
		return errLinuxNotWired("白名单哈希写入未接线")
	}
	return b.AllowHashFn(hash, note)
}

func (b *LinuxBackend) AllowPath(path, note string) error {
	if b.AllowPathFn == nil {
		return errLinuxNotWired("白名单路径写入未接线")
	}
	return b.AllowPathFn(path, note)
}

func (b *LinuxBackend) Allowlist() []allow.Entry {
	if b.AllowlistFn == nil {
		return []allow.Entry{}
	}
	return b.AllowlistFn()
}

func (b *LinuxBackend) RemoveAllow(typ, value string) error {
	if b.RemoveAllowFn == nil {
		return errLinuxNotWired("白名单删除未接线")
	}
	return b.RemoveAllowFn(typ, value)
}

func (b *LinuxBackend) WhitelistSize() map[string]int {
	if b.WhitelistFn == nil {
		return map[string]int{}
	}
	return b.WhitelistFn()
}

func (b *LinuxBackend) PersistItems() []persist.Item {
	if b.PersistItemsFn == nil {
		return []persist.Item{}
	}
	return b.PersistItemsFn()
}

func (b *LinuxBackend) QuarantineEntries() []quarantine.Entry {
	if b.QuarantineFn == nil {
		return []quarantine.Entry{}
	}
	return b.QuarantineFn()
}

// ---- 体检面：诚实空值 + note（hygiene Linux 采集面集成前的接口位）----

func (b *LinuxBackend) Apps() []InstalledAppView {
	return []InstalledAppView{}
}

func (b *LinuxBackend) Posture() []CheckView {
	// 单条 info 项承载"为什么是空的"：列表接口没有独立 note 位，
	// 合成项是唯一能穿透到前端的诚实说明通道。
	return []CheckView{{
		ID: "linux_hygiene_not_wired", Group: "config",
		Title: "泛安全体检（Linux）", State: "info", Value: "未接入",
		Why:  linuxHygieneNote,
		Note: linuxHygieneNote,
	}}
}

func (b *LinuxBackend) Exposure() ExposureView {
	return ExposureView{
		Listeners: []linuxListener{},
		Hosts:     linuxHostsReport{Entries: []linuxHostEntry{}, Note: linuxHygieneNote},
		Proxy:     linuxProxyReport{},
		Note:      linuxHygieneNote,
	}
}

func (b *LinuxBackend) BrowserAudit() BrowserView {
	return BrowserView{
		Extensions: []linuxBrowserExt{},
		Policies:   []linuxBrowserPolicy{},
		Scanned:    []string{},
		Note:       linuxHygieneNote,
	}
}

func (b *LinuxBackend) PersistAudit() []PersistAuditView {
	return []PersistAuditView{}
}

// errLinuxNotWired 是写操作钩子未接线时的统一错误（诚实表达"能力在，
// 组合根没接"，而非静默成功）。
func errLinuxNotWired(what string) error {
	return &apperrNotWired{what: what}
}

// apperrNotWired 是 errLinuxNotWired 的载体：实现 error 接口的最小类型
// （localapi 不引入 apperr 依赖也能给出规范文案）。
type apperrNotWired struct{ what string }

func (e *apperrNotWired) Error() string {
	return e.what + "（Linux 组合根未接线，诚实拒绝）"
}
