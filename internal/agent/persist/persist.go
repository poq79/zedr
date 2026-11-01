// Package persist 实现持久化项（自启动）监控。
//
// 设计取舍：
//
//  1. 首次运行只建立基线、不产生任何告警。用户机器上已有的几百个自启动项
//     是"当前状态"，不是"异常"，一次性喷出来只会让人立刻卸掉产品。
//  2. 之后每次扫描只对**新增项**做判定。这牺牲了"安装前就存在的后门"的
//     发现能力，换取可接受的噪声水平——这是所有同类产品的共同取舍。
//  3. 判定不只看"新增"，还看**新增到哪里、指向什么**：新增到 Temp 目录
//     并指向未签名文件，和新增一个微软签名的服务，风险差三个数量级。
package persist

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"hostguard/internal/agent/enrich"
	"hostguard/internal/agent/winapi"
	"hostguard/internal/model"
)

// record 是基线里的一条记录。
type record struct {
	Command   string    `json:"command"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

// baselineSchema 是基线内容的结构版本。
//
// 每次"采集口径"发生不兼容变化（比如计划任务从只记路径改为解析执行命令）时
// 必须递增。老基线在加载时会被静默丢弃并重建，否则升级那一刻，
// 所有同类条目都会因为"命令文本变了"而被判成变更——
// 本机 184 个计划任务会瞬间刷出上百条告警，运维第一反应就是关掉产品。
//
// 代价是升级窗口内的真实变更会被吞掉，但窗口只有一次扫描周期，可以接受。
const baselineSchema = 2

// baselineFile 是基线落盘格式。
type baselineFile struct {
	Version   int               `json:"version"`
	Schema    int               `json:"schema"`
	UpdatedAt time.Time         `json:"updated_at"`
	Items     map[string]record `json:"items"`
}

// Finding 是一条需要关注的持久化变更。
type Finding struct {
	Item     winapi.PersistItem
	Path     string // 解析出的可执行路径（可能为空）
	Score    int
	Verdict  model.Verdict
	Severity model.Severity
	Reasons  []string
	Hash     string
	Signed   bool
	Signer   string
	MITRE    []string
}

// Result 是一轮扫描的结果。
type Result struct {
	// Initial=true 表示这次是建立基线（不产生告警）。
	Initial bool
	Total   int
	Added   []Finding
	// Removed 只用于展示，默认不告警：删除自启动项也可能是攻击者清理痕迹，
	// 但更多是正常软件卸载，噪声比太高。
	Removed []string
	// Changed 记录命令被改写的情况（常见于"合法项被劫持"）。
	Changed []Finding
	Errs    []string
}

// Monitor 维护持久化基线并做增量对比。
type Monitor struct {
	path string
	enr  *enrich.Enricher

	mu     sync.Mutex
	items  map[string]record
	loaded bool
	savedAt time.Time
}

// New 创建监控器。path 是基线文件路径。
func New(path string, enr *enrich.Enricher) *Monitor {
	return &Monitor{path: path, enr: enr, items: make(map[string]record, 512)}
}

// Load 从磁盘读取基线。
func (m *Monitor) Load() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.loadLocked()
}

func (m *Monitor) loadLocked() error {
	raw, err := os.ReadFile(m.path)
	if err != nil {
		if os.IsNotExist(err) {
			m.loaded = true
			return nil
		}
		return err
	}
	var f baselineFile
	if err := json.Unmarshal(raw, &f); err != nil {
		return fmt.Errorf("持久化基线损坏: %w", err)
	}
	// 采集口径变了：丢弃旧基线，让下一次 Scan 走"首次建立"路径（不告警）
	if f.Schema != baselineSchema {
		m.loaded = true
		return nil
	}
	if f.Items != nil {
		m.items = f.Items
	}
	m.loaded = true
	m.savedAt, _ = time.Parse(time.RFC3339, f.UpdatedAt.Format(time.RFC3339))
	return nil
}

// Size 返回基线中记录的自启动项数量。
func (m *Monitor) Size() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.items)
}

// Save 落盘。
func (m *Monitor) Save() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.saveLocked()
}

func (m *Monitor) saveLocked() error {
	if err := os.MkdirAll(filepath.Dir(m.path), 0o755); err != nil {
		return err
	}
	f := baselineFile{Version: 1, Schema: baselineSchema, UpdatedAt: time.Now(), Items: m.items}
	raw, err := json.Marshal(&f)
	if err != nil {
		return err
	}
	tmp := m.path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, m.path)
}

// Scan 枚举当前持久化项并与基线对比。
func (m *Monitor) Scan() (*Result, error) {
	m.mu.Lock()
	if !m.loaded {
		_ = m.loadLocked()
	}
	wasEmpty := len(m.items) == 0
	m.mu.Unlock()

	items, errs := winapi.EnumeratePersistence()
	res := &Result{Total: len(items), Errs: errs}

	now := time.Now()
	seen := make(map[string]struct{}, len(items))
	var added []winapi.PersistItem
	var changed []struct {
		item winapi.PersistItem
		old  string
	}

	m.mu.Lock()
	for _, it := range items {
		seen[it.Key] = struct{}{}
		old, exists := m.items[it.Key]
		switch {
		case !exists:
			added = append(added, it)
			m.items[it.Key] = record{Command: it.Command, FirstSeen: now, LastSeen: now}
		case !sameCommand(old.Command, it.Command):
			changed = append(changed, struct {
				item winapi.PersistItem
				old  string
			}{it, old.Command})
			m.items[it.Key] = record{Command: it.Command, FirstSeen: old.FirstSeen, LastSeen: now}
		default:
			r := old
			r.LastSeen = now
			m.items[it.Key] = r
		}
	}
	for key := range m.items {
		if _, ok := seen[key]; !ok {
			res.Removed = append(res.Removed, key)
			delete(m.items, key)
		}
	}
	m.mu.Unlock()

	sort.Strings(res.Removed)

	// 首次建立基线：登记但绝不告警
	if wasEmpty {
		res.Initial = true
		_ = m.Save()
		return res, nil
	}

	for _, it := range added {
		res.Added = append(res.Added, m.assess(it, false))
	}
	for _, c := range changed {
		res.Changed = append(res.Changed, m.assess(c.item, true))
	}
	sort.Slice(res.Added, func(i, j int) bool { return res.Added[i].Score > res.Added[j].Score })
	sort.Slice(res.Changed, func(i, j int) bool { return res.Changed[i].Score > res.Changed[j].Score })

	_ = m.Save()
	return res, nil
}

// sameCommand 比较命令是否实质相同。
// 有些软件每次启动都会改写参数（比如带随机会话 ID），因此只在
// 规范化后的命令差异较大时才认为"被改写"。
func sameCommand(a, b string) bool {
	pa := strings.ToLower(strings.TrimSpace(winapi.PersistCommandPath(a)))
	pb := strings.ToLower(strings.TrimSpace(winapi.PersistCommandPath(b)))
	if pa != "" && pb != "" {
		return pa == pb
	}
	return strings.EqualFold(strings.TrimSpace(a), strings.TrimSpace(b))
}

// 可写目录：攻击者最容易落地的地方。命中这些位置的自启动项风险显著更高。
var writableMarkers = []string{
	`\temp\`, `\tmp\`, `\downloads\`, `\appdata\local\temp`,
	`\users\public\`, `\programdata\`, `\recycle`, `\$recycle.bin\`,
	`\windows\temp\`, `\perflogs\`, `\desktop\`, `\documents\`,
}

// 危险命令解释器：自启动项通过它们拉起载荷，是"间接启动"的典型形态。
var dangerousHosts = []string{
	"powershell", "pwsh", "mshta", "rundll32", "regsvr32", "wscript",
	"cscript", "cmd.exe", "cmd /c", "certutil", "bitsadmin", "msiexec",
}

// assess 对单个持久化项做信誉判定。
func (m *Monitor) assess(it winapi.PersistItem, isChange bool) Finding {
	f := Finding{Item: it, MITRE: mitreFor(it.Type)}

	path := winapi.PersistCommandPath(it.Command)
	f.Path = path
	cmdLower := strings.ToLower(it.Command)

	add := func(n int, reason string) {
		f.Score += n
		f.Reasons = append(f.Reasons, reason)
	}

	// 1) 基础分：新增自启动项本身就是"有新东西要长期运行"
	if isChange {
		add(34, "已有自启动项的命令被改写（可能是合法项被劫持）")
	} else {
		add(28, "新增自启动项")
	}

	// 2) 落点信誉
	lowPath := strings.ToLower(path)
	if lowPath == "" {
		add(8, "无法解析出可执行文件路径")
	} else {
		for _, mk := range writableMarkers {
			if strings.Contains(lowPath, mk) {
				add(26, "指向用户可写目录："+locateMarker(lowPath, mk))
				break
			}
		}
		if strings.HasPrefix(lowPath, `\\`) {
			add(22, "指向 UNC 网络路径")
		}
		if !fileExists(path) {
			add(14, "指向的文件不存在（留空壳自启动项）")
		}
	}

	// 2.5) 权限与触发方式（主要针对计划任务）
	//
	// "以最高权限运行 + 开机即触发 + 指向可写目录"是持久化里风险最高的组合：
	// 它同时满足了自动性、高权限和不可信载荷三个条件。
	// 单看任何一条都不够，凑齐才有判别力，因此这里只做组合加分。
	if it.Elevated && strings.Contains(it.Trigger, "开机") {
		add(14, "计划任务以最高权限在开机时运行")
	} else if it.Elevated && it.Type == winapi.PersistScheduledTask {
		add(6, "计划任务以最高权限运行")
	}
	if it.RunAs != "" && strings.Contains(strings.ToLower(it.RunAs), "system") &&
		it.Type == winapi.PersistScheduledTask {
		add(4, "计划任务以 SYSTEM 身份运行")
	}

	// 3) 间接启动：通过命令解释器拉起
	for _, h := range dangerousHosts {
		if strings.Contains(cmdLower, h) {
			add(16, "通过命令解释器启动（"+h+"）")
			break
		}
	}
	// 编码/隐藏参数
	for _, kw := range []string{"-enc", "-encodedcommand", "hidden", "bypass", "-w hidden", "/c start"} {
		if strings.Contains(cmdLower, kw) {
			add(18, "命令行含隐藏/编码参数（"+kw+"）")
			break
		}
	}

	// 4) 签名与哈希（成本较高，只对已有文件做）
	if path != "" && fileExists(path) && m.enr != nil {
		meta := m.enr.Describe(path)
		f.Hash = meta.Hash
		f.Signed = meta.Signed && meta.SignatureOK
		f.Signer = meta.Signer
		switch {
		case !meta.Signed:
			add(18, "可执行文件无数字签名")
		case !meta.SignatureOK:
			add(26, "可执行文件签名无效（被篡改或伪造）")
		}
	}

	// 定级
	switch {
	case f.Score >= 70:
		f.Verdict = model.VerdictMalicious
		f.Severity = model.SeverityHigh
	case f.Score >= 38:
		f.Verdict = model.VerdictSuspicious
		f.Severity = model.SeverityMedium
	default:
		f.Verdict = model.VerdictSafe
		f.Severity = model.SeverityLow
	}
	if f.Score >= 90 {
		f.Severity = model.SeverityCritical
	}
	return f
}

func locateMarker(path, marker string) string {
	if i := strings.Index(path, marker); i >= 0 {
		return path[:i+len(marker)-1]
	}
	return marker
}

func fileExists(p string) bool {
	if p == "" {
		return false
	}
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}

// mitreFor 把持久化类型映射到 ATT&CK 技术编号。
func mitreFor(typ string) []string {
	switch typ {
	case winapi.PersistRegistryRun, winapi.PersistRegistryRunOnce:
		return []string{"T1547.001"}
	case winapi.PersistStartupFolder:
		return []string{"T1547.001"}
	case winapi.PersistService:
		return []string{"T1543.003"}
	case winapi.PersistScheduledTask:
		return []string{"T1053.005"}
	case winapi.PersistWinlogon:
		return []string{"T1547.004"}
	case winapi.PersistIFEO:
		return []string{"T1546.012"}
	default:
		return []string{"T1547"}
	}
}

// ToAlert 把 Finding 转成告警信封。
// 只有越过可疑阈值的项才会被上层转成告警。
func (f Finding) ToAlert(hostname string) model.AlertEnvelope {
	title := "新增自启动项：" + winapi.PersistLocationLabel(f.Item.Type)
	if f.Score < 38 {
		title = "自启动项变更：" + winapi.PersistLocationLabel(f.Item.Type)
	}

	summary := strings.Join(f.Reasons, "；")
	if summary == "" {
		summary = "自启动项发生变化"
	}

	signals := make([]model.Signal, 0, len(f.Reasons)+1)
	signals = append(signals, model.Signal{
		Layer: "persist", ID: "P-001", Name: "持久化项变更",
		Score: f.Score, Note: f.Item.Location, MITRE: strings.Join(f.MITRE, ","),
	})
	for _, r := range f.Reasons {
		signals = append(signals, model.Signal{Layer: "persist", ID: "P-002", Name: r})
	}

	return model.AlertEnvelope{
		Fingerprint: "persist:" + f.Item.Key,
		Title:       title,
		Summary:     summary,
		Verdict:     f.Verdict,
		Severity:    f.Severity,
		Score:       f.Score,
		ProcessName: f.Item.Name,
		ImagePath:   f.Path,
		CmdLine:     f.Item.Command,
		ProcUser:    "SYSTEM/PERSISTENCE",
		HashSHA256:  f.Hash,
		Signer:      f.Signer,
		Signed:      f.Signed,
		RuleIDs:     []string{"P-001"},
		MITRE:       f.MITRE,
		Evidence: model.Evidence{
			Process: model.ProcEvidence{
				Name: f.Item.Name, Path: f.Path, CmdLine: f.Item.Command,
				HashSHA256: f.Hash, Signer: f.Signer, Signed: f.Signed,
				SignatureOK: f.Signed,
			},
			Signals: signals,
			Notes:   f.Reasons,
		},
		OccurredAt: time.Now(),
	}
}
