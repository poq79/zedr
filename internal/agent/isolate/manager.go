package isolate

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"

	"sync"
	"time"
)

// Firewall 是隔离规则的实际执行面（Windows=netsh 实现；测试=内存假实现）。
// 接口刻意只暴露三个动作：加规则/按名删规则/列现存规则名——篡改检测需要
// "防火墙的真实状态"，不能只信自己记录的状态文件。
type Firewall interface {
	AddBlock(name, direction, cidr string) error
	DeleteByPrefix(prefix string) (int, error)
	ListByPrefix(prefix string) ([]string, error)
	// ProfileStates 返回各防火墙 profile（domain/private/public）是否
	// 启用。规则存在但 mpssvc 被关 = 规则不执行——真机实测抓到的坑
	//（安全软件接管的机器常关防火墙），必须纳入检查与篡改修复。
	ProfileStates() (map[string]bool, error)
	// SetProfileEnabled 逐 profile 启停（隔离启用全部；解除/回滚按施加
	// 前原状逐个还原——不能全量 off，那会把原本开启的 profile 误关）。
	SetProfileEnabled(profile string, on bool) error
}

// fwProfiles 是防火墙 profile 的标准名集合（netsh 与状态记录共用）。
var fwProfiles = []string{"domain", "private", "public"}

// RulePrefix 是全部隔离规则的公共前缀（删除/枚举按它定位）。
const RulePrefix = "ZEDR-ISOLATION-"

// DefaultTTL 是隔离未显式给时限时的自动解除时长（24h，强制人工复核；
// Defender 是 7 天——我们的单客户自托管形态需要更紧的复核节奏）。
const DefaultTTL = 24 * time.Hour

// MinTTL/MaxTTL 是指令可携带 ttl_sec 的钳制范围：下限防手滑秒解（隔离
// 形同虚设），上限防"忘了解封"把机器锁一周以上。
const (
	MinTTL = 5 * time.Minute
	MaxTTL = 72 * time.Hour
)

// State 是隔离态的落盘结构（数据目录 isolation.json）：agent 重启后
// 由此判断"隔离中要重施加"还是"清孤儿规则"。
type State struct {
	Until    time.Time `json:"until"`
	Server   string    `json:"server"` // keep 集合的来源（host/IP 文本）
	Source   string    `json:"source"` // "command"（人工审批来源审计回溯用）
	DNSCount int       `json:"dns_count"`
	// OriginalProfiles 记录施加前各防火墙 profile 的启停态（R+3 真机
	// 实测教训：规则存在但 mpssvc 关闭时不执行，隔离必须隐式启用防火墙；
	// 解除时还原原状——不把用户机器的防火墙配置永久改变）。
	OriginalProfiles map[string]bool `json:"original_profiles,omitempty"`
}

// Manager 是隔离的探针侧总控：施加/解除/篡改修复/TTL 到期。
// 所有方法并发安全（指令处理与扫描周期是两个 goroutine）。
type Manager struct {
	fw        Firewall
	statePath string
	dnsFn     func() []netip.Addr // 系统解析器地址（nil=不掏 DNS，诚实降级）
	log       *slog.Logger

	mu     sync.Mutex
	active *State
}

// NewManager 构造。statePath 为空表示纯内存态（测试用）——落盘是
// "隔离跨重启持续"的根基，生产路径必须给。
func NewManager(fw Firewall, statePath string, dnsFn func() []netip.Addr, log *slog.Logger) *Manager {
	return &Manager{fw: fw, statePath: statePath, dnsFn: dnsFn, log: log}
}

// Active 返回当前隔离态（nil=未隔离）。
func (m *Manager) Active() *State {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.active == nil {
		return nil
	}
	s := *m.active
	return &s
}

// Isolated 是心跳回传的便捷口径。
func (m *Manager) Isolated() bool { return m.Active() != nil }

// Apply 施加隔离：解析 server 地址 → 构建规则集 → 逐条施加 → 落盘。
// 解析失败直接拒绝执行（绝不"先断网再说"——连接不上的隔离是盲盒）。
func (m *Manager) Apply(serverHost string, ttl time.Duration, source string) error {
	if ttl <= 0 {
		ttl = DefaultTTL
	}
	if ttl < MinTTL {
		ttl = MinTTL
	}
	if ttl > MaxTTL {
		ttl = MaxTTL
	}

	ip, err := resolveServer(serverHost)
	if err != nil {
		return fmt.Errorf("解析 server 地址失败，拒绝隔离（避免盲盒断网）: %w", err)
	}

	keep := KeepSet{
		Server:   netip.PrefixFrom(ip, ip.BitLen()).Masked(),
		Loopback: netip.MustParsePrefix("127.0.0.0/8"),
	}
	if ip.Is6() {
		keep.Loopback = netip.MustParsePrefix("::1/128")
	}
	if m.dnsFn != nil {
		for _, d := range m.dnsFn() {
			keep.DNS = append(keep.DNS, netip.PrefixFrom(d, d.BitLen()).Masked())
		}
	}

	// 防火墙启停态：规则存在但 mpssvc 关闭时不执行（真机实测抓到的坑，
	// 安全软件接管的机器常见）。施加前记录原状 → 隐式启用；解除时还原
	//——不把用户机器的防火墙配置永久改变。
	origProfiles, perr := m.fw.ProfileStates()
	if perr != nil {
		return fmt.Errorf("读取防火墙启停态失败: %w", perr)
	}
	if err := enableAllProfiles(m.fw); err != nil {
		return fmt.Errorf("启用防火墙失败（规则将不执行）: %w", err)
	}

	rules := BuildRules(keep)
	SortRules(rules)
	for _, r := range rules {
		if err := m.fw.AddBlock(r.Name, r.Direction, r.CIDR); err != nil {
			// 施加中途失败必须回滚已加规则：半隔离比不隔离更危险
			//（业务断了、对手通道还在）——按名全删回到干净态，防火墙
			// 启停态也按原状还原（否则机器停留在"被隔离"的中间态）。
			if _, derr := m.fw.DeleteByPrefix(RulePrefix); derr != nil {
				m.log.Error("isolate_rollback_delete_failed", "err", derr.Error())
			}
			restoreProfiles(m.fw, origProfiles, m.log)
			return fmt.Errorf("施加规则 %s 失败，已回滚: %w", r.Name, err)
		}
	}

	st := &State{
		Until:            time.Now().Add(ttl),
		Server:           serverHost,
		Source:           source,
		DNSCount:         len(keep.DNS),
		OriginalProfiles: origProfiles,
	}
	if err := m.saveState(st); err != nil && m.statePath != "" {
		// 落盘失败仍保持内存态隔离，但日志要喊出来——重启后孤儿规则
		// 会被清理逻辑当垃圾删掉（fail-open），必须有人看到。
		m.log.Error("isolate_state_persist_failed", "err", err.Error())
	}
	m.mu.Lock()
	m.active = st
	m.mu.Unlock()
	m.log.Warn("isolate_applied", "server", serverHost, "rules", len(rules),
		"ttl_sec", int(ttl.Seconds()), "until", st.Until.Format(time.RFC3339))
	return nil
}

// Release 解除隔离：删规则 + 删状态文件 + 还原防火墙启停原状。
func (m *Manager) Release() error {
	st := m.Active()
	n, err := m.fw.DeleteByPrefix(RulePrefix)
	if err != nil {
		return err
	}
	m.clearState()
	// 防火墙启停态还原：施加时隐式启用过，解除按施加前原状逐个还原
	//（不还原 = 解除后机器防火墙全开，改变了用户机器的安全 posture）
	if st != nil {
		restoreProfiles(m.fw, st.OriginalProfiles, m.log)
	}
	m.mu.Lock()
	m.active = nil
	m.mu.Unlock()
	m.log.Info("isolate_released", "rules_deleted", n)
	return nil
}

// enableAllProfiles 启用全部 profile（隔离的执行前提）。
func enableAllProfiles(fw Firewall) error {
	for _, p := range fwProfiles {
		if err := fw.SetProfileEnabled(p, true); err != nil {
			return fmt.Errorf("启用 profile %s 失败: %w", p, err)
		}
	}
	return nil
}

// restoreProfiles 按 OriginalProfiles 逐个还原（nil 记录=施加前状态
// 未知，保守保持现状不动）。
func restoreProfiles(fw Firewall, orig map[string]bool, log *slog.Logger) {
	if orig == nil {
		return
	}
	for _, p := range fwProfiles {
		if on, ok := orig[p]; ok {
			if err := fw.SetProfileEnabled(p, on); err != nil {
				log.Warn("isolate_profile_restore_failed", "profile", p, "err", err.Error())
			}
		}
	}
}

// Repair 篡改检测：隔离中但防火墙里的规则数对不上期望，或防火墙整个
// 被关闭 → 全量重施加/重新启用（确定性命名让重施加幂等）。返回是否
// 发生了修复。
func (m *Manager) Repair() (bool, error) {
	st := m.Active()
	if st == nil {
		return false, nil
	}
	tampered := false

	// ① 防火墙启停态：被关 = 规则不执行 = 隔离是纸面隔离（真机实测
	// 抓到的坑）——重新启用并计入篡改。
	states, perr := m.fw.ProfileStates()
	if perr == nil {
		for _, p := range fwProfiles {
			if on, ok := states[p]; ok && !on {
				if err := m.fw.SetProfileEnabled(p, true); err == nil {
					m.log.Warn("isolate_profile_reenabled", "profile", p)
					tampered = true
				}
			}
		}
	}

	live, err := m.fw.ListByPrefix(RulePrefix)
	if err != nil {
		return false, err
	}
	ip, rerr := resolveServer(st.Server)
	if rerr != nil {
		// server 地址解析不了（网络已断）：不重算规则集，只按数量缺口判断
		if len(live) == 0 {
			m.log.Error("isolate_tamper_all_rules_gone", "server_resolve", rerr.Error())
			return false, fmt.Errorf("隔离规则全部丢失且 server 不可达，无法重施加: %w", rerr)
		}
		return false, nil
	}
	keep := KeepSet{
		Server:   netip.PrefixFrom(ip, ip.BitLen()).Masked(),
		Loopback: netip.MustParsePrefix("127.0.0.0/8"),
	}
	if m.dnsFn != nil {
		for _, d := range m.dnsFn() {
			keep.DNS = append(keep.DNS, netip.PrefixFrom(d, d.BitLen()).Masked())
		}
	}
	want := len(BuildRules(keep))
	if len(live) < want {
		m.log.Warn("isolate_tamper_detected", "live", len(live), "want", want)
		// 全量重施加：先删（清掉被改名/替换的残件）再加
		if _, err := m.fw.DeleteByPrefix(RulePrefix); err != nil {
			return tampered, err
		}
		rules := BuildRules(keep)
		SortRules(rules)
		for _, r := range rules {
			if err := m.fw.AddBlock(r.Name, r.Direction, r.CIDR); err != nil {
				return tampered, err
			}
		}
		tampered = true
	}
	return tampered, nil
}

// CheckExpiry TTL 到期自动解除（扫描周期调用）。返回是否发生了解除。
func (m *Manager) CheckExpiry(now time.Time) (bool, error) {
	st := m.Active()
	if st == nil || now.Before(st.Until) {
		return false, nil
	}
	m.log.Warn("isolate_ttl_expired", "until", st.Until.Format(time.RFC3339))
	return true, m.Release()
}

// LoadStartup 启动引导：有未过期隔离态 → 重施加（fail-closed，隔离跨
// 重启持续，对齐 CrowdStrike）；过期态或无态但有规则残留 → 清理
// （fail-open，防历史残留把一台好机器永久断网）。
func (m *Manager) LoadStartup() error {
	st, err := m.loadState()
	if err != nil {
		m.log.Warn("isolate_state_load_failed", "err", err.Error())
	}
	live, lerr := m.fw.ListByPrefix(RulePrefix)
	if st != nil && time.Now().Before(st.Until) {
		// 重施加会先算规则再逐条加——现存残件被确定性命名覆盖
		m.mu.Lock()
		m.active = st
		m.mu.Unlock()
		if _, rerr := m.Repair(); rerr != nil {
			return rerr
		}
		m.log.Warn("isolate_resumed_after_restart", "until", st.Until.Format(time.RFC3339))
		return nil
	}
	// 无有效态：有残留规则就清（孤儿规则是"某台机器莫名其妙断网"的
	// 事故源头，宁可放过对手也不冤枉自己人）
	if lerr == nil && len(live) > 0 {
		m.log.Warn("isolate_orphan_rules_cleaned", "count", len(live))
		_, _ = m.fw.DeleteByPrefix(RulePrefix)
	}
	return nil
}

// resolveServer 把 serverHost 解析成单个地址（IP 字面量直用；主机名走
// 系统 DNS）。只取第一个 IPv4/IPv6。
func resolveServer(host string) (netip.Addr, error) {
	if addr, err := netip.ParseAddr(host); err == nil {
		return addr.Unmap(), nil
	}
	addrs, err := net.LookupHost(host)
	if err != nil {
		return netip.Addr{}, err
	}
	for _, a := range addrs {
		if ip, perr := netip.ParseAddr(a); perr == nil {
			return ip.Unmap(), nil
		}
	}
	return netip.Addr{}, fmt.Errorf("无可解析地址: %s", host)
}

// saveState 原子落盘（tmp+rename）。
func (m *Manager) saveState(st *State) error {
	if m.statePath == "" {
		return nil
	}
	b, err := json.Marshal(st)
	if err != nil {
		return err
	}
	tmp := m.statePath + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, m.statePath)
}

func (m *Manager) loadState() (*State, error) {
	if m.statePath == "" {
		return nil, nil
	}
	b, err := os.ReadFile(m.statePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var st State
	if err := json.Unmarshal(b, &st); err != nil {
		return nil, err
	}
	return &st, nil
}

func (m *Manager) clearState() {
	if m.statePath == "" {
		return
	}
	_ = os.Remove(m.statePath)
	_ = os.Remove(m.statePath + ".tmp") // 原子写残留的 tmp 一并清
}
