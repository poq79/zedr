//go:build linux

// localapi.Backend 的 Linux 实现：状态/白名单/驻留面直通组合根真实组件，
// 体检五视图接 hygiene Linux 采集器（SD1 交付的 hygiene_linux），视图
// 类型做逐字段转换（localapi 视图与 hygiene 类型字段对齐，但跨包命名
// 类型无法直接赋值）。未在 Linux 实机验证。
package lapp

import (
	"fmt"
	"strings"

	"zedr/internal/agent/allow"
	"zedr/internal/agent/hygiene"
	"zedr/internal/agent/localapi"
	"zedr/internal/agent/persist"
	"zedr/internal/agent/quarantine"
	"zedr/internal/agent/state"
)

// localBackend 实现 localapi.Backend（与 Windows 版 app.Agent 的实现
// 逐方法同构）。
type localBackend struct {
	a *Agent
}

// newLocalBackend 构造本地接口 Backend。
func newLocalBackend(a *Agent) localapi.Backend { return &localBackend{a: a} }

func (b *localBackend) Runtime() state.RuntimeInfo { return b.a.store.Runtime() }
func (b *localBackend) Procs(limit int) []state.ProcRow {
	return b.a.store.Procs(limit)
}
func (b *localBackend) Alerts(limit int) []*state.Alert { return b.a.store.Alerts(limit) }
func (b *localBackend) AlertByID(id string) *state.Alert {
	return b.a.store.AlertByID(id)
}
func (b *localBackend) Rescan() {
	select {
	case b.a.scanReq <- true:
	default:
	}
}

func (b *localBackend) AllowHash(hash, note string) error {
	if strings.TrimSpace(hash) == "" {
		return fmt.Errorf("哈希不能为空")
	}
	if err := b.a.alw.AddLocal(allow.TypeHash, hash, note); err != nil {
		return err
	}
	b.a.purgeChainsOnAllowlist()
	return nil
}

func (b *localBackend) AllowPath(path, note string) error {
	if strings.TrimSpace(path) == "" {
		return fmt.Errorf("路径不能为空")
	}
	if err := b.a.alw.AddLocal(allow.TypePath, path, note); err != nil {
		return err
	}
	b.a.purgeChainsOnAllowlist()
	return nil
}

func (b *localBackend) Allowlist() []allow.Entry { return b.a.alw.Local() }
func (b *localBackend) RemoveAllow(typ, value string) error {
	return b.a.alw.RemoveLocal(typ, value)
}
func (b *localBackend) WhitelistSize() map[string]int { return b.a.alw.Size() }

func (b *localBackend) PersistItems() []persist.Item {
	if b.a.pm == nil {
		return nil
	}
	return b.a.pm.Items()
}

// QuarantineEntries：Linux v1 未接线处置能力（诚实空值，与指令回执
// 口径一致）。
func (b *localBackend) QuarantineEntries() []quarantine.Entry { return nil }

// ---- 体检五视图：hygiene Linux 采集器 → localapi 视图 ----

func (b *localBackend) Apps() []localapi.InstalledAppView {
	apps := hygiene.Apps()
	out := make([]localapi.InstalledAppView, 0, len(apps))
	for _, it := range apps {
		out = append(out, localapi.InstalledAppView{
			Name: it.Name, Version: it.Version, Publisher: it.Publisher,
			InstallDate: it.InstallDate, SizeKB: it.SizeKB, Location: it.Location,
			Source: it.Source, Hidden: it.Hidden, NoRemove: it.NoRemove,
		})
	}
	return out
}

func (b *localBackend) Posture() []localapi.CheckView {
	checks := hygiene.Posture()
	out := make([]localapi.CheckView, 0, len(checks))
	for _, it := range checks {
		out = append(out, localapi.CheckView{
			ID: it.ID, Group: it.Group, Title: it.Title, State: it.State,
			Value: it.Value, Why: it.Why, Advice: it.Advice,
		})
	}
	return out
}

func (b *localBackend) Exposure() localapi.ExposureView {
	pidName := make(map[uint32]string)
	for _, p := range b.a.store.Procs(2000) {
		if p.PID > 0 {
			pidName[p.PID] = p.Name
		}
	}
	rep := hygiene.Exposure(pidName)
	out := localapi.ExposureView{
		Listeners: make([]localapi.LinuxListener, 0, len(rep.Listeners)),
		Hosts: localapi.LinuxHostsReport{
			Readable: rep.Hosts.Readable, Note: rep.Hosts.Note,
		},
		Proxy: localapi.LinuxProxyReport{
			Enabled:       rep.Proxy.Enabled,
			Server:        rep.Proxy.Server,
			AutoConfigURL: rep.Proxy.AutoConfigURL,
			Override:      rep.Proxy.Override,
		},
	}
	for _, l := range rep.Listeners {
		out.Listeners = append(out.Listeners, localapi.LinuxListener{
			Proto: l.Proto, Addr: l.Addr, Port: l.Port,
			Scope: l.Scope, Process: l.Process,
		})
	}
	for _, e := range rep.Hosts.Entries {
		out.Hosts.Entries = append(out.Hosts.Entries, localapi.LinuxHostEntry{
			IP: e.IP, Hostname: e.Hostname,
		})
	}
	return out
}

func (b *localBackend) BrowserAudit() localapi.BrowserView {
	rep := hygiene.BrowserAudit()
	out := localapi.BrowserView{
		Extensions: make([]localapi.LinuxBrowserExt, 0, len(rep.Extensions)),
		Policies:   make([]localapi.LinuxBrowserPolicy, 0, len(rep.Policies)),
		Scanned:    rep.Scanned,
	}
	for _, e := range rep.Extensions {
		out.Extensions = append(out.Extensions, localapi.LinuxBrowserExt{
			Browser: e.Browser, Profile: e.Profile, ID: e.ID, Name: e.Name,
			Version: e.Version, HostWide: e.HostWide, RiskyPerms: e.RiskyPerms,
		})
	}
	for _, p := range rep.Policies {
		out.Policies = append(out.Policies, localapi.LinuxBrowserPolicy{
			Browser: p.Browser, Key: p.Key, Detail: p.Detail, Count: p.Count,
		})
	}
	return out
}

func (b *localBackend) PersistAudit() []localapi.PersistAuditView {
	aud := hygiene.NewAuditor()
	if aud == nil {
		return nil
	}
	// 基线键集合来自 persist 监控（与 Windows 同口径：基线外 = 新驻留）
	baseline := make(map[string]bool)
	if b.a.pm != nil {
		for _, it := range b.a.pm.Items() {
			baseline[it.Key] = true
		}
	}
	// PersistAudit 需要 []persist.PersistItem；基线里只有记录投影
	//（persist.Item），按同字段重建（评分钩子需要的字段齐备）
	items := make([]persist.PersistItem, 0, len(b.a.pm.Items()))
	for _, it := range b.a.pm.Items() {
		items = append(items, persist.PersistItem{
			Key: it.Key, Type: it.Kind, Location: it.Location,
			Name: it.Key, Command: it.Value, Enabled: true,
		})
	}
	findings := aud.AuditPersistItems(items, baseline)
	out := make([]localapi.PersistAuditView, 0, len(findings))
	for _, f := range findings {
		out = append(out, localapi.PersistAuditView{
			Key: f.Key, Kind: f.Kind, Location: f.Location, Name: f.Name,
			Command: f.Command, Enabled: f.Enabled, RunAs: f.RunAs,
			Elevated: f.Elevated, Trigger: f.Trigger, ExePath: f.ExePath,
			File: localapi.LinuxFileMeta{
				Exists: f.File.Exists, Signed: f.File.Signed,
				SigState: f.File.SigState, Signer: f.File.Signer,
				Company: f.File.Company, Description: f.File.Description,
			},
			InBaseline: f.InBaseline, Flags: f.Flags,
		})
	}
	return out
}
