package isolate

import (
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// 补集正确性是本功能的安全根基：补集 ∪ kept 必须 = universe，且两两
// 不相交。用点采样验证（前缀代数对拍容易共享同一个错误假设）。
func TestCarveCoversUniverseExactly(t *testing.T) {
	kept := []netip.Prefix{
		netip.MustParsePrefix("10.1.2.3/32"),
		netip.MustParsePrefix("127.0.0.0/8"),
		netip.MustParsePrefix("10.9.0.0/16"),
	}
	universe := netip.MustParsePrefix("0.0.0.0/0")
	comp := Carve(universe, kept)

	if len(comp) > CoverCount(kept) {
		t.Fatalf("补集条数 %d 超上界 %d", len(comp), CoverCount(kept))
	}
	for _, c := range comp {
		for _, k := range kept {
			if k.Contains(c.Addr()) {
				t.Fatalf("补集前缀 %s 落在 kept %s 内", c, k)
			}
		}
	}
	check := func(ip netip.Addr, wantInKeep bool) {
		t.Helper()
		inKeep := false
		for _, k := range kept {
			if k.Contains(ip) {
				inKeep = true
			}
		}
		if inKeep != wantInKeep {
			t.Fatalf("%s inKeep=%v want=%v", ip, inKeep, wantInKeep)
		}
		hits := 0
		for _, c := range comp {
			if c.Contains(ip) {
				hits++
			}
		}
		if wantInKeep && hits != 0 {
			t.Fatalf("kept 点 %s 被补集覆盖 %d 次（必须在掏空区之外）", ip, hits)
		}
		if !wantInKeep && hits != 1 {
			t.Fatalf("非 kept 点 %s 被补集覆盖 %d 次（必须恰好 1 片）", ip, hits)
		}
	}
	check(netip.MustParseAddr("10.1.2.3"), true)
	check(netip.MustParseAddr("10.1.2.4"), false) // server /32 的邻居必须被 block
	check(netip.MustParseAddr("127.0.0.1"), true)
	check(netip.MustParseAddr("10.9.255.255"), true)
	check(netip.MustParseAddr("10.10.0.1"), false)
	check(netip.MustParseAddr("8.8.8.8"), false)
	check(netip.MustParseAddr("192.168.1.1"), false)
}

func TestCarveIPv6(t *testing.T) {
	universe := netip.MustParsePrefix("::/0")
	kept := []netip.Prefix{netip.MustParsePrefix("::1/128"), netip.MustParsePrefix("2001:db8::/32")}
	comp := Carve(universe, kept)
	if len(comp) == 0 || len(comp) > CoverCount(kept) {
		t.Fatalf("v6 补集条数异常: %d", len(comp))
	}
	for _, c := range comp {
		if c.Contains(netip.MustParseAddr("::1")) {
			t.Fatal("::1 被补集覆盖")
		}
		if c.Contains(netip.MustParseAddr("2001:db8::1")) {
			t.Fatal("2001:db8::1 被补集覆盖")
		}
	}
}

// BuildRules 的确定性：同一 KeepSet 两次构建规则完全一致——篡改重施加
// 的幂等性根基；保留地址绝不能出现在任何 block CIDR 里。
func TestBuildRulesDeterministic(t *testing.T) {
	keep := KeepSet{
		Server:   netip.MustParsePrefix("10.1.2.3/32"),
		Loopback: netip.MustParsePrefix("127.0.0.0/8"),
		DNS:      []netip.Prefix{netip.MustParsePrefix("10.0.0.1/32")},
	}
	a := BuildRules(keep)
	b := BuildRules(keep)
	if len(a) != len(b) {
		t.Fatalf("两次构建规则数不同: %d vs %d", len(a), len(b))
	}
	for i := range a {
		if a[i].Name != b[i].Name || a[i].CIDR != b[i].CIDR || a[i].Direction != b[i].Direction {
			t.Fatalf("第 %d 条不一致: %+v vs %+v", i, a[i], b[i])
		}
	}
	for _, r := range a {
		p := netip.MustParsePrefix(r.CIDR)
		// 出站必须保住全部保留地址；入站只保 loopback（server→agent 无
		// 入站需求，出站回包由防火墙状态化放行，不受入站 block 影响）
		if r.Direction == "out" {
			for _, kept := range []netip.Prefix{keep.Server, keep.Loopback, keep.DNS[0]} {
				if p.Contains(kept.Addr()) {
					t.Fatalf("出站规则 %s(%s) 包含保留地址 %s", r.Name, r.CIDR, kept)
				}
			}
		} else if p.Contains(keep.Loopback.Addr()) {
			t.Fatalf("入站规则 %s(%s) 包含 loopback", r.Name, r.CIDR)
		}
		if r.Direction == "in" && r.CIDR == "0.0.0.0/0" {
			t.Fatal("入站存在 0.0.0.0/0 全断规则——loopback 会被杀")
		}
	}
}

// fakeFW 是内存防火墙：单条规则粒度（name+direction+cidr）+ profile 启停。
type fakeFW struct {
	mu       sync.Mutex
	rules    map[string]Rule
	profiles map[string]bool
}

func newFakeFW() *fakeFW {
	return &fakeFW{
		rules:    map[string]Rule{},
		profiles: map[string]bool{"domain": false, "private": false, "public": false},
	}
}

func (f *fakeFW) AddBlock(name, direction, cidr string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rules[name] = Rule{Name: name, Direction: direction, CIDR: cidr}
	return nil
}
func (f *fakeFW) DeleteByPrefix(prefix string) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for k := range f.rules {
		if len(k) >= len(prefix) && k[:len(prefix)] == prefix {
			delete(f.rules, k)
			n++
		}
	}
	return n, nil
}
func (f *fakeFW) ListByPrefix(prefix string) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for k := range f.rules {
		if len(k) >= len(prefix) && k[:len(prefix)] == prefix {
			out = append(out, k)
		}
	}
	return out, nil
}
func (f *fakeFW) ProfileStates() (map[string]bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := map[string]bool{}
	for k, v := range f.profiles {
		out[k] = v
	}
	return out, nil
}
func (f *fakeFW) SetProfileEnabled(profile string, on bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.profiles[profile]; !ok {
		return fmt.Errorf("未知 profile: %s", profile)
	}
	f.profiles[profile] = on
	return nil
}

func newTestMgr(t *testing.T, fw Firewall) *Manager {
	t.Helper()
	return NewManager(fw, filepath.Join(t.TempDir(), "isolation.json"), func() []netip.Addr {
		return []netip.Addr{netip.MustParseAddr("10.0.0.1")}
	}, testLogger())
}

// TestIsolateLifecycle 施加→落盘→篡改→修复→TTL 到期→解除 全流程。
func TestIsolateLifecycle(t *testing.T) {
	fw := newFakeFW()
	m := newTestMgr(t, fw)

	if err := m.Apply("10.1.2.3", MinTTL, "test"); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !m.Isolated() {
		t.Fatal("施加后应处于隔离态")
	}
	if _, err := os.Stat(m.statePath); err != nil {
		t.Fatalf("状态文件未落盘: %v", err)
	}

	// 篡改：规则全删，Repair 应识别并恢复
	_, _ = fw.DeleteByPrefix(RulePrefix)
	tampered, err := m.Repair()
	if err != nil {
		t.Fatalf("Repair: %v", err)
	}
	if !tampered {
		t.Fatal("规则全删后 Repair 应报告篡改")
	}
	live, _ := fw.ListByPrefix(RulePrefix)
	if len(live) == 0 {
		t.Fatal("Repair 后规则应恢复")
	}

	// TTL 到期自动解除
	m.mu.Lock()
	m.active.Until = time.Now().Add(-time.Second)
	m.mu.Unlock()
	released, err := m.CheckExpiry(time.Now())
	if err != nil || !released {
		t.Fatalf("CheckExpiry: released=%v err=%v", released, err)
	}
	if m.Isolated() {
		t.Fatal("TTL 到期后应解除隔离")
	}
	if n, _ := fw.ListByPrefix(RulePrefix); len(n) != 0 {
		t.Fatalf("解除后规则应清空，剩 %d", len(n))
	}
}

// TestStartupOrphanCleanup 重启无态 + 有残规则 → 清理（fail-open）；
// 重启有未过期态 → 恢复隔离（fail-closed）。
func TestStartupOrphanCleanup(t *testing.T) {
	fw := newFakeFW()
	m := newTestMgr(t, fw)
	_ = fw.AddBlock(RulePrefix+"OUT-000", "out", "1.0.0.0/8")
	if err := m.LoadStartup(); err != nil {
		t.Fatalf("LoadStartup: %v", err)
	}
	if n, _ := fw.ListByPrefix(RulePrefix); len(n) != 0 {
		t.Fatalf("孤儿规则应被清理，剩 %d", len(n))
	}

	fw2 := newFakeFW()
	m2 := newTestMgr(t, fw2)
	if err := m2.Apply("10.1.2.3", MinTTL, "test"); err != nil {
		t.Fatal(err)
	}
	// 模拟重启：新 Manager 读同一状态文件
	m3 := NewManager(fw2, m2.statePath, m2.dnsFn, testLogger())
	if err := m3.LoadStartup(); err != nil {
		t.Fatalf("重启恢复: %v", err)
	}
	if !m3.Isolated() {
		t.Fatal("未过期隔离态重启后应恢复隔离（fail-closed）")
	}
}

// TestApplyRejectsUnresolvable 解析失败必须拒绝——盲盒隔离是事故。
func TestApplyRejectsUnresolvable(t *testing.T) {
	fw := newFakeFW()
	m := NewManager(fw, "", nil, testLogger())
	if err := m.Apply("nonexistent.invalid.example", 0, "test"); err == nil {
		t.Fatal("不可解析的 server 必须拒绝隔离")
	}
	if m.Isolated() {
		t.Fatal("拒绝执行后不应处于隔离态")
	}
	if n, _ := fw.ListByPrefix(RulePrefix); len(n) != 0 {
		t.Fatal("拒绝执行不应留下规则")
	}
}

// TestTTLClamp ttl 钳制：秒级手滑抬到 MinTTL，超长压到 MaxTTL。
func TestTTLClamp(t *testing.T) {
	fw := newFakeFW()
	m := newTestMgr(t, fw)
	if err := m.Apply("10.1.2.3", time.Second, "test"); err != nil {
		t.Fatal(err)
	}
	if until := m.Active().Until; time.Until(until) > MinTTL+time.Minute {
		t.Fatalf("秒级 ttl 应被钳到 MinTTL, got %v", time.Until(until))
	}
	if err := m.Release(); err != nil {
		t.Fatal(err)
	}
	if err := m.Apply("10.1.2.3", 30*24*time.Hour, "test"); err != nil {
		t.Fatal(err)
	}
	if until := m.Active().Until; time.Until(until) > MaxTTL+time.Minute {
		t.Fatalf("超长 ttl 应被钳到 MaxTTL, got %v", time.Until(until))
	}
}

// TestProfileStateLifecycle 真机实测教训的回归：防火墙关闭的机器上
// 规则不执行——施加必须隐式启用并记录原状，解除还原（不永久改用户
// 机器的防火墙配置）；隔离中防火墙被关 → Repair 重新启用并计篡改。
func TestProfileStateLifecycle(t *testing.T) {
	fw := newFakeFW()
	m := newTestMgr(t, fw)
	if err := m.Apply("10.1.2.3", MinTTL, "test"); err != nil {
		t.Fatal(err)
	}
	states, _ := fw.ProfileStates()
	for p, on := range states {
		if !on {
			t.Fatalf("施加后 profile %s 应启用", p)
		}
	}
	// 篡改：把防火墙整个关掉
	_ = fw.SetProfileEnabled("private", false)
	tampered, err := m.Repair()
	if err != nil {
		t.Fatalf("Repair: %v", err)
	}
	if !tampered {
		t.Fatal("防火墙被关应报告篡改")
	}
	states, _ = fw.ProfileStates()
	if !states["private"] {
		t.Fatal("Repair 后 private 应重新启用")
	}
	// 解除还原：原状全 off → 全 off
	if err := m.Release(); err != nil {
		t.Fatal(err)
	}
	states, _ = fw.ProfileStates()
	for p, on := range states {
		if on {
			t.Fatalf("解除后 profile %s 应还原为关闭", p)
		}
	}
}
