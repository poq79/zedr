//go:build windows

// ScanRegistry/registryTypes 是 Windows regwatch 路径的子集语义；
// winapi.PersistItem 构造夹具需要 winapi（Linux 构建不参与编译）。
package persist

import (
	"path/filepath"
	"testing"

	"zedr/internal/agent/winapi"
)

// 定向重扫（ScanRegistry）的子集语义是 regwatch 路径的安全前提：
// 只枚举注册表节时，其他节的基线记录既不许误报 Removed、也不许被删——
// 否则每 3s 一次的事件重扫会把全部服务/计划任务基线清空，
// 下一轮全量扫描集体误报 Added。
//
// 注：winapi.PersistItem → persist.PersistItem 经逐字段转换（scanWith
// 的入参形状是 persist 包自有类型，跨平台单一事实源），转换不改变
// 本测试的子集语义。
func TestScanRegistrySubsetKeepsOtherSections(t *testing.T) {
	dir := t.TempDir()
	m := New(filepath.Join(dir, "baseline.json"), nil)
	_ = m.Load()

	convert := func(items []winapi.PersistItem) []PersistItem {
		out := make([]PersistItem, 0, len(items))
		for _, it := range items {
			out = append(out, PersistItem{
				Key: it.Key, Type: it.Type, Location: it.Location, Name: it.Name,
				Command: it.Command, Enabled: it.Enabled,
				RunAs: it.RunAs, Elevated: it.Elevated, Trigger: it.Trigger,
			})
		}
		return out
	}

	regItem := winapi.PersistItem{Key: "reg|x", Type: winapi.PersistRegistryRun,
		Name: "x", Command: `C:\Windows\System32\notepad.exe`, Location: `HKLM\...\Run`}
	svcItem := winapi.PersistItem{Key: "svc|y", Type: winapi.PersistService,
		Name: "y", Command: `C:\Windows\System32\svchost.exe -k x`, Location: "Services"}

	all := func() ([]PersistItem, []string) {
		return convert([]winapi.PersistItem{regItem, svcItem}), nil
	}
	regOnly := func() ([]PersistItem, []string) {
		return convert([]winapi.PersistItem{regItem}), nil
	}

	// 全量首扫：两条进基线（wasEmpty → Initial，不产告警）
	res, err := m.scanWith(all, nil)
	if err != nil || !res.Initial {
		t.Fatalf("首扫应建基线: %+v, %v", res, err)
	}

	// 定向重扫：svc 不在枚举里，但也不许被误判 Removed/删记录
	res, err = m.scanWith(regOnly, registryTypes)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Removed) != 0 {
		t.Fatalf("定向重扫把非注册表基线判成 Removed: %v", res.Removed)
	}
	m.mu.Lock()
	_, svcKept := m.items["svc|y"]
	m.mu.Unlock()
	if !svcKept {
		t.Fatal("定向重扫删除了非注册表基线记录")
	}

	// 全量复扫：无任何变更（svc 仍在、reg 未变）
	res, err = m.scanWith(all, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Added)+len(res.Changed)+len(res.Removed) != 0 {
		t.Fatalf("复扫不应产生变更: added=%d changed=%d removed=%d",
			len(res.Added), len(res.Changed), len(res.Removed))
	}
}
