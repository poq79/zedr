//go:build windows
// +build windows

package winapi

import (
	"os"
	"strings"
	"testing"
	"time"
)

// 本文件是资产盘点函数的真机冒烟测试：本机就是 Windows，函数直接真调。
//
// 断言只保持"基本合理"水位（数量级 / 非零 / 包含系统盘），不绑定具体
// 环境数值——这台机器的服务数、任务数都会随时间漂移，测具体数字
// 只会让测试变成维护负担。

func TestUDPListeners(t *testing.T) {
	entries, err := UDPListeners()
	if err != nil {
		t.Fatalf("UDPListeners 失败: %v", err)
	}
	t.Logf("UDP 监听 %d 条", len(entries))
	for i, e := range entries {
		if i >= 5 {
			break
		}
		t.Logf("  port=%d pid=%d", e.Port, e.PID)
	}
}

func TestAdapters(t *testing.T) {
	adapters, err := Adapters()
	if err != nil {
		t.Fatalf("Adapters 失败: %v", err)
	}
	if len(adapters) < 1 {
		t.Fatalf("Adapters 返回 0 条，正常机器至少有回环/物理网卡")
	}
	for _, a := range adapters {
		t.Logf("  name=%q mac=%s oper=%s ips=%v gw=%s dns=%v",
			a.Name, a.MAC, a.OperState, a.IPs, a.Gateway, a.DNS)
	}
}

func TestServiceList(t *testing.T) {
	svcs, err := ServiceList()
	if err != nil {
		t.Fatalf("ServiceList 失败: %v", err)
	}
	if len(svcs) < 10 {
		t.Fatalf("ServiceList 仅 %d 条，低于合理下限 10", len(svcs))
	}
	withPath := 0
	for _, s := range svcs {
		if s.State == "" {
			t.Errorf("服务 %s 的 State 为空", s.Name)
		}
		if s.PathName != "" {
			withPath++
		}
	}
	if withPath == 0 {
		t.Errorf("没有任何服务的 PathName 非空，QueryServiceConfig 可能整体失败")
	}
	t.Logf("服务 %d 条，PathName 非空 %d 条", len(svcs), withPath)
	for i, s := range svcs {
		if i >= 5 {
			break
		}
		t.Logf("  %s [%s] state=%s mode=%s acct=%q path=%q",
			s.Name, s.DisplayName, s.State, s.StartMode, s.Account, s.PathName)
	}
}

func TestTaskList(t *testing.T) {
	tasks, err := TaskList()
	if err != nil {
		t.Fatalf("TaskList 失败: %v", err)
	}
	if len(tasks) < 1 {
		t.Errorf("TaskList 返回 0 条，正常 Windows 至少有微软默认任务")
	}
	for i, tk := range tasks {
		if i >= 5 {
			break
		}
		t.Logf("  path=%s name=%s state=%s", tk.Path, tk.Name, tk.State)
	}
}

func TestDiskVolumes(t *testing.T) {
	vols, err := DiskVolumes()
	if err != nil {
		t.Fatalf("DiskVolumes 失败: %v", err)
	}
	sysDrive := strings.ToUpper(strings.TrimSuffix(os.Getenv("SystemDrive"), `\`))
	if sysDrive == "" {
		sysDrive = "C:"
	}
	found := false
	for _, v := range vols {
		t.Logf("  %s total=%dMB free=%dMB", v.Drive, v.TotalMB, v.FreeMB)
		if v.Drive == sysDrive {
			found = true
			if v.TotalMB == 0 {
				t.Errorf("系统盘 %s TotalMB 为 0", sysDrive)
			}
			if v.FreeMB > v.TotalMB {
				t.Errorf("系统盘 %s 剩余 %dMB 大于总量 %dMB", sysDrive, v.FreeMB, v.TotalMB)
			}
		}
	}
	if !found {
		t.Errorf("未找到系统盘 %s（返回 %d 个卷）", sysDrive, len(vols))
	}
}

func TestMemoryStats(t *testing.T) {
	total, free, err := MemoryStats()
	if err != nil {
		t.Fatalf("MemoryStats 失败: %v", err)
	}
	if total == 0 {
		t.Errorf("totalMB 为 0")
	}
	if free == 0 || free > total {
		t.Errorf("freeMB=%d / totalMB=%d 不合理", free, total)
	}
	t.Logf("内存 total=%dMB free=%dMB", total, free)
}

func TestCPUInfo(t *testing.T) {
	name, cores, err := CPUInfo()
	if err != nil {
		t.Fatalf("CPUInfo 失败: %v", err)
	}
	if cores < 1 {
		t.Errorf("cores=%d", cores)
	}
	if name == "" {
		t.Errorf("CPU 名称为空")
	}
	t.Logf("CPU %s / %d 逻辑核", name, cores)
}

func TestBootTime(t *testing.T) {
	boot, err := BootTime()
	if err != nil {
		t.Fatalf("BootTime 失败: %v", err)
	}
	now := time.Now()
	if boot.After(now) {
		t.Errorf("开机时间 %v 在未来", boot)
	}
	if boot.Before(now.Add(-90 * 24 * time.Hour)) {
		t.Errorf("开机时间 %v 超出 90 天窗口", boot)
	}
	t.Logf("开机时间 %s（已运行 %s）", boot.Format(time.RFC3339), now.Sub(boot).Round(time.Minute))
}

// TestInventoryTiming 记录每个函数的真实耗时。
// <50ms 是设计目标，不做过硬断言（CI 抖动会造成假红），只对失败报错。
func TestInventoryTiming(t *testing.T) {
	for _, tc := range []struct {
		name string
		fn   func() error
	}{
		{"UDPListeners", func() error { _, err := UDPListeners(); return err }},
		{"Adapters", func() error { _, err := Adapters(); return err }},
		{"ServiceList", func() error { _, err := ServiceList(); return err }},
		{"TaskList", func() error { _, err := TaskList(); return err }},
		{"DiskVolumes", func() error { _, err := DiskVolumes(); return err }},
		{"MemoryStats", func() error { _, _, err := MemoryStats(); return err }},
		{"CPUInfo", func() error { _, _, err := CPUInfo(); return err }},
		{"BootTime", func() error { _, err := BootTime(); return err }},
	} {
		start := time.Now()
		err := tc.fn()
		if err != nil {
			t.Errorf("%s 失败: %v", tc.name, err)
			continue
		}
		t.Logf("%-14s %v", tc.name, time.Since(start).Round(time.Microsecond))
	}
}
