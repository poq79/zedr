package winapi

import (
	"regexp"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// TestUsbstorFriendly 覆盖友好名解析的规整路径与失败兜底。
// 锚定样例来自契约：Disk&Ven_Kingston&Prod_DataTraveler_3.0
// → "Ven_Kingston Prod_DataTraveler_3.0"。
func TestUsbstorFriendly(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"Disk&Ven_Kingston&Prod_DataTraveler_3.0", "Ven_Kingston Prod_DataTraveler_3.0"},
		// Rev_ 段不属于 "Ven名 Prod名" 形态，规整时丢弃
		{"Disk&Ven_Kingston&Prod_DataTraveler_3.0&Rev_1.00", "Ven_Kingston Prod_DataTraveler_3.0"},
		{"CdRom&Ven_HP&Prod_CDDVDW_SN-208AB&Rev_SC00", "Ven_HP Prod_CDDVDW_SN-208AB"},
		// 前缀匹配大小写不敏感，段内保留原大小写
		{"disk&ven_kingston&prod_datatraveler_3.0", "ven_kingston prod_datatraveler_3.0"},
		// 解析失败兜底：给原键名，不给空串
		{"WeirdDevice", "WeirdDevice"},
		{"Disk&Foo&Bar", "Disk&Foo&Bar"},
		{"", ""},
	}
	for _, c := range cases {
		if got := usbstorFriendly(c.in); got != c.want {
			t.Errorf("usbstorFriendly(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestUsbRemovableVolumesSmoke 冒烟：返回值形如 "X:"、都属于当前逻辑盘、
// 有序。本机可能没有可移动介质——空结果合法，不报错。
func TestUsbRemovableVolumesSmoke(t *testing.T) {
	got := RemovableVolumes()

	mask, err := windows.GetLogicalDrives()
	if err != nil {
		t.Skipf("GetLogicalDrives 不可用: %v", err)
	}
	logical := make(map[string]bool)
	for i := 0; i < 26; i++ {
		if mask&(1<<uint(i)) != 0 {
			logical[string(rune('A'+i))+":"] = true
		}
	}

	volRe := regexp.MustCompile(`^[A-Z]:$`)
	for _, v := range got {
		if !volRe.MatchString(v) {
			t.Errorf("盘符格式非法: %q", v)
		}
		if !logical[v] {
			t.Errorf("返回了不存在的逻辑盘: %q", v)
		}
	}
	for i := 1; i < len(got); i++ {
		if got[i-1] >= got[i] {
			t.Errorf("未按稳定升序排列: %v", got)
			break
		}
	}
	t.Logf("可移动卷 %d 个: %v", len(got), got)
}

// TestUsbStorDevicesSmoke 冒烟：真实机器枚举不报错（函数无错误返回，
// 失败即空切片）；有记录时 Key 形态/Friendly/LastWrite 合理，且两次
// 调用结果一致（基线 diff 依赖确定性输出）。
func TestUsbStorDevicesSmoke(t *testing.T) {
	got := UsbStorDevices()
	now := time.Now()
	for _, d := range got {
		if d.Key == "" {
			t.Fatal("存在空 Key 的记录")
		}
		if !strings.HasPrefix(d.Key, `USBSTOR\`) || strings.Count(d.Key, `\`) != 2 {
			t.Errorf("Key 路径形态非法（应为 USBSTOR\\设备\\序列号）: %q", d.Key)
		}
		if d.Friendly == "" {
			t.Errorf("键 %q 的 Friendly 为空（解析失败也应回原键名）", d.Key)
		}
		if !d.LastWrite.IsZero() && d.LastWrite.After(now.Add(time.Hour)) {
			t.Errorf("键 %q 的 LastWrite 落在未来: %v", d.Key, d.LastWrite)
		}
	}

	// 稳定排序 + 确定性：两次调用输出完全一致。测试窗口内恰有设备
	// 插入会自然造成长度差，那种情况下只提示不算失败。
	again := UsbStorDevices()
	if len(again) == len(got) {
		for i := range got {
			if got[i] != again[i] {
				t.Errorf("两次枚举不一致:\n got[%d] = %+v\nagain[%d] = %+v", i, got[i], i, again[i])
			}
		}
		for i := 1; i < len(got); i++ {
			if got[i-1].Key >= got[i].Key {
				t.Errorf("未按 Key 稳定升序排列: %v", got)
				break
			}
		}
	} else {
		t.Logf("两次枚举条数变化（测试期间有设备接入/移除?）: %d -> %d", len(got), len(again))
	}
	t.Logf("USBSTOR 历史设备 %d 条", len(got))
}
