// 本测试文件 NEUTRAL：/services Linux 投影纯逻辑在 Windows 上跑。
// 夹具：testdata/systemd-unit.service。
package liveapi

import (
	"strings"
	"testing"
)

func TestBuildLinuxServicesResult(t *testing.T) {
	raws := []linuxServiceRaw{
		{
			Name:        "sshd",
			Description: "OpenBSD Secure Shell server",
			ExecStart:   "/usr/sbin/sshd -D",
			UnitPath:    "/usr/lib/systemd/system/ssh.service",
			Enabled:     true,
		},
		{
			Name:        "cups",
			Description: "CUPS scheduler",
			ExecStart:   "/usr/sbin/cupsd -l",
			UnitPath:    "/usr/lib/systemd/system/cups.service",
		},
		{
			Name:     "oneshot-without-exec",
			UnitPath: "/etc/systemd/system/mount-thing.service",
			Enabled:  true,
		},
	}

	res := buildLinuxServicesResult(raws, "", "", 500)
	items := res["items"].([]linuxServiceItem)
	if len(items) != 3 || res["total"] != 3 || res["truncated"] != false {
		t.Fatalf("全量口径不符: %v", res)
	}
	// 按 name 排序：cups, oneshot-without-exec, sshd
	if items[0].Name != "cups" || items[2].Name != "sshd" {
		t.Errorf("排序口径不符: %+v", items)
	}

	// enabled → state=enabled + start_mode=auto + path_name=ExecStart 完整行
	sshd := items[2]
	if sshd.State != "enabled" || sshd.StartMode != "auto" ||
		sshd.PathName != "/usr/sbin/sshd -D" || sshd.DisplayName != "OpenBSD Secure Shell server" {
		t.Errorf("enabled unit 投影不符: %+v", sshd)
	}
	// 未启用 → disabled 二分（static 归并，注释见 services_linuxparse.go）
	cups := items[0]
	if cups.State != "disabled" || cups.StartMode != "disabled" || cups.PathName != "/usr/sbin/cupsd -l" {
		t.Errorf("disabled unit 投影不符: %+v", cups)
	}
	// 无 ExecStart → path_name 回退 unit 路径
	if o := items[1]; o.PathName != "/etc/systemd/system/mount-thing.service" {
		t.Errorf("无 ExecStart 应回退 unit 路径: %+v", o)
	}
	// state 口径 note 恒在（Linux 特有键）
	if note, ok := res["note"].(string); !ok || !strings.Contains(note, "启用口径") {
		t.Errorf("state 口径 note 缺失: %v", res["note"])
	}

	// filter：服务名或显示名（大小写不敏感），Windows 同口径
	res = buildLinuxServicesResult(raws, "OPENBSD", "", 500)
	items = res["items"].([]linuxServiceItem)
	if len(items) != 1 || items[0].Name != "sshd" {
		t.Errorf("filter 按显示名匹配失败: %+v", items)
	}
	res = buildLinuxServicesResult(raws, "cups", "", 500)
	if items = res["items"].([]linuxServiceItem); len(items) != 1 || items[0].Name != "cups" {
		t.Errorf("filter 按服务名匹配失败: %+v", items)
	}

	// state 过滤（Linux 词汇 enabled/disabled）；传 Windows 词汇得空集——诚实结果
	res = buildLinuxServicesResult(raws, "", "disabled", 500)
	if items = res["items"].([]linuxServiceItem); len(items) != 1 || items[0].Name != "cups" {
		t.Errorf("state=disabled 过滤不符: %+v", items)
	}
	res = buildLinuxServicesResult(raws, "", "running", 500)
	if items = res["items"].([]linuxServiceItem); len(items) != 0 {
		t.Errorf("state=running（Windows 词汇）应得空集: %+v", items)
	}

	// limit 截断
	res = buildLinuxServicesResult(raws, "", "", 1)
	if items = res["items"].([]linuxServiceItem); len(items) != 1 || res["truncated"] != true {
		t.Errorf("limit 截断口径不符: %v", res)
	}
}

func TestParseLinuxUnitExecStartPrefix(t *testing.T) {
	// 前缀修饰符剥离（与 parseSystemdUnitExec 同口径）
	unit := []byte("[Service]\nExecStart=-/usr/sbin/srv --flag\n")
	if got := parseLinuxUnit(unit).ExecStart; got != "/usr/sbin/srv --flag" {
		t.Errorf("前缀修饰符应剥离且保留参数: %q", got)
	}
}
