// 本测试文件 NEUTRAL：/tasks Linux 投影纯逻辑在 Windows 上跑。
// 夹具：testdata/crontab-system、testdata/crontab-spool-alice、
// testdata/systemd-timer.timer、testdata/systemd-timer-paired.service、
// testdata/systemd-unit.service。
package liveapi

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestParseCrontabEntriesFixture(t *testing.T) {
	sys := parseCrontabEntries("/etc/crontab", mustFixture(t, "crontab-system"), true)
	// SHELL/PATH 环境行、注释、空行、"残行不够长"（1 列）全部跳过
	if len(sys) != 5 {
		t.Fatalf("系统表期望 5 条实得 %d: %+v", len(sys), sys)
	}
	if sys[0].Schedule != "17 * * * *" || sys[0].User != "root" ||
		!strings.HasPrefix(sys[0].Command, "cd / && run-parts") {
		t.Errorf("系统表条目口径不符: %+v", sys[0])
	}
	if sys[2].Schedule != "@reboot" || !strings.HasPrefix(sys[2].Command, "/usr/local/bin/phonedome.sh") {
		t.Errorf("@reboot 条目口径不符: %+v", sys[2])
	}
	if sys[3].User != "backup" || sys[3].Schedule != "0 3 * * *" {
		t.Errorf("多 user 列口径不符: %+v", sys[3])
	}
	if !strings.HasPrefix(sys[4].Command, "curl") {
		t.Errorf("管道命令应原样呈现: %+v", sys[4])
	}

	// parseCrontabFile（/persistence 旧口径）与新解析互为镜像
	persist := parseCrontabFile("/etc/crontab", mustFixture(t, "crontab-system"), true)
	if len(persist) != 5 || persist[0].Source != "task" || persist[0].Name != "/etc/crontab" {
		t.Errorf("parseCrontabFile 投影漂移: %+v", persist[0])
	}

	spool := parseCrontabEntries("/var/spool/cron/crontabs/alice", mustFixture(t, "crontab-spool-alice"), false)
	if len(spool) != 3 || spool[0].User != "" || spool[1].Schedule != "@daily" {
		t.Errorf("spool 口径不符: %+v", spool)
	}
}

func TestCronTriggerType(t *testing.T) {
	cases := map[string]string{
		"@reboot":     "Boot",
		"@daily":      "Daily",
		"@midnight":   "Daily",
		"@weekly":     "Weekly",
		"@monthly":    "Monthly",
		"@yearly":     "Monthly",
		"@annually":   "Monthly",
		"@hourly":     "Time",
		"0 3 * * *":   "Cron",
		"*/5 * * * *": "Cron",
	}
	for in, want := range cases {
		if got := cronTriggerType(in); got != want {
			t.Errorf("cronTriggerType(%q)=%q 期望 %q", in, got, want)
		}
	}
}

func TestTimerTriggerType(t *testing.T) {
	cases := map[string]string{
		"OnBootSec":         "Boot",
		"OnStartupSec":      "Boot",
		"OnCalendar":        "Calendar",
		"OnUnitActiveSec":   "Time",
		"OnUnitInactiveSec": "Time",
		"":                  "Timer",
		"OnUnknownFuture":   "Timer",
	}
	for in, want := range cases {
		if got := timerTriggerType(in); got != want {
			t.Errorf("timerTriggerType(%q)=%q 期望 %q", in, got, want)
		}
	}
}

func TestParseLinuxUnitFixture(t *testing.T) {
	svc := parseLinuxUnit(mustFixture(t, "systemd-unit.service"))
	if svc.Description != "OpenBSD Secure Shell server" {
		t.Errorf("Description 口径不符: %q", svc.Description)
	}
	// ExecStart 完整命令行（含参数/变量），ExecStartPre 不串味
	if svc.ExecStart != "/usr/sbin/sshd -D $SSHD_OPTS" {
		t.Errorf("ExecStart 口径不符: %q", svc.ExecStart)
	}
	if svc.User != "" {
		t.Errorf("未显式 User= 应为空: %q", svc.User)
	}
	if svc.TimerKey != "" {
		t.Errorf("service 不应有 timer 键: %q", svc.TimerKey)
	}

	timer := parseLinuxUnit(mustFixture(t, "systemd-timer.timer"))
	if timer.TimerKey != "OnCalendar" || timer.TimerValue != "*-*-* 06:00" {
		t.Errorf("timer 键口径不符: %+v", timer)
	}

	paired := parseLinuxUnit(mustFixture(t, "systemd-timer-paired.service"))
	if paired.ExecStart != "/usr/bin/apt-get autoclean" || paired.User != "apt-cleaner" {
		t.Errorf("配套 service 口径不符: %+v", paired)
	}
}

func TestCronEntryToTaskItem(t *testing.T) {
	item := cronEntryToTaskItem("/etc/crontab", linuxCronEntry{
		Schedule: "@reboot", User: "root", Command: "/usr/local/bin/x.sh --now",
	})
	if item.Path != "/etc/crontab" || item.Name != "@reboot" || item.State != "unknown" ||
		item.Author != "root" || !item.Enabled || item.RunLevel != "" {
		t.Errorf("cron 条目投影口径不符: %+v", item)
	}
	if len(item.Triggers) != 1 || item.Triggers[0].Type != "Boot" || !item.Triggers[0].Enabled {
		t.Errorf("triggers 口径不符: %+v", item.Triggers)
	}
	if len(item.Actions) != 1 || item.Actions[0].Command != "/usr/local/bin/x.sh --now" ||
		item.Actions[0].Arguments != "" {
		t.Errorf("actions 口径不符: %+v", item.Actions)
	}

	// JSON 形状锁：与 Windows taskItem 逐字一致（+ 嵌套结构）
	b, _ := json.Marshal(item)
	var probe map[string]any
	if err := json.Unmarshal(b, &probe); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"path", "name", "state", "author", "enabled", "run_level", "triggers", "actions"} {
		if _, ok := probe[k]; !ok {
			t.Errorf("taskItem 缺少字段 %q: %s", k, b)
		}
	}
	btrig, _ := json.Marshal(item.Triggers[0])
	var trig map[string]any
	_ = json.Unmarshal(btrig, &trig)
	for _, k := range []string{"type", "enabled"} {
		if _, ok := trig[k]; !ok {
			t.Errorf("triggers[] 缺少字段 %q: %s", k, btrig)
		}
	}
	bact, _ := json.Marshal(item.Actions[0])
	var act map[string]any
	_ = json.Unmarshal(bact, &act)
	for _, k := range []string{"command", "arguments"} {
		if _, ok := act[k]; !ok {
			t.Errorf("actions[] 缺少字段 %q: %s", k, bact)
		}
	}
}

func TestTimerToTaskItem(t *testing.T) {
	info := linuxUnitInfo{TimerKey: "OnCalendar", TimerValue: "*-*-* 06:00"}
	item := timerToTaskItem("/etc/systemd/system/apt-daily.timer", "apt-daily",
		info, true, "/usr/bin/apt-get autoclean", "apt-cleaner")
	if item.Name != "apt-daily" || !item.Enabled || item.State != "unknown" {
		t.Errorf("timer 投影口径不符: %+v", item)
	}
	if item.Triggers[0].Type != "Calendar" {
		t.Errorf("OnCalendar 应映射 Calendar: %+v", item.Triggers)
	}
	if item.Author != "apt-cleaner" || len(item.Actions) != 1 ||
		item.Actions[0].Command != "/usr/bin/apt-get autoclean" {
		t.Errorf("run-as/执行体借用口径不符: %+v", item)
	}

	// 配套 service 缺失：actions 空数组（null 不行，Windows 同口径收敛）
	noSvc := timerToTaskItem("/x/a.timer", "a", info, false, "", "")
	if noSvc.Enabled || len(noSvc.Actions) != 0 || noSvc.Author != "" {
		t.Errorf("无配套 service 口径不符: %+v", noSvc)
	}
}

func TestBuildLinuxTasksResult(t *testing.T) {
	items := []linuxTaskItem{
		{Path: "/etc/crontab", Name: "@reboot"},
		{Path: "/etc/crontab", Name: "0 3 * * *"},
		{Path: "/etc/cron.d/backup", Name: "30 2 * * *"},
		{Path: "/var/spool/cron/crontabs/alice", Name: "@daily"},
		{Path: "/etc/systemd/system/apt-daily.timer", Name: "apt-daily"},
	}
	res := buildLinuxTasksResult(items, "cron.d", 200)
	if res["total"] != 5 {
		t.Errorf("total 是过滤前全量: %v", res["total"])
	}
	matched := res["items"].([]linuxTaskItem)
	if len(matched) != 1 || matched[0].Path != "/etc/cron.d/backup" {
		t.Errorf("filter 按 path 子串匹配: %+v", matched)
	}
	if res["truncated"] != false {
		t.Errorf("未截断时 truncated=false: %v", res["truncated"])
	}

	// 排序：path → name；截断在排序后
	res = buildLinuxTasksResult(items, "", 2)
	matched = res["items"].([]linuxTaskItem)
	if len(matched) != 2 || res["truncated"] != true {
		t.Fatalf("截断口径不符: %v", res)
	}
	if matched[0].Path != "/etc/cron.d/backup" || matched[1].Path != "/etc/crontab" ||
		matched[1].Name != "0 3 * * *" {
		t.Errorf("排序口径不符: %+v", matched)
	}
}
