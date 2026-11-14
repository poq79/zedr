// 本测试文件 NEUTRAL：/sessions utmp 解析纯逻辑在 Windows 上跑。
// 夹具 testdata/utmp 为按 x86_64 glibc 布局手工构造的 5 条记录
// （生成口径见 sessions_linuxparse.go 头注释）。
package liveapi

import (
	"encoding/binary"
	"encoding/json"
	"strings"
	"testing"
)

func TestParseUtmpActiveSessionsFixture(t *testing.T) {
	data := mustFixture(t, "utmp")
	if len(data) != 5*400 {
		t.Fatalf("夹具应为 5 条 x86_64 记录（2000B）实得 %dB", len(data))
	}

	items, ok := parseUtmpActiveSessions(data)
	if !ok {
		t.Fatal("夹具应按 x86_64 布局解析成功")
	}
	if len(items) != 2 {
		t.Fatalf("应只有 2 条 USER_PROCESS 实得 %d: %+v", len(items), items)
	}

	res := buildLinuxSessionsResult(items, "")
	if res["total"] != 2 || res["note"] != nil {
		t.Errorf("投影 total/note 口径不符: %v", res)
	}

	// 排序：logon_time 倒序 → kali(pts/0, 1700000100) 在前，root(tty1)在后
	sorted := res["items"].([]linuxSessionItem)
	if sorted[0].Username != "kali" || sorted[1].Username != "root" {
		t.Fatalf("排序/用户名不符: %+v", sorted)
	}
	kali := sorted[0]
	if kali.LogonID != 4321 { // logon_id = ut_pid（登录进程号）
		t.Errorf("logon_id 应为 ut_pid=4321: %+v", kali)
	}
	if kali.LogonTypeName != "remote" { // pts + 远端 host
		t.Errorf("pts+host 应判 remote: %+v", kali)
	}
	if kali.LogonTime == nil || *kali.LogonTime != 1700000100 {
		t.Errorf("logon_time 应为 1700000100: %+v", kali)
	}
	if kali.Domain != "" || kali.AuthPackage != "" || kali.Session != 0 || kali.LogonType != 0 {
		t.Errorf("无对等字段应留空/零: %+v", kali)
	}
	root := sorted[1]
	if root.LogonTypeName != "console" || root.LogonID != 990 {
		t.Errorf("tty 会话口径不符: %+v", root)
	}

	// JSON 形状锁：与 Windows sessionItem 的 json tag 逐字一致
	b, _ := json.Marshal(kali)
	var probe map[string]any
	if err := json.Unmarshal(b, &probe); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"logon_id", "username", "domain", "logon_type",
		"logon_type_name", "session", "logon_time", "auth_package"} {
		if _, ok := probe[k]; !ok {
			t.Errorf("items[] 缺少字段 %q: %s", k, b)
		}
	}
}

func TestParseUtmpEdgeCases(t *testing.T) {
	// 空文件 = 无会话（不是错误）
	if items, ok := parseUtmpActiveSessions(nil); !ok || items != nil {
		t.Errorf("空文件应 ok 且无条目: %v %v", items, ok)
	}

	// 布局不匹配：长度不整除
	if _, ok := parseUtmpActiveSessions(make([]byte, 399)); ok {
		t.Error("399B 应判布局不匹配")
	}

	// 布局不匹配：整除但 ut_type 越界（800B 垃圾）→ 整表放弃
	junk := make([]byte, 800)
	binary.LittleEndian.PutUint16(junk[0:], 77)
	if _, ok := parseUtmpActiveSessions(junk); ok {
		t.Error("ut_type 越界应整表放弃")
	}

	// i386 布局兜底：384B 记录可解析（tv_sec@340 4B）
	rec := utmpFixtureRecord(utmpLayout386, utmpUserProcess, 55, "pts/3", "s/3", "alice", "", 1700000200)
	items, ok := parseUtmpActiveSessions(rec)
	if !ok || len(items) != 1 || items[0].Username != "alice" {
		t.Fatalf("i386 布局解析不符: %v %+v", ok, items)
	}
	if items[0].LogonTime == nil || *items[0].LogonTime != 1700000200 {
		t.Errorf("i386 布局 tv_sec 偏移不符: %+v", items[0])
	}

	// USER_PROCESS 但 user 为空：宁缺毋滥跳过
	bad := utmpFixtureRecord(utmpLayoutAMD64, utmpUserProcess, 1, "pts/9", "s/9", "", "", 1700000000)
	if items, ok := parseUtmpActiveSessions(bad); !ok || len(items) != 0 {
		t.Errorf("空 user 记录应跳过: %v %+v", ok, items)
	}
}

func TestUtmpSessionTypeName(t *testing.T) {
	cases := map[[2]string]string{
		{"tty1", ""}:          "console",
		{"console", ""}:       "other", // console 不带 tty 前缀，落 other（不硬套词汇）
		{"pts/0", "10.1.2.3"}: "remote",
		{"pts/0", ""}:         "local-pts",
		{"pts/0", ":0"}:       "local-pts",
		{"", ":0"}:            "display",
		{"", ""}:              "other",
	}
	for in, want := range cases {
		if got := utmpSessionTypeName(in[0], in[1]); got != want {
			t.Errorf("utmpSessionTypeName(%q,%q)=%q 期望 %q", in[0], in[1], got, want)
		}
	}
}

func TestBuildLinuxSessionsResultEmpty(t *testing.T) {
	res := buildLinuxSessionsResult(nil, "无会话")
	if res["total"] != 0 {
		t.Errorf("total 应为 0: %v", res["total"])
	}
	items, ok := res["items"].([]linuxSessionItem)
	if !ok || items == nil || len(items) != 0 {
		t.Errorf("items 应为空数组而非 null: %T", res["items"])
	}
	if note, ok := res["note"].(string); !ok || !strings.Contains(note, "会话") {
		t.Errorf("note 应透传: %v", res["note"])
	}
}
