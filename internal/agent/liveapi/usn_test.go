package liveapi

// usn_test.go：/usn 的纯逻辑单测（盘符归一/扩展名归一/环形截取/reason
// 位映射）+ 真机冒烟（C: 卷预算内扫描、非法卷 400、name 过滤语义）。
// USN 读取依赖管理员句柄与真实 NTFS 卷，离线部分全平台可跑。

import (
	"net/http"
	"runtime"
	"testing"
	"time"

	"zedr/internal/agent/winapi"
)

func TestNormalizeUSNVolume(t *testing.T) {
	cases := []struct {
		in   string
		want string
		ok   bool
	}{
		{"", "C:", true},
		{"C:", "C:", true},
		{"c", "C:", true},
		{`C:\`, "C:", true},
		{"c:/", "C:", true},
		{"  d: ", "D:", true},
		{"Q", "Q:", true},
		{"CC:", "", false},
		{`C:\dir`, "", false},
		{"1:", "", false},
		{":C", "", false},
		{"C::", "", false},
	}
	for _, c := range cases {
		got, ok := normalizeUSNVolume(c.in)
		if ok != c.ok || got != c.want {
			t.Errorf("normalizeUSNVolume(%q) = (%q,%v)，期望 (%q,%v)", c.in, got, ok, c.want, c.ok)
		}
	}
}

func TestNormalizeUSNExt(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", ""},
		{"  ", ""},
		{".exe", ".exe"},
		{"exe", ".exe"},
		{" EXE ", ".exe"},
		{".PDF", ".pdf"},
	}
	for _, c := range cases {
		if got := normalizeUSNExt(c.in); got != c.want {
			t.Errorf("normalizeUSNExt(%q) = %q，期望 %q", c.in, got, c.want)
		}
	}
}

func TestUSNReasonNames(t *testing.T) {
	// 组合位按表序展开
	got := usnReasonNames(0x00002001) // data_overwrite | rename_new_name
	if got[0] != "data_overwrite" || got[1] != "rename_new_name" || len(got) != 2 {
		t.Errorf("组合位映射不符: %v", got)
	}
	// CLOSE 也在表内
	got = usnReasonNames(0x80000100) // file_create | close
	if len(got) != 2 || got[0] != "file_create" || got[1] != "close" {
		t.Errorf("close 位映射不符: %v", got)
	}
	// 未识别位不静默丢弃
	got = usnReasonNames(0x01000002) // data_extend | 0x01000000（表外）
	if len(got) != 2 || got[0] != "data_extend" || got[1] != "unknown_0x01000000" {
		t.Errorf("未知位应保留为 unknown 段: %v", got)
	}
}

// TestFilterUSNRecordsRing 验证"匹配总数超 max 时保留最近的那批"：
// 记录按 USN 升序注入，max=3 注入 5 条，留下的应是 #3/#4/#5 且保持时间序。
func TestFilterUSNRecordsRing(t *testing.T) {
	base := time.Unix(1700000000, 0)
	recs := make([]winapi.USNRecord, 0, 5)
	for i := 1; i <= 5; i++ {
		recs = append(recs, winapi.USNRecord{
			USN:  uint64(100 + i),
			Name: "f" + string(rune('0'+i)) + ".exe",
			When: base.Add(time.Duration(i) * time.Second),
		})
	}
	items, matched := filterUSNRecords(recs, "", "", 3)
	if matched != 5 {
		t.Errorf("matched 应为 5 实得 %d", matched)
	}
	if len(items) != 3 {
		t.Fatalf("应保留 3 条实得 %d", len(items))
	}
	wantUSN := []uint64{103, 104, 105}
	for i, w := range wantUSN {
		if items[i].USN != w {
			t.Errorf("items[%d].usn = %d，期望 %d（应保留最近且时间序）", i, items[i].USN, w)
		}
		if items[i].TsUnix != base.Unix()+int64(i+3) {
			t.Errorf("items[%d].ts_unix = %d 不符", i, items[i].TsUnix)
		}
	}

	// 恰好 max 条：不环绕、原序保留
	items, matched = filterUSNRecords(recs[:3], "", "", 3)
	if matched != 3 || len(items) != 3 || items[0].USN != 101 {
		t.Errorf("恰好 max 条应原序保留: matched=%d items=%+v", matched, items)
	}

	// name 过滤大小写不敏感 + matched 只数匹配项
	recs = append(recs, winapi.USNRecord{USN: 200, Name: "Report.PDF", When: base})
	items, matched = filterUSNRecords(recs, "report", "", 10)
	if matched != 1 || len(items) != 1 || items[0].Name != "Report.PDF" {
		t.Errorf("name 过滤应大小写不敏感: matched=%d items=%+v", matched, items)
	}

	// ext 过滤：后缀匹配；.pdf 不匹配 .exe（补点/小写归一在 handler 的
	// normalizeUSNExt 做，filterUSNRecords 只收已归一的过滤串）
	items, matched = filterUSNRecords(recs, "", ".exe", 10)
	if matched != 5 {
		t.Errorf("ext=.exe 应匹配 5 条 exe 实得 %d", matched)
	}
	items, matched = filterUSNRecords(recs, "", ".pdf", 10)
	if matched != 1 || items[0].Name != "Report.PDF" {
		t.Errorf("ext=.pdf 应只匹配 PDF: matched=%d", matched)
	}

	// 双过滤叠加：name+ext 都命中才保留
	items, matched = filterUSNRecords(recs, "f1", ".exe", 10)
	if matched != 1 || len(items) != 1 || items[0].USN != 101 {
		t.Errorf("双过滤不符: matched=%d items=%+v", matched, items)
	}
}

// TestUSNRealSmoke 真机冒烟：C: 卷 120 分钟窗口预算内扫描；不存在的盘
// 400；name 过滤不存在的子串 items 空 matched=0。
func TestUSNRealSmoke(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("仅 Windows")
	}
	h := http.HandlerFunc((&server{}).handleUSN)

	start := time.Now()
	code, body := doGet(t, h, "/usn?volume=C:&minutes=120&max=10")
	if code != http.StatusOK {
		t.Fatalf("期望 200 实得 %d body=%v", code, body)
	}
	t.Logf("C: 120min 扫描耗时 %s", time.Since(start))
	d := dataOf(t, body)

	journal, ok := d["journal"].(map[string]any)
	if !ok {
		t.Skipf("本机 C: journal 不可用（note=%v），跳过窗口断言", d["note"])
	}
	if _, ok := journal["first_usn"].(float64); !ok {
		t.Errorf("journal.first_usn 应为数字: %v", journal)
	}
	if _, ok := journal["next_usn"].(float64); !ok {
		t.Errorf("journal.next_usn 应为数字: %v", journal)
	}

	items, _ := d["items"].([]any)
	if len(items) > 10 {
		t.Fatalf("max=10 应最多 10 条实得 %d", len(items))
	}
	scanned, _ := d["scanned"].(float64)
	matched, _ := d["matched"].(float64)
	if matched > scanned {
		t.Errorf("matched(%d) 不应超过 scanned(%d)", int(matched), int(scanned))
	}
	if trunc, ok := d["truncated"].(bool); !ok {
		t.Errorf("truncated 应为 bool: %T", d["truncated"])
	} else if trunc && matched <= float64(len(items)) {
		// truncated=true 且条数没截：必须能给出原因（预算或中途失败）
		_, hasBudget := d["budget_note"]
		_, hasNote := d["note"]
		if !hasBudget && !hasNote {
			t.Errorf("预算/失败停止的 truncated=true 应带 budget_note 或 note: %v", d)
		}
	}
	for i, raw := range items {
		m, _ := raw.(map[string]any)
		name, _ := m["name"].(string)
		if name == "" {
			t.Errorf("items[%d].name 不应为空", i)
		}
		reasons, ok := m["reasons"].([]any)
		if !ok || len(reasons) == 0 {
			t.Errorf("items[%d].reasons 应为非空数组: %v", i, m["reasons"])
		}
		if ts, _ := m["ts_unix"].(float64); ts <= 0 {
			t.Errorf("items[%d].ts_unix 应为正: %v", i, m["ts_unix"])
		}
		if _, ok := m["usn"].(float64); !ok {
			t.Errorf("items[%d].usn 应为数字: %T", i, m["usn"])
		}
	}
	t.Logf("scanned=%d matched=%d items=%d", int(scanned), int(matched), len(items))

	// 盘符变体（"C" 与 `C:\`）与 "C:" 同语义
	code, _ = doGet(t, h, "/usn?volume=C&minutes=1&max=1")
	if code != http.StatusOK {
		t.Fatalf(`volume=C 应接受（200）实得 %d`, code)
	}

	// 不存在的盘 → 400。按契约用 Q:；若本机 Q: 恰好是合法固定 NTFS 卷
	// （异常环境），退而选一个确实不在列表里的盘符。
	vol := "Q:"
	for _, v := range winapi.FixedNTFSVolumes() {
		if v == vol {
			for l := 'D'; l <= 'Z'; l++ {
				cand := string(l) + ":"
				found := false
				for _, v2 := range winapi.FixedNTFSVolumes() {
					if v2 == cand {
						found = true
						break
					}
				}
				if !found {
					vol = cand
					break
				}
			}
			break
		}
	}
	code, body = doGet(t, h, "/usn?volume="+vol)
	if code != http.StatusBadRequest {
		t.Fatalf("非法卷 %s 期望 400 实得 %d", vol, code)
	}
	if msg := errMsg(t, body); msg == "" {
		t.Error("400 应带错误说明")
	}

	// name 过滤不存在的子串：items 空、matched=0（scanned 仍应非 0）
	code, body = doGet(t, h, `/usn?volume=C:\&name=__no_such_file_substring_zz__&minutes=120`)
	if code != http.StatusOK {
		t.Fatalf("期望 200 实得 %d", code)
	}
	d = dataOf(t, body)
	if m, _ := d["matched"].(float64); m != 0 {
		t.Errorf("不存在的子串 matched 应为 0 实得 %d", int(m))
	}
	if items, _ := d["items"].([]any); len(items) != 0 {
		t.Errorf("不存在的子串 items 应为空: %d", len(items))
	}
	if s, _ := d["scanned"].(float64); s == 0 {
		t.Logf("提示：scanned=0，本机 C: journal 120 分钟窗口内无任何记录（安静机器属正常）")
	}
}
