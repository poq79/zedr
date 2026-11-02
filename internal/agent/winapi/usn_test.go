package winapi

import (
	"encoding/binary"
	"testing"
	"time"
	"unicode/utf16"
)

func usnRecord(name string, reason, attrs uint32, frn, usn uint64, when time.Time) []byte {
	u := utf16.Encode([]rune(name))
	nameBytes := len(u) * 2
	recLen := (60 + nameBytes + 7) &^ 7 // 8 字节对齐
	buf := make([]byte, recLen)
	binary.LittleEndian.PutUint32(buf[0:4], uint32(recLen))
	binary.LittleEndian.PutUint16(buf[4:6], 2) // V2
	binary.LittleEndian.PutUint64(buf[8:16], frn)
	binary.LittleEndian.PutUint64(buf[24:32], usn)
	const epochDiff = 116444736000000000
	ft := uint64(when.UnixNano()/100 + epochDiff)
	binary.LittleEndian.PutUint64(buf[32:40], ft)
	binary.LittleEndian.PutUint32(buf[40:44], reason)
	binary.LittleEndian.PutUint32(buf[52:56], attrs)
	binary.LittleEndian.PutUint16(buf[56:58], uint16(nameBytes))
	binary.LittleEndian.PutUint16(buf[58:60], 60)
	for i, c := range u {
		binary.LittleEndian.PutUint16(buf[60+i*2:], c)
	}
	return buf
}

func usnBuffer(next uint64, records ...[]byte) []byte {
	buf := make([]byte, 8)
	binary.LittleEndian.PutUint64(buf, next)
	for _, r := range records {
		buf = append(buf, r...)
	}
	return buf
}

func TestParseUSNBufferEmitsAllKinds(t *testing.T) {
	when := time.Now().Add(-time.Minute).UTC().Truncate(time.Second)
	buf := usnBuffer(1000,
		usnRecord("payload.exe", usnReasonFileCreate, 0x80, 42, 100, when),
		usnRecord("somedir", usnReasonFileCreate, fileAttributeDirectory, 43, 200, when),
		usnRecord("gone.docx", usnReasonFileDelete, 0x80, 44, 300, when),
		usnRecord("old.docx", usnReasonRenameOldName, 0x80, 45, 400, when),
		usnRecord("renamed.ps1", usnReasonRenameNewName, 0x80, 46, 500, when),
		usnRecord("grow.log", usnReasonDataExtend, 0x80, 47, 600, when),
		// 纯元数据/关闭：不产出事件
		usnRecord("meta.db", 0x80008000 /* BASIC_INFO_CHANGE|CLOSE */, 0x80, 48, 700, when),
	)

	events, next, truncated := parseUSNBuffer(buf, 10)
	if truncated {
		t.Fatal("truncated = true, want false")
	}
	if next != 1000 {
		t.Fatalf("next = %d, want 1000（整段处理完用 buffer 头部的 next）", next)
	}
	if len(events) != 5 {
		t.Fatalf("events = %+v, want 5 条（目录与纯元数据剔除，删除/改名旧名保留）", events)
	}
	want := []struct {
		name string
		kind USNKind
		frn  uint64
	}{
		{"payload.exe", USNKindCreate, 42},
		{"gone.docx", USNKindDelete, 44},
		{"old.docx", USNKindRenameOld, 45},
		{"renamed.ps1", USNKindRenameNew, 46},
		{"grow.log", USNKindWrite, 47},
	}
	for i, w := range want {
		if events[i].Name != w.name || events[i].Kind != w.kind || events[i].FRN != w.frn {
			t.Fatalf("events[%d] = {%s %s frn=%d}, want {%s %s frn=%d}",
				i, events[i].Name, events[i].Kind, events[i].FRN, w.name, w.kind, w.frn)
		}
		if events[i].Reason == 0 {
			t.Fatalf("events[%d].Reason = 0，应保留原始 reason 位", i)
		}
	}
	if d := events[0].When.Sub(when); d > time.Second || d < -time.Second {
		t.Fatalf("When = %v, want %v（USN 记录时间，而非采集时刻）", events[0].When, when)
	}
}

// 删除与改名旧名覆盖改名覆盖目标等"多 reason 位"记录：FILE_DELETE 优先级
// 最高（数据没了才是最强信号）。
func TestUSNKindOfPriority(t *testing.T) {
	cases := []struct {
		reason uint32
		want   USNKind
		ok     bool
	}{
		{usnReasonFileDelete | usnReasonRenameOldName, USNKindDelete, true},
		{usnReasonRenameOldName | usnReasonFileCreate, USNKindRenameOld, true},
		{usnReasonRenameNewName, USNKindRenameNew, true},
		{usnReasonFileCreate | usnReasonDataExtend, USNKindCreate, true},
		{usnReasonDataOverwrite, USNKindWrite, true},
		{0x80000000, "", false}, // 只有 CLOSE
		{0, "", false},
	}
	for _, c := range cases {
		kind, ok := usnKindOf(c.reason)
		if kind != c.want || ok != c.ok {
			t.Fatalf("usnKindOf(0x%x) = (%s, %v), want (%s, %v)", c.reason, kind, ok, c.want, c.ok)
		}
	}
}

func TestParseUSNBufferTruncatesAtRecordBoundary(t *testing.T) {
	when := time.Now().Add(-time.Minute)
	buf := usnBuffer(999,
		usnRecord("a.exe", usnReasonFileCreate, 0x80, 1, 100, when),
		usnRecord("b.exe", usnReasonFileCreate, 0x80, 2, 200, when),
	)

	events, next, truncated := parseUSNBuffer(buf, 1)
	if !truncated {
		t.Fatal("truncated = false, want true")
	}
	if len(events) != 1 || events[0].Name != "a.exe" {
		t.Fatalf("events = %+v, want [a.exe]", events)
	}
	// 下一条未处理记录的 USN：从 200 继续（>= 语义不会跳过 b.exe）
	if next != 200 {
		t.Fatalf("next = %d, want 200", next)
	}
}

func TestParseUSNBufferIgnoresShortPayload(t *testing.T) {
	events, next, truncated := parseUSNBuffer([]byte{1, 2, 3}, 10)
	if len(events) != 0 || next != 0 || truncated {
		t.Fatalf("short buffer = events=%v next=%d truncated=%v, want empty", events, next, truncated)
	}
}

func TestPairUSNRenames(t *testing.T) {
	events := []USNEvent{
		{Name: "a.docx", Kind: USNKindRenameOld, FRN: 7},
		{Name: "b.enc", Kind: USNKindRenameNew, FRN: 7},
		{Name: "c.docx", Kind: USNKindRenameOld, FRN: 8},
		{Name: "d.txt", Kind: USNKindRenameNew, FRN: 9}, // FRN 9 无配对
		{Name: "e.rtf", Kind: USNKindCreate, FRN: 8},    // 非 rename 事件不参与
	}
	pairUSNRenames(events)

	if events[1].OldName != "a.docx" {
		t.Fatalf("rename_new OldName = %q, want %q（同 FRN 配对）", events[1].OldName, "a.docx")
	}
	if events[3].OldName != "" {
		t.Fatalf("无配对的 rename_new OldName = %q, want 空（跨 FRN 不猜）", events[3].OldName)
	}
	if events[2].Kind != USNKindRenameOld || events[2].Name != "c.docx" {
		t.Fatalf("rename_old 事件应原样保留，got %+v", events[2])
	}
}

// 连续两次改名同一 FRN：第一个 rename_old 已被第一个 rename_new 消费，
// 第二个 rename_old 未配对，不污染。
func TestPairUSNRenamesDoubleRename(t *testing.T) {
	events := []USNEvent{
		{Name: "a.docx", Kind: USNKindRenameOld, FRN: 5},
		{Name: "b.tmp", Kind: USNKindRenameNew, FRN: 5},
		{Name: "b.tmp", Kind: USNKindRenameOld, FRN: 5},
		{Name: "c.enc", Kind: USNKindRenameNew, FRN: 5},
	}
	pairUSNRenames(events)
	if events[1].OldName != "a.docx" {
		t.Fatalf("events[1].OldName = %q, want a.docx", events[1].OldName)
	}
	if events[3].OldName != "b.tmp" {
		t.Fatalf("events[3].OldName = %q, want b.tmp", events[3].OldName)
	}
}
