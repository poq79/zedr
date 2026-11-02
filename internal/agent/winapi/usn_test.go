package winapi

import (
	"encoding/binary"
	"testing"
	"time"
	"unicode/utf16"
)

func usnRecord(name string, reason, attrs uint32, usn uint64, when time.Time) []byte {
	u := utf16.Encode([]rune(name))
	nameBytes := len(u) * 2
	recLen := (60 + nameBytes + 7) &^ 7 // 8 字节对齐
	buf := make([]byte, recLen)
	binary.LittleEndian.PutUint32(buf[0:4], uint32(recLen))
	binary.LittleEndian.PutUint16(buf[4:6], 2) // V2
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

func TestParseUSNBufferFiltersAndDecodes(t *testing.T) {
	when := time.Now().Add(-time.Minute).UTC().Truncate(time.Second)
	buf := usnBuffer(1000,
		usnRecord("payload.exe", usnReasonFileCreate, 0x80, 100, when),
		usnRecord("somedir", usnReasonFileCreate, fileAttributeDirectory, 200, when),
		usnRecord("deleted.exe", 0x00000200 /* FILE_DELETE */, 0x80, 300, when),
		usnRecord("renamed.ps1", usnReasonRenameNewName, 0x80, 400, when),
	)

	events, next, truncated := parseUSNBuffer(buf, 10)
	if truncated {
		t.Fatal("truncated = true, want false")
	}
	if next != 1000 {
		t.Fatalf("next = %d, want 1000（整段处理完用 buffer 头部的 next）", next)
	}
	if len(events) != 2 {
		t.Fatalf("events = %+v, want payload.exe + renamed.ps1", events)
	}
	if events[0].Name != "payload.exe" || events[1].Name != "renamed.ps1" {
		t.Fatalf("events = %+v", events)
	}
	if d := events[0].When.Sub(when); d > time.Second || d < -time.Second {
		t.Fatalf("When = %v, want %v（USN 记录时间，而非采集时刻）", events[0].When, when)
	}
}

func TestParseUSNBufferTruncatesAtRecordBoundary(t *testing.T) {
	when := time.Now().Add(-time.Minute)
	buf := usnBuffer(999,
		usnRecord("a.exe", usnReasonFileCreate, 0x80, 100, when),
		usnRecord("b.exe", usnReasonFileCreate, 0x80, 200, when),
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
