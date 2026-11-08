package winapi

import (
	"testing"
	"time"
)

// usnsnapshot_test.go：parseUSNSnapshot 的合成缓冲单测（不需要管理员
// 权限/真实卷），与 usn_test.go 共用 usnRecord/usnBuffer 夹具。
// 快照口径与补采口径的差异点各有一条断言：保留 USN 值、保留全部 reason
// 位、纯 CLOSE 剔除、窗口外计入 scanned 不保留。

func TestParseUSNSnapshotKeepsRawRecords(t *testing.T) {
	now := time.Now()
	inWindow := now.Add(-time.Minute).UTC().Truncate(time.Second)
	outOfWindow := now.Add(-time.Hour).UTC().Truncate(time.Second)
	buf := usnBuffer(1000,
		usnRecord("stale.exe", usnReasonFileCreate, 0x80, 41, 50, outOfWindow),
		usnRecord("payload.exe", usnReasonFileCreate, 0x80, 42, 100, inWindow),
		usnRecord("somedir", usnReasonFileCreate, fileAttributeDirectory, 43, 200, inWindow),
		// 纯 CLOSE（打开未改）：快照口径同样剔除
		usnRecord("idle.db", usnReasonClose, 0x80, 44, 300, inWindow),
		usnRecord("gone.docx", usnReasonFileDelete|usnReasonClose, 0x80, 45, 400, inWindow),
	)

	kept, chunkNext, scanned, hitCap := parseUSNSnapshot(buf, now.Add(-30*time.Minute), -1)
	if hitCap {
		t.Fatal("hitCap = true, want false（未设上限）")
	}
	if chunkNext != 1000 {
		t.Fatalf("chunkNext = %d, want 1000", chunkNext)
	}
	// scanned 数全部 5 条（含窗口外/目录/纯 CLOSE），kept 只留 2 条
	if scanned != 5 {
		t.Fatalf("scanned = %d, want 5（扫描成本含被跳过的记录）", scanned)
	}
	if len(kept) != 2 {
		t.Fatalf("kept = %+v, want 2 条", kept)
	}
	if kept[0].Name != "payload.exe" || kept[0].USN != 100 || kept[0].FRN != 42 {
		t.Fatalf("kept[0] = %+v, want payload.exe usn=100 frn=42", kept[0])
	}
	// reason 原样保留（快照不做 Kind 归类），CLOSE 位不剥离
	if kept[1].Name != "gone.docx" || kept[1].Reason != usnReasonFileDelete|usnReasonClose {
		t.Fatalf("kept[1] = %+v, want gone.docx reason 原样含 CLOSE", kept[1])
	}
	if d := kept[0].When.Sub(inWindow); d > time.Second || d < -time.Second {
		t.Fatalf("When = %v, want %v", kept[0].When, inWindow)
	}
}

func TestParseUSNSnapshotStopsAtRecordBoundary(t *testing.T) {
	inWindow := time.Now().Add(-time.Minute)
	buf := usnBuffer(999,
		usnRecord("a.exe", usnReasonFileCreate, 0x80, 1, 100, inWindow),
		usnRecord("b.exe", usnReasonFileCreate, 0x80, 2, 200, inWindow),
		usnRecord("c.exe", usnReasonFileCreate, 0x80, 3, 300, inWindow),
	)

	kept, chunkNext, scanned, hitCap := parseUSNSnapshot(buf, inWindow.Add(-30*time.Minute), 2)
	if !hitCap {
		t.Fatal("hitCap = false, want true")
	}
	if len(kept) != 2 || scanned != 2 {
		t.Fatalf("kept=%d scanned=%d, want 2/2", len(kept), scanned)
	}
	// 停在记录边界：chunkNext 指向第一条未处理记录（>= 语义不漏）
	if chunkNext != 300 {
		t.Fatalf("chunkNext = %d, want 300", chunkNext)
	}
}
