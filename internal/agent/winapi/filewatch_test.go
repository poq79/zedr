package winapi

import (
	"encoding/binary"
	"path/filepath"
	"testing"
	"time"
	"unicode/utf16"
)

// fniRecord 手工构造一条 FILE_NOTIFY_INFORMATION（NextEntryOffset 指向
// 下一条，4 字节对齐），用于直接喂 parse，不依赖真实目录句柄。
func fniRecord(action uint32, name string) []byte {
	u := utf16.Encode([]rune(name))
	nameBytes := len(u) * 2
	recLen := (12 + nameBytes + 3) &^ 3
	buf := make([]byte, recLen)
	binary.LittleEndian.PutUint32(buf[0:4], uint32(recLen))
	binary.LittleEndian.PutUint32(buf[4:8], action)
	binary.LittleEndian.PutUint32(buf[8:12], uint32(nameBytes))
	for i, c := range u {
		binary.LittleEndian.PutUint16(buf[12+i*2:], c)
	}
	return buf
}

// fniChain 串联多条记录，最后一条 NextEntryOffset 置 0。
func fniChain(recs ...[]byte) []byte {
	var buf []byte
	for _, r := range recs {
		buf = append(buf, r...)
	}
	last := recs[len(recs)-1]
	off := len(buf) - len(last)
	binary.LittleEndian.PutUint32(buf[off:off+4], 0)
	return buf
}

func testWatcher() *FileWatcher {
	return &FileWatcher{
		recent: make(map[string]Drop, 16),
		byBase: make(map[string]Drop, 16),
		max:    64,
	}
}

// 核心验收：删除/改名事件派发 + 回调不受落地扩展名过滤（诱饵是 .docx，
// 落地索引根本不收 .docx，若沿用过滤勒索检测就瞎了）。
func TestParseDispatchesRemovedAndRenamePair(t *testing.T) {
	w := testWatcher()
	var got []FileEvent
	w.SetOnFileEvent(func(fe FileEvent) { got = append(got, fe) })

	buf := fniChain(
		fniRecord(fileActionAdded, "tool.exe"),
		fniRecord(fileActionRemoved, "backup_report.docx"),
		fniRecord(fileActionRenamedOld, "预算汇总.xlsx"),
		fniRecord(fileActionRenamedNew, "预算汇总.enc"),
	)
	w.parse(`C:\w`, buf)

	wantKinds := []string{"added", "removed", "renamed_old", "renamed"}
	if len(got) != len(wantKinds) {
		t.Fatalf("events = %+v, want %v", got, wantKinds)
	}
	for i, k := range wantKinds {
		if got[i].Kind != k {
			t.Fatalf("events[%d].Kind = %s, want %s", i, got[i].Kind, k)
		}
		if got[i].When.IsZero() {
			t.Fatalf("events[%d].When 未填充", i)
		}
	}
	if got[1].Path != filepath.Join(`C:\w`, "backup_report.docx") {
		t.Fatalf("removed.Path = %s", got[1].Path)
	}
	// 同缓冲配对：renamed 带旧路径
	if got[3].OldPath != filepath.Join(`C:\w`, "预算汇总.xlsx") {
		t.Fatalf("renamed.OldPath = %s, want 旧路径配对", got[3].OldPath)
	}
	if got[3].Path != filepath.Join(`C:\w`, "预算汇总.enc") {
		t.Fatalf("renamed.Path = %s", got[3].Path)
	}

	// 落地索引口径不变：只有 .exe 入索引；.docx/.xlsx/.enc 都不该进
	if w.Events() != 1 {
		t.Fatalf("Events() = %d, want 1（只有 tool.exe 进落地索引）", w.Events())
	}
	if _, ok := w.RecentByPath(filepath.Join(`C:\w`, "tool.exe"), time.Minute); !ok {
		t.Fatal("tool.exe 应在落地索引中")
	}
	if _, ok := w.RecentByPath(filepath.Join(`C:\w`, "backup_report.docx"), time.Minute); ok {
		t.Fatal("被删除的 .docx 不应进落地索引")
	}
}

// 改名出监控树：只有 renamed_old，无 renamed；且下一个缓冲里的
// renamed_new 不能与上一个缓冲的 renamed_old 配对（跨缓冲不配对）。
func TestParseRenameOutOfTreeNotPaired(t *testing.T) {
	w := testWatcher()
	var got []FileEvent
	w.SetOnFileEvent(func(fe FileEvent) { got = append(got, fe) })

	w.parse(`C:\w`, fniChain(fniRecord(fileActionRenamedOld, "a.docx")))
	if len(got) != 1 || got[0].Kind != "renamed_old" {
		t.Fatalf("got = %+v, want 单条 renamed_old", got)
	}
	w.parse(`C:\w`, fniChain(fniRecord(fileActionRenamedNew, "b.docx")))
	if len(got) != 2 || got[1].Kind != "renamed" {
		t.Fatalf("got = %+v, want 第二条为 renamed", got)
	}
	if got[1].OldPath != "" {
		t.Fatalf("跨缓冲 renamed.OldPath = %q, want 空（不跨缓冲配对）", got[1].OldPath)
	}
}

// added/modified 照常派发且记录口径不变：非关注扩展名只派发不记录。
func TestParseDispatchesModifiedWithoutExtFilter(t *testing.T) {
	w := testWatcher()
	var kinds []string
	w.SetOnFileEvent(func(fe FileEvent) { kinds = append(kinds, fe.Kind) })

	w.parse(`C:\w`, fniChain(
		fniRecord(fileActionModified, "notes.txt"),
		fniRecord(fileActionAdded, "evil.dll"),
	))
	if len(kinds) != 2 || kinds[0] != "modified" || kinds[1] != "added" {
		t.Fatalf("kinds = %v", kinds)
	}
	if w.Events() != 1 {
		t.Fatalf("Events() = %d, want 1（.txt 不进落地索引，.dll 进）", w.Events())
	}
}

// SetOnFileEvent(nil) 关闭分发；未设置回调时 parse 不 panic。
func TestParseNilCallbackSafe(t *testing.T) {
	w := testWatcher()
	w.parse(`C:\w`, fniChain(fniRecord(fileActionRemoved, "x.docx"))) // 未设置
	w.SetOnFileEvent(nil)
	w.parse(`C:\w`, fniChain(fniRecord(fileActionRemoved, "x.docx")))
	if w.Events() != 0 {
		t.Fatalf("Events() = %d, want 0", w.Events())
	}
}
