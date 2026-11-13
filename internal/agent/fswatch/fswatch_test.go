// 纯逻辑测试，Windows 上直接跑（go test ./internal/agent/fswatch/）。
// 覆盖三块：KindFromMask 全分支、MapBatch 的 MOVED_FROM/TO 配对语义
// （与 Windows parse 的"同缓冲配对"口径逐条对齐）、DirsToWatch 的种子
// 计算（含 /tmp vs /tmpfoo 前缀边界）。系统调用层不在覆盖范围——见包
// 注释的诚实边界：本包未在 Linux 实机验证，验证口径=交叉编译+纯逻辑单测。
package fswatch

import (
	"testing"
	"time"

	"zedr/internal/agent/nettypes"
)

var testNow = time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)

func kindsOf(evs []nettypes.FileEvent) []string {
	out := make([]string, 0, len(evs))
	for _, e := range evs {
		out = append(out, e.Kind)
	}
	return out
}

func TestKindFromMask(t *testing.T) {
	cases := []struct {
		name string
		mask uint32
		want string
	}{
		{"create", IN_CREATE, "added"},
		{"create_dir", IN_CREATE | IN_ISDIR, "added"},
		{"delete", IN_DELETE, "removed"},
		{"delete_dir", IN_DELETE | IN_ISDIR, "removed"},
		{"modify", IN_MODIFY, "modified"},
		{"modify_dir_修饰位不改变kind", IN_MODIFY | IN_ISDIR, "modified"},
		{"close_write", IN_CLOSE_WRITE, "modified"},
		{"moved_from", IN_MOVED_FROM, "renamed_old"},
		{"moved_from_dir", IN_MOVED_FROM | IN_ISDIR, "renamed_old"},
		{"moved_to_未配对缺省", IN_MOVED_TO, "added"},
		{"moved_to_dir", IN_MOVED_TO | IN_ISDIR, "added"},
		{"overflow_无kind_计数在实现层", IN_Q_OVERFLOW, ""},
		{"ignored_内核回收watch", IN_IGNORED, ""},
		{"delete_self", IN_DELETE_SELF, ""},
		{"move_self", IN_MOVE_SELF, ""},
		{"unmount", IN_UNMOUNT, ""},
		{"isdir_alone_纯修饰位无kind", IN_ISDIR, ""},
		{"attrib_未订阅噪声", IN_ATTRIB, ""},
		{"open_未订阅噪声", IN_OPEN, ""},
		{"access_未订阅噪声", IN_ACCESS, ""},
		{"close_nowrite_未订阅噪声", IN_CLOSE_NOWRITE, ""},
		{"unknown_bit", 0x00010000, ""},
		{"zero", 0, ""},
	}
	for _, c := range cases {
		if got := KindFromMask(c.mask); got != c.want {
			t.Errorf("%s: KindFromMask(%#x) = %q, want %q", c.name, c.mask, got, c.want)
		}
	}
}

func TestMapBatchRenamePairedSameBatch(t *testing.T) {
	batch := []EventSpec{
		{Dir: "/tmp", Name: "old.bin", Mask: IN_MOVED_FROM, Cookie: 7},
		{Dir: "/tmp", Name: "new.bin", Mask: IN_MOVED_TO, Cookie: 7},
	}
	got := MapBatch(batch, testNow)
	if len(got) != 2 {
		t.Fatalf("got %d events (%v), want 2", len(got), kindsOf(got))
	}
	// renamed_old 恒发（含配对成功的情况）——Windows dispatch 同口径，
	// 消费方做速率统计只用 renamed，两条都计会双重计数。
	if got[0].Kind != "renamed_old" || got[0].Path != "/tmp/old.bin" || got[0].OldPath != "" {
		t.Errorf("ev0 = %+v, want renamed_old /tmp/old.bin 无 OldPath", got[0])
	}
	if got[1].Kind != "renamed" || got[1].Path != "/tmp/new.bin" || got[1].OldPath != "/tmp/old.bin" {
		t.Errorf("ev1 = %+v, want renamed /tmp/new.bin OldPath=/tmp/old.bin", got[1])
	}
	if !got[0].When.Equal(testNow) {
		t.Errorf("When 应为传入的 parse 时刻（RDCW 口径），got %v", got[0].When)
	}
}

func TestMapBatchRenameAcrossBatchesNotPaired(t *testing.T) {
	// 跨批次视为旧名未知（Windows：跨 parse 缓冲不配对）：
	// FROM 在上一批已作为 renamed_old 发出，本批的 TO 只能是 added。
	from := MapBatch([]EventSpec{{Dir: "/tmp", Name: "a", Mask: IN_MOVED_FROM, Cookie: 9}}, testNow)
	if len(from) != 1 || from[0].Kind != "renamed_old" || from[0].Path != "/tmp/a" {
		t.Fatalf("batch1 = %+v, want 单条 renamed_old /tmp/a", from)
	}
	to := MapBatch([]EventSpec{{Dir: "/tmp", Name: "b", Mask: IN_MOVED_TO, Cookie: 9}}, testNow)
	if len(to) != 1 || to[0].Kind != "added" || to[0].OldPath != "" || to[0].Path != "/tmp/b" {
		t.Errorf("batch2 = %+v, want added /tmp/b 无 OldPath", to)
	}
}

func TestMapBatchMovedOutOnly(t *testing.T) {
	// 只有 FROM：移出监控树，后续不会有 renamed，消费方靠 renamed_old 兜底。
	got := MapBatch([]EventSpec{{Dir: "/tmp", Name: "x", Mask: IN_MOVED_FROM, Cookie: 3}}, testNow)
	if len(got) != 1 || got[0].Kind != "renamed_old" || got[0].Path != "/tmp/x" {
		t.Errorf("got %+v, want 单条 renamed_old /tmp/x", got)
	}
}

func TestMapBatchMovedInOnly(t *testing.T) {
	// 只有 TO：移入监控树，无旧路径可配 → added。
	got := MapBatch([]EventSpec{{Dir: "/tmp", Name: "y", Mask: IN_MOVED_TO, Cookie: 4}}, testNow)
	if len(got) != 1 || got[0].Kind != "added" || got[0].OldPath != "" || got[0].Path != "/tmp/y" {
		t.Errorf("got %+v, want added /tmp/y 无 OldPath", got)
	}
}

func TestMapBatchTwoRenamesSameBatchNoCrossPairing(t *testing.T) {
	// 同批两次独立改名（cookie 1/2）：各配各的，不许串线。
	batch := []EventSpec{
		{Dir: "/tmp", Name: "x1", Mask: IN_MOVED_FROM, Cookie: 1},
		{Dir: "/tmp", Name: "y1", Mask: IN_MOVED_TO, Cookie: 1},
		{Dir: "/tmp", Name: "x2", Mask: IN_MOVED_FROM, Cookie: 2},
		{Dir: "/tmp", Name: "y2", Mask: IN_MOVED_TO, Cookie: 2},
	}
	got := MapBatch(batch, testNow)
	if len(got) != 4 {
		t.Fatalf("got %d events (%v), want 4", len(got), kindsOf(got))
	}
	wantOld := []string{"/tmp/x1", "/tmp/x2"}
	wantNew := []string{"/tmp/y1", "/tmp/y2"}
	for i, w := range []int{1, 3} { // renamed 落在序 1/3，OldPath 各自对应
		if got[w].Kind != "renamed" || got[w].OldPath != wantOld[i] || got[w].Path != wantNew[i] {
			t.Errorf("ev%d = %+v, want renamed %s OldPath=%s", w, got[w], wantNew[i], wantOld[i])
		}
	}
}

func TestMapBatchModifiedDedupSameBatch(t *testing.T) {
	// 一次 write+close（MODIFY 紧随 CLOSE_WRITE，同批）只算一次变更——
	// 不去重的话速率类检测（勒索窗口）会被双倍计数。
	batch := []EventSpec{
		{Dir: "/tmp", Name: "f.bin", Mask: IN_MODIFY},
		{Dir: "/tmp", Name: "f.bin", Mask: IN_CLOSE_WRITE},
	}
	got := MapBatch(batch, testNow)
	if len(got) != 1 || got[0].Kind != "modified" || got[0].Path != "/tmp/f.bin" {
		t.Errorf("同批 modify+close 应合并为 1 条 modified，got %+v", got)
	}

	// 不同文件互不影响去重。
	batch = []EventSpec{
		{Dir: "/tmp", Name: "f", Mask: IN_MODIFY},
		{Dir: "/tmp", Name: "g", Mask: IN_MODIFY},
		{Dir: "/tmp", Name: "f", Mask: IN_CLOSE_WRITE},
		{Dir: "/tmp", Name: "g", Mask: IN_CLOSE_WRITE},
	}
	got = MapBatch(batch, testNow)
	if len(got) != 2 {
		t.Errorf("两个文件各一次写收尾，want 2 条 modified，got %+v", got)
	}
}

func TestMapBatchModifiedCloseAlone(t *testing.T) {
	// 孤立 CLOSE_WRITE（无同批 MODIFY）：mmap 写盘 / 跨批长写的收尾，
	// 必须照发 modified——去重只针对同批 MODIFY 之后的那一次。
	got := MapBatch([]EventSpec{{Dir: "/tmp", Name: "m", Mask: IN_CLOSE_WRITE}}, testNow)
	if len(got) != 1 || got[0].Kind != "modified" || got[0].Path != "/tmp/m" {
		t.Errorf("got %+v, want modified /tmp/m", got)
	}
}

func TestMapBatchModifiedNotDedupedAcrossBatches(t *testing.T) {
	// 跨批次不去重（保持与 RDCW LastWrite 重复上报同噪声量级，且不引入
	// 需要 (key,timestamp) 淘汰纪律的跨批状态）。
	b1 := MapBatch([]EventSpec{{Dir: "/tmp", Name: "f", Mask: IN_MODIFY}}, testNow)
	b2 := MapBatch([]EventSpec{{Dir: "/tmp", Name: "f", Mask: IN_CLOSE_WRITE}}, testNow)
	if len(b1) != 1 || len(b2) != 1 {
		t.Errorf("跨批 modify/close 各发一条，got %v / %v", b1, b2)
	}
}

func TestMapBatchBasicKindsAndStamp(t *testing.T) {
	batch := []EventSpec{
		{Dir: "/home/u/Downloads", Name: "a.sh", Mask: IN_CREATE},
		{Dir: "/home/u/Downloads", Name: "b", Mask: IN_DELETE | IN_ISDIR},
		{Dir: "/home/u/Downloads", Name: "c.txt", Mask: IN_MODIFY},
	}
	got := MapBatch(batch, testNow)
	if len(got) != 3 {
		t.Fatalf("got %d events (%v), want 3", len(got), kindsOf(got))
	}
	want := []nettypes.FileEvent{
		{Kind: "added", Path: "/home/u/Downloads/a.sh", When: testNow},
		{Kind: "removed", Path: "/home/u/Downloads/b", When: testNow},
		{Kind: "modified", Path: "/home/u/Downloads/c.txt", When: testNow},
	}
	for i, w := range want {
		if got[i] != w {
			t.Errorf("ev%d = %+v, want %+v", i, got[i], w)
		}
	}
}

func TestMapBatchSkipsNamelessAndEmpty(t *testing.T) {
	// 无名事件（DELETE_SELF/MOVE_SELF/Q_OVERFLOW/IGNORED）不产生文件事件：
	// 树管理在 linux 实现层做，溢出计数也在实现层，MapBatch 只管文件语义。
	batch := []EventSpec{
		{Dir: "/tmp", Mask: IN_DELETE_SELF},
		{Dir: "/tmp", Mask: IN_MOVE_SELF},
		{Dir: "", Mask: IN_Q_OVERFLOW},
		{Mask: IN_IGNORED},
	}
	if got := MapBatch(batch, testNow); got != nil {
		t.Errorf("无名事件应全部过滤，got %+v", got)
	}
	if got := MapBatch(nil, testNow); got != nil {
		t.Errorf("空批应返回 nil，got %+v", got)
	}
}

func TestMapBatchPosixJoinOnAnyHost(t *testing.T) {
	// 映射层用 path（POSIX）而非 filepath：Windows 上跑单测也必须得到
	// 与 Linux 一致的路径形状，否则测试结果依赖跑测平台。
	got := MapBatch([]EventSpec{{Dir: "/var/tmp", Name: "drop.elf", Mask: IN_CREATE}}, testNow)
	if len(got) != 1 || got[0].Path != "/var/tmp/drop.elf" {
		t.Errorf("got %+v, want /var/tmp/drop.elf（正斜杠）", got)
	}
}

func TestDirsToWatch(t *testing.T) {
	roots := []string{"/tmp", "/home/u/Downloads"}
	existing := map[string]bool{"/tmp": true, "/home/u/Downloads": true}

	// 非目录事件不补挂（文件不需要 watch）。
	if got := DirsToWatch(existing, roots, "/tmp/a.txt", false); got != nil {
		t.Errorf("文件事件不应产生种子，got %v", got)
	}
	// 新目录 → 种子。
	if got := DirsToWatch(existing, roots, "/tmp/newd", true); len(got) != 1 || got[0] != "/tmp/newd" {
		t.Errorf("新目录应返回种子 [/tmp/newd]，got %v", got)
	}
	// 已在监控中。
	if got := DirsToWatch(existing, roots, "/tmp", true); got != nil {
		t.Errorf("已挂 watch 的目录不应重挂，got %v", got)
	}
	// 不在任何监控根之下。
	if got := DirsToWatch(existing, roots, "/var/evil", true); got != nil {
		t.Errorf("监控根之外的目录不应补挂，got %v", got)
	}
	// 前缀边界（关键）：/tmpfoo 与 /tmpfoo/x 都不属于 /tmp——不带分隔符
	// 边界的前缀比较会把兄弟路径误吞进监控树。
	if got := DirsToWatch(existing, roots, "/tmpfoo", true); got != nil {
		t.Errorf("/tmpfoo 不是 /tmp 之下，got %v", got)
	}
	if got := DirsToWatch(existing, roots, "/tmpfoo/x", true); got != nil {
		t.Errorf("/tmpfoo/x 不是 /tmp 之下，got %v", got)
	}
	// 深层新目录（父目录已在监控中）。
	if got := DirsToWatch(existing, roots, "/home/u/Downloads/a/b/c", true); len(got) != 1 || got[0] != "/home/u/Downloads/a/b/c" {
		t.Errorf("深层目录应返回自身为种子，got %v", got)
	}
	// Clean 归一：尾分隔符与已有 key 判等。
	if got := DirsToWatch(map[string]bool{"/tmp/x": true}, roots, "/tmp/x/", true); got != nil {
		t.Errorf("尾分隔符应 Clean 后判等，got %v", got)
	}
	// nil existing（New 初始形态）：读 nil map 合法，应正常给出种子。
	if got := DirsToWatch(nil, roots, "/tmp/n", true); len(got) != 1 || got[0] != "/tmp/n" {
		t.Errorf("nil existing 应返回种子，got %v", got)
	}
	// 相对路径/退化路径不补挂。
	for _, p := range []string{"", ".", ".."} {
		if got := DirsToWatch(existing, roots, p, true); got != nil {
			t.Errorf("退化路径 %q 不应产生种子，got %v", p, got)
		}
	}
	// 监控根为顶层 "/" 时包含一切（语义诚实记录，实际不这么配置）。
	if got := DirsToWatch(map[string]bool{}, []string{"/"}, "/etc/evil", true); len(got) != 1 {
		t.Errorf("根为 / 应视为包含一切，got %v", got)
	}
}
