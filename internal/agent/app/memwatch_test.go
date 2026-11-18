//go:build windows
// +build windows

package agentapp

import (
	"testing"
	"time"

	"zedr/internal/agent/state"
)

func mkRow(pid uint32, score int, name string, age time.Duration) state.ProcRow {
	return state.ProcRow{PID: pid, Name: name, Score: score, FirstSeen: time.Now().Add(-age)}
}

// 巡检选样纯函数：只选引擎有信号的进程、按分数降序/最新优先、预算截断、
// 排除探针自身——内存巡检是"对可疑者的深查"，不做全量盲扫。
func TestSelectMemCandidates(t *testing.T) {
	rows := []state.ProcRow{
		mkRow(1, 0, "quiet.exe", time.Hour),      // 无信号：不选
		mkRow(2, 55, "loud.exe", time.Hour),      // 高分
		mkRow(3, 40, "mid.exe", 2*time.Hour),     // 中分（更老）
		mkRow(4, 40, "mid_new.exe", time.Minute), // 中分（更新，同级优先）
		mkRow(100, 99, "self.exe", time.Minute),  // 探针自身：排除
	}
	got := selectMemCandidates(rows, 100, 3, nil)
	if len(got) != 3 {
		t.Fatalf("预算 3 应截断为 3，实际 %d", len(got))
	}
	if got[0].PID != 2 {
		t.Fatalf("最高分应最先: %+v", got[0])
	}
	if got[1].PID != 4 || got[2].PID != 3 {
		t.Fatalf("同级应最新优先: %+v", got)
	}
	for _, c := range got {
		if c.PID == 100 {
			t.Fatal("探针自身不应入选")
		}
	}
	// 落地优先：tier1 排在分数更高的 tier2 前
	landed := map[uint32]time.Time{3: time.Now()}
	got = selectMemCandidates(rows, 100, 3, landed)
	if got[0].PID != 3 {
		t.Fatalf("落地关联进程应优先: %+v", got)
	}
}

// avVendorSigner：已知安全厂商签名跳过的判定表（MEM-1055 误报治理）。
func TestAVVendorSigner(t *testing.T) {
	yes := []string{
		"奇虎360计算机技术（北京）有限公司",
		"Qihoo 360 Software Co., Ltd.",
		"北京火绒网络科技有限公司", "Huorong Internet Security",
		"Kingsoft Corporation", "金山软件",
		"Kaspersky Lab", "ESET, spol. s r.o.", "AVAST Software s.r.o.",
		"Bitdefender SRL", "McAfee, Inc.", "Symantec Corporation",
		"北京瑞星信息技术股份有限公司", "Rising Information Technology",
	}
	for _, s := range yes {
		if !avVendorSigner(s) {
			t.Fatalf("avVendorSigner(%q) = false, want true", s)
		}
	}
	no := []string{
		"",                                   // 空签名者恒否
		"Microsoft Corporation",              // 发行面太宽，由 InSystem 兜底
		"Tencent Technology (Shenzhen)",      // 同上：签名覆盖全产品线
		"SomeRandom Software Ltd.",
	}
	for _, s := range no {
		if avVendorSigner(s) {
			t.Fatalf("avVendorSigner(%q) = true, want false", s)
		}
	}
}
