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
		mkRow(1, 0, "quiet.exe", time.Hour),           // 无信号：不选
		mkRow(2, 55, "loud.exe", time.Hour),           // 高分
		mkRow(3, 40, "mid.exe", 2*time.Hour),          // 中分（更老）
		mkRow(4, 40, "mid_new.exe", time.Minute),      // 中分（更新，同级优先）
		mkRow(100, 99, "self.exe", time.Minute),       // 探针自身：排除
	}
	got := selectMemCandidates(rows, 100, 3)
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
}
