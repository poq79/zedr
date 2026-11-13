//go:build windows
// +build windows

package agentapp

import (
	"testing"
	"time"

	"zedr/internal/agent/winapi"
)

// evtData 的双口径取值：真实 7045（Server 2022）的 EventData 是 Name
// 属性型（ServiceName/ImagePath/...），合成样例的无名假设不成立——
// e2e 首测全空早退的根因。回归锁死命名优先、位序兜底、缺失返回空。
func TestEvtDataDualConvention(t *testing.T) {
	named := map[string]string{"servicename": "zedr-svc", "imagepath": `C:\Temp\x.exe`}
	if got := evtData(named, []string{"servicename"}, 0); got != "zedr-svc" {
		t.Fatalf("命名口径取值失败: %q", got)
	}
	unnamed := map[string]string{"data[0]": "zedr-svc", "data[1]": `C:\Temp\x.exe`}
	if got := evtData(unnamed, []string{"servicename"}, 0); got != "zedr-svc" {
		t.Fatalf("位序兜底取值失败: %q", got)
	}
	if got := evtData(map[string]string{}, []string{"x"}, 3); got != "" {
		t.Fatalf("缺失应返回空: %q", got)
	}
}

// 4625 聚合窗口语义（低于阈值不告警——emitAlert 依赖 store/uplink，
// 告警装配由 e2e 覆盖；这里锁窗口/陈旧批/清理三个语义）：
//   - 窗口按**事件时间**盖章：游标追赶读到的陈旧失败不会被误算成
//     "当前正在暴破"（wall-clock 盖章版本的实锤缺陷）；
//   - 陈旧批达到阈值也不告警、不占冷却；
//   - 过期样本随下一次 push 清理。
func TestEvtBruteWindowSemantics(t *testing.T) {
	a := &Agent{}
	base := time.Now()
	push := func(evAt time.Time) {
		a.evtBrutePush(winapi.EvtEvent{
			EventID:     4625,
			TimeCreated: evAt,
			Data:        map[string]string{"targetusername": "admin", "ipaddress": "203.0.113.7"},
		})
	}
	snap := func() (int, time.Time) {
		a.brute.mu.Lock()
		defer a.brute.mu.Unlock()
		return len(a.brute.window), a.brute.lastHit
	}

	// 陈旧批 12 次（都在 2 分钟前）：达阈值也不触发、不占冷却
	for i := 0; i < evtBruteThreshold+2; i++ {
		push(base.Add(-2 * time.Minute))
	}
	if n, cooled := snap(); n < evtBruteThreshold {
		t.Fatalf("陈旧批应留在窗口内（自然过期），实际 %d", n)
	} else if !cooled.IsZero() {
		t.Fatalf("陈旧批不应置冷却: %v", cooled)
	}

	// 新鲜失败逐次进来：陈旧样本被清理，未达阈值不置冷却
	push(base.Add(-5 * time.Second))
	if n, cooled := snap(); n != 1 || !cooled.IsZero() {
		t.Fatalf("新鲜 push 后窗口应只剩 1 条且无冷却，实际 %d/%v", n, cooled)
	}
	// 窗口已有 1 条，再推 threshold-2 条 = threshold-1（不触发）
	for i := 0; i < evtBruteThreshold-2; i++ {
		push(base.Add(-time.Duration(i) * time.Second))
	}
	if n, cooled := snap(); n != evtBruteThreshold-1 {
		t.Fatalf("新鲜失败应累计到阈值-1，实际 %d", n)
	} else if !cooled.IsZero() {
		t.Fatalf("测试仅推进到阈值-1，不应触发告警: %v", cooled)
	}
}
