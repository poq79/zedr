package service

import (
	"testing"
	"time"
)

// dupSuppress 自适应抑制分级：固定 5min 窗口挡不住"每 30s 重放一轮"的
// 源头故障（E1 游标死循环单机 13 天 11.5 万行），分级升级是底线。
// 本表锁定四个档位的行为边界，防止后续调参把"低频真实重现"也折叠掉。
func TestDupSuppressTiers(t *testing.T) {
	now := time.Now()
	base := 5 * time.Minute
	cases := []struct {
		name        string
		count       int
		lastSeenAgo time.Duration
		want        bool
	}{
		// 基础窗口：5min 内再现，并入（既有行为不变）
		{"base_window_hit", 1, 2 * time.Minute, true},
		// 出了基础窗口且行数不足：低频重现必须出新行（真实攻击的间歇重试）
		{"rare_recurrence_new_row", 1, 6 * time.Minute, false},
		{"rare_two_rows_new_row", 2, 30 * time.Minute, false},
		// 中频复发：≥3 行且 1h 内出现过，并入（MEM-1055 长驻进程周期命中）
		{"escalate_recent", 3, 30 * time.Minute, true},
		{"escalate_boundary", 3, time.Hour, true},
		// 中频档超窗：1h 没再出现就放行出新行
		{"escalate_expired", 3, 2 * time.Hour, false},
		// 风暴级：≥15 行不管多久前都并入（E1 死循环形态，一天最多一行）
		{"storm_absorbs", 15, 20 * time.Hour, true},
		// 静默期后复发（洪水停在视野外）：放行出新行——风暴档同样受视野约束
		{"beyond_horizon", 15, 25 * time.Hour, false},
	}
	for _, c := range cases {
		got := dupSuppress(c.count, now.Add(-c.lastSeenAgo), now, base)
		if got != c.want {
			t.Fatalf("%s: count=%d ago=%s want=%v got=%v",
				c.name, c.count, c.lastSeenAgo, c.want, got)
		}
	}
}
