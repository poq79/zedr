package agentapp

import (
	"math/rand"
	"time"
)

// HeartbeatJitterFrac 是心跳节拍的抖动比例。固定节拍下，一批机器同时
// 重启（升级/断电恢复/服务端发布）会让心跳、注册、上报挤在同一秒——
// SCALE.md §2.3 重连风暴的第一块骨牌。±15% 足够打散同拍，又不会让
// 间隔漂移到难排查。
const HeartbeatJitterFrac = 0.15

// JitterInterval 在 base 上加 ±frac 的均匀随机抖动；base<=0 或 frac<=0
// 原样返回。Windows（app）与 Linux（lapp）两个组合根共用，心跳语义
// 保持逐行同构。
func JitterInterval(base time.Duration, frac float64) time.Duration {
	if base <= 0 || frac <= 0 {
		return base
	}
	span := time.Duration(float64(base) * frac)
	return base + time.Duration(rand.Int63n(int64(2*span)+1)) - span
}

// JitterDuration 在 [0, limit] 内均匀取随机时长（首拍错峰用）；
// limit<=0 返回 0。
func JitterDuration(limit time.Duration) time.Duration {
	if limit <= 0 {
		return 0
	}
	return time.Duration(rand.Int63n(int64(limit) + 1))
}
