// Package isolate 主机网络隔离（R+3，设计见 zedr-private-docs/docs/
// RESEARCH-HOST-ISOLATION.md）。
//
// 语义对齐业界（MDE/CrowdStrike，2026-11-21 查阅）：隔离 = 断业务网络 +
// 保管理通道。实现走 Windows 防火墙 block 规则 + CIDR 掏空：block 压过
// allow（IPsec bypass 除外），所以"放行 agent 通道"不能靠 allow 规则，
// 只能把"允许的地址"从"全部地址"里挖掉再 block 补集。
//
// cidr.go 是纯数学，不加 build tag——补集正确性是本功能的安全根基，
// 必须在 CI 的 linux job 也能被测试。
package isolate

import (
	"math/big"
	"net/netip"
	"sort"
)

// Carve 返回 universe 去掉 kept 之后的补集 CIDR 列表（最小化到每层至多
// 两片，标准二分掏空算法）。kept 里超出 universe 范围或与 universe 不相交
// 的条目被忽略；kept 之间的重叠天然无害（挖两次同一片结果一致）。
//
// 复杂度 O(n·d)（n=kept 数，d=universe 深度 /32）——kept 是个位数，
// 结果条数上界 Σdᵢ（一个 /24 挖 24 条、/8 挖 8 条），实测 <50。
func Carve(universe netip.Prefix, kept []netip.Prefix) []netip.Prefix {
	// 只保留与 universe 有效相交的 kept，规范到 Masked 形式
	valid := make([]netip.Prefix, 0, len(kept))
	for _, p := range kept {
		if !p.IsValid() || p.Addr().Is4() != universe.Addr().Is4() {
			continue
		}
		if !universe.Contains(p.Addr()) {
			continue
		}
		valid = append(valid, p.Masked())
	}
	if len(valid) == 0 {
		return []netip.Prefix{universe}
	}

	out := []netip.Prefix{}
	queue := []netip.Prefix{universe}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]

		// 判定顺序不可换：先完整扫一遍"整片覆盖"（kept 前缀 <= cur 且
		// 含 cur 首地址），命中即丢弃——否则与内部 kept 相交的早退会让
		// 后面的覆盖性 kept 被漏看，多出一批不该 block 的 CIDR。
		covered := false
		for _, p := range valid {
			if p.Bits() <= cur.Bits() && p.Contains(cur.Addr()) {
				covered = true
				break
			}
		}
		if covered {
			continue
		}

		// 有 kept 落在 cur 内部（前缀更深且被 cur 包含）→ 二分；
		// 其余 kept 与 cur 不相交（前缀关系只有包含或不相交两种）。
		split := false
		for _, p := range valid {
			if p.Bits() > cur.Bits() && cur.Contains(p.Addr()) {
				split = true
				break
			}
		}
		if !split {
			out = append(out, cur)
			continue
		}

		// 二分到主机位（IPv4 /32、IPv6 /128）为止
		if cur.Bits() >= cur.Addr().BitLen() {
			out = append(out, cur)
			continue
		}
		left, _ := cur.Addr().Prefix(cur.Bits() + 1)
		rightAddr := nextHalf(cur)
		right := netip.PrefixFrom(rightAddr, cur.Bits()+1)
		queue = append(queue, left.Masked(), right.Masked())
	}

	sort.Slice(out, func(i, j int) bool { return out[i].Addr().Less(out[j].Addr()) })
	return out
}

// nextHalf 返回 cur 前缀内后半块的首地址（v4/v6 通用：base 视为大端整数
// 加半个块的步长）。
func nextHalf(cur netip.Prefix) netip.Addr {
	step := new(big.Int).Lsh(big.NewInt(1), uint(cur.Addr().BitLen()-cur.Bits()-1))
	a16 := cur.Addr().As16()
	base := new(big.Int).SetBytes(a16[:])
	base.Add(base, step)
	var b [16]byte
	base.FillBytes(b[:])
	return netip.AddrFrom16(b).Unmap()
}

// CoverCount 估算 kept 各前缀掏空的规则条数上界（Σdᵢ），供护栏与测试用。
func CoverCount(kept []netip.Prefix) int {
	n := 0
	for _, p := range kept {
		if p.IsValid() {
			n += p.Bits()
		}
	}
	return n
}
