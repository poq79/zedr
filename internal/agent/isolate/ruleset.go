package isolate

import (
	"fmt"
	"net/netip"
	"sort"
)

// RuleNameIn / RuleNameOutPrefix 是隔离规则命名空间：diag -unisolate 与
// agent 的孤儿清理都按这个名字前缀批量删除，改名等于破坏恢复路径。
const (
	RuleNameIn        = "ZEDR-ISOLATION-IN"
	RuleNameOutPrefix = "ZEDR-ISOLATION-OUT-"
)

// Rule 是一条待施加的防火墙 block 规则（纯数据，Runner 消费）。
type Rule struct {
	Name      string
	Direction string // "in" | "out"
	CIDR      string
}

// KeepSet 是隔离期间仍允许通信的地址集合。
type KeepSet struct {
	Server netip.Prefix // server 所在 /24（agent↔server 管理通道）
	Loopback netip.Prefix // 127.0.0.0/8（本机 UI/本地 API/server 同机部署）
	DNS    []netip.Prefix // 系统 DNS /32（agent 按主机名重连时解析必需）
}

// BuildRules 生成隔离规则集：出站 block = 0.0.0.0/0 掏空 KeepSet 的补集；
// 入站 block = 0.0.0.0/0 掏空 loopback 的补集（探针零监听无入站需求，
// 本机 UI/本地 API 走 loopback 不受影响——绝不能加 0.0.0.0/0 全断入站，
// 那会把 loopback 一起杀掉）。规则名按 CIDR 排序确定性编号——篡改重施加
// 时名字不变，按名删除才可靠。
func BuildRules(keep KeepSet) []Rule {
	outKept := []netip.Prefix{keep.Server, keep.Loopback}
	outKept = append(outKept, keep.DNS...)
	universe := netip.MustParsePrefix("0.0.0.0/0")

	outBlocks := Carve(universe, outKept)
	inBlocks := Carve(universe, []netip.Prefix{keep.Loopback})

	rules := make([]Rule, 0, len(outBlocks)+len(inBlocks))
	for i, c := range outBlocks {
		rules = append(rules, Rule{
			Name:      fmt.Sprintf("%s%03d", RuleNameOutPrefix, i),
			Direction: "out",
			CIDR:      c.String(),
		})
	}
	for i, c := range inBlocks {
		rules = append(rules, Rule{
			Name:      fmt.Sprintf("%s-%03d", RuleNameIn, i),
			Direction: "in",
			CIDR:      c.String(),
		})
	}
	return rules
}

// SortRules 稳定排序（规则名序）——重施加时输出确定性顺序。
func SortRules(rules []Rule) {
	sort.Slice(rules, func(i, j int) bool { return rules[i].Name < rules[j].Name })
}
