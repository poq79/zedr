package attack

import (
	"testing"

	"zedr/internal/rules"
)

// TestCatalogConsistency 验证目录自身一致性：
// 每个技术引用的战术必须存在，未分类兜底排在最后。
func TestCatalogConsistency(t *testing.T) {
	validTactics := map[string]bool{}
	for _, tac := range tactics {
		if tac.ID == "" || tac.Name == "" {
			t.Fatalf("战术字段不完整: %+v", tac)
		}
		if validTactics[tac.ID] {
			t.Fatalf("战术 ID 重复: %s", tac.ID)
		}
		validTactics[tac.ID] = true
	}

	for id, tech := range techniques {
		if id != tech.ID {
			t.Fatalf("技术 map 键与 ID 不一致: %s vs %s", id, tech.ID)
		}
		if !validTactics[tech.TacticID] {
			t.Fatalf("技术 %s 引用了不存在的战术 %q", tech.ID, tech.TacticID)
		}
		if tech.NameZh == "" {
			t.Fatalf("技术 %s 缺少中文名", tech.ID)
		}
	}

	ts := Tactics()
	if last := ts[len(ts)-1]; last.ID != UncategorizedTacticID {
		t.Fatalf("未分类兜底应排在最后，实际 %s", last.ID)
	}
}

// TestCatalogCoversBuiltinRules 内置规则引用的每个技术编号都必须在目录里。
// 这是目录与规则库的同步护栏：新增规则用了新编号而目录没跟上的话，
// 矩阵会把该编号打进"未分类"，专业观感直接掉档。
func TestCatalogCoversBuiltinRules(t *testing.T) {
	for _, b := range rules.Builtins() {
		for _, m := range b.MITRE {
			if _, ok := LookupTechnique(m); !ok {
				t.Fatalf("内置规则 %s 引用的技术 %s 不在目录中", b.ID, m)
			}
		}
	}
}

// TestNormalizeTech 验证编号归一：小写与带空白都能转回规范形式。
func TestNormalizeTech(t *testing.T) {
	cases := map[string]string{
		"t1059.001": "T1059.001",
		" T1036 ":   "T1036",
		"T1490":     "T1490",
	}
	for in, want := range cases {
		if got := NormalizeTech(in); got != want {
			t.Fatalf("NormalizeTech(%q) = %q, want %q", in, got, want)
		}
	}
}
