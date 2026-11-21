package rules

import (
	"encoding/json"
	"strings"
	"testing"
)

// Sigma 导入转换器测试：样本全部为自造良性结构（无明文恶意工具名/命令，
// 遵守 §5.1），重点锁定三类契约——门禁拒绝原因、字段/修饰符映射、
// DNF 展开与 not 语义。

const sampleBase = `
status: stable
level: high
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\\\\bin\\\\demo.exe'
  condition: selection
`

func TestConvertSigmaBasic(t *testing.T) {
	doc := `
title: 演示进程创建规则
id: 11111111-2222-3333-4444-555555555555
status: stable
description: 自造样例
level: high
tags:
  - attack.t1059
logsource:
  category: process_creation
  product: windows
detection:
  selection_img:
    Image|endswith: '\\bin\\demo.exe'
    CommandLine|contains: '/demo-flag'
  condition: selection_img
`
	drafts, skipped, err := ConvertSigma([]byte(doc))
	if err != nil || skipped.Title != "" {
		t.Fatalf("应转换成功: err=%v skip=%+v", err, skipped)
	}
	if len(drafts) != 1 {
		t.Fatalf("应产出 1 条，实际 %d", len(drafts))
	}
	d := drafts[0]
	if d.Severity != "high" || d.Score != 75 {
		t.Errorf("severity/score 映射错误: %s/%d", d.Severity, d.Score)
	}
	if len(d.MITRE) != 1 || d.MITRE[0] != "T1059" {
		t.Errorf("MITRE 提取错误: %v", d.MITRE)
	}
	var def Definition
	if err := json.Unmarshal([]byte(d.Definition), &def); err != nil {
		t.Fatal(err)
	}
	if len(def.All) != 2 {
		t.Fatalf("两个标量字段应进 All，实际 %d 条: %+v", len(def.All), def.All)
	}
	// Image|endswith → process.path + suffix；CommandLine|contains → icontains
	ops := map[string]string{}
	for _, c := range def.All {
		ops[c.Field] = c.Op
	}
	if ops["process.path"] != "suffix" || ops["process.cmdline"] != "icontains" {
		t.Errorf("字段/操作符映射错误: %+v", ops)
	}
	// 编译期校验必须通过（转换结果与 Compile 严格校验同口径）
	if _, err := Compile(d.Definition); err != nil {
		t.Errorf("转换结果应通过 Compile: %v", err)
	}
}

func TestConvertSigmaMultiValueORAndAll(t *testing.T) {
	doc := `
title: 多值语义样例
status: stable
level: medium
logsource:
  category: process_creation
  product: windows
detection:
  sel_any:
    CommandLine|contains:
      - '/alpha'
      - '/beta'
  sel_all:
    Image|endswith:
      - 'a.exe'
      - 'b.exe'
  condition: sel_any and sel_all
`
	drafts, skipped, err := ConvertSigma([]byte(doc))
	if err != nil || skipped.Title != "" {
		t.Fatalf("应转换成功: err=%v skip=%+v", err, skipped)
	}
	// (C1∨C2)∧(E1∨E2) 按笛卡尔积展开为 4 条规则（tyrian DNF 口径）
	if len(drafts) != 4 {
		t.Fatalf("双 OR 块应展开为 4 条规则，实际 %d", len(drafts))
	}
	var def Definition
	json.Unmarshal([]byte(drafts[0].Definition), &def)
	// 展开后每条规则只剩 All（单值条件 AND）
	if len(def.All) != 2 || len(def.Any) != 0 {
		t.Fatalf("展开规则应为纯 All: %+v", def)
	}
}

func TestConvertSigmaOrDNFExpansion(t *testing.T) {
	doc := `
title: or 分支展开样例
status: stable
level: high
logsource:
  category: process_creation
  product: windows
detection:
  sel_a:
    Image|endswith: 'a.exe'
  sel_b:
    Image|endswith: 'b.exe'
  condition: sel_a or sel_b
`
	drafts, _, err := ConvertSigma([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	if len(drafts) != 2 {
		t.Fatalf("or 两分支应展开为 2 条规则，实际 %d", len(drafts))
	}
	if !strings.Contains(drafts[0].Title, "1/2") || !strings.Contains(drafts[1].Title, "2/2") {
		t.Errorf("展开规则应带分支序号后缀: %q / %q", drafts[0].Title, drafts[1].Title)
	}
}

func TestConvertSigmaNotSingleCondition(t *testing.T) {
	doc := `
title: not 排除样例
status: stable
level: high
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: 'demo.exe'
  filter:
    User|contains: 'SYSTEM'
  condition: selection and not filter
`
	drafts, skipped, err := ConvertSigma([]byte(doc))
	if err != nil || skipped.Title != "" {
		t.Fatalf("应转换成功: err=%v skip=%+v", err, skipped)
	}
	var def Definition
	json.Unmarshal([]byte(drafts[0].Definition), &def)
	if len(def.None) != 1 || def.None[0].Field != "process.user" {
		t.Fatalf("not 块应进 None: %+v", def)
	}
}

func TestConvertSigmaGates(t *testing.T) {
	gates := []struct {
		name   string
		yaml   string
		reason string
	}{
		{"registry 类别拒绝", `
title: r
status: stable
level: high
logsource:
  category: registry_event
  product: windows
detection:
  selection:
    TargetObject: 'HKLM\\x'
  condition: selection
`, "暂无对应遥测维度"},
		{"experimental 拒绝", `
title: r
status: experimental
level: high
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: 'x.exe'
  condition: selection
`, "experimental"},
		{"informational 拒绝", `
title: r
status: stable
level: informational
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: 'x.exe'
  condition: selection
`, "informational"},
		{"未知字段拒绝", `
title: r
status: stable
level: high
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Hashes|contains: 'abc'
  condition: selection
`, "无映射"},
		{"未知修饰符拒绝", `
title: r
status: stable
level: high
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|base64offset|contains: 'abc'
  condition: selection
`, "base64offset"},
		{"condition 通配拒绝", `
title: r
status: stable
level: high
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: 'x.exe'
  condition: 1 of selection*
`, "通配"},
	}
	for _, g := range gates {
		drafts, skipped, err := ConvertSigma([]byte(g.yaml))
		if err != nil {
			t.Errorf("%s: 不应返回硬错误: %v", g.name, err)
			continue
		}
		if len(drafts) != 0 {
			t.Errorf("%s: 应拒绝，实际产出 %d 条", g.name, len(drafts))
			continue
		}
		if !strings.Contains(skipped.Reason, g.reason) {
			t.Errorf("%s: 原因应含 %q，实际 %q", g.name, g.reason, skipped.Reason)
		}
	}
}

func TestConvertSigmaNotMultiConditionRejected(t *testing.T) {
	doc := `
title: not 多条件样例
status: stable
level: high
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: 'demo.exe'
  filter:
    User: 'SYSTEM'
    CommandLine|contains: '/safe'
  condition: selection and not filter
`
	_, skipped, err := ConvertSigma([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	if len(skipped.Reason) == 0 || skipped.Title == "" {
		t.Fatalf("not 多条件块应跳过并报告原因: %+v", skipped)
	}
}
