package rules

import (
	"encoding/json"
	"testing"
)

// TestTemplatesCompile 每个模板都必须能通过引擎的严格编译校验。
// 模板是给运营者的起点——起点本身就是坏的，等于把 5.1 节
// "规则看似存在实际从未生效"的事故做成了产品功能。
func TestTemplatesCompile(t *testing.T) {
	tpls := Templates()
	if len(tpls) < 8 {
		t.Fatalf("模板数量异常: %d", len(tpls))
	}
	seen := map[string]bool{}
	for _, tp := range tpls {
		if seen[tp.ID] {
			t.Fatalf("模板 ID 重复: %s", tp.ID)
		}
		seen[tp.ID] = true
		raw, err := json.Marshal(tp.Definition)
		if err != nil {
			t.Fatalf("模板 %s 序列化失败: %v", tp.ID, err)
		}
		if _, err := Compile(string(raw)); err != nil {
			t.Fatalf("模板 %s(%s) 编译失败: %v", tp.ID, tp.Name, err)
		}
	}
}

// TestSchemaMatchesDSL schema 参考表与 DSL 白名单必须严格一致：
// 表里多一个引擎不认的字段/操作符，前端就会让运营者写出保存必拒、
// 甚至加载期静默失效的规则。
func TestSchemaMatchesDSL(t *testing.T) {
	fields, ops := Schema()
	if len(fields) == 0 || len(ops) == 0 {
		t.Fatal("schema 不应为空")
	}
	for _, f := range fields {
		kind, ok := validFields[f.Field]
		if !ok {
			t.Fatalf("schema 字段 %q 不在 DSL 白名单中", f.Field)
		}
		var want KindName
		switch kind {
		case kindString:
			want = KindString
		case kindBool:
			want = KindBool
		case kindInt:
			want = KindInt
		case kindStringList:
			want = KindStringList
		case kindIntList:
			want = KindIntList
		}
		if f.Kind != want {
			t.Fatalf("schema 字段 %q 类型标注 %q 与 DSL %v 不符", f.Field, f.Kind, kind)
		}
	}
	for _, o := range ops {
		if _, ok := validOps[o.Op]; !ok {
			t.Fatalf("schema 操作符 %q 不在 DSL 白名单中", o.Op)
		}
	}
	// 反向：DSL 白名单里的每个字段都应出现在 schema（漏一个 = 前端写不出）。
	// proc.* 是为老规则保留的历史别名，schema 只暴露规范名——别名集合
	// 若有增删，这里会失败并提示同步更新。
	aliases := map[string]bool{"proc.name": true, "proc.path": true, "proc.cmdline": true, "proc.user": true}
	for a := range aliases {
		if _, ok := validFields[a]; !ok {
			t.Fatalf("别名 %q 已不在 DSL 白名单中，请同步更新本测试", a)
		}
	}
	docs := map[string]bool{}
	for _, f := range fields {
		docs[f.Field] = true
	}
	for f := range validFields {
		if !docs[f] && !aliases[f] {
			t.Fatalf("DSL 字段 %q 未收录进 schema（前端表单写不出该字段）", f)
		}
	}
}

// TestBlankTemplateNeverMatches 占位模板的条件必须永不命中——
// 运营者选了空白模板忘改值时，最坏结果应该是"规则不响"，
// 而不是"每个进程都 +30 分"的误报风暴。
func TestBlankTemplateNeverMatches(t *testing.T) {
	for _, tp := range Templates() {
		if tp.ID != "tpl-blank" {
			continue
		}
		ok, _ := tp.Definition.Match(&Target{
			Name: "notepad.exe", Path: `C:\Windows\System32\notepad.exe`,
			Signed: true, SignatureOK: true, InSystem: true,
		})
		if ok {
			t.Fatal("空白模板占位条件不应命中任何正常进程")
		}
	}
}
