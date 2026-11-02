package rules

import (
	"strings"
	"testing"
)

// 内置规则必须全部通过严格校验：新增规则若写错字段/操作符，
// 这条测试会在 CI 里直接失败，而不是让规则上线后静默失效。
func TestBuiltinRulesCompileStrictly(t *testing.T) {
	for _, b := range Builtins() {
		if _, err := Compile(b.JSON()); err != nil {
			t.Fatalf("内置规则 %s 校验失败: %v", b.ID, err)
		}
	}
}

func TestCompileRejectsUnknownField(t *testing.T) {
	_, err := Compile(`{"all":[{"field":"process.nmae","op":"eq","value":"cmd.exe"}]}`)
	if err == nil || !strings.Contains(err.Error(), "未知字段") {
		t.Fatalf("err = %v, want 未知字段", err)
	}
}

func TestCompileRejectsUnknownOp(t *testing.T) {
	_, err := Compile(`{"all":[{"field":"process.name","op":"match","value":"cmd.exe"}]}`)
	if err == nil || !strings.Contains(err.Error(), "未知操作符") {
		t.Fatalf("err = %v, want 未知操作符", err)
	}
}

func TestCompileRejectsUnknownJSONKey(t *testing.T) {
	// 经典拼写错误：vale 而不是 value。json.Unmarshal 默认会忽略它，
	// 结果 contains 拿到 nil 变成"匹配空串"——必须拒绝。
	_, err := Compile(`{"all":[{"field":"process.cmdline","op":"contains","vale":"-enc"}]}`)
	if err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("err = %v, want unknown field", err)
	}
}

func TestCompileRejectsBadRegex(t *testing.T) {
	_, err := Compile(`{"any":[{"field":"process.cmdline","op":"regex","value":"([a-z"}]}`)
	if err == nil || !strings.Contains(err.Error(), "正则非法") {
		t.Fatalf("err = %v, want 正则非法", err)
	}
}

func TestCompileRejectsBadType(t *testing.T) {
	_, err := Compile(`{"all":[{"field":"network.count","op":"gt","value":"many"}]}`)
	if err == nil || !strings.Contains(err.Error(), "需要数值") {
		t.Fatalf("err = %v, want 需要数值", err)
	}
}

func TestCompiledRuleStillMatches(t *testing.T) {
	d, err := Compile(`{"all":[{"field":"process.name","op":"in","value":["cmd.exe"]}],
		"any":[{"field":"process.cmdline","op":"icontains","value":"/c whoami"}]}`)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	ok, hits := d.Match(&Target{Name: "cmd.exe", CmdLine: `C:\Windows\system32\cmd.exe /c whoami`})
	if !ok || len(hits) != 2 {
		t.Fatalf("Match = %v, hits=%v; want true with 2 hits", ok, hits)
	}
}
