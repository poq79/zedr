// 本测试文件 NEUTRAL（无构建标签）：Linux 路径校验与属性映射的纯逻辑
// 在 Windows 上跑（验证口径，见 linuxpath.go 头注释）。覆盖点：
//   - validateLinuxAbsPath 的放行/拒绝矩阵（绝对路径、穿越、NUL、Clean 归一）；
//   - attrsFromStat 的四属性映射口径。
package liveapi

import (
	"os"
	"strings"
	"testing"

	"zedr/internal/platform/apperr"
)

func TestValidateLinuxAbsPathOK(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"/tmp/x", "/tmp/x"},
		{"/tmp//x", "/tmp/x"},      // 连续分隔符归一
		{"/etc/../etc/passwd", ""}, // .. 段（拒绝，want 空由下方分支处理）
		{"/proc/1/root/etc/passwd", "/proc/1/root/etc/passwd"},
		{"/", "/"},
		{"/tmp/x/", "/tmp/x"}, // 尾分隔符归一
	}
	for _, c := range cases {
		got, err := validateLinuxAbsPath(c.in)
		if strings.Contains(c.in, "..") {
			if err == nil {
				t.Errorf("穿越路径 %q 应被拒绝", c.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("合法路径 %q 不应报错: %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("%q: 期望 %q 实得 %q", c.in, c.want, got)
		}
	}
}

func TestValidateLinuxAbsPathReject(t *testing.T) {
	cases := []string{
		"",             // 空
		"tmp/x",        // 相对路径
		"./x",          // 相对路径
		"/a/../b",      // 穿越（Clean 会吞掉，必须按原始输入拒绝）
		"/..",          // 根级穿越
		"/a/../../etc", // 多级穿越
		"/tmp/\x00x",   // NUL 字节
	}
	for _, in := range cases {
		_, err := validateLinuxAbsPath(in)
		if err == nil {
			t.Errorf("非法路径 %q 应被拒绝", in)
			continue
		}
		var ae *apperr.Error
		if !asApperr(err, &ae) || ae.Status != 400 {
			t.Errorf("非法路径 %q 应返回 400 类错误: %v", in, err)
		}
	}
}

// asApperr 是 errors.As 的本地小包装（测试文件不引入额外依赖）。
func asApperr(err error, target **apperr.Error) bool {
	for err != nil {
		if ae, ok := err.(*apperr.Error); ok {
			*target = ae
			return true
		}
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}

func TestAttrsFromStat(t *testing.T) {
	cases := []struct {
		name            string
		mode            os.FileMode
		hidden, ro, rep bool
	}{
		{"run.sh", 0o755, false, false, false},               // 普通可执行
		{".bashrc", 0o644, true, false, false},               // 点文件 → hidden
		{"backup.tgz", 0o444, false, true, false},            // 全无写位 → readonly
		{"link", os.ModeSymlink | 0o777, false, false, true}, // symlink → reparse
		{"writable", 0o666, false, false, false},             // 有写位 → 非 readonly
		{"normal", 0o644, false, false, false},               // system 恒 false（不在断言里单列）
	}
	for _, c := range cases {
		a := attrsFromStat(c.name, c.mode)
		if a.Hidden != c.hidden {
			t.Errorf("%s: hidden 期望 %v 实得 %v", c.name, c.hidden, a.Hidden)
		}
		if a.Readonly != c.ro {
			t.Errorf("%s: readonly 期望 %v 实得 %v", c.name, c.ro, a.Readonly)
		}
		if a.Reparse != c.rep {
			t.Errorf("%s: reparse 期望 %v 实得 %v", c.name, c.rep, a.Reparse)
		}
		if a.System {
			t.Errorf("%s: system 应恒 false（Linux 无该语义，不猜测）", c.name)
		}
	}
}
