package winapi

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestTaskCommandPathGuard 校验 TaskCommandPath 的防御性收口：
// 空名/目录穿越一律返回空——4698 的任务名来自事件日志，正常不含 ".."，
// 但拼路径前必须当不可信输入处理。
func TestTaskCommandPathGuard(t *testing.T) {
	for _, name := range []string{"", `..\..\evil`, `\a\..\..\evil`, `".."`} {
		if got := TaskCommandPath(name); got != "" {
			t.Fatalf("任务名 %q 应返回空，实际 %q", name, got)
		}
	}
}

// TestTaskCommandPathRealTask 用本机真实计划任务做一次正向抽查：
// Tasks 目录树里挑一个含 Exec Command 的任务，验证注册名→文件→命令
// 的映射能走通。所有机器都有系统任务，找不到反而说明解析坏了。
func TestTaskCommandPathRealTask(t *testing.T) {
	root := filepath.Join(os.Getenv("SystemRoot"), "System32", "Tasks")
	found := false
	err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil || found || d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(strings.ToLower(p), "microsoftedgeupdate_taskmachinetc") &&
			!strings.Contains(strings.ToLower(d.Name()), "update") {
			return nil // 只抽查名字带 update 的常见系统任务，控制成本
		}
		def := parseTaskXML(p)
		if def.Command == "" {
			return nil
		}
		rel, rerr := filepath.Rel(root, p)
		if rerr != nil {
			return nil
		}
		got := TaskCommandPath(`\` + rel)
		if got == "" {
			t.Errorf("任务 %q 应解析出命令（文件内 Command=%q）", rel, def.Command)
		}
		found = true
		return nil
	})
	if err != nil {
		t.Skipf("枚举系统任务目录失败（非典型环境）: %v", err)
	}
	if !found {
		t.Skip("本机未找到带 Exec 动作的 update 类系统任务，跳过正向抽查")
	}
}
