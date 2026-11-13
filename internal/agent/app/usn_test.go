//go:build windows
// +build windows

package agentapp

import (
	"fmt"
	"testing"
	"time"

	"zedr/internal/agent/ransom"
	"zedr/internal/agent/winapi"
)

// USN 未配对 rename_old 按 renamed_old 投递：canary 按名匹配要能抓到
// "诱饵被改名走"（改出本卷/跨批次时 rename_new 不在同批次，此前漏报）；
// 同时 renamed_old 在速率窗口权重为 0——正常改名的海量 rename_old
// 不能变成勒索速率噪声（投 removed 就会，这里是两者的分界线）。
func TestDispatchUSNRenameOldFeedsDefense(t *testing.T) {
	dir := t.TempDir()
	var fs []ransom.Finding
	d := ransom.New(ransom.Options{
		CanaryDirs: []string{dir},
		OnFinding:  func(f ransom.Finding) { fs = append(fs, f) },
	})
	a := &Agent{fileDefense: d}
	now := time.Now()

	// 诱饵被改名走（旧名命中）
	a.dispatchUSNEvents([]winapi.USNEvent{{
		Name: "backup_report.docx", Kind: winapi.USNKindRenameOld, When: now,
	}}, false, now)
	hit := false
	for _, f := range fs {
		if f.RuleID == "FILE-CANARY" {
			hit = true
		}
	}
	if !hit {
		t.Fatalf("rename_old 未触发 canary 命中: %+v", fs)
	}

	// 25 个非诱饵文件的 rename_old：不进速率窗口
	for i := 0; i < 25; i++ {
		a.dispatchUSNEvents([]winapi.USNEvent{{
			Name: fmt.Sprintf("doc%02d.docx", i), Kind: winapi.USNKindRenameOld, When: now,
		}}, false, now)
	}
	for _, f := range fs {
		if f.RuleID == "FILE-RANSOM" {
			t.Fatal("rename_old 不应进速率窗口（正常改名会变成勒索噪声）")
		}
	}
	d.Close()
}
