//go:build windows
// +build windows

// filedef 接线层：勒索防御（canary/速率）Finding → 统一告警出口，
// 与 netwatch/persist 的接线层同构（机制在 ransom 包，策略在这里）。
package agentapp

import (
	"os"
	"path/filepath"
	"strings"
	"time"

	"zedr/internal/agent/ransom"
	"zedr/internal/model"
)

// canaryDirs 返回诱饵落点目录（只收真实存在的目录）。
//
// 选型理由：诱饵要放在"勒索软件必然扫到、人类与安装器很少动"的位置。
// 用户文档四目录（Desktop/Documents/Downloads/PUBLIC）符合前者；
// TEMP/ProgramData 是安装器与清理工具的常驻地，误报面大，刻意不放。
func canaryDirs() []string {
	var out []string
	seen := map[string]bool{}
	add := func(p string) {
		if p == "" {
			return
		}
		key := strings.ToLower(p)
		if seen[key] {
			return
		}
		// 不存在的目录跳过且不代建：探针不应在用户机器上凭空造目录
		//（ransom.New 同口径，这里先过滤只为让日志干净）
		if st, err := os.Stat(p); err == nil && st.IsDir() {
			seen[key] = true
			out = append(out, p)
		}
	}
	if up := os.Getenv("USERPROFILE"); up != "" {
		add(filepath.Join(up, "Desktop"))
		add(filepath.Join(up, "Documents"))
		add(filepath.Join(up, "Downloads"))
	}
	add(os.Getenv("PUBLIC"))
	return out
}

// emitFileDefenseFinding 把勒索防御 Finding 转成统一告警。
//
// 指纹取"规则 + 证据主路径/目录"：同一诱饵的重复命中交给服务端指纹窗口
// 吸收，不同诱饵/不同目录互不去重；agent 侧 15min 冷却已保证不刷屏。
func (a *Agent) emitFileDefenseFinding(f ransom.Finding) {
	fp := f.RuleID
	for _, n := range f.Notes {
		for _, prefix := range []string{"path=", "dir="} {
			if v, ok := strings.CutPrefix(n, prefix); ok && v != "" {
				fp += ":" + strings.ToLower(v)
				break
			}
		}
		if fp != f.RuleID {
			break
		}
	}
	a.emitAlert(model.AlertEnvelope{
		Fingerprint: fp,
		Title:       f.Title,
		Summary:     f.Summary,
		Verdict:     f.Verdict,
		Severity:    f.Severity,
		Score:       f.Score,
		// 两路事件源都不带发起者 PID（ransom 包的诚实边界），
		// ProcUser 用命名空间占位说明信号来源，对齐 persist 的
		// "SYSTEM/PERSISTENCE" 先例——空 source 字段在 UI 上更难解释
		ProcUser: "SYSTEM/FILE-DEFENSE",
		RuleIDs:  []string{f.RuleID},
		MITRE:    f.MITRE,
		Evidence: model.Evidence{
			Signals: []model.Signal{{
				Layer: "filedef", ID: f.RuleID, Name: "文件防御（诱饵/勒索行为）",
				Score: f.Score, Note: f.Summary, MITRE: strings.Join(f.MITRE, ","),
			}},
			Notes: f.Notes,
		},
		OccurredAt: time.Now(),
	})
}
