package service

import (
	"context"
	"fmt"
	"strings"

	"zedr/internal/rules"
	"zedr/internal/server/domain"
)

// Sigma 批量导入（M1，2026-11-21）：转换器在 internal/rules/sigma.go
// （门禁/映射/DNF 展开见其注释），本文件负责入库编排——
// 多文档拆分、查重防覆盖、观察模式入库、三态报告。

// sigmaImportMaxRules 是单次导入的展开规则数上限：
// 数百条是 Security Onion 默认包的同量级口径；引擎逐条线性求值，
// 无配额的长尾导入会直接放大每进程检测成本。
const sigmaImportMaxRules = 200

// SigmaSkipReport 是导入报告里的一条跳过/失败记录。
type SigmaSkipReport struct {
	Title  string `json:"title"`
	Reason string `json:"reason"`
}

// SigmaImportReport 是 Sigma 批量导入的三态报告。
type SigmaImportReport struct {
	Docs     int               `json:"docs"`               // 解析出的 Sigma 文档数
	Created  []domain.Rule     `json:"created"`            // 已入库（observe 模式）
	Skipped  []SigmaSkipReport `json:"skipped"`            // 门禁拒绝/转换失败及原因
	TotalDoc int               `json:"total_generated"`    // 展开后的规则总数（含未入库）
}

// splitYAMLDocs 按独立行 "---" 切分多文档 YAML。
// YAML 规范的多文档分隔符就是行首 ---，bufio 逐行扫描比 yaml.Decoder
// 更稳（后者要求每个文档都能被 sigmaRule 结构完整吃下，而分隔行
// 之外的注释/空行由 yaml 自身容错）。
func splitYAMLDocs(text string) []string {
	var docs []string
	var cur []string
	for _, line := range strings.Split(text, "\n") {
		t := strings.TrimSpace(line)
		if t == "---" {
			if len(cur) > 0 {
				docs = append(docs, strings.Join(cur, "\n"))
				cur = nil
			}
			continue
		}
		cur = append(cur, line)
	}
	if len(cur) > 0 {
		docs = append(docs, strings.Join(cur, "\n"))
	}
	return docs
}

// SigmaImport 批量导入 Sigma YAML：转换→查重→observe 入库。
// 任何一条入库失败（编译校验/存储错误）整批中止并返回错误——
// 部分成功会让分析员误以为全部规则都在生效；跳过类（门禁/不支持）
// 不算失败，逐条报告原因。
func (s *RuleService) SigmaImport(ctx context.Context, yamlText, by string) (*SigmaImportReport, error) {
	docs := splitYAMLDocs(yamlText)
	rep := &SigmaImportReport{Docs: len(docs), Created: []domain.Rule{}, Skipped: []SigmaSkipReport{}}

	// 查重集合：已有规则名（同名覆盖既有规则是事故——Upsert 是按 ID
	// 语义，导入一律新建，名称冲突直接跳过报告）
	existing, err := s.repos.Rules.List(ctx)
	if err != nil {
		return nil, err
	}
	byName := make(map[string]bool, len(existing))
	for _, r := range existing {
		byName[strings.ToLower(r.Name)] = true
	}

	created := 0
	for i, doc := range docs {
		if strings.TrimSpace(doc) == "" {
			continue
		}
		drafts, skipped, err := rules.ConvertSigma([]byte(doc))
		if err != nil {
			rep.Skipped = append(rep.Skipped, SigmaSkipReport{
				Title:  fmt.Sprintf("文档 #%d", i+1),
				Reason: err.Error(),
			})
			continue
		}
		if skipped.Reason != "" {
			rep.Skipped = append(rep.Skipped, SigmaSkipReport{Title: skipped.Title, Reason: skipped.Reason})
			continue
		}
		for _, d := range drafts {
			if rep.TotalDoc+created >= sigmaImportMaxRules {
				rep.Skipped = append(rep.Skipped, SigmaSkipReport{
					Title:  d.Title,
					Reason: fmt.Sprintf("超出单次导入上限 %d 条（展开后口径）", sigmaImportMaxRules),
				})
				continue
			}
			if byName[strings.ToLower(d.Title)] {
				rep.Skipped = append(rep.Skipped, SigmaSkipReport{
					Title:  d.Title,
					Reason: "同名规则已存在（防覆盖）",
				})
				continue
			}
			rule := &domain.Rule{
				Name:        d.Title,
				Description: d.Description,
				Severity:    domain.Severity(d.Severity),
				MITRE:       d.MITRE,
				Score:       d.Score,
				Enabled:     false,          // 入库即禁用：转正是人工决策
				Mode:        "observe",      // 先观察后转正（Sigma bake 期对应物）
				Definition:  d.Definition,
				Builtin:     false,
			}
			saved, err := s.Upsert(ctx, rule, by)
			if err != nil {
				rep.Skipped = append(rep.Skipped, SigmaSkipReport{
					Title:  d.Title,
					Reason: "入库失败：" + err.Error(),
				})
				continue
			}
			byName[strings.ToLower(saved.Name)] = true
			rep.Created = append(rep.Created, *saved)
			created++
		}
	}
	return rep, nil
}
