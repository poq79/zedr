// Package redact 对将要落库/上报的文本做脱敏与截断。
//
// 为什么必须做：命令行是检测的核心证据，但它同时也是最容易被忽视的
// 敏感信息泄露渠道——安装脚本里的 --password=xxx、自动化工具里的
// --token=xxx、数据库客户端的 -p xxx 都会原样进入告警库、数据库、
// 管理台页面和日志。安全产品自己泄露凭据是最讽刺的事故。
package redact

import (
	"regexp"
	"strings"
)

// maxCmdLine 是命令行保留的最大字节数。
// 超长命令行本身也是可疑特征（攻击者常用超长参数做混淆），
// 因此不直接丢弃，而是截断并标注。
const maxCmdLine = 600

// 敏感参数名。覆盖 Windows / Linux / 常见工具三种风格。
const sensitiveNames = `(?:password|passwd|pwd|token|secret|apikey|api[_-]?key|access[_-]?key|credential|auth)`

var (
	// --token=value / -password=value / token=value
	reEqForm = regexp.MustCompile(`(?i)([-/]{0,2}` + sensitiveNames + `\s*=\s*)([^\s"']+)`)
	// --token value / -p value（后者仅在参数名本身足够明确时匹配）
	reSpacedForm = regexp.MustCompile(`(?i)([-/]{1,2}` + sensitiveNames + `\s+)([^\s"']+)`)
	// 引号包裹的值：password="my secret"
	reQuotedForm = regexp.MustCompile(`(?i)([-/]{0,2}` + sensitiveNames + `\s*=\s*)("[^"]*"|'[^']*')`)
)

// CmdLine 返回脱敏并截断后的命令行。
func CmdLine(s string) string {
	if s == "" {
		return ""
	}
	out := s
	// 先处理带引号的，避免被等号形式提前吃掉一半
	out = reQuotedForm.ReplaceAllString(out, `${1}***`)
	out = reEqForm.ReplaceAllString(out, `${1}***`)
	out = reSpacedForm.ReplaceAllString(out, `${1}***`)
	return Truncate(out, maxCmdLine)
}

// Truncate 按字节截断，但保证不切断 UTF-8 字符。
func Truncate(s string, n int) string {
	if n <= 0 || len(s) <= n {
		return s
	}
	cut := n
	for cut > 0 && !utf8RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "…(已截断)"
}

// 判断某字节是否是 UTF-8 字符的起始字节。
func utf8RuneStart(b byte) bool {
	return b&0xC0 != 0x80
}

// Path 对路径做轻度处理：仅截断，不做参数打码（路径本身通常不是机密）。
func Path(s string) string { return Truncate(s, 512) }

// Text 用于摘要类文本。
func Text(s string) string { return Truncate(strings.TrimSpace(s), 1000) }
