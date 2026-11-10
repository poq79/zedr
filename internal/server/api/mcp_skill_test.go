package api

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"zedr/internal/mcp"
)

// 验证 GET /mcp/skill.md 输出对齐 agentskills.io SKILL.md 开放标准
//（2026-11-10 查阅）：YAML frontmatter（name/description/license/metadata）
// + 原有正文，curl 示例带 Streamable HTTP 规范要求的 Accept 头。
func TestSkillMarkdownFrontmatter(t *testing.T) {
	d := Deps{MCP: &mcp.Server{
		Name:    "zedr-edr",
		Version: "v9",
		Tools: []mcp.Tool{{
			Name:        "t",
			Description: "d",
			InputSchema: json.RawMessage(`{"type":"object"}`),
		}},
	}}
	out := skillMarkdown(d)
	s := string(out)

	// frontmatter 必须以固定 name 开头（agentskills.io：name 与目录同名、
	// 小写字母数字+连字符）
	if !bytes.HasPrefix(out, []byte("---\nname: zedr-edr\n")) {
		t.Fatalf("输出必须以 SKILL.md frontmatter 开头，实际开头 %.80q", s)
	}
	if !strings.Contains(s, "description: \"") {
		t.Fatalf("frontmatter 缺 description（须引号包裹保证 YAML 安全）：%.200q", s)
	}
	if !strings.Contains(s, "license: Proprietary") {
		t.Fatal("frontmatter 缺 license（仓库无 LICENSE 文件，按 Proprietary 标注）")
	}
	if !strings.Contains(s, "  version: \"v9\"") {
		t.Fatal("metadata 缺 version（应取自 mcp.Server.Version）")
	}
	if !strings.Contains(s, "  generated-date: \"") {
		t.Fatal("metadata 缺 generated-date（UTC 日期，YYYY-MM-DD）")
	}
	if strings.Count(s, "\n---\n") < 1 {
		t.Fatal("frontmatter 缺闭合分隔线 ---")
	}
	// description 规范上限 1024 字符且必须单行；按字节断言（多字节中文
	// 每字符 ≥1 字节，字节数不超则字符数必不超，口径更严）
	if len(skillDescription) > 1024 {
		t.Fatalf("description 超 1024 字符上限：%d 字节", len(skillDescription))
	}
	if strings.ContainsAny(skillDescription, "\n:\"\\") {
		t.Fatal("description 含换行/冒号/引号/反斜杠，违背措辞规避口径（应保持双引号标量零转义）")
	}
	// Streamable HTTP 规范要求的 Accept 头（缺了被官方 SDK 服务端 400 拒绝，
	// 协议迁移 SDK v1.8.0 时实测）
	if !strings.Contains(s, "-H 'Accept: application/json, text/event-stream'") {
		t.Fatal("curl 示例缺 Streamable HTTP 要求的 Accept 头")
	}
	// 2026-07-28 无状态规范的能力探测说明
	if !strings.Contains(s, "server/discover") {
		t.Fatal("连接方式缺 server/discover 能力探测说明")
	}
	// 正文原有段落保留抽查
	for _, want := range []string{"## 连接方式", "## 工具清单", "`t` | d |", "## 使用纪律（重要）", "## 示例问题", "## 直接调用示例"} {
		if !strings.Contains(s, want) {
			t.Fatalf("正文缺原有段落 %q", want)
		}
	}
}
