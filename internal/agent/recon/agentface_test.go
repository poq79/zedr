//go:build windows

// agentface_test.go：agent_face 三块清点的夹具测试。
// 夹具全部落在 t.TempDir + t.Setenv 重定向 APPDATA/USERPROFILE，不碰
// 真实用户目录；真机冒烟是显式 opt-in 的独立测试（ZEDR_RECON_SMOKE=1）。
// 脱敏红线断言（env value / URL userinfo 不出现在线协议）在每个相关
// 测试里都做——这是本文件最重要的断言。
package recon

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeSkill 在 root 下建 skill 目录并写 SKILL.md。
func writeSkill(t *testing.T, root, dir, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(root, dir), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, dir, "SKILL.md"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestAgentFaceMCPServersRedaction(t *testing.T) {
	tmp := t.TempDir()
	appData := filepath.Join(tmp, "AppData", "Roaming")
	home := filepath.Join(tmp, "home")
	t.Setenv("APPDATA", appData)
	t.Setenv("USERPROFILE", home)

	// Claude Desktop：stdio server（带 env）+ 远程 server（URL 内嵌 userinfo）。
	claudeDir := filepath.Join(appData, "Claude")
	if err := os.MkdirAll(claudeDir, 0o755); err != nil {
		t.Fatal(err)
	}
	claudeCfg := `{
	  "mcpServers": {
	    "remote": {"type": "sse", "url": "https://user:pass@mcp.example.com/sse"},
	    "filesystem": {
	      "command": "npx",
	      "args": ["-y", "@modelcontextprotocol/server-filesystem", "C:\\Users\\dev\\data"],
	      "env": {"ZTOKEN": "tok-value-leak-me-not", "API_SECRET_VALUE": "sk-super-secret-do-not-leak"}
	    }
	  }
	}`
	if err := os.WriteFile(filepath.Join(claudeDir, "claude_desktop_config.json"), []byte(claudeCfg), 0o644); err != nil {
		t.Fatal(err)
	}
	// Cursor：第二个来源，验证 client/source_path 归因。
	cursorDir := filepath.Join(home, ".cursor")
	if err := os.MkdirAll(cursorDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cursorDir, "mcp.json"),
		[]byte(`{"mcpServers":{"playwright":{"command":"npx","args":["@playwright/mcp"]}}}`), 0o644); err != nil {
		t.Fatal(err)
	}

	b := newTestBase(nil, nil, false)
	cat, err := detectAIFace(context.Background(), b)
	if err != nil {
		t.Fatalf("detectAIFace: %v", err)
	}
	if cat.AgentFace == nil {
		t.Fatal("agent_face 应非 nil")
	}
	af := cat.AgentFace
	if len(af.MCPServers) != 3 {
		t.Fatalf("期望 3 个 MCP 条目，实得 %d: %+v", len(af.MCPServers), af.MCPServers)
	}

	// 同一文件内按名字排序（可 diff）；来源顺序按扫描表。
	fs := af.MCPServers[0]
	if fs.Name != "filesystem" || fs.Client != "claude_desktop" {
		t.Fatalf("条目 0 归因不符: %+v", fs)
	}
	if fs.Command != "npx" {
		t.Fatalf("command 摘取不符: %q", fs.Command)
	}
	wantArgs := []string{"-y", "@modelcontextprotocol/server-filesystem", `C:\Users\dev\data`}
	if strings.Join(fs.Args, "|") != strings.Join(wantArgs, "|") {
		t.Fatalf("args 摘取不符: %v", fs.Args)
	}
	if strings.Join(fs.EnvKeys, "|") != "API_SECRET_VALUE|ZTOKEN" {
		t.Fatalf("env key 应只有 key 名且有序: %v", fs.EnvKeys)
	}

	remote := af.MCPServers[1]
	if remote.Name != "remote" {
		t.Fatalf("条目 1 不符: %+v", remote)
	}
	if remote.URL != "https://***@mcp.example.com/sse" {
		t.Fatalf("URL userinfo 应打码: %q", remote.URL)
	}

	cursor := af.MCPServers[2]
	if cursor.Client != "cursor" || cursor.SourcePath != filepath.Join(cursorDir, "mcp.json") {
		t.Fatalf("cursor 条目归因不符: %+v", cursor)
	}

	// 脱敏红线：env value 与 URL userinfo 绝不出现在整份线协议里。
	wire, err := json.Marshal(cat)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, secret := range []string{"sk-super-secret-do-not-leak", "tok-value-leak-me-not", "user:pass", "pass@mcp"} {
		if strings.Contains(string(wire), secret) {
			t.Fatalf("凭据泄漏到线协议: %s\nwire=%s", secret, wire)
		}
	}
}

func TestAgentFaceNoConfigEmptyProfile(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("APPDATA", filepath.Join(tmp, "no-appdata"))
	t.Setenv("USERPROFILE", filepath.Join(tmp, "no-home"))

	b := newTestBase(nil, nil, false)
	cat, err := detectAIFace(context.Background(), b)
	if err != nil {
		t.Fatalf("detectAIFace: %v", err)
	}
	af := cat.AgentFace
	if af == nil {
		t.Fatal("无配置环境也应输出 agent_face（空清单 + note）")
	}
	if len(af.MCPServers) != 0 || len(af.Skills) != 0 {
		t.Fatalf("空环境应为空清单: %+v", af)
	}
	if af.MCPTruncated || af.SkillsTruncated {
		t.Fatal("空环境不应置 truncated")
	}
	found := false
	for _, n := range af.MCPNotes {
		if strings.Contains(n, "未发现 MCP server 配置") {
			found = true
		}
	}
	if !found {
		t.Fatalf("应有未发现 MCP 配置的 note: %v", af.MCPNotes)
	}
	// 空数组输出 [] 而非 null（契约稳定，前端不判空指针）。
	wire, _ := json.Marshal(af)
	if !strings.Contains(string(wire), `"mcp_servers":[]`) || !strings.Contains(string(wire), `"skills":[]`) {
		t.Fatalf("空清单应输出 [] 而非 null: %s", wire)
	}
	// 覆盖边界恒输出（清单自带口径）。
	if !strings.Contains(string(wire), "覆盖边界") {
		t.Fatalf("覆盖边界说明缺失: %s", wire)
	}
}

func TestAgentFaceSkillsFrontmatter(t *testing.T) {
	home := t.TempDir()
	t.Setenv("USERPROFILE", home)
	t.Setenv("APPDATA", filepath.Join(home, "no-appdata"))

	skillsRoot := filepath.Join(home, ".claude", "skills")
	if err := os.MkdirAll(skillsRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	writeSkill(t, skillsRoot, "b-my-skill", "---\nname: my-skill\ndescription: \"Reads local files and queries APIs\"\nallowed-tools: Read, Grep\n---\n\n# body\n")
	// CRLF + 单引号 + 无 name 键。
	writeSkill(t, skillsRoot, "a-quoted", "---\r\ndescription: '另一段描述，无 name 键'\r\n---\r\nbody\r\n")
	// 恶意超长 description：截断不 panic。
	writeSkill(t, skillsRoot, "c-long", "---\ndescription: "+strings.Repeat("A", 400000)+"\n---\nbody\n")
	// 无闭合围栏：正文里的 name/description 不得被当清单事实。
	writeSkill(t, skillsRoot, "d-nofence", "# plain\nname: sneaky\ndescription: sneaky-desc\n")
	// 块标量（|/-）：首行内容为 description，第二行不看。
	writeSkill(t, skillsRoot, "e-block", "---\nname: block-skill\ndescription: |-\n  First line of a block scalar description\n  second line ignored\n---\nbody\n")
	// 根下的散文件不是 skill。
	if err := os.WriteFile(filepath.Join(skillsRoot, "stray.txt"), []byte("not a skill"), 0o644); err != nil {
		t.Fatal(err)
	}

	b := newTestBase(nil, nil, false)
	cat, err := detectAIFace(context.Background(), b)
	if err != nil {
		t.Fatalf("detectAIFace: %v", err)
	}
	af := cat.AgentFace
	if len(af.Skills) != 5 {
		t.Fatalf("期望 5 个 skill（散文件忽略），实得 %d: %+v", len(af.Skills), af.Skills)
	}
	if af.Skills[0].Dir != "a-quoted" || af.Skills[0].Description != "另一段描述，无 name 键" {
		t.Fatalf("CRLF/单引号解析不符: %+v", af.Skills[0])
	}
	if af.Skills[1].Dir != "b-my-skill" || af.Skills[1].Name != "my-skill" ||
		af.Skills[1].Description != "Reads local files and queries APIs" {
		t.Fatalf("name/description 摘取不符: %+v", af.Skills[1])
	}
	if af.Skills[1].SourcePath != filepath.Join(skillsRoot, "b-my-skill", "SKILL.md") {
		t.Fatalf("source_path 不符: %q", af.Skills[1].SourcePath)
	}
	long := af.Skills[2].Description
	if !strings.HasPrefix(long, "AAAA") || !strings.Contains(long, "已截断") || len(long) > 220 {
		t.Fatalf("恶意超长 description 应截断（不 panic）: len=%d %q", len(long), long[:min(60, len(long))])
	}
	if af.Skills[3].Dir != "d-nofence" || af.Skills[3].Name != "" || af.Skills[3].Description != "" {
		t.Fatalf("无闭合围栏不应摘取正文键: %+v", af.Skills[3])
	}
	if af.Skills[4].Dir != "e-block" || af.Skills[4].Name != "block-skill" ||
		af.Skills[4].Description != "First line of a block scalar description" {
		t.Fatalf("块标量应取首行内容: %+v", af.Skills[4])
	}
	// frontmatter 其余字段（allowed-tools）与正文不进输出。
	wire, _ := json.Marshal(af)
	for _, banned := range []string{"allowed-tools", "sneaky", "Read, Grep"} {
		if strings.Contains(string(wire), banned) {
			t.Fatalf("非清单字段泄漏: %s", banned)
		}
	}
}

func TestAgentFaceDegradations(t *testing.T) {
	tmp := t.TempDir()
	appData := filepath.Join(tmp, "AppData", "Roaming")
	home := filepath.Join(tmp, "home")
	t.Setenv("APPDATA", appData)
	t.Setenv("USERPROFILE", home)

	// 1) JSON 解析失败：诚实降级为 note，不出条目、不报错。
	claudeDir := filepath.Join(appData, "Claude")
	if err := os.MkdirAll(claudeDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(claudeDir, "claude_desktop_config.json"), []byte("{ nope }"), 0o644); err != nil {
		t.Fatal(err)
	}
	// 2) 合法 JSON 但无 mcpServers 段（用 windsurf 路径，cursor 留给用例 4）。
	wsDir := filepath.Join(home, ".codeium", "windsurf")
	if err := os.MkdirAll(wsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(wsDir, "mcp_config.json"), []byte(`{"foo":1}`), 0o644); err != nil {
		t.Fatal(err)
	}
	// 4) 用例：cursor 配置 env key 超上限。
	cursorDir := filepath.Join(home, ".cursor")
	if err := os.MkdirAll(cursorDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// 3) Codex TOML：只计数 [mcp_servers.*] 段。
	codexDir := filepath.Join(home, ".codex")
	if err := os.MkdirAll(codexDir, 0o755); err != nil {
		t.Fatal(err)
	}
	codexCfg := "model = \"gpt-x\"\n[mcp_servers.filesystem]\ncommand = \"npx\"\n\n[mcp_servers.fetch]\nurl = \"https://x\"\n"
	if err := os.WriteFile(filepath.Join(codexDir, "config.toml"), []byte(codexCfg), 0o644); err != nil {
		t.Fatal(err)
	}
	// 4) env key 超上限：截到 32 + truncated 标记，value 绝不出现。
	var sb strings.Builder
	sb.WriteString(`{"mcpServers":{"envcap":{"command":"npx","env":{`)
	for i := 0; i < 40; i++ {
		if i > 0 {
			sb.WriteString(",")
		}
		sb.WriteString(fmt.Sprintf(`"K%02d":"leak-me-%02d"`, i, i))
	}
	sb.WriteString(`}}}}`)
	if err := os.WriteFile(filepath.Join(cursorDir, "mcp.json"), []byte(sb.String()), 0o644); err != nil {
		t.Fatal(err)
	}

	b := newTestBase(nil, nil, false)
	cat, err := detectAIFace(context.Background(), b)
	if err != nil {
		t.Fatalf("detectAIFace: %v", err)
	}
	af := cat.AgentFace
	notes := strings.Join(af.MCPNotes, "\n")
	if !strings.Contains(notes, "claude_desktop: 配置解析失败") {
		t.Fatalf("解析失败应有 note: %v", af.MCPNotes)
	}
	if !strings.Contains(notes, "windsurf: 未含 mcpServers 段或为空") {
		t.Fatalf("无 mcpServers 段应有 note: %v", af.MCPNotes)
	}
	if !strings.Contains(notes, "codex_cli: TOML 配置存在，检出 2 个 [mcp_servers.*] 段") {
		t.Fatalf("codex TOML 应只计数: %v", af.MCPNotes)
	}
	if !af.MCPTruncated {
		t.Fatal("env key 截断应置 mcp_truncated")
	}
	var envcap *MCPServerEntry
	for i := range af.MCPServers {
		if af.MCPServers[i].Name == "envcap" {
			envcap = &af.MCPServers[i]
		}
	}
	if envcap == nil {
		t.Fatalf("envcap 条目缺失: %+v", af.MCPServers)
	}
	if len(envcap.EnvKeys) != agentFaceMaxEnvKeys {
		t.Fatalf("env key 应截到 %d，实得 %d", agentFaceMaxEnvKeys, len(envcap.EnvKeys))
	}
	wire, _ := json.Marshal(cat)
	if strings.Contains(string(wire), "leak-me-") {
		t.Fatal("env value 泄漏到线协议")
	}
}

func TestAgentFaceBudgetCanceled(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("APPDATA", filepath.Join(tmp, "appdata"))
	t.Setenv("USERPROFILE", filepath.Join(tmp, "home"))

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	cat, err := detectAIFace(ctx, newTestBase(nil, nil, false))
	if err != nil {
		t.Fatalf("detectAIFace: %v", err)
	}
	af := cat.AgentFace
	if af == nil {
		t.Fatal("预算耗尽也应返回空清单 + 标记")
	}
	if !af.MCPTruncated || !af.SkillsTruncated {
		t.Fatalf("上游取消应置 truncated: %+v", af)
	}
	if len(af.MCPServers) != 0 || len(af.Skills) != 0 {
		t.Fatalf("取消后不应有条目: %+v", af)
	}
	if !strings.Contains(strings.Join(af.MCPNotes, "\n"), "预算耗尽") {
		t.Fatalf("应有预算 note: %v", af.MCPNotes)
	}
}

// TestAgentFaceRealMachineSmoke 真机冒烟（可选）：本机有真实
// .claude/.workbuddy/Claude 等配置，读的是白名单内的真实用户目录
// （全程只读）。默认跳过，ZEDR_RECON_SMOKE=1 显式开启，避免 CI/
// 其他机器依赖本机配置状态。
func TestAgentFaceRealMachineSmoke(t *testing.T) {
	if os.Getenv("ZEDR_RECON_SMOKE") == "" {
		t.Skip("真机冒烟为显式 opt-in：设置 ZEDR_RECON_SMOKE=1 后运行")
	}
	cat, err := detectAIFace(context.Background(), newTestBase(nil, nil, false))
	if err != nil {
		t.Fatalf("detectAIFace: %v", err)
	}
	af := cat.AgentFace
	if af == nil {
		t.Fatal("agent_face 应非 nil")
	}
	t.Logf("mcp_servers=%d skills=%d mcp_truncated=%v skills_truncated=%v",
		len(af.MCPServers), len(af.Skills), af.MCPTruncated, af.SkillsTruncated)
	for _, e := range af.MCPServers {
		t.Logf("mcp: name=%s client=%s command=%q url=%q env_keys=%v source=%s",
			e.Name, e.Client, e.Command, e.URL, e.EnvKeys, e.SourcePath)
	}
	for _, s := range af.Skills {
		t.Logf("skill: dir=%s name=%q desc=%q source=%s", s.Dir, s.Name, s.Description, s.SourcePath)
	}
	t.Logf("notes=%v", af.Notes)
	t.Logf("mcp_notes=%v", af.MCPNotes)
	t.Logf("skills_notes=%v", af.SkillsNotes)
	if len(af.MCPNotes) == 0 || len(af.SkillsNotes) == 0 || len(af.Notes) == 0 {
		t.Fatal("notes 应非空（覆盖边界恒输出）")
	}
}
