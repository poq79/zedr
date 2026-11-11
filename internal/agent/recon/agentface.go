package recon

// agentface.go：端侧 AI 面清点（agent_face），挂 recon 的 ai 类。
// 2026-11-12 新增。对标：SentinelOne Singularity ADR（2026-10-21 OneCon
// 发布）把 "Agent and MCP inventory" 列为核心能力——清点每个
// agent/tool/skill/connector/MCP server 及其权限（2026-11-10 联网取证）。
// 本项目按"检测优先 + 用户态低侵入"（AGENTS.md §3.8）取其最小子集：
// 只读清单、不评判、不拦截，风险判断留给服务端与分析员。
//
// 三块内容：
//  1. MCP server 配置：已知客户端配置文件里的 mcpServers 段；
//  2. Agent Skills 目录：SKILL.md frontmatter 的 name/description；
//  3. AI agent 进程识别：不在这里重复实现——detectAI（ai.go）已含
//     进程名/命令行维度（Hermes/dsh/Claude Code/Codex/CrewAI 等），
//     本块只在 notes 挂引用与计数（重复造轮子=两套指纹漂移）。
//
// 诚实边界（先于能力声明）：
//   - 用户态只读：只 os.Stat/os.ReadFile/os.ReadDir 下方白名单路径，
//     零网络请求、零执行、零内核调用；
//   - env 值永不出探针：MCP 配置的 env 段只输出 key 名（env_keys），
//     value 在 json.RawMessage 解析阶段即被丢弃，不进任何输出结构/
//     日志——里面是 API key/令牌，脱敏红线；
//   - args 仍过 redact.CmdLine：--api-key=xxx 这类参数形态照打码
//     （安全产品自己泄露凭据是最讽刺的事故，见 redact 包头注释）；
//   - 文件读取 ≤1MB/个（readTextFile 上限），整段预算 agentFaceBudget，
//     超时置 mcp_truncated/skills_truncated 并保留已收集部分；
//   - 配置不存在是常态不算错误；JSON 解析失败/字段缺省降级为 note。
//
// 覆盖面与"未核实"标注（AGENTS.md §5.5，2026-11-12 口径）：
//   - 已扫描（JSON mcpServers 段，长期公开口径）：
//       Claude Desktop  %APPDATA%\Claude\claude_desktop_config.json
//       Cursor          %USERPROFILE%\.cursor\mcp.json
//       Windsurf        %USERPROFILE%\.codeium\windsurf\mcp_config.json
//       用户级          %USERPROFILE%\.mcp.json
//   - 只计数不解析：Codex CLI %USERPROFILE%\.codex\config.toml 为 TOML，
//     只数 [mcp_servers.*] 表头（形状未核实），结果进 mcp_notes；
//   - 未核实路径，跳过：Cline（VS Code globalStorage 扩展目录，路径随
//     VS Code 布局/扩展 ID 变化，未核实 2026 现状）；
//   - 项目级配置（仓库内 .mcp.json、.claude/.zcode/skills 等）：任意
//     仓库目录不在固定白名单内，不做全盘遍历，边界写进 notes。
//
// 接线点：recon.go detectorTable["ai"] → detectAIFace（本文件）。

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"zedr/internal/platform/redact"
)

// 预算与上限（任务口径：整段 ≤10s、文件读取 ≤1MB/个）。数量/长度上限
// 是给"清单摘要"定的，不是配置备份：畸形/恶意配置撑不大输出。
const (
	agentFaceBudget            = 10 * time.Second
	agentFaceFileLimit         = 1 << 20
	agentFaceMaxServersPerFile = 100
	agentFaceMaxServersTotal   = 200
	agentFaceMaxSkills         = 200
	agentFaceMaxArgs           = 32
	agentFaceMaxEnvKeys        = 32
	agentFaceMaxArgLen         = 256
	agentFaceMaxFieldLen       = 512
	agentFaceMaxDescLen        = 200
	agentFaceMaxNameLen        = 128
	// frontmatter 扫描行数上限：没有闭合围栏的文件按"无 frontmatter"
	// 处理，不把正文里的 name/description 误当清单事实。
	agentFaceMaxFMLines = 4096
)

// MCPServerEntry 是一个 MCP server 配置条目。只摘 name/command/args/url
// 四个字段；env 只输出 key 名（env_keys），value 永不出探针。
// Args/EnvKeys 恒输出 []（空数组而非 null），契约稳定可 diff。
type MCPServerEntry struct {
	Name       string   `json:"name"`
	Client     string   `json:"client"`
	SourcePath string   `json:"source_path"`
	Command    string   `json:"command,omitempty"`
	URL        string   `json:"url,omitempty"`
	Args       []string `json:"args"`
	EnvKeys    []string `json:"env_keys"`
}

// SkillEntry 是一个 Agent Skill 目录条目。Dir 是 skill 目录名（清单的
// 主键），Name 是 frontmatter name（缺省不输出）；Description 是
// frontmatter description 首行（≤200 字符，截断带标记）。
type SkillEntry struct {
	Dir         string `json:"dir"`
	Name        string `json:"name,omitempty"`
	Description string `json:"description,omitempty"`
	SourcePath  string `json:"source_path"`
}

// AgentFace 是 ai 类的端侧 AI 面清点子对象（Category.AgentFace）。
// 向后兼容只增不改：其他类目恒 nil（omitempty），老消费端忽略新键。
// 每块带 truncated（预算语义）+ notes（覆盖边界/降级原因）。
type AgentFace struct {
	MCPServers      []MCPServerEntry `json:"mcp_servers"`
	MCPNotes        []string         `json:"mcp_notes"`
	MCPTruncated    bool             `json:"mcp_truncated"`
	Skills          []SkillEntry     `json:"skills"`
	SkillsNotes     []string         `json:"skills_notes"`
	SkillsTruncated bool             `json:"skills_truncated"`
	Notes           []string         `json:"notes"`
}

// detectAIFace 是 ai 类的新入口：既有 harness 识别（进程/端口/探测）
// + agent_face 端侧清点。挂在同一类目而非新增第七类——契约 §12 的六类
// 是稳定面，清点是 ai 类的深化不是新维度。预算已尽时也照常收集：
// collectAgentFace 对已取消的 ctx 会立即返回空清单 + truncated，
// "空+标记"比缺字段更能区分"没清点"和"清点了没有"。
func detectAIFace(ctx context.Context, b *base) (Category, error) {
	cat, err := detectAI(ctx, b)
	cat.AgentFace = collectAgentFace(ctx, &cat)
	return cat, err
}

// collectAgentFace 执行三块清点。cat 是 detectAI 已填充的 ai 类目，
// 只读它来挂进程维度的引用，不复算。
func collectAgentFace(ctx context.Context, cat *Category) *AgentFace {
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, agentFaceBudget)
	defer cancel()

	af := &AgentFace{
		MCPServers:  []MCPServerEntry{},
		MCPNotes:    []string{},
		Skills:      []SkillEntry{},
		SkillsNotes: []string{},
		Notes:       []string{},
	}
	af.MCPNotes = append(af.MCPNotes, agentFaceMCPCoverage)
	af.SkillsNotes = append(af.SkillsNotes, agentFaceSkillsCoverage)

	// 第三块：进程维度复用 detectAI 结果（只引用，不重算）。
	procCount := 0
	kinds := []string{}
	for i := range cat.Items {
		if cat.Items[i].Process != nil {
			procCount++
			kinds = append(kinds, cat.Items[i].Kind)
		}
	}
	if procCount > 0 {
		af.Notes = append(af.Notes, fmt.Sprintf(
			"AI agent 进程维度复用既有 harness 检测（本类目 %d 条资产带进程归属：%s，指纹见 items[].process），此处不重复清点",
			procCount, strings.Join(kinds, ",")))
	} else {
		af.Notes = append(af.Notes, "AI agent 进程维度复用既有 harness 检测（本类目暂无带进程归属的资产），此处不重复清点")
	}

	collectMCPConfigs(ctx, af)
	collectSkillDirs(ctx, af)
	return af
}

// 覆盖边界是静态事实，无论机器上有什么都如实输出，让每份清单自带口径。
const (
	agentFaceMCPCoverage = "覆盖边界：只扫描 Claude Desktop/Cursor/Windsurf/用户级 .mcp.json 四个 JSON 路径；" +
		"Codex CLI 为 TOML 只计数；Cline 路径未核实（2026-11）未纳入；项目级 .mcp.json 不在固定白名单"
	agentFaceSkillsCoverage = "覆盖边界：只枚举用户级 .claude/.agents/.workbuddy 三个 skills 目录；" +
		"项目级 .zcode/skills 等不在固定白名单，未扫描"
)

// mcpConfigSource 描述一个已知 MCP 配置文件来源。
type mcpConfigSource struct {
	Client string // 客户端标识，进输出的 client 字段
	Path   string // %VAR% 形式；输出 SourcePath 用展开后的绝对路径
	// TOMLCount=true 表示该配置是 TOML（Codex），只数 [mcp_servers.*]
	// 表头不解析键值——形状未核实（2026-11），宁可少说。
	TOMLCount bool
}

var mcpConfigSources = []mcpConfigSource{
	{Client: "claude_desktop", Path: `%APPDATA%\Claude\claude_desktop_config.json`},
	{Client: "cursor", Path: `%USERPROFILE%\.cursor\mcp.json`},
	{Client: "windsurf", Path: `%USERPROFILE%\.codeium\windsurf\mcp_config.json`},
	{Client: "user_mcp_json", Path: `%USERPROFILE%\.mcp.json`},
	{Client: "codex_cli", Path: `%USERPROFILE%\.codex\config.toml`, TOMLCount: true},
}

var skillRootSources = []struct {
	Label string
	Path  string
}{
	{Label: "claude_code", Path: `%USERPROFILE%\.claude\skills`},
	{Label: "agents", Path: `%USERPROFILE%\.agents\skills`},
	{Label: "workbuddy", Path: `%USERPROFILE%\.workbuddy\skills`},
}

// collectMCPConfigs 逐个白名单配置文件清点 MCP server。文件不存在是
// 常态静默跳过；读得了但解析不了才记 note（诚实降级）。
func collectMCPConfigs(ctx context.Context, af *AgentFace) {
	total := 0
	for _, src := range mcpConfigSources {
		if ctx.Err() != nil {
			af.MCPTruncated = true
			af.MCPNotes = append(af.MCPNotes, "预算耗尽，剩余配置文件未扫描")
			return
		}
		path := expandPath(src.Path)
		if path == "" {
			continue
		}
		text, err := readTextFile(path, agentFaceFileLimit)
		if err != nil {
			if !os.IsNotExist(err) {
				// 存在但读不了（权限/是目录/超限）：点一句，不假装没看见。
				af.MCPNotes = append(af.MCPNotes, fmt.Sprintf("%s: 配置存在但读取失败（%v）", src.Client, err))
			}
			continue
		}
		if src.TOMLCount {
			collectCodexTOMLCount(af, src.Client, text)
			continue
		}
		entries, notes, truncated := parseMCPServersJSON(src.Client, path, text)
		af.MCPNotes = append(af.MCPNotes, notes...)
		af.MCPTruncated = af.MCPTruncated || truncated
		for _, e := range entries {
			if total >= agentFaceMaxServersTotal {
				af.MCPTruncated = true
				af.MCPNotes = append(af.MCPNotes, fmt.Sprintf("全部来源 server 总数超过 %d，剩余未列出", agentFaceMaxServersTotal))
				return
			}
			af.MCPServers = append(af.MCPServers, e)
			total++
		}
	}
	if len(af.MCPServers) == 0 {
		af.MCPNotes = append(af.MCPNotes, "白名单路径内未发现 MCP server 配置（不代表机器上没有 AI 客户端）")
	}
}

// mcpServerCfg 是 mcpServers 段的单个 server 配置。env 用 RawMessage：
// value 只在内存里过一手即丢弃，只有 key 进输出（脱敏红线的实现点）。
type mcpServerCfg struct {
	Command string                     `json:"command"`
	Args    []string                   `json:"args"`
	URL     string                     `json:"url"`
	Env     map[string]json.RawMessage `json:"env"`
}

// parseMCPServersJSON 从配置文本提取 mcpServers 清单。只摘
// name/command/args/url；env 只留 key 名。解析失败/无段返回 note 降级
// （JSONC 带注释的配置会走到"解析失败"——不猜测、不半解析）。
func parseMCPServersJSON(client, path, text string) (entries []MCPServerEntry, notes []string, truncated bool) {
	var doc struct {
		MCPServers map[string]mcpServerCfg `json:"mcpServers"`
	}
	if err := json.Unmarshal([]byte(text), &doc); err != nil {
		return nil, []string{fmt.Sprintf("%s: 配置解析失败（%v），跳过", client, err)}, false
	}
	if len(doc.MCPServers) == 0 {
		return nil, []string{fmt.Sprintf("%s: 未含 mcpServers 段或为空", client)}, false
	}
	// map 无序：按 server 名排序，前后两次侦查结果可 diff。
	names := make([]string, 0, len(doc.MCPServers))
	for name := range doc.MCPServers {
		names = append(names, name)
	}
	sort.Strings(names)

	entries = make([]MCPServerEntry, 0, len(names))
	for _, name := range names {
		if len(entries) >= agentFaceMaxServersPerFile {
			notes = append(notes, fmt.Sprintf("%s: server 数超过 %d，剩余未列出", client, agentFaceMaxServersPerFile))
			return entries, notes, true
		}
		cfg := doc.MCPServers[name]
		entry := MCPServerEntry{
			Name:       redact.Truncate(strings.TrimSpace(name), agentFaceMaxNameLen),
			Client:     client,
			SourcePath: path,
			Command:    redact.Truncate(strings.TrimSpace(cfg.Command), agentFaceMaxFieldLen),
			URL:        scrubURLUserInfo(redact.Truncate(strings.TrimSpace(cfg.URL), agentFaceMaxFieldLen)),
			Args:       []string{},
			EnvKeys:    []string{},
		}
		args := cfg.Args
		if len(args) > agentFaceMaxArgs {
			args = args[:agentFaceMaxArgs]
			notes = append(notes, fmt.Sprintf("%s/%s: args 超过 %d 项，已截断", client, name, agentFaceMaxArgs))
			truncated = true
		}
		for _, a := range args {
			// 参数里可能带 --api-key=xxx：先按命令行规则打码再截断
			// （先截断会把被切开的值留在输出里，先打码则不会）。
			entry.Args = append(entry.Args, redact.Truncate(redact.CmdLine(a), agentFaceMaxArgLen))
		}
		keys := make([]string, 0, len(cfg.Env))
		for k := range cfg.Env {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		if len(keys) > agentFaceMaxEnvKeys {
			keys = keys[:agentFaceMaxEnvKeys]
			notes = append(notes, fmt.Sprintf("%s/%s: env key 数超过 %d，已截断", client, name, agentFaceMaxEnvKeys))
			truncated = true
		}
		for i, k := range keys {
			// 只留 key 名；key 名本身也可能超长（恶意配置），照截断。
			keys[i] = redact.Truncate(k, agentFaceMaxNameLen)
		}
		entry.EnvKeys = keys
		entries = append(entries, entry)
	}
	return entries, notes, truncated
}

// scrubURLUserInfo 打码 URL 里的 user:password@ 形态（远程 MCP 端点
// 有时把凭据内嵌在 userinfo）。只处理 scheme:// 后第一个 @ 之前且
// 不含 / 的段，避免误伤路径里的 @。
func scrubURLUserInfo(u string) string {
	i := strings.Index(u, "://")
	if i < 0 {
		return u
	}
	rest := u[i+3:]
	at := strings.IndexByte(rest, '@')
	if at < 0 || strings.Contains(rest[:at], "/") {
		return u
	}
	return u[:i+3] + "***@" + rest[at+1:]
}

// codexMCPServerRe 匹配 TOML 表头 [mcp_servers.<name>]（空白宽容）。
// 只数数量不解析键值——TOML 形状未核实（2026-11），数错宁可少说。
var codexMCPServerRe = regexp.MustCompile(`(?m)^\s*\[mcp_servers\.[^\]]+\]`)

// collectCodexTOMLCount 对 Codex 的 TOML 配置只输出 server 段计数，
// 条目内容未知（进 mcp_notes，不进 mcp_servers）。
func collectCodexTOMLCount(af *AgentFace, client, text string) {
	n := len(codexMCPServerRe.FindAllString(text, -1))
	if n == 0 {
		af.MCPNotes = append(af.MCPNotes, client+": TOML 配置存在但未发现 [mcp_servers.*] 段")
		return
	}
	af.MCPNotes = append(af.MCPNotes, fmt.Sprintf(
		"%s: TOML 配置存在，检出 %d 个 [mcp_servers.*] 段（TOML 不解析，条目内容未知）", client, n))
}

// collectSkillDirs 枚举白名单 skills 根目录下的 skill 目录。
// os.ReadDir 保证按文件名排序：输出顺序稳定可 diff。
func collectSkillDirs(ctx context.Context, af *AgentFace) {
	foundRoot := false
	for _, root := range skillRootSources {
		if ctx.Err() != nil {
			af.SkillsTruncated = true
			af.SkillsNotes = append(af.SkillsNotes, "预算耗尽，剩余 skills 未枚举")
			return
		}
		dir := expandPath(root.Path)
		if !pathIsDir(dir) {
			continue
		}
		foundRoot = true
		dirs, err := os.ReadDir(dir)
		if err != nil {
			af.SkillsNotes = append(af.SkillsNotes, fmt.Sprintf("%s: 目录枚举失败（%v）", root.Label, err))
			continue
		}
		for _, de := range dirs {
			if ctx.Err() != nil {
				af.SkillsTruncated = true
				af.SkillsNotes = append(af.SkillsNotes, "预算耗尽，剩余 skills 未枚举")
				return
			}
			// 约定是每 skill 一个目录（含 SKILL.md）；根下的散文件不是 skill。
			if !de.IsDir() {
				continue
			}
			if len(af.Skills) >= agentFaceMaxSkills {
				af.SkillsTruncated = true
				af.SkillsNotes = append(af.SkillsNotes, fmt.Sprintf("skills 总数超过 %d，剩余未列出", agentFaceMaxSkills))
				return
			}
			af.Skills = append(af.Skills, collectOneSkill(dir, de.Name()))
		}
	}
	if !foundRoot && len(af.Skills) == 0 {
		af.SkillsNotes = append(af.SkillsNotes, "未发现已知 skills 目录（不代表机器上没有 agent skills）")
	}
}

// collectOneSkill 读单个 skill 目录的 SKILL.md 并摘 frontmatter。
// 没有 SKILL.md/读不了：仍列出目录名（目录存在本身就是清单事实），
// name/description 留空——不猜。
func collectOneSkill(rootDir, name string) SkillEntry {
	mdPath := filepath.Join(rootDir, name, "SKILL.md")
	entry := SkillEntry{
		Dir:        redact.Truncate(name, agentFaceMaxNameLen),
		SourcePath: mdPath,
	}
	text, err := readTextFile(mdPath, agentFaceFileLimit)
	if err != nil {
		return entry
	}
	fmName, desc := parseSkillFrontmatter(text)
	if fmName != "" {
		entry.Name = fmName
	}
	entry.Description = desc
	return entry
}

// parseSkillFrontmatter 从 SKILL.md 提取 frontmatter 的 name/description。
// 只做行级解析（不引 YAML 依赖、不做完整 YAML 语义）：文件须以 ---
// 开头、到下一个 --- 闭合；只看无缩进的顶层键，值去成对引号；重复键
// 取首个（"首行"口径）；块标量（|、>- 等）取第一行缩进内容。allowed-tools
// 等其余字段与正文一概不读不输出——技能清单不是内容审计。恶意超长行：
// 读文件有 1MB 帽 + 输出截断，不会 panic、不会撑爆输出。
func parseSkillFrontmatter(text string) (name, desc string) {
	lines := strings.Split(text, "\n")
	if len(lines) == 0 || strings.TrimSpace(lines[0]) != "---" {
		return "", ""
	}
	end := -1
	for i := 1; i < len(lines) && i < agentFaceMaxFMLines; i++ {
		if strings.TrimSpace(lines[i]) == "---" {
			end = i
			break
		}
	}
	if end < 0 {
		return "", "" // 没有闭合围栏：格式不完整，不半猜
	}
	fm := lines[1:end]
	for idx, raw := range fm {
		line := strings.TrimRight(raw, "\r")
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if line[0] == ' ' || line[0] == '\t' {
			continue // 嵌套键/续行不是我们要的两个顶层键
		}
		key, val, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		val = strings.TrimSpace(val)
		switch key {
		case "name":
			if name == "" {
				name = redact.Truncate(unquoteYAML(val), agentFaceMaxNameLen)
			}
		case "description":
			if desc == "" {
				desc = redact.Truncate(unquoteYAML(blockScalarFirstLine(val, fm, idx)), agentFaceMaxDescLen)
			}
		}
	}
	return name, desc
}

// blockScalarFirstLine 处理 YAML 块标量（|、>- 等指示符）：值的首行是
// frontmatter 里键之后第一个非空且更缩进的行；没有则返回空串。普通
// 行内值原样返回。只按我们要的两个键的需要近似，不做完整 YAML 语义。
func blockScalarFirstLine(val string, fm []string, idx int) string {
	if val == "" || (val[0] != '|' && val[0] != '>') {
		return val
	}
	for _, raw := range fm[idx+1:] {
		line := strings.TrimRight(raw, "\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		// 块标量内容必须比顶层键（无缩进）更缩进；遇到无缩进非空行
		// 说明块已结束且没有内容（畸形/空块），返回空不硬凑。
		if len(line) > 0 && (line[0] == ' ' || line[0] == '\t') {
			return unquoteYAML(trimmed)
		}
		return ""
	}
	return ""
}

// unquoteYAML 去掉成对的单/双引号包裹；其余原样返回（不做转义展开
// ——清单摘要不需要，还可能把畸形输入放大）。
func unquoteYAML(v string) string {
	if len(v) >= 2 {
		if (v[0] == '"' && v[len(v)-1] == '"') || (v[0] == '\'' && v[len(v)-1] == '\'') {
			return v[1 : len(v)-1]
		}
	}
	return v
}
