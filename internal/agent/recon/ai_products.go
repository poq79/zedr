package recon

// ai_products.go：AI Agent Harness 产品指纹表（契约 §12.3 ai 类）。
//
// 识别顺序：进程名/命令行 → 默认端口 → 探测确认。产品表只描述"长什么样"，
// 判定逻辑在 ai.go；新增产品只加一行，不改探测/曝露判定代码。
//
// 默认口令列（DefaultCredNote）严格限定为文献级提示：只描述公开研究里
// 出现过的产品风险，不包含任何具体凭据，也绝不尝试登录。

import (
	"regexp"
	"strings"

	"zedr/internal/agent/state"
)

// 能力端点类型：决定响应怎么解析、200 是否能作为"匿名可用"证据。
const (
	capOllamaTags      = "ollama_tags"   // {"models":[{"name":...}]}
	capOpenAIModels    = "openai_models" // {"data":[{"id":...}]}
	capLocalAIModels   = "localai_models"
	capHealth          = "health"     // 仅存活/健康，200 不等于无认证
	capN8NHealth       = "n8n_health" // /healthz 存活；认证看根页
	capOpenWebUIConfig = "openwebui_config"
	capFlowisePing     = "flowise_ping"
	capAnythingPing    = "anythingllm_ping"
	capDifySetup       = "dify_setup" // 200 = 未初始化（等于无认证设置面）
	capComfyStats      = "comfy_stats"
	capSDModels        = "sd_models"
	capRootOnly        = "root_only"
	capLiteLLMHealth   = "litellm_health"
	capOpenAPI         = "openapi" // /openapi.json 形如 {"openapi":"3.1.0","paths":{...}}
)

// aiProduct 是一款 AI/Agent 产品的被动 + 主动指纹。
type aiProduct struct {
	Kind       string
	Title      string
	Ports      []uint16
	ProcNames  []string // 小写、不含 .exe
	CmdRe      *regexp.Regexp
	RootMarker string // 根页/标题里的产品标记（大小写不敏感）
	CapPath    string
	CapKind    string
	// NoAuthDefault 表示产品默认不带认证（文献级事实），根页无登录表单
	// 时可直接判 open；有认证的产品必须看到能力端点匿名 200 才判 open。
	NoAuthDefault   bool
	DefaultCredNote string

	// RequireName/RequireAll/RequireAny 用于收紧模糊的 cmdline 指纹：
	// 只有进程名命中 ProcNames 时才直接通过；仅 cmdline 命中时再校验
	// 这些约束，避免把 "codex" 这类常见单词误认成产品。
	RequireName string
	RequireAll  []string
	RequireAny  []string

	// ConfigDir/ConfigDirEnv/PluginsDir 用于终端 Agent 本地环境事实
	// （只读文件存在性，不算网络探测）。ConfigDirEnv 非空且已设置时
	// 优先于 ConfigDir。
	ConfigDir    string
	ConfigDirEnv string
	PluginsDir   string

	// ProcessOnly 表示产品没有固定网络端点，只报"框架/agent 进程在运行"。
	ProcessOnly bool
	ProcessNote string

	// AuthHint 在探测判定 auth_required 时追加到 details.auth_hint。
	AuthHint string
}

// aiProducts 顺序即"同进程命中多个产品"时的优先级；精确产品在前，
// 通用/兼容实现在后。
var aiProducts = []aiProduct{
	{
		Kind: "ollama", Title: "Ollama", Ports: []uint16{11434},
		ProcNames:  []string{"ollama"},
		CmdRe:      regexp.MustCompile(`(?i)(^|[\\/\s"])ollama(\.exe)?([\s"]|$)`),
		RootMarker: "Ollama is running", CapPath: "/api/tags", CapKind: capOllamaTags,
		NoAuthDefault:   true,
		DefaultCredNote: "Ollama 默认监听 0.0.0.0:11434 且无认证，模型可被匿名调用（公开研究常见暴露面）",
	},
	{
		Kind: "open-webui", Title: "Open WebUI", Ports: []uint16{3000, 8080},
		ProcNames:  []string{"open-webui", "open_webui", "openwebui"},
		CmdRe:      regexp.MustCompile(`(?i)open[-_ ]?webui`),
		RootMarker: "Open WebUI", CapPath: "/api/config", CapKind: capOpenWebUIConfig,
		DefaultCredNote: "Open WebUI 首个注册用户会成为管理员，暴露的实例应确认是否已完成初始化",
	},
	{
		Kind: "vllm", Title: "vLLM", Ports: []uint16{8000},
		ProcNames:  []string{"vllm"},
		CmdRe:      regexp.MustCompile(`(?i)(^|[\\/\s"])vllm(\.exe)?([\s"]|$)`),
		RootMarker: "vLLM", CapPath: "/v1/models", CapKind: capOpenAIModels,
		NoAuthDefault:   true,
		DefaultCredNote: "vLLM OpenAI 兼容服务默认无认证，可匿名推理与枚举模型",
	},
	{
		Kind: "localai", Title: "LocalAI", Ports: []uint16{8080},
		ProcNames:  []string{"local-ai", "localai"},
		CmdRe:      regexp.MustCompile(`(?i)(^|[\\/\s"])local[-_]?ai(\.exe)?([\s"]|$)`),
		RootMarker: "LocalAI", CapPath: "/models", CapKind: capOpenAIModels,
		NoAuthDefault:   true,
		DefaultCredNote: "LocalAI 默认无认证，模型与推理接口可被匿名访问",
	},
	{
		Kind: "litellm", Title: "LiteLLM Proxy", Ports: []uint16{4000},
		ProcNames:  []string{"litellm"},
		CmdRe:      regexp.MustCompile(`(?i)(^|[\\/\s"])litellm(\.exe)?([\s"]|$)`),
		RootMarker: "LiteLLM", CapPath: "/health", CapKind: capLiteLLMHealth,
		DefaultCredNote: "LiteLLM 以 master key 保护代理；/health 返回 401 说明已启用鉴权",
	},
	{
		Kind: "lm-studio", Title: "LM Studio", Ports: []uint16{1234},
		ProcNames:  []string{"lm studio", "lmstudio", "lms"},
		CmdRe:      regexp.MustCompile(`(?i)lm[-_ ]?studio|(^|[\\/\s"])lms(\.exe)?([\s"]|$)`),
		RootMarker: "LM Studio", CapPath: "/v1/models", CapKind: capOpenAIModels,
		NoAuthDefault:   true,
		DefaultCredNote: "LM Studio 本地服务器默认无认证",
	},
	{
		Kind: "llama.cpp", Title: "llama.cpp Server", Ports: []uint16{8000, 8080},
		ProcNames:  []string{"llama-server", "llama-cli"},
		CmdRe:      regexp.MustCompile(`(?i)llama[.-]?cpp|llama-server|llama-cli`),
		RootMarker: "llama.cpp", CapPath: "/v1/models", CapKind: capOpenAIModels,
		NoAuthDefault:   true,
		DefaultCredNote: "llama.cpp server 默认无认证，模型可被匿名调用",
	},
	{
		Kind: "anythingllm", Title: "AnythingLLM", Ports: []uint16{3001},
		ProcNames:  []string{"anythingllm", "anythingllm-desktop"},
		CmdRe:      regexp.MustCompile(`(?i)anything[-_ ]?llm`),
		RootMarker: "AnythingLLM", CapPath: "/api/ping", CapKind: capAnythingPing,
		DefaultCredNote: "AnythingLLM 的管理端可管理工作区与模型密钥，暴露前应确认认证",
	},
	{
		Kind: "flowise", Title: "Flowise", Ports: []uint16{3000},
		ProcNames:  []string{"flowise"},
		CmdRe:      regexp.MustCompile(`(?i)flowise`),
		RootMarker: "Flowise", CapPath: "/api/v1/ping", CapKind: capFlowisePing,
		DefaultCredNote: "Flowise 历史版本存在默认口令/未授权工作流访问风险（文献级提示）",
	},
	{
		Kind: "langflow", Title: "Langflow", Ports: []uint16{7860},
		ProcNames:  []string{"langflow"},
		CmdRe:      regexp.MustCompile(`(?i)langflow`),
		RootMarker: "Langflow", CapPath: "/health", CapKind: capHealth,
		DefaultCredNote: "Langflow 工作流可能包含模型/数据库凭据，应确认认证与访问范围",
	},
	{
		Kind: "n8n", Title: "n8n", Ports: []uint16{5678},
		ProcNames:  []string{"n8n"},
		CmdRe:      regexp.MustCompile(`(?i)(^|[\\/\s"])n8n(\.exe)?([\s"]|$)`),
		RootMarker: "n8n", CapPath: "/healthz", CapKind: capN8NHealth,
		DefaultCredNote: "n8n 旧版本默认无认证；工作流中常存第三方凭据，暴露即高风险（文献级提示）",
	},
	{
		Kind: "dify", Title: "Dify", Ports: []uint16{5003, 80},
		ProcNames:  []string{"dify"},
		CmdRe:      regexp.MustCompile(`(?i)(^|[\\/\s"])dify(\.exe)?([\s"]|$)`),
		RootMarker: "Dify", CapPath: "/console/api/setup", CapKind: capDifySetup,
		DefaultCredNote: "Dify /console/api/setup 返回 200 表示尚未初始化，任何访问者都可完成管理员设置",
	},
	{
		Kind: "comfyui", Title: "ComfyUI", Ports: []uint16{8188},
		ProcNames:  []string{"comfyui"},
		CmdRe:      regexp.MustCompile(`(?i)comfy[-_ ]?ui`),
		RootMarker: "ComfyUI", CapPath: "/system_stats", CapKind: capComfyStats,
		NoAuthDefault:   true,
		DefaultCredNote: "ComfyUI 默认无认证，且可加载任意自定义节点（等同代码执行面）",
	},
	{
		Kind: "sd-webui", Title: "Stable Diffusion WebUI", Ports: []uint16{7860},
		ProcNames:  []string{"webui"},
		CmdRe:      regexp.MustCompile(`(?i)stable[-_ ]diffusion[-_ ]webui|sd[-_]webui`),
		RootMarker: "Stable Diffusion", CapPath: "/sdapi/v1/sd-models", CapKind: capSDModels,
		NoAuthDefault:   true,
		DefaultCredNote: "Stable Diffusion WebUI 默认无认证，API 可提交任意生成任务",
	},
	{
		Kind: "text-gen-webui", Title: "Text Generation WebUI", Ports: []uint16{5000},
		ProcNames:  []string{"text-generation-webui", "text_generation_webui"},
		CmdRe:      regexp.MustCompile(`(?i)text[-_]generation[-_]webui|oobabooga`),
		RootMarker: "Text generation web UI", CapPath: "/v1/models", CapKind: capOpenAIModels,
		NoAuthDefault:   true,
		DefaultCredNote: "text-generation-webui 默认无认证，模型与生成接口可匿名访问",
	},
	{
		Kind: "gpt4all", Title: "GPT4All", Ports: []uint16{4891},
		ProcNames:  []string{"gpt4all"},
		CmdRe:      regexp.MustCompile(`(?i)gpt4all`),
		RootMarker: "GPT4All", CapPath: "/v1/models", CapKind: capOpenAIModels,
		NoAuthDefault:   true,
		DefaultCredNote: "GPT4All 本地 API 默认无认证",
	},
	{
		Kind: "jan", Title: "Jan", Ports: []uint16{1337},
		ProcNames:  []string{"jan"},
		CmdRe:      regexp.MustCompile(`(?i)(^|[\\/\s"])jan(\.exe)?([\s"]|$)`),
		RootMarker: "Jan", CapPath: "/v1/models", CapKind: capOpenAIModels,
		NoAuthDefault:   true,
		DefaultCredNote: "Jan 本地 API 默认无认证",
	},

	// ---- 2026-11 追加：Hermes / DeepSeek Harness / OpenHands / 终端 Agent ----
	{
		Kind: "hermes-gateway", Title: "Hermes Agent Gateway", Ports: []uint16{8642},
		CmdRe:      regexp.MustCompile(`(?i)hermes\s+gateway\b`),
		RootMarker: "Hermes", CapPath: "/v1/models", CapKind: capOpenAIModels,
		ConfigDirEnv: "HERMES_HOME", ConfigDir: `%USERPROFILE%\.hermes`,
		AuthHint:        "gateway 需要 api_server_key；401/403 说明已启用 API 鉴权",
		DefaultCredNote: "Hermes gateway 未设置 api_server_key 时会匿名开放模型接口",
	},
	{
		Kind: "hermes-dashboard", Title: "Hermes Agent Dashboard", Ports: []uint16{9119},
		CmdRe:      regexp.MustCompile(`(?i)hermes\s+dashboard\b`),
		RootMarker: "Hermes", CapPath: "/", CapKind: capRootOnly,
		NoAuthDefault: true,
		ConfigDirEnv:  "HERMES_HOME", ConfigDir: `%USERPROFILE%\.hermes`,
		DefaultCredNote: "Dashboard 有登录页表示已启用账号体系；匿名可达即高风险",
	},
	{
		Kind: "hermes-webui", Title: "Hermes Agent Web UI", Ports: []uint16{8787, 3000},
		CmdRe:      regexp.MustCompile(`(?i)hermes\s+(?:webui|web(?:-ui)?|workspace)\b`),
		RootMarker: "Hermes", CapPath: "/", CapKind: capRootOnly,
		NoAuthDefault: true,
		ConfigDirEnv:  "HERMES_HOME", ConfigDir: `%USERPROFILE%\.hermes`,
		DefaultCredNote: "Hermes Web/Workspace UI 匿名可达时可管理 agent 与凭据",
	},
	{
		Kind: "dsh", Title: "DeepSeek Harness (dsh)", Ports: []uint16{3080},
		RequireName: "node",
		CmdRe:       regexp.MustCompile(`(?i)@deepseek-ai[\\/]dsh|(?:^|[\\/\s"])dsh\s+web\b`),
		// 版本/CVE 由 enrichAIProduct 读 package.json 后判定（本地只读）。
		DefaultCredNote: "dsh CVE-2026-82533（Host 头信任→沙箱自解除）影响 <0.1.2-alpha.2",
	},
	{
		Kind: "openhands", Title: "OpenHands", Ports: []uint16{3000},
		ProcNames:  []string{"openhands"},
		CmdRe:      regexp.MustCompile(`(?i)openhands`),
		RootMarker: "OpenHands", CapPath: "/", CapKind: capRootOnly,
		NoAuthDefault:   true,
		DefaultCredNote: "OpenHands 默认本地运行，匿名可达时可提交任务并执行工具",
	},
	{
		Kind: "crewai", Title: "CrewAI",
		ProcNames:   []string{"crewai"},
		CmdRe:       regexp.MustCompile(`(?i)(^|[\\/\s"])crewai(\.exe)?([\s"]|$)|crewai\s+(?:run|serve)\b`),
		ProcessOnly: true,
		ProcessNote: "CrewAI agent 以当前用户权限执行工具调用；确认任务来源、工具白名单与凭据作用域",
	},
	{
		Kind: "langserve", Title: "LangServe", Ports: []uint16{8000},
		CmdRe:      regexp.MustCompile(`(?i)langserve`),
		RootMarker: "LangServe", CapPath: "/openapi.json", CapKind: capOpenAPI,
		DefaultCredNote: "LangServe 通常无认证，/openapi.json 可枚举全部路由",
	},
	{
		Kind: "claude-code", Title: "Claude Code",
		ProcNames:  []string{"claude"},
		CmdRe:      regexp.MustCompile(`(?i)(?:@anthropic-ai[\\/]claude-code|claude[^\r\n]*cli\.js|(?:^|[\\/\s"])claude(\.exe)?([\s"]|$))`),
		RequireAll: []string{"claude"}, RequireAny: []string{"node", "cli.js", "@anthropic-ai", "claude"},
		ConfigDir: `%USERPROFILE%\.claude`, PluginsDir: "plugins",
		ProcessOnly: true,
		ProcessNote: "Claude Code 终端 agent 以当前用户权限运行；插件可绕过 agent 权限控制（CERT-EU 2026-10 风险）",
	},
	{
		Kind: "codex-cli", Title: "Codex CLI",
		ProcNames:   []string{"codex"},
		CmdRe:       regexp.MustCompile(`(?i)(?:@openai[\\/]codex|(?:^|[\\/\s"])codex(\.exe)?([\s"]|$))`),
		ConfigDir:   `%USERPROFILE%\.codex`,
		PluginsDir:  "plugins",
		ProcessOnly: true,
		ProcessNote: "Codex CLI 终端 agent 以当前用户权限运行；插件/配置可绕过 agent 权限控制（CERT-EU 2026-10 风险）",
	},
	{
		Kind: "pi-agent", Title: "Pi Agent",
		ProcNames: []string{"pi-agent"},
		CmdRe:     regexp.MustCompile(`(?i)\bpi\b`),
		RequireAny: []string{
			`node_modules\@pi`, "node_modules/@pi", `.pi\`, ".pi/", "pi-agent",
		},
		ConfigDir: `%USERPROFILE%\.pi`, PluginsDir: "plugins",
		ProcessOnly: true,
		ProcessNote: "Pi agent 终端 agent 以当前用户权限运行；插件可绕过 agent 权限控制（CERT-EU 2026-10 风险）",
	},
}

// aiProductsByPort 按默认端口建反向索引（启动时构建一次）。
var aiProductsByPort = func() map[uint16][]*aiProduct {
	m := make(map[uint16][]*aiProduct, 32)
	for i := range aiProducts {
		for _, p := range aiProducts[i].Ports {
			m[p] = append(m[p], &aiProducts[i])
		}
	}
	return m
}()

// procBaseName 取小写 basename 并去掉 .exe。
func procBaseName(name string) string {
	name = strings.TrimSpace(name)
	if i := strings.LastIndexAny(name, `\/`); i >= 0 {
		name = name[i+1:]
	}
	name = strings.ToLower(name)
	name = strings.TrimSuffix(name, ".exe")
	return name
}

// matches 判断进程是否命中产品指纹。
//
// 进程名精确命中是强指纹，直接通过；仅命令行命中时再应用
// RequireName/RequireAll/RequireAny 收紧条件（避免 "codex" 等
// 常见单词出现在任意脚本参数里就误报）。
func (p *aiProduct) matches(row state.ProcRow) bool {
	name := procBaseName(row.Name)
	for _, n := range p.ProcNames {
		if name == strings.ToLower(n) {
			return true
		}
	}
	if p.CmdRe == nil || !p.CmdRe.MatchString(row.CmdLine) {
		return false
	}
	if p.RequireName != "" && name != strings.ToLower(p.RequireName) {
		return false
	}
	cmd := strings.ToLower(row.CmdLine)
	for _, s := range p.RequireAll {
		if !strings.Contains(cmd, strings.ToLower(s)) {
			return false
		}
	}
	if len(p.RequireAny) > 0 {
		any := false
		for _, s := range p.RequireAny {
			if strings.Contains(cmd, strings.ToLower(s)) {
				any = true
				break
			}
		}
		if !any {
			return false
		}
	}
	return true
}
