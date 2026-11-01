package recon

// dev.go：开发/自动化工具识别（契约 §12.3 dev 类）。
//
// 这一类的高价值目标是"带执行能力的调试面"：Jupyter、Node Inspector、
// 浏览器 CDP、Selenium、Jenkins。它们一旦匿名可达，等价于在本机执行
// 代码/命令，因此 open 一律 high；Jupyter token 出现在命令行则无需探测
// 就是 high（本机任意进程可读取）。
//
// Playwright/Puppeteer/MCP/GitLab Runner 更多是"环境事实"，给 info/low，
// 不制造风险噪音。

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"zedr/internal/agent/state"
	"zedr/internal/platform/redact"
)

var (
	reJupyterName = regexp.MustCompile(`(?i)^jupyter(?:-|$)|^jupyter-(?:notebook|lab|console)$`)
	reJupyterCmd  = regexp.MustCompile(`(?i)\bjupyter(?:-|\s+)(?:notebook|lab|console)\b|jupyter\.exe`)
	// token 取值只用于判定"是否明文出现在命令行"，绝不写进响应。
	reJupyterToken = regexp.MustCompile(`(?i)(?:--(?:NotebookApp|ServerApp)\.token=|(?:^|\s)token=)([^\s"']+)`)
	reInspect      = regexp.MustCompile(`(?i)--inspect(?:-brk)?(?:=([^\s]+))?(?:\s|$)`)
	reChromePort   = regexp.MustCompile(`(?i)--remote-debugging-port=(\d+)`)
	reSelenium     = regexp.MustCompile(`(?i)selenium[-_ ]?(?:server|standalone|grid)|selenium-server`)
	reJenkins      = regexp.MustCompile(`(?i)jenkins(?:\.war)?`)
	rePlaywright   = regexp.MustCompile(`(?i)playwright`)
	rePuppeteer    = regexp.MustCompile(`(?i)puppeteer`)
	reMCP          = regexp.MustCompile(`(?i)@modelcontextprotocol/|mcp-server-`)
	reNPXUVX       = regexp.MustCompile(`(?i)\b(?:npx|uvx)\b`)
)

// detectDev 是 dev 类入口。
func detectDev(ctx context.Context, b *base) (Category, error) {
	cat := newCategory("dev", CategoryTitle("dev"))

	b.detectJupyter(ctx, &cat)
	b.detectCodeServer(ctx, &cat)
	b.detectNodeInspector(ctx, &cat)
	b.detectBrowserCDP(ctx, &cat)
	b.detectSelenium(ctx, &cat)
	b.detectJenkins(ctx, &cat)
	b.detectProcessOnly(ctx, &cat, "gitlab-runner", "GitLab Runner", []string{"gitlab-runner"}, nil, LevelInfo,
		"GitLab Runner 在运行", "Runner 持有注册令牌/执行器权限，确认是否为本机预期")
	b.detectProcessOnly(ctx, &cat, "playwright", "Playwright", []string{"playwright"}, rePlaywright, LevelInfo,
		"Playwright 进程在运行", "自动化测试框架；若由未知父进程拉起应复核")
	b.detectProcessOnly(ctx, &cat, "puppeteer", "Puppeteer", []string{"puppeteer"}, rePuppeteer, LevelInfo,
		"Puppeteer 进程在运行", "自动化测试框架；若由未知父进程拉起应复核")
	b.detectMCP(ctx, &cat)

	sortItems(cat.Items)
	return cat, nil
}

// ---------------------------------------------------------------- Jupyter

// isJupyterProc 判断进程是否是 Jupyter 服务进程。
func isJupyterProc(row state.ProcRow) bool {
	name := procBaseName(row.Name)
	if reJupyterName.MatchString(name) {
		return true
	}
	return reJupyterCmd.MatchString(row.CmdLine)
}

// jupyterTokenInCmdline 判断命令行是否包含明文 token 参数。
// 值形如 $ENV_VAR 时仍算"参数出现"，因为泄露的是配置方式而非值；
// 但 finding 文案只说"token 参数出现在命令行"，不展示值。
func jupyterTokenInCmdline(cmdline string) bool {
	m := reJupyterToken.FindStringSubmatch(cmdline)
	if len(m) < 2 {
		return false
	}
	v := strings.TrimSpace(m[1])
	return v != "" && v != "''" && v != `""`
}

// jupyterTokenFindings 在 ai 类里留类目级高风险证据（Jupyter 资产归 dev）。
func jupyterTokenFindings(cat *Category, b *base) {
	for _, row := range b.procs {
		if !isJupyterProc(row) || !jupyterTokenInCmdline(row.CmdLine) {
			continue
		}
		cat.Findings = append(cat.Findings, Finding{
			AssetID: fmt.Sprintf("jupyter-%d", row.PID),
			Level:   LevelHigh,
			Title:   "Jupyter token 出现在命令行",
			Detail: fmt.Sprintf("PID %d（%s）的启动参数包含明文 token，本机任意进程可读取并接管 Notebook；建议改用配置文件/环境变量并轮换 token",
				row.PID, row.Name),
		})
	}
}

func (b *base) detectJupyter(ctx context.Context, cat *Category) {
	for _, row := range b.procs {
		if ctx.Err() != nil {
			return
		}
		if !isJupyterProc(row) {
			continue
		}
		ports := b.tcpPorts(b.portsForPID(row.PID))
		if len(ports) == 0 {
			ports = b.tcpPorts(b.existingPorts([]uint16{8888, 8889}))
		}
		tokenInCmd := jupyterTokenInCmdline(row.CmdLine)
		details := map[string]any{
			"product":          "jupyter",
			"token_in_cmdline": tokenInCmd,
			"dashboard_url":    "",
			"auth_state":       AuthUnknown,
		}
		item := b.newAsset("dev", "jupyter", "Jupyter Notebook/Lab", row.PID, ports, details)
		item.Exposure = passiveExposure(item.Listens, true)
		if len(ports) > 0 {
			ip := b.probeIP(ports[0])
			item.Endpoint = endpointHTTP(ip, ports[0])
			details["dashboard_url"] = item.Endpoint
			if b.probe != nil {
				status, title, auth, evidence, perr := b.probeRootAuth(ctx, ip, ports[0])
				if title != "" {
					details["title"] = title
				}
				if status != 0 {
					details["probe_status"] = status
				}
				if auth != AuthUnknown {
					details["auth_state"] = auth
					item.Exposure = authExposure(auth, LevelHigh, item.Listens)
					item.Exposure.Evidence = append(evidence, item.Exposure.Evidence...)
				} else if perr != "" {
					details["probe_error"] = perr
					item.Exposure = Exposure{Level: LevelUnknown, Evidence: evidence}
				}
			}
		}
		if tokenInCmd {
			item.Exposure = Exposure{
				Level:    LevelHigh,
				Evidence: []string{"命令行参数包含明文 token（本机任意进程可读）"},
			}
			addFinding(cat, &item, LevelHigh, "Jupyter token 出现在命令行",
				"启动参数含明文 token；本机任意进程可读取后接管 Notebook。建议改用配置文件/环境变量并轮换 token")
		} else if item.Details["auth_state"] == AuthOpen {
			addFinding(cat, &item, LevelHigh, "Jupyter 未要求认证",
				"根页可直接进入 Notebook UI，等同本机代码执行面；建议设置 token/密码并仅绑定回环")
		}
		cat.Items = append(cat.Items, item)
	}
}

// ---------------------------------------------------------------- code-server

func (b *base) detectCodeServer(ctx context.Context, cat *Category) {
	for _, row := range b.procs {
		if ctx.Err() != nil {
			return
		}
		if procBaseName(row.Name) != "code-server" {
			continue
		}
		ports := b.tcpPorts(b.portsForPID(row.PID))
		if len(ports) == 0 {
			ports = b.tcpPorts(b.existingPorts([]uint16{8080}))
		}
		details := map[string]any{"product": "code-server", "auth_state": AuthUnknown, "dashboard_url": ""}
		item := b.newAsset("dev", "code-server", "code-server (VS Code Web)", row.PID, ports, details)
		item.Exposure = passiveExposure(item.Listens, true)
		if len(ports) > 0 {
			ip := b.probeIP(ports[0])
			item.Endpoint = endpointHTTP(ip, ports[0])
			details["dashboard_url"] = item.Endpoint
			if b.probe != nil {
				status, title, auth, evidence, perr := b.probeRootAuth(ctx, ip, ports[0])
				if title != "" {
					details["title"] = title
				}
				if status != 0 {
					details["probe_status"] = status
				}
				if auth != AuthUnknown {
					details["auth_state"] = auth
					item.Exposure = authExposure(auth, LevelHigh, item.Listens)
					item.Exposure.Evidence = append(evidence, item.Exposure.Evidence...)
				} else if perr != "" {
					details["probe_error"] = perr
					item.Exposure = Exposure{Level: LevelUnknown, Evidence: evidence}
				}
			}
		}
		if item.Details["auth_state"] == AuthOpen {
			addFinding(cat, &item, LevelHigh, "code-server 未要求认证",
				"Web IDE 匿名可进入等同文件读写与终端执行；建议启用 password 并仅绑定回环")
		}
		cat.Items = append(cat.Items, item)
	}
}

// ---------------------------------------------------------------- Node inspector

func (b *base) detectNodeInspector(ctx context.Context, cat *Category) {
	for _, row := range b.procs {
		if ctx.Err() != nil {
			return
		}
		if procBaseName(row.Name) != "node" && procBaseName(row.Name) != "nodejs" {
			continue
		}
		port, bindAll, ok := parseInspectPort(row.CmdLine)
		if !ok {
			continue
		}
		ports := b.tcpPorts(b.portsForPID(row.PID))
		if len(ports) == 0 {
			ports = b.tcpPorts(b.existingPorts([]uint16{port}))
		}
		details := map[string]any{
			"product":    "node-inspector",
			"debug_port": port,
			"bind_all":   bindAll,
			"auth_state": AuthUnknown,
		}
		item := b.newAsset("dev", "node-inspector", "Node.js Inspector", row.PID, ports, details)
		item.Exposure = passiveExposure(item.Listens, true)
		if bindAll {
			item.Exposure.Evidence = append(item.Exposure.Evidence, "命令行显式绑定非回环地址")
		}
		if len(ports) > 0 && b.probe != nil {
			ip := b.probeIP(ports[0])
			item.Endpoint = endpointHTTP(ip, ports[0])
			details["dashboard_url"] = item.Endpoint
			auth, status, evidence, perr := b.probeJSONControl(ctx, ip, ports[0], []string{"/json/list", "/json"})
			details["probe_status"] = status
			details["auth_state"] = auth
			switch auth {
			case AuthOpen:
				item.Exposure = Exposure{Level: LevelHigh, Evidence: evidence}
				addFinding(cat, &item, LevelHigh, "Node Inspector 未认证",
					"调试端口可匿名访问，可通过 WebSocket 在目标进程执行任意代码；建议移除 --inspect 或仅绑定 127.0.0.1")
			case AuthRequired:
				item.Exposure = authExposure(AuthRequired, LevelHigh, item.Listens)
				item.Exposure.Evidence = append(evidence, item.Exposure.Evidence...)
			default:
				if perr != "" {
					details["probe_error"] = perr
					item.Exposure = Exposure{Level: LevelUnknown, Evidence: evidence}
				}
			}
		}
		cat.Items = append(cat.Items, item)
	}
}

// parseInspectPort 从 node 命令行解析 --inspect[=host:port]。
// 无值默认 9229；bindAll=true 表示显式绑到非回环地址（暴露面更强）。
func parseInspectPort(cmdline string) (port uint16, bindAll bool, ok bool) {
	m := reInspect.FindStringSubmatch(cmdline)
	if len(m) == 0 {
		return 0, false, false
	}
	raw := ""
	if len(m) > 1 {
		raw = strings.TrimSpace(m[1])
	}
	if raw == "" {
		return 9229, false, true
	}
	host := ""
	portStr := raw
	if i := strings.LastIndexByte(raw, ':'); i >= 0 {
		host = strings.Trim(raw[:i], "[]")
		portStr = raw[i+1:]
	}
	n, err := strconv.Atoi(portStr)
	if err != nil || n < 1 || n > 65535 {
		return 9229, false, true // 参数格式异常时按默认端口，不丢资产
	}
	if host != "" && host != "127.0.0.1" && host != "::1" && host != "localhost" {
		bindAll = true
	}
	return uint16(n), bindAll, true
}

// ---------------------------------------------------------------- Chrome / Edge CDP

func (b *base) detectBrowserCDP(ctx context.Context, cat *Category) {
	for _, row := range b.procs {
		if ctx.Err() != nil {
			return
		}
		name := procBaseName(row.Name)
		if name != "chrome" && name != "msedge" && name != "chromium" {
			continue
		}
		m := reChromePort.FindStringSubmatch(row.CmdLine)
		if len(m) < 2 {
			continue
		}
		n, err := strconv.Atoi(m[1])
		if err != nil || n < 1 || n > 65535 {
			continue
		}
		port := uint16(n)
		ports := b.tcpPorts(b.portsForPID(row.PID))
		if len(ports) == 0 {
			ports = b.tcpPorts(b.existingPorts([]uint16{port}))
		}
		details := map[string]any{
			"product":    "browser-cdp",
			"browser":    name,
			"debug_port": port,
			"auth_state": AuthUnknown,
		}
		title := "Chrome 远程调试"
		kind := "chrome-debug"
		if name == "msedge" {
			title = "Edge 远程调试"
			kind = "edge-debug"
		}
		item := b.newAsset("dev", kind, title, row.PID, ports, details)
		item.Exposure = passiveExposure(item.Listens, true)
		if len(ports) > 0 && b.probe != nil {
			ip := b.probeIP(ports[0])
			item.Endpoint = endpointHTTP(ip, ports[0])
			details["dashboard_url"] = item.Endpoint
			auth, status, evidence, perr := b.probeJSONControl(ctx, ip, ports[0], []string{"/json/version"})
			details["probe_status"] = status
			details["auth_state"] = auth
			switch auth {
			case AuthOpen:
				item.Exposure = Exposure{Level: LevelHigh, Evidence: evidence}
				addFinding(cat, &item, LevelHigh, "浏览器远程调试端口未认证",
					"CDP 可达意味着可在浏览器上下文执行任意脚本并读取已登录会话；建议关闭 --remote-debugging-port")
			case AuthRequired:
				item.Exposure = authExposure(AuthRequired, LevelHigh, item.Listens)
				item.Exposure.Evidence = append(evidence, item.Exposure.Evidence...)
			default:
				if perr != "" {
					details["probe_error"] = perr
					item.Exposure = Exposure{Level: LevelUnknown, Evidence: evidence}
				}
			}
		}
		cat.Items = append(cat.Items, item)
	}
}

// ---------------------------------------------------------------- Selenium

func (b *base) detectSelenium(ctx context.Context, cat *Category) {
	seenPID := make(map[uint32]struct{}, 4)
	for _, row := range b.procs {
		if ctx.Err() != nil {
			return
		}
		if !reSelenium.MatchString(row.CmdLine) && procBaseName(row.Name) != "selenium-server" {
			continue
		}
		seenPID[row.PID] = struct{}{}
		b.appendSelenium(ctx, cat, row.PID)
	}
	// 端口优先：进程可能是 java 且启动参数被包装，4444 监听本身就是证据。
	if len(b.byPort[4444]) > 0 {
		pid := b.portListenerPID(4444)
		if _, ok := seenPID[pid]; !ok {
			b.appendSelenium(ctx, cat, pid)
		}
	}
}

func (b *base) appendSelenium(ctx context.Context, cat *Category, pid uint32) {
	ports := b.tcpPorts(b.portsForPID(pid))
	if len(ports) == 0 {
		ports = b.tcpPorts(b.existingPorts([]uint16{4444}))
	}
	details := map[string]any{"product": "selenium", "port": 4444, "auth_state": AuthUnknown, "dashboard_url": ""}
	item := b.newAsset("dev", "selenium", "Selenium Grid", pid, ports, details)
	item.Exposure = passiveExposure(item.Listens, true)
	if len(ports) > 0 {
		ip := b.probeIP(ports[0])
		item.Endpoint = endpointHTTP(ip, ports[0])
		details["dashboard_url"] = item.Endpoint
		if b.probe != nil {
			resp := b.probe.get(ctx, item.Endpoint+"/status")
			details["probe_status"] = resp.Status
			switch {
			case resp.Err != nil:
				details["probe_error"] = resp.Err.Error()
				item.Exposure = Exposure{Level: LevelUnknown, Evidence: []string{"探测失败: " + resp.Err.Error()}}
			case resp.Status == 401 || resp.Status == 403:
				details["auth_state"] = AuthRequired
				item.Exposure = authExposure(AuthRequired, LevelHigh, item.Listens)
			case resp.Status == 200 && json.Valid(resp.Body):
				details["auth_state"] = AuthOpen
				item.Exposure = Exposure{Level: LevelHigh, Evidence: []string{"GET /status → 200（匿名）"}}
				addFinding(cat, &item, LevelHigh, "Selenium Grid 未认证",
					"/status 匿名 200，可提交浏览器会话与任意导航/脚本；建议关闭 Grid 或加认证网关")
			default:
				item.Exposure = Exposure{Level: LevelUnknown, Evidence: []string{fmt.Sprintf("GET /status → %d", resp.Status)}}
			}
		}
	}
	cat.Items = append(cat.Items, item)
}

// ---------------------------------------------------------------- Jenkins

func (b *base) detectJenkins(ctx context.Context, cat *Category) {
	for _, row := range b.procs {
		if ctx.Err() != nil {
			return
		}
		name := procBaseName(row.Name)
		// Jenkins 以 java -jar jenkins.war 运行为常态；限定 java/jenkins
		// 进程可避免"命令行里恰好有 jenkins 路径"的无关进程误报。
		if name != "jenkins" && name != "java" && name != "javaw" {
			continue
		}
		if name != "jenkins" && !reJenkins.MatchString(row.CmdLine) {
			continue
		}
		ports := b.tcpPorts(b.portsForPID(row.PID))
		if len(ports) == 0 {
			ports = b.tcpPorts(b.existingPorts([]uint16{8080}))
		}
		details := map[string]any{"product": "jenkins", "auth_state": AuthUnknown, "dashboard_url": ""}
		item := b.newAsset("dev", "jenkins", "Jenkins", row.PID, ports, details)
		item.Exposure = passiveExposure(item.Listens, true)
		if len(ports) > 0 {
			ip := b.probeIP(ports[0])
			item.Endpoint = endpointHTTP(ip, ports[0])
			details["dashboard_url"] = item.Endpoint
			if b.probe != nil {
				resp := b.probe.get(ctx, item.Endpoint+"/api/json")
				details["probe_status"] = resp.Status
				switch {
				case resp.Err != nil:
					details["probe_error"] = resp.Err.Error()
					item.Exposure = Exposure{Level: LevelUnknown, Evidence: []string{"探测失败: " + resp.Err.Error()}}
				case resp.Status == 401 || resp.Status == 403:
					details["auth_state"] = AuthRequired
					item.Exposure = authExposure(AuthRequired, LevelHigh, item.Listens)
				case resp.Status == 200 && json.Valid(resp.Body):
					details["auth_state"] = AuthOpen
					item.Exposure = Exposure{Level: LevelHigh, Evidence: []string{"GET /api/json → 200（匿名）"}}
					addFinding(cat, &item, LevelHigh, "Jenkins API 匿名可访问",
						"/api/json 未认证返回任务信息；Jenkins Script Console 可执行任意 Groovy，建议启用安全域并限制访问")
				default:
					item.Exposure = Exposure{Level: LevelUnknown, Evidence: []string{fmt.Sprintf("GET /api/json → %d", resp.Status)}}
				}
			}
		}
		cat.Items = append(cat.Items, item)
	}
}

// ---------------------------------------------------------------- 通用进程类

// detectProcessOnly 处理没有固定端口的开发工具（Runner/Playwright/Puppeteer）。
func (b *base) detectProcessOnly(ctx context.Context, cat *Category, kind, title string, names []string, cmdRe *regexp.Regexp, level, findingTitle, findingDetail string) {
	for _, row := range b.procs {
		if ctx.Err() != nil {
			return
		}
		name := procBaseName(row.Name)
		match := false
		for _, n := range names {
			if name == strings.ToLower(n) {
				match = true
				break
			}
		}
		if !match && cmdRe != nil {
			match = cmdRe.MatchString(row.CmdLine)
		}
		if !match {
			continue
		}
		ports := b.tcpPorts(b.portsForPID(row.PID))
		details := map[string]any{"product": kind}
		item := b.newAsset("dev", kind, title, row.PID, ports, details)
		item.Exposure = Exposure{Level: level, Evidence: []string{fmt.Sprintf("进程 %s（PID %d）在运行", row.Name, row.PID)}}
		if findingTitle != "" {
			addFinding(cat, &item, level, findingTitle, findingDetail)
		}
		cat.Items = append(cat.Items, item)
	}
}

// detectMCP 识别 MCP server 进程。
// 判定收紧：必须有 @modelcontextprotocol/ 或 mcp-server- 明确标记；
// 仅 npx/uvx 不够（大量普通工具都用 npx），还要求命令里出现 mcp。
func (b *base) detectMCP(ctx context.Context, cat *Category) {
	for _, row := range b.procs {
		if ctx.Err() != nil {
			return
		}
		if !isMCPProcess(row) {
			continue
		}
		details := map[string]any{
			"product": "mcp_server",
			"cmdline": redact.CmdLine(row.CmdLine),
		}
		if v := transportFlag(row.CmdLine); v != "" {
			details["transport"] = v
		}
		item := b.newAsset("dev", "mcp_server", "MCP Server", row.PID, b.tcpPorts(b.portsForPID(row.PID)), details)
		item.Exposure = Exposure{Level: LevelLow, Evidence: []string{fmt.Sprintf("MCP server 进程 %s（PID %d）在运行", row.Name, row.PID)}}
		addFinding(cat, &item, LevelLow, "MCP Server 进程在运行",
			"MCP server 暴露工具调用面；确认其来源、允许的工具集与传输方式（stdio/HTTP）")
		cat.Items = append(cat.Items, item)
	}
}

func isMCPProcess(row state.ProcRow) bool {
	cmd := row.CmdLine
	if reMCP.MatchString(cmd) {
		return true
	}
	if !reNPXUVX.MatchString(cmd) {
		return false
	}
	lower := strings.ToLower(cmd)
	return strings.Contains(lower, "mcp")
}

func transportFlag(cmdline string) string {
	m := regexp.MustCompile(`(?i)--transport[=\s]+([a-z]+)`).FindStringSubmatch(cmdline)
	if len(m) > 1 {
		return strings.ToLower(m[1])
	}
	return ""
}

// probeRootAuth 探测根页并判定认证状态（Jupyter/code-server 用）。
func (b *base) probeRootAuth(ctx context.Context, ip string, port uint16) (status int, title, auth string, evidence []string, perr string) {
	auth = AuthUnknown
	resp := b.probe.get(ctx, endpointHTTP(ip, port)+"/")
	if resp.Err != nil {
		return 0, "", AuthUnknown, []string{"根页探测失败: " + resp.Err.Error()}, resp.Err.Error()
	}
	status = resp.Status
	title = htmlTitle(resp.Body)
	evidence = append(evidence, fmt.Sprintf("GET / → %d", resp.Status))
	if resp.Status == 401 || resp.Status == 403 {
		return status, title, AuthRequired, evidence, ""
	}
	if looksLikeLoginPage(resp.Body, title) {
		return status, title, AuthRequired, append(evidence, "根页包含登录表单/口令输入"), ""
	}
	if resp.Status == 200 {
		return status, title, AuthOpen, evidence, ""
	}
	return status, title, AuthUnknown, evidence, ""
}

// probeJSONControl 探测调试端点：200 + 合法 JSON 视为控制面开放；
// 401/403 视为有认证；其他状态 unknown。
func (b *base) probeJSONControl(ctx context.Context, ip string, port uint16, paths []string) (auth string, status int, evidence []string, perr string) {
	for _, path := range paths {
		resp := b.probe.get(ctx, endpointHTTP(ip, port)+path)
		if resp.Err != nil {
			return AuthUnknown, 0, []string{fmt.Sprintf("GET %s 失败: %v", path, resp.Err)}, resp.Err.Error()
		}
		evidence = append(evidence, fmt.Sprintf("GET %s → %d", path, resp.Status))
		status = resp.Status
		switch {
		case resp.Status == 401 || resp.Status == 403:
			return AuthRequired, status, evidence, ""
		case resp.Status == 200 && json.Valid(resp.Body):
			return AuthOpen, status, evidence, ""
		}
	}
	return AuthUnknown, status, evidence, ""
}
