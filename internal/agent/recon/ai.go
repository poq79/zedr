package recon

// ai.go：AI Agent Harness 识别（契约 §12.3 ai 类，明星类）。
//
// 三步识别：
//  1. 进程名/命令行（强指纹）；
//  2. 默认端口（弱指纹，8080 等共享端口需探测消歧）；
//  3. 主动探测：根页标记 + 能力端点。只有"匿名 200 且返回产品数据"
//     才判 open；401/403 或登录页判 auth_required；连不上判 unknown。
//
// 默认口令只写进 details.default_cred_note（文献级提示），本文件
// 不存在任何提交凭据/尝试登录的代码路径。

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// aiProbeOutcome 是一次产品探测的结论。
type aiProbeOutcome struct {
	Confirmed  bool
	AuthState  string
	Models     []string
	Evidence   []string
	RootTitle  string
	Server     string
	RootStatus int
	CapStatus  int
	CapPath    string
	Err        string
}

// detectAI 是 ai 类入口。
func detectAI(ctx context.Context, b *base) (Category, error) {
	cat := newCategory("ai", CategoryTitle("ai"))
	claimedPorts := make(map[uint16]struct{}, 8)
	seen := make(map[string]struct{}, 8)

	// 第一轮：进程/命令行。命中即认产品，端口从该进程的监听表取；
	// 没有监听时退回产品默认端口（仅当本机确实有该端口监听）。
	for _, row := range b.procs {
		if ctx.Err() != nil {
			return cat, nil
		}
		for i := range aiProducts {
			prod := &aiProducts[i]
			if !prod.matches(row) {
				continue
			}
			ports := b.tcpPorts(b.portsForPID(row.PID))
			if len(ports) == 0 {
				ports = b.tcpPorts(b.existingPorts(prod.Ports))
			}
			item, ok := b.aiAsset(ctx, &cat, prod, row.PID, ports, "process")
			if !ok {
				continue
			}
			if _, dup := seen[item.ID]; dup {
				continue
			}
			seen[item.ID] = struct{}{}
			cat.Items = append(cat.Items, item)
			for _, p := range ports {
				claimedPorts[p] = struct{}{}
			}
			break // 一个进程只归一个产品，避免 python.exe 多产品重复
		}
	}

	// 第二轮：端口。跳过已由进程认领的端口；共享端口用探测消歧。
	for _, port := range b.listenerPorts() {
		if ctx.Err() != nil {
			return cat, nil
		}
		if _, ok := claimedPorts[port]; ok {
			continue
		}
		if len(b.tcpPorts([]uint16{port})) == 0 {
			continue // 探测只对 TCP HTTP 端点有意义
		}
		cands := aiProductsByPort[port]
		if len(cands) == 0 {
			continue
		}
		pid := b.portListenerPID(port)
		if len(cands) == 1 {
			item, ok := b.aiAsset(ctx, &cat, cands[0], pid, []uint16{port}, "port")
			if !ok {
				continue
			}
			cat.Items = append(cat.Items, item)
			claimedPorts[port] = struct{}{}
			continue
		}
		// 共享端口（8080 等）：被动模式给一个诚实的总括条目；
		// 探测模式逐个确认，只保留能证明身份的候选。
		if b.probe == nil {
			details := map[string]any{
				"candidate_products": productKinds(cands),
				"auth_state":         AuthUnknown,
				"confidence":         "port",
			}
			item := b.newAsset("ai", "ai_endpoint", fmt.Sprintf("AI/HTTP 端点 :%d", port), pid, []uint16{port}, details)
			item.Exposure = passiveExposure(item.Listens, true)
			cat.Items = append(cat.Items, item)
			claimedPorts[port] = struct{}{}
			continue
		}
		kept := false
		for _, prod := range cands {
			item, ok := b.aiAsset(ctx, &cat, prod, pid, []uint16{port}, "port")
			if !ok {
				continue
			}
			// 共享端口上只保留探测确认或认证挑战的候选，避免把
			// 任意 8080 服务误标成 AI 产品。
			if confirmed, _ := item.Details["probe_confirmed"].(bool); !confirmed && item.Details["auth_state"] != AuthRequired {
				continue
			}
			cat.Items = append(cat.Items, item)
			kept = true
		}
		if kept {
			claimedPorts[port] = struct{}{}
		}
	}

	// 契约 ai 类附加项：Jupyter token 出现在命令行是真实高风险证据，
	// 即使 Jupyter 资产本身归 dev 类，也在 ai 类留一条类目级 finding。
	jupyterTokenFindings(&cat, b)
	sortItems(cat.Items)
	return cat, nil
}

// aiAsset 组装一条 AI 资产并按需探测。ok=false 表示端口消歧失败
// （探测返回了不相干的 200 页面），调用方应丢弃该候选。
func (b *base) aiAsset(ctx context.Context, cat *Category, prod *aiProduct, pid uint32, ports []uint16, confidence string) (AssetItem, bool) {
	details := map[string]any{
		"product":       prod.Kind,
		"models":        []string{},
		"dashboard_url": "",
		"auth_state":    AuthUnknown,
		"confidence":    confidence,
	}
	if prod.DefaultCredNote != "" {
		details["default_cred_note"] = prod.DefaultCredNote
	}
	item := b.newAsset("ai", prod.Kind, prod.Title, pid, ports, details)
	item.Exposure = passiveExposure(item.Listens, true)
	// 本地环境事实（config/plugins 目录、dsh 版本/CVE、纯进程框架提示）
	// 先于网络探测落盘：即使探测失败，这些证据也要出现在结果里。
	b.enrichAIProduct(cat, &item, prod, pid)
	if prod.Kind == "dsh" && confidence == "port" {
		// 仅端口命中时要求归属进程确实是 node，且能读到 dsh package.json：
		// 否则任意 3080 服务都可能被报成 critical 的 CVE 受影响资产。
		if row, ok := b.byPID[pid]; !ok || procBaseName(row.Name) != "node" {
			return item, false
		}
		if v, _ := details["version"].(string); v == "" {
			return item, false
		}
	}

	if len(ports) == 0 {
		return item, true
	}
	port := ports[0]
	ip := b.probeIP(port)
	endpoint := endpointHTTP(ip, port)
	item.Endpoint = endpoint
	details["dashboard_url"] = endpoint

	if b.probe == nil {
		return item, true
	}
	// 没有根页标记也没有能力端点（如 dsh 只做版本判定）时不发无用请求。
	if prod.CapPath == "" && prod.RootMarker == "" {
		return item, true
	}

	out := b.probeProduct(ctx, prod, ip, port)
	probePath, probeStatus := out.CapPath, out.CapStatus
	if probePath == "" || probePath == "/" || probeStatus == 0 {
		probePath, probeStatus = "/", out.RootStatus
	}
	details["probe_path"] = probePath
	if probeStatus != 0 {
		details["probe_status"] = probeStatus
	}
	if out.RootTitle != "" {
		details["title"] = out.RootTitle
	}
	if out.Server != "" {
		details["server_header"] = out.Server
	}
	if len(out.Models) > 0 {
		details["models"] = out.Models
	}
	details["probe_confirmed"] = out.Confirmed

	switch out.AuthState {
	case AuthOpen:
		details["auth_state"] = AuthOpen
		item.Exposure = authExposure(AuthOpen, LevelHigh, item.Listens)
		item.Exposure.Evidence = append(out.Evidence, item.Exposure.Evidence...)
		detail := fmt.Sprintf("%s 的 AI 能力端点匿名可访问（%s，HTTP %d）", prod.Title, probePath, probeStatus)
		if len(out.Models) > 0 {
			detail += fmt.Sprintf("，可枚举 %d 个模型", len(out.Models))
		}
		addFinding(cat, &item, LevelHigh, "AI 端点未要求认证", detail+"；建议仅绑定回环或前置认证网关")
	case AuthRequired:
		details["auth_state"] = AuthRequired
		if prod.AuthHint != "" {
			details["auth_hint"] = prod.AuthHint
		}
		item.Exposure = authExposure(AuthRequired, LevelHigh, item.Listens)
		item.Exposure.Evidence = append(out.Evidence, item.Exposure.Evidence...)
	default:
		details["auth_state"] = AuthUnknown
		if out.Err != "" {
			details["probe_error"] = out.Err
			item.Exposure = Exposure{Level: LevelUnknown, Evidence: out.Evidence}
		}
		// 端口消歧：探测到 200 但既无产品标记也无认证挑战 → 不是该产品。
		if confidence == "port" && !out.Confirmed && out.AuthState == AuthUnknown && out.Err == "" {
			return item, false
		}
	}
	return item, true
}

// probeProduct 执行根页 + 能力端点探测并归因。所有请求都走
// probeClient 的回环/GET/超时/预算红线。
func (b *base) probeProduct(ctx context.Context, prod *aiProduct, ip string, port uint16) aiProbeOutcome {
	out := aiProbeOutcome{AuthState: AuthUnknown, CapPath: prod.CapPath, Models: []string{}}
	baseURL := endpointHTTP(ip, port)

	root := b.probe.get(ctx, baseURL+"/")
	if root.Err != nil {
		out.Err = root.Err.Error()
		out.Evidence = append(out.Evidence, "根页探测失败: "+root.Err.Error())
	}
	if root.Err == nil {
		out.RootStatus = root.Status
		out.Server = root.Header.Get("Server")
		out.RootTitle = htmlTitle(root.Body)
		out.Evidence = append(out.Evidence, fmt.Sprintf("GET / → %d", root.Status))
	}
	rootBody := root.Body
	rootTitle := out.RootTitle
	markerHit := prod.RootMarker != "" && pageContains(rootBody, rootTitle, prod.RootMarker)
	loginPage := root.Err == nil && root.Status == 200 && looksLikeLoginPage(rootBody, rootTitle)
	if markerHit {
		out.Evidence = append(out.Evidence, "根页命中产品标记 "+prod.RootMarker)
	}
	if loginPage {
		out.Evidence = append(out.Evidence, "根页包含登录表单/口令输入")
	}

	var capBody []byte
	if prod.CapPath != "" && prod.CapPath != "/" {
		capResp := b.probe.get(ctx, baseURL+prod.CapPath)
		if capResp.Err != nil {
			if out.Err == "" {
				out.Err = capResp.Err.Error()
			}
			out.Evidence = append(out.Evidence, fmt.Sprintf("GET %s 失败: %v", prod.CapPath, capResp.Err))
		} else {
			out.CapStatus = capResp.Status
			capBody = capResp.Body
			out.Evidence = append(out.Evidence, fmt.Sprintf("GET %s → %d", prod.CapPath, capResp.Status))
		}
	}

	// 认证挑战优先：401/403 是比任何页面文本都硬的证据。
	switch {
	case out.RootStatus == 401 || out.RootStatus == 403 ||
		out.CapStatus == 401 || out.CapStatus == 403:
		out.AuthState = AuthRequired
		out.Confirmed = markerHit || out.CapStatus == 401 || out.CapStatus == 403
		return out
	case loginPage:
		out.AuthState = AuthRequired
		out.Confirmed = markerHit
		return out
	}

	// LiteLLM：/health 200 是公开存活端点，不能据此判无认证；
	// 再探 /v1/models，401 才是"有 master key"的硬证据。
	if prod.CapKind == capLiteLLMHealth && out.CapStatus == 200 {
		models := b.probe.get(ctx, baseURL+"/v1/models")
		if models.Err == nil {
			out.Evidence = append(out.Evidence, fmt.Sprintf("GET /v1/models → %d", models.Status))
			switch models.Status {
			case 401, 403:
				out.AuthState = AuthRequired
				out.Confirmed = true
				return out
			case 200:
				if got := parseModels(capOpenAIModels, models.Body); len(got) > 0 {
					out.Models = got
					out.AuthState = AuthOpen
					out.Confirmed = true
					return out
				}
			}
		}
	}

	models := parseModels(prod.CapKind, capBody)
	if len(models) > 0 {
		out.Models = models
	}
	capShape := capKindShape(prod.CapKind, out.CapStatus, capBody)
	openByCap := capKindProvesOpen(prod.CapKind, out.CapStatus, capBody)
	if capShape {
		out.Confirmed = true
	}
	if openByCap {
		out.AuthState = AuthOpen
		out.Confirmed = true
		return out
	}

	// 无认证默认产品：根页命中标记且没有登录表单，即视为开放。
	// 有认证默认的产品只凭根页不能判 open（匿名根页也可能只是营销页），
	// 必须能力端点给出数据证据。
	if markerHit && prod.NoAuthDefault && root.Err == nil {
		out.AuthState = AuthOpen
		out.Confirmed = true
		return out
	}
	if markerHit {
		out.Confirmed = true
	}
	return out
}

// capKindShape 判断能力端点响应是否"像该产品的数据"（用于身份确认）。
func capKindShape(kind string, status int, body []byte) bool {
	if status != 200 {
		return false
	}
	switch kind {
	case capOllamaTags:
		return jsonHasKey(body, "models")
	case capOpenAIModels, capLocalAIModels:
		return jsonHasKey(body, "data") || jsonHasKey(body, "object") || jsonHasKey(body, "models")
	case capComfyStats:
		return json.Valid(body)
	case capSDModels:
		return json.Valid(body)
	case capOpenAPI:
		return jsonHasKey(body, "openapi") || jsonHasKey(body, "paths")
	case capDifySetup:
		return len(body) > 0
	}
	return false
}

// capKindProvesOpen 只有"匿名 200 且返回产品数据/状态"才证明无认证。
// health/ping/config 类端点本身是公开的，不在此列（它们只用于身份确认）。
func capKindProvesOpen(kind string, status int, body []byte) bool {
	if status != 200 {
		return false
	}
	switch kind {
	case capOllamaTags:
		return jsonHasKey(body, "models")
	case capOpenAIModels, capLocalAIModels:
		return jsonHasKey(body, "data") || jsonHasKey(body, "models")
	case capComfyStats, capSDModels:
		return json.Valid(body)
	case capOpenAPI:
		return jsonHasKey(body, "openapi") || jsonHasKey(body, "paths")
	case capDifySetup:
		// /console/api/setup 200 = 尚未完成初始化，任何访问者都能设置管理员
		return true
	}
	return false
}

// parseModels 从能力端点 JSON 提取模型名（最多 100 个，避免超长响应
// 把详情撑爆）。兼容 Ollama/OpenAI/Stable Diffusion 三种形状。
func parseModels(kind string, body []byte) []string {
	if len(body) == 0 {
		return []string{}
	}
	if kind == capSDModels {
		var arr []struct {
			Title     string `json:"title"`
			ModelName string `json:"model_name"`
		}
		if json.Unmarshal(body, &arr) == nil {
			out := make([]string, 0, len(arr))
			for _, m := range arr {
				name := m.ModelName
				if name == "" {
					name = m.Title
				}
				if name != "" {
					out = append(out, name)
				}
				if len(out) >= 100 {
					break
				}
			}
			return out
		}
	}
	var v struct {
		Models []struct {
			Name string `json:"name"`
			ID   string `json:"id"`
		} `json:"models"`
		Data []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"data"`
	}
	if json.Unmarshal(body, &v) != nil {
		return []string{}
	}
	out := make([]string, 0, 8)
	seen := make(map[string]struct{}, 8)
	add := func(s string) {
		s = strings.TrimSpace(s)
		if s == "" {
			return
		}
		if _, ok := seen[s]; ok {
			return
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	if kind == capOllamaTags {
		for _, m := range v.Models {
			if m.Name != "" {
				add(m.Name)
			} else {
				add(m.ID)
			}
		}
	} else {
		for _, m := range v.Data {
			if m.ID != "" {
				add(m.ID)
			} else {
				add(m.Name)
			}
		}
		for _, m := range v.Models {
			if m.Name != "" {
				add(m.Name)
			}
		}
	}
	if len(out) > 100 {
		out = out[:100]
	}
	return out
}

// pageContains 在根页正文或标题里找产品标记（大小写不敏感）。
func pageContains(body []byte, title, marker string) bool {
	if marker == "" {
		return false
	}
	m := strings.ToLower(marker)
	return strings.Contains(strings.ToLower(title), m) ||
		strings.Contains(strings.ToLower(string(body)), m)
}

// productKinds 返回候选产品 kind 列表（共享端口被动模式用）。
func productKinds(products []*aiProduct) []string {
	out := make([]string, 0, len(products))
	for _, p := range products {
		out = append(out, p.Kind)
	}
	return out
}

// ---------------------------------------------------------------- 本地环境事实

// enrichAIProduct 补充不依赖网络的产品事实：配置目录/插件目录存在性、
// 纯进程框架提示、dsh 的 package.json 版本与 CVE 判定。全部是只读本地
// 文件/环境变量读取，不消耗探测预算。
func (b *base) enrichAIProduct(cat *Category, item *AssetItem, prod *aiProduct, pid uint32) {
	details := item.Details
	if dir := resolveConfigDir(prod); dir != "" {
		details["config_dir"] = dir
		details["config_dir_exists"] = pathIsDir(dir)
		if prod.PluginsDir != "" {
			pdir := filepath.Join(dir, prod.PluginsDir)
			exists := pathIsDir(pdir)
			details["plugins_dir"] = pdir
			details["plugins_dir_exists"] = exists
			if exists {
				addFinding(cat, item, LevelMedium, "Agent 插件目录存在",
					"第三方插件以当前用户权限执行，可绕过 agent 权限控制（CERT-EU 2026-10-30 预警）；建议审计插件来源与权限")
				if item.Exposure.Level == LevelInfo || item.Exposure.Level == LevelLow {
					item.Exposure = Exposure{Level: LevelMedium, Evidence: []string{"插件目录存在: " + pdir}}
				}
			}
		}
	}
	if prod.ProcessOnly && pid != 0 {
		note := prod.ProcessNote
		if note == "" {
			note = "Agent 框架进程在运行；确认任务来源、工具权限与凭据作用域"
		}
		addFinding(cat, item, LevelInfo, "Agent 框架进程在运行", note)
	}
	if prod.Kind == "dsh" {
		b.enrichDSH(cat, item, pid)
	}
}

// resolveConfigDir 解析产品的配置目录：环境变量覆盖 > 默认路径（展开
// %USERPROFILE% 等）。返回空串表示该产品没有配置目录语义。
func resolveConfigDir(prod *aiProduct) string {
	raw := ""
	if prod.ConfigDirEnv != "" {
		raw = strings.TrimSpace(os.Getenv(prod.ConfigDirEnv))
	}
	if raw == "" {
		raw = prod.ConfigDir
	}
	if raw == "" {
		return ""
	}
	return expandPath(raw)
}

// pathIsDir 判断路径存在且是目录（配置目录语义；文件不算存在）。
func pathIsDir(path string) bool {
	if path == "" {
		return false
	}
	st, err := os.Stat(path)
	return err == nil && st.IsDir()
}

// ---------------------------------------------------------------- dsh CVE

const (
	// dshFixedVersion 是 CVE-2026-82533 的修复版本（Host 头信任→沙箱自解除）。
	dshFixedVersion = "0.1.2-alpha.2"
	dshCVE          = "CVE-2026-82533"
)

// dshPkgPathRe 从命令行里提取 npm 包目录（支持空格与正反斜杠）。
// 只提取到 dsh 目录，避免把后面的参数吞进路径。
var dshPkgPathRe = regexp.MustCompile(`(?i)([A-Za-z]:[^"]*?node_modules[\\/]@deepseek-ai[\\/]dsh)`)

// enrichDSH 读 node_modules/@deepseek-ai/dsh/package.json 的 version，
// 判定 CVE-2026-82533：低于修复版本或无法确认版本均 critical。
// 读文件是本机只读事实，不算 §12.4 的网络探测。
func (b *base) enrichDSH(cat *Category, item *AssetItem, pid uint32) {
	cmdline := ""
	if row, ok := b.byPID[pid]; ok {
		cmdline = row.CmdLine
	}
	version, pkgPath := dshVersion(cmdline)
	item.Details["cve"] = dshCVE
	item.Details["version"] = version
	if pkgPath != "" {
		item.Details["package_json"] = pkgPath
	}

	fixed := dshVersionAtLeast(version)
	item.Details["cve_affected"] = !fixed
	if fixed {
		return
	}
	display := version
	if display == "" {
		display = "无法确认"
	}
	item.Exposure = Exposure{
		Level:    LevelCritical,
		Evidence: []string{fmt.Sprintf("dsh 版本 %s < 修复版本 %s", display, dshFixedVersion)},
	}
	addFinding(cat, item, LevelCritical, "DeepSeek Harness 受 CVE-2026-82533 影响",
		fmt.Sprintf("当前版本 %s 低于 %s（或无法确认版本）；该漏洞通过 Host 头信任导致沙箱自解除，建议立即升级到 >=%s",
			display, dshFixedVersion, dshFixedVersion))
}

// dshVersion 按"命令行里的绝对包路径 → 常见全局 npm 目录"顺序找
// package.json 并读 version。找不到返回 ("", "")。
func dshVersion(cmdline string) (version, pkgPath string) {
	candidates := make([]string, 0, 6)
	if m := dshPkgPathRe.FindStringSubmatch(cmdline); len(m) > 1 {
		candidates = append(candidates, filepath.Join(strings.TrimSpace(m[1]), "package.json"))
	}
	for _, root := range []string{
		os.Getenv("APPDATA"),
		os.Getenv("ProgramFiles"),
		os.Getenv("ProgramFiles(x86)"),
		os.Getenv("USERPROFILE"),
	} {
		if root == "" {
			continue
		}
		candidates = append(candidates,
			filepath.Join(root, "npm", "node_modules", "@deepseek-ai", "dsh", "package.json"),
			filepath.Join(root, "nodejs", "node_modules", "@deepseek-ai", "dsh", "package.json"),
			filepath.Join(root, ".npm-global", "node_modules", "@deepseek-ai", "dsh", "package.json"),
		)
	}
	seen := make(map[string]struct{}, len(candidates))
	for _, p := range candidates {
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		// 复用带大小上限的只读文本读取：package.json 正常 <10KB，
		// 1MB 上限防恶意/损坏文件把侦查内存打爆。
		text, err := readTextFile(p, 1<<20)
		if err != nil {
			continue
		}
		var pkg struct {
			Version string `json:"version"`
		}
		if json.Unmarshal([]byte(text), &pkg) != nil || strings.TrimSpace(pkg.Version) == "" {
			continue
		}
		return strings.TrimSpace(pkg.Version), p
	}
	return "", ""
}

// dshVersionAtLeast 判断 version >= dshFixedVersion。
// 版本无法解析按"受影响"处理（未知版本不能假设安全）。
func dshVersionAtLeast(version string) bool {
	if strings.TrimSpace(version) == "" {
		return false
	}
	a, ap, ok := parseSemver(version)
	f, fp, okf := parseSemver(dshFixedVersion)
	if !ok || !okf {
		return false
	}
	for i := 0; i < 3; i++ {
		if a[i] != f[i] {
			return a[i] > f[i]
		}
	}
	return comparePrerelease(ap, fp) >= 0
}

// parseSemver 解析 major.minor.patch[-prerelease][+build]。
// 只支持数字段 + 点分 prerelease；npm 生态的版本号足够用。
func parseSemver(v string) (core [3]int, pre []string, ok bool) {
	v = strings.TrimSpace(v)
	v = strings.TrimPrefix(v, "v")
	if i := strings.IndexByte(v, '+'); i >= 0 {
		v = v[:i]
	}
	if i := strings.IndexByte(v, '-'); i >= 0 {
		if i+1 < len(v) {
			pre = strings.Split(v[i+1:], ".")
		}
		v = v[:i]
	}
	parts := strings.Split(v, ".")
	if len(parts) != 3 {
		return core, nil, false
	}
	for i, p := range parts {
		n, err := strconv.Atoi(strings.TrimSpace(p))
		if err != nil || n < 0 {
			return core, nil, false
		}
		core[i] = n
	}
	return core, pre, true
}

// comparePrerelease 按 semver 规则比较 prerelease：
// 无 prerelease > 有 prerelease；数字段按数值、数字 < 非数字、其余字典序。
func comparePrerelease(a, b []string) int {
	if len(a) == 0 && len(b) == 0 {
		return 0
	}
	if len(a) == 0 {
		return 1 // release > prerelease
	}
	if len(b) == 0 {
		return -1
	}
	for i := 0; i < len(a) && i < len(b); i++ {
		ai, aerr := strconv.Atoi(a[i])
		bi, berr := strconv.Atoi(b[i])
		aNum, bNum := aerr == nil, berr == nil
		switch {
		case aNum && bNum:
			if ai != bi {
				if ai < bi {
					return -1
				}
				return 1
			}
		case aNum:
			return -1 // 数字标识符优先级低于字母
		case bNum:
			return 1
		default:
			if a[i] != b[i] {
				if a[i] < b[i] {
					return -1
				}
				return 1
			}
		}
	}
	if len(a) == len(b) {
		return 0
	}
	if len(a) < len(b) {
		return -1
	}
	return 1
}
