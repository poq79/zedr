package recon

// web.go：Web 服务识别（契约 §12.3 web 类）。
//
// IIS 走配置解析（applicationHost.config 是唯一事实源：site→bindings→
// application→virtualDirectory physicalPath）；nginx/httpd/tomcat/caddy/
// lighttpd 走"进程 + 命令行 -c/-f/--config + 进程目录附近默认配置"，
// 配置文本正则提取 DocumentRoot/root；最后补一层通用 HTTP 服务
// （监听端口 + 进程名像 httpd/nginx/node/python/go + 根页 Server/title）。
//
// 所有配置读取都是只读、限长（2MB），不执行任何配置里的指令。

import (
	"context"
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"zedr/internal/agent/state"
)

// ---------------------------------------------------------------- IIS

// iisBindingInfo 是站点绑定的展示结构。
type iisBindingInfo struct {
	Protocol string `json:"protocol"`
	Address  string `json:"address"`
	Port     uint16 `json:"port"`
	Host     string `json:"host,omitempty"`
}

// iisSiteInfo 是一个 IIS 站点。
//
// bindings 输出字符串数组（"http:*:80:host"），与 F4 前端表格的渲染口径
// 一致；结构化字段另放 binding_details，供需要协议/地址/端口分列消费方。
// physicalPath 是 F4 表格读取的键名，与 webroot 同值（一个是站点视角，
// 一个是顶层抽查视角）。
type iisSiteInfo struct {
	Name           string           `json:"name"`
	ID             string           `json:"id,omitempty"`
	Bindings       []string         `json:"bindings"`
	BindingDetails []iisBindingInfo `json:"binding_details,omitempty"`
	PhysicalPath   string           `json:"physicalPath,omitempty"`
	Webroot        string           `json:"webroot,omitempty"`
	ASPXPresent    bool             `json:"aspx_present"`
	ASPXFiles      int              `json:"aspx_files,omitempty"`
	HasWebConfig   bool             `json:"has_web_config,omitempty"`
	HasBin         bool             `json:"has_bin,omitempty"`
}

type iisConfigXML struct {
	SystemApplicationHost struct {
		Sites struct {
			Sites []iisSiteXML `xml:"site"`
		} `xml:"sites"`
	} `xml:"system.applicationHost"`
}

type iisSiteXML struct {
	Name         string       `xml:"name,attr"`
	ID           string       `xml:"id,attr"`
	Bindings     []iisBindXML `xml:"bindings>binding"`
	Applications []iisAppXML  `xml:"application"`
}

type iisBindXML struct {
	Protocol string `xml:"protocol,attr"`
	Info     string `xml:"bindingInformation,attr"`
}

type iisAppXML struct {
	Path     string       `xml:"path,attr"`
	VirtDirs []iisVDirXML `xml:"virtualDirectory"`
}

type iisVDirXML struct {
	Path         string `xml:"path,attr"`
	PhysicalPath string `xml:"physicalPath,attr"`
}

// iisConfigPath 返回 applicationHost.config 的标准路径。
func iisConfigPath() string {
	root := os.Getenv("SystemRoot")
	if root == "" {
		root = `C:\Windows`
	}
	return filepath.Join(root, "System32", "inetsrv", "config", "applicationHost.config")
}

// parseIISConfig 解析 applicationHost.config 并做 webroot 顶层抽查。
// 返回的 sites 即使没有 webroot 也会保留（绑定的价值独立于目录）。
func parseIISConfig(path string) ([]iisSiteInfo, error) {
	text, err := readTextFile(path, 16<<20) // IIS 配置可能到 MB 级
	if err != nil {
		return nil, err
	}
	var doc iisConfigXML
	if err := xml.Unmarshal([]byte(text), &doc); err != nil {
		return nil, fmt.Errorf("解析 applicationHost.config 失败: %w", err)
	}
	sites := make([]iisSiteInfo, 0, len(doc.SystemApplicationHost.Sites.Sites))
	for _, s := range doc.SystemApplicationHost.Sites.Sites {
		site := iisSiteInfo{
			Name:           s.Name,
			ID:             s.ID,
			Bindings:       make([]string, 0, len(s.Bindings)),
			BindingDetails: make([]iisBindingInfo, 0, len(s.Bindings)),
		}
		for _, bind := range s.Bindings {
			proto := strings.ToLower(strings.TrimSpace(bind.Protocol))
			if proto == "" {
				proto = "http"
			}
			addr, port, host, ok := parseIISBinding(bind.Info)
			if !ok {
				continue
			}
			info := iisBindingInfo{Protocol: proto, Address: addr, Port: port, Host: host}
			site.BindingDetails = append(site.BindingDetails, info)
			site.Bindings = append(site.Bindings, fmt.Sprintf("%s:%s:%d:%s", proto, addr, port, host))
		}
		site.Webroot = iisSiteWebroot(s.Applications)
		site.PhysicalPath = site.Webroot
		if site.Webroot != "" {
			site.ASPXPresent, site.ASPXFiles, site.HasWebConfig, site.HasBin = inspectWebroot(site.Webroot)
		}
		sites = append(sites, site)
	}
	return sites, nil
}

// parseIISBinding 解析 "IP:port:host"（IPv6 形式为 "[::]:80:host"）。
func parseIISBinding(info string) (addr string, port uint16, host string, ok bool) {
	info = strings.TrimSpace(info)
	if info == "" {
		return "", 0, "", false
	}
	if strings.HasPrefix(info, "[") {
		end := strings.IndexByte(info, ']')
		if end < 0 {
			return "", 0, "", false
		}
		addr = info[:end+1]
		rest := strings.TrimPrefix(info[end+1:], ":")
		parts := strings.SplitN(rest, ":", 2)
		if len(parts) < 1 {
			return "", 0, "", false
		}
		n, err := parsePort(parts[0])
		if err != nil {
			return "", 0, "", false
		}
		if len(parts) > 1 {
			host = parts[1]
		}
		return addr, n, host, true
	}
	parts := strings.SplitN(info, ":", 3)
	if len(parts) < 2 {
		return "", 0, "", false
	}
	n, err := parsePort(parts[1])
	if err != nil {
		return "", 0, "", false
	}
	return parts[0], n, strings.Join(parts[2:], ":"), true
}

func parsePort(s string) (uint16, error) {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return 0, err
	}
	if n < 1 || n > 65535 {
		return 0, fmt.Errorf("端口越界 %d", n)
	}
	return uint16(n), nil
}

// iisSiteWebroot 优先取 path="/" 的应用；否则取第一个有 physicalPath 的目录。
func iisSiteWebroot(apps []iisAppXML) string {
	for _, app := range apps {
		appPath := strings.TrimSpace(app.Path)
		for _, vd := range app.VirtDirs {
			if strings.TrimSpace(vd.PhysicalPath) == "" {
				continue
			}
			if appPath == "/" || appPath == "" {
				return expandPath(vd.PhysicalPath)
			}
		}
	}
	for _, app := range apps {
		for _, vd := range app.VirtDirs {
			if strings.TrimSpace(vd.PhysicalPath) != "" {
				return expandPath(vd.PhysicalPath)
			}
		}
	}
	return ""
}

// inspectWebroot 顶层抽查（前 200 项）：aspx/asax/ashx、web.config、bin。
// 只看顶层是成本与收益的折中：IIS 站点根目录通常直接放 Default.aspx，
// 深层目录靠后续按需文件浏览，不在这里递归。
func inspectWebroot(webroot string) (aspx bool, aspxFiles int, hasWebConfig, hasBin bool) {
	entries, err := os.ReadDir(webroot)
	if err != nil {
		return false, 0, false, false
	}
	for i, e := range entries {
		if i >= 200 {
			break
		}
		name := strings.ToLower(e.Name())
		if e.IsDir() {
			if name == "bin" {
				hasBin = true
			}
			continue
		}
		switch name {
		case "web.config":
			hasWebConfig = true
		}
		switch filepath.Ext(name) {
		case ".aspx", ".asax", ".ashx":
			aspxFiles++
		}
	}
	return aspxFiles > 0 || hasWebConfig || hasBin, aspxFiles, hasWebConfig, hasBin
}

// ---------------------------------------------------------------- 非 IIS Web 服务器

type webServerProduct struct {
	Kind         string
	Title        string
	Names        []string
	CmdRe        *regexp.Regexp
	DefaultPaths func(exeDir string) []string
}

var webServerProducts = []webServerProduct{
	{
		Kind: "nginx", Title: "nginx",
		Names: []string{"nginx"},
		CmdRe: regexp.MustCompile(`(?i)(^|[\\/\s"])nginx(\.exe)?([\s"]|$)`),
		DefaultPaths: func(dir string) []string {
			return []string{
				filepath.Join(dir, "conf", "nginx.conf"),
				filepath.Join(dir, "nginx.conf"),
				filepath.Join(filepath.Dir(dir), "conf", "nginx.conf"),
				`C:\nginx\conf\nginx.conf`,
			}
		},
	},
	{
		Kind: "httpd", Title: "Apache httpd",
		Names: []string{"httpd", "apache", "apache2"},
		CmdRe: regexp.MustCompile(`(?i)(^|[\\/\s"])(httpd|apache2?)(\.exe)?([\s"]|$)`),
		DefaultPaths: func(dir string) []string {
			return []string{
				filepath.Join(dir, "conf", "httpd.conf"),
				filepath.Join(filepath.Dir(dir), "conf", "httpd.conf"),
				`C:\Apache24\conf\httpd.conf`,
			}
		},
	},
	{
		Kind: "tomcat", Title: "Apache Tomcat",
		Names: []string{"tomcat", "tomcat9", "tomcat10", "catalina"},
		CmdRe: regexp.MustCompile(`(?i)catalina|tomcat`),
		// Tomcat 的配置路径由 detectTomcatConfig 单独处理（-Dcatalina.*）。
		DefaultPaths: nil,
	},
	{
		Kind: "caddy", Title: "Caddy",
		Names: []string{"caddy"},
		CmdRe: regexp.MustCompile(`(?i)(^|[\\/\s"])caddy(\.exe)?([\s"]|$)`),
		DefaultPaths: func(dir string) []string {
			return []string{
				filepath.Join(dir, "Caddyfile"),
				filepath.Join(dir, "config", "Caddyfile"),
				filepath.Join(filepath.Dir(dir), "Caddyfile"),
			}
		},
	},
	{
		Kind: "lighttpd", Title: "lighttpd",
		Names: []string{"lighttpd"},
		CmdRe: regexp.MustCompile(`(?i)(^|[\\/\s"])lighttpd(\.exe)?([\s"]|$)`),
		DefaultPaths: func(dir string) []string {
			return []string{
				filepath.Join(dir, "conf", "lighttpd.conf"),
				filepath.Join(dir, "lighttpd.conf"),
			}
		},
	},
}

// detectWeb 是 web 类入口。
func detectWeb(ctx context.Context, b *base) (Category, error) {
	cat := newCategory("web", CategoryTitle("web"))
	b.detectIIS(ctx, &cat)

	claimedPorts := make(map[uint16]struct{}, 8)
	for _, prod := range webServerProducts {
		if ctx.Err() != nil {
			return cat, nil
		}
		// nginx/apache 是 master+workers 多进程模型，逐个进程建资产会
		// 产生大量重复条目；每个产品只保留一个代表进程（优先有监听者）。
		var matched []state.ProcRow
		for _, row := range b.procs {
			if webServerMatches(prod, row) {
				matched = append(matched, row)
			}
		}
		if len(matched) == 0 {
			continue
		}
		rep := matched[0]
		for _, row := range matched {
			if len(b.tcpPorts(b.portsForPID(row.PID))) > 0 {
				rep = row
				break
			}
		}
		item := b.webServerAsset(ctx, &cat, prod, rep)
		cat.Items = append(cat.Items, item)
		for _, l := range item.Listens {
			claimedPorts[l.Port] = struct{}{}
		}
	}

	// 通用 HTTP：监听端口 + 进程名像 Web 运行时。已知产品端口跳过，
	// 避免与上面/IIS 重复；仅对常见 Web 端口做被动识别，减少噪音。
	for _, port := range b.listenerPorts() {
		if ctx.Err() != nil {
			return cat, nil
		}
		if _, ok := claimedPorts[port]; ok {
			continue
		}
		if _, ok := nonWebPortSet[port]; ok {
			continue
		}
		pid := b.portListenerPID(port)
		row, ok := b.byPID[pid]
		if !ok {
			continue
		}
		name := procBaseName(row.Name)
		if !genericWebName(name) {
			continue
		}
		_, knownPort := knownWebPortSet[port]
		if !isServerName(name) && !knownPort {
			continue
		}
		item := b.genericHTTPAsset(ctx, &cat, pid, row, port)
		cat.Items = append(cat.Items, item)
	}

	sortItems(cat.Items)
	return cat, nil
}

func (b *base) detectIIS(ctx context.Context, cat *Category) {
	config := iisConfigPath()
	sites, parseErr := parseIISConfig(config)
	worker := b.firstProcByName("w3wp")
	if len(sites) == 0 && worker == nil {
		return // 没装 IIS / 没在跑：不是资产
	}

	var pid uint32
	if worker != nil {
		pid = worker.PID
	}
	ports := make([]uint16, 0, 8)
	seen := make(map[uint16]struct{}, 8)
	nonLoopback := false
	aspx := false
	for _, site := range sites {
		for _, bind := range site.BindingDetails {
			if _, ok := seen[bind.Port]; !ok {
				seen[bind.Port] = struct{}{}
				ports = append(ports, bind.Port)
			}
			if !addrIsLoopback(bind.Address) {
				nonLoopback = true
			}
		}
		if site.ASPXPresent {
			aspx = true
		}
	}
	if len(ports) > 0 && pid == 0 {
		pid = b.portListenerPID(ports[0])
	}

	if sites == nil {
		sites = []iisSiteInfo{} // JSON 输出 [] 而非 null
	}
	details := map[string]any{
		"product":     "iis",
		"sites":       sites,
		"config_path": config,
	}
	if parseErr == nil {
		// 配置读不到时不输出 aspx_present，避免把"没读到"伪装成"未发现"。
		details["aspx_present"] = aspx
	}
	if len(sites) > 0 && sites[0].Webroot != "" {
		// 顶层 webroot 取首个站点：F4 的 WebDetails 用它做"站点根目录"
		// 单行摘要；完整多站点信息在 sites[] 里。
		details["webroot"] = sites[0].Webroot
	}
	if parseErr != nil {
		details["config_error"] = parseErr.Error()
	}
	item := b.newAsset("web", "iis", "IIS Web 服务器", pid, ports, details)
	running := worker != nil || len(item.Listens) > 0
	switch {
	case !running:
		// 只有配置没有进程/监听：IIS 已安装但服务未运行。这是环境事实，
		// 不应该给出"网络暴露"结论。
		item.Exposure = Exposure{Level: LevelInfo, Evidence: []string{"发现 IIS 配置，但未检测到 w3wp 或监听端口"}}
	case nonLoopback:
		item.Exposure = Exposure{Level: LevelMedium, Evidence: []string{"IIS 绑定包含非回环地址（* / 0.0.0.0 / 具体网卡）"}}
	default:
		item.Exposure = passiveExposure(item.Listens, true)
	}
	if aspx && nonLoopback && running {
		addFinding(cat, &item, LevelMedium, "IIS 站点对网络暴露且含动态内容",
			"站点绑定非回环地址，webroot 顶层存在 aspx/asax/ashx/web.config/bin；确认应用鉴权与补丁状态")
	}
	if len(ports) > 0 {
		httpPort := firstHTTPBindingPort(sites)
		if httpPort != 0 && b.firstListeningPort([]uint16{httpPort}) != 0 {
			ip := b.probeIP(httpPort)
			item.Endpoint = endpointHTTP(ip, httpPort)
			if b.probe != nil {
				bi := b.httpBanner(ctx, ip, httpPort)
				if bi.Server != "" {
					details["server_header"] = bi.Server
				}
				if bi.Title != "" {
					details["title"] = bi.Title
				}
			}
		}
	}
	cat.Items = append(cat.Items, item)
}

// webServerAsset 组装一条非 IIS Web 服务器资产。
func (b *base) webServerAsset(ctx context.Context, cat *Category, prod webServerProduct, row state.ProcRow) AssetItem {
	exeDir := ""
	if row.Path != "" {
		exeDir = filepath.Dir(row.Path)
	}
	configPath := ""
	if prod.Kind == "tomcat" {
		configPath = detectTomcatConfig(row)
	} else {
		args := configFlagCandidates(prod.Kind)
		if v := flagValue(row.CmdLine, args...); v != "" {
			configPath = expandPath(v)
		}
		if configPath == "" && exeDir != "" && prod.DefaultPaths != nil {
			configPath = pickExisting(prod.DefaultPaths(exeDir))
		}
	}
	if configPath != "" {
		// 命令行里的 -c/-f 可能指向已删除/错位的文件；契约要求
		// "找不到就 config_path 空"，不能让详情指向一个不存在的路径。
		if st, err := os.Stat(configPath); err != nil || st.IsDir() {
			configPath = ""
		}
	}
	webroot := ""
	var tomcatPorts []uint16
	if configPath != "" {
		switch prod.Kind {
		case "tomcat":
			webroot, tomcatPorts = parseTomcatConfig(configPath)
		case "httpd":
			webroot = regexWebroot(configPath, `(?mi)^\s*DocumentRoot\s+"?([^"\r\n]+)"?`)
		case "lighttpd":
			webroot = regexWebroot(configPath, `(?mi)server\.document-root\s*=\s*"([^"]+)"`)
		case "caddy":
			webroot = regexWebroot(configPath, `(?mi)^\s*root\s+(?:\*\s+)?([^\s{]+)`)
		default: // nginx
			webroot = regexWebroot(configPath, `(?mi)^\s*root\s+([^;#\r\n]+);`)
		}
	}
	ports := b.tcpPorts(b.portsForPID(row.PID))
	ports = mergePorts(ports, tomcatPorts)
	if len(ports) == 0 && len(tomcatPorts) == 0 {
		ports = b.tcpPorts(b.existingPorts([]uint16{80, 8080}))
	}

	details := map[string]any{
		"product":     prod.Kind,
		"config_path": configPath,
		"webroot":     webroot,
	}
	item := b.newAsset("web", prod.Kind, prod.Title, row.PID, ports, details)
	item.Exposure = passiveExposure(item.Listens, true)
	if anyNonLoopback(item.Listens) {
		item.Exposure = Exposure{Level: LevelMedium, Evidence: []string{fmt.Sprintf("%s 监听非回环地址", prod.Title)}}
		addFinding(cat, &item, LevelMedium, "Web 服务器监听非回环地址",
			fmt.Sprintf("%s 对外提供 HTTP 服务；确认站点鉴权、版本补丁与目录权限", prod.Title))
	}
	if listenPort := b.firstListeningPort(ports); listenPort != 0 {
		ip := b.probeIP(listenPort)
		item.Endpoint = endpointHTTP(ip, listenPort)
		if b.probe != nil {
			bi := b.httpBanner(ctx, ip, listenPort)
			if bi.Server != "" {
				details["server_header"] = bi.Server
			}
			if bi.PoweredBy != "" {
				details["x_powered_by"] = bi.PoweredBy
			}
			if bi.Title != "" {
				details["title"] = bi.Title
			}
		}
	}
	return item
}

// genericHTTPAsset 组装一条通用 HTTP 资产。
func (b *base) genericHTTPAsset(ctx context.Context, cat *Category, pid uint32, row state.ProcRow, port uint16) AssetItem {
	details := map[string]any{
		"product":      "http",
		"process_name": row.Name,
	}
	item := b.newAsset("web", "http", fmt.Sprintf("HTTP 服务 :%d (%s)", port, row.Name), pid, []uint16{port}, details)
	item.Exposure = passiveExposure(item.Listens, true)
	ip := b.probeIP(port)
	item.Endpoint = endpointHTTP(ip, port)
	if b.probe != nil {
		bi := b.httpBanner(ctx, ip, port)
		if bi.Server != "" {
			details["server_header"] = bi.Server
		}
		if bi.PoweredBy != "" {
			details["x_powered_by"] = bi.PoweredBy
		}
		if bi.Title != "" {
			details["title"] = bi.Title
		}
	}
	if anyNonLoopback(item.Listens) {
		item.Exposure = Exposure{Level: LevelMedium, Evidence: []string{"HTTP 服务监听非回环地址"}}
		addFinding(cat, &item, LevelMedium, "通用 HTTP 服务监听非回环地址",
			"确认服务用途、版本与访问控制（本类只做指纹，不判定业务风险）")
	}
	return item
}

// ---------------------------------------------------------------- 配置解析辅助

// readTextFile 读取文本配置，带大小上限（防止误读巨型文件拖垮侦查）。
func readTextFile(path string, limit int64) (string, error) {
	st, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if st.IsDir() {
		return "", fmt.Errorf("%s 是目录", path)
	}
	if st.Size() > limit {
		return "", fmt.Errorf("%s 超过读取上限 %d 字节", path, limit)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	// IIS/Tomcat 配置在部分环境下带 UTF-8 BOM；encoding/xml 会把它当
	// 非法字符，先剥掉。
	return strings.TrimPrefix(string(data), "\uFEFF"), nil
}

// regexWebroot 从配置文本提取根目录（只取第一个匹配）。
func regexWebroot(path, pattern string) string {
	text, err := readTextFile(path, 2<<20)
	if err != nil {
		return ""
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return ""
	}
	m := re.FindStringSubmatch(text)
	if len(m) < 2 {
		return ""
	}
	return expandPath(strings.Trim(strings.TrimSpace(m[1]), `"'`))
}

// configFlagCandidates 返回各产品常见的配置路径参数。
func configFlagCandidates(kind string) []string {
	switch kind {
	case "nginx":
		return []string{"-c"}
	case "httpd":
		return []string{"-f", "-c"}
	case "caddy":
		return []string{"--config", "-c"}
	case "lighttpd":
		return []string{"-f"}
	}
	return []string{"-c", "--config"}
}

// flagValue 从命令行提取 "-c path" / "-c=path" / "--config path" 的值。
// 支持双引号包裹的含空格路径；找不到返回空串。
func flagValue(cmdline string, names ...string) string {
	for _, name := range names {
		// 用非贪婪字符类而非 [^\s]+，配合两种引号分支。
		pattern := `(?i)(?:^|\s)` + regexp.QuoteMeta(name) + `(?:=|\s+)(?:"([^"]+)"|'([^']+)'|([^\s]+))`
		re, err := regexp.Compile(pattern)
		if err != nil {
			continue
		}
		m := re.FindStringSubmatch(cmdline)
		if len(m) == 0 {
			continue
		}
		for i := 1; i < len(m); i++ {
			if strings.TrimSpace(m[i]) != "" {
				return strings.TrimSpace(m[i])
			}
		}
	}
	return ""
}

// pickExisting 返回候选路径中第一个存在的普通文件。
func pickExisting(paths []string) string {
	for _, p := range paths {
		if p == "" {
			continue
		}
		st, err := os.Stat(p)
		if err == nil && !st.IsDir() {
			return p
		}
	}
	return ""
}

// detectTomcatConfig 按 -Dcatalina.base/home、环境变量、bin 目录父级推断。
func detectTomcatConfig(row state.ProcRow) string {
	var roots []string
	for _, flag := range []string{`-Dcatalina.base=`, `-Dcatalina.home=`} {
		re := regexp.MustCompile(`(?i)` + regexp.QuoteMeta(flag) + `(?:"([^"]+)"|([^\s"']+))`)
		if m := re.FindStringSubmatch(row.CmdLine); len(m) > 0 {
			for i := 1; i < len(m); i++ {
				if strings.TrimSpace(m[i]) != "" {
					roots = append(roots, strings.TrimSpace(m[i]))
					break
				}
			}
		}
	}
	for _, env := range []string{"CATALINA_BASE", "CATALINA_HOME"} {
		if v := os.Getenv(env); v != "" {
			roots = append(roots, v)
		}
	}
	if row.Path != "" {
		dir := filepath.Dir(row.Path)
		if strings.EqualFold(filepath.Base(dir), "bin") {
			roots = append(roots, filepath.Dir(dir))
		}
	}
	for _, root := range roots {
		p := filepath.Join(expandPath(root), "conf", "server.xml")
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p
		}
	}
	return ""
}

// parseTomcatConfig 从 server.xml 提取 Host appBase 与 Connector 端口。
func parseTomcatConfig(path string) (webroot string, ports []uint16) {
	text, err := readTextFile(path, 2<<20)
	if err != nil {
		return "", nil
	}
	var doc struct {
		Connectors []struct {
			Port string `xml:"port,attr"`
		} `xml:"Service>Connector"`
		Hosts []struct {
			AppBase string `xml:"appBase,attr"`
		} `xml:"Service>Engine>Host"`
	}
	if err := xml.Unmarshal([]byte(text), &doc); err != nil {
		return "", nil
	}
	seen := make(map[uint16]struct{}, len(doc.Connectors))
	for _, c := range doc.Connectors {
		n, err := parsePort(c.Port)
		if err != nil {
			continue
		}
		if _, ok := seen[n]; ok {
			continue
		}
		seen[n] = struct{}{}
		ports = append(ports, n)
	}
	home := filepath.Dir(filepath.Dir(path)) // conf/server.xml → CATALINA_HOME
	for _, h := range doc.Hosts {
		if strings.TrimSpace(h.AppBase) == "" {
			continue
		}
		appBase := expandPath(h.AppBase)
		if filepath.IsAbs(appBase) {
			return appBase, ports
		}
		return filepath.Join(home, appBase), ports
	}
	return "", ports
}

// ---------------------------------------------------------------- 匹配与集合

func webServerMatches(prod webServerProduct, row state.ProcRow) bool {
	name := procBaseName(row.Name)
	for _, n := range prod.Names {
		if name == strings.ToLower(n) {
			return true
		}
	}
	if prod.Kind == "tomcat" {
		// java.exe 目录里没有 tomcat 字样是常态，命令行里有 catalina/tomcat 才认
		if name == "java" || name == "javaw" {
			return prod.CmdRe != nil && prod.CmdRe.MatchString(row.CmdLine)
		}
	}
	return prod.CmdRe != nil && prod.CmdRe.MatchString(row.CmdLine)
}

func (b *base) firstProcByName(name string) *state.ProcRow {
	name = strings.ToLower(name)
	for i := range b.procs {
		if procBaseName(b.procs[i].Name) == name {
			return &b.procs[i]
		}
	}
	return nil
}

// firstHTTPBindingPort 返回第一个 http 协议绑定的端口（探测用；https
// 不在本轮探测能力内，避免引入 TLS 信任问题）。没有 http 绑定返回 0，
// 不拿 HTTPS 端口凑数——那会把 http:// 探测指向 TLS 端口，结论必然错。
func firstHTTPBindingPort(sites []iisSiteInfo) uint16 {
	for _, site := range sites {
		for _, bind := range site.BindingDetails {
			if bind.Protocol == "http" {
				return bind.Port
			}
		}
	}
	return 0
}

// genericWebName 判断进程名是否像 Web 运行时。
func genericWebName(name string) bool {
	return isServerName(name) || name == "node" || name == "nodejs" ||
		name == "python" || name == "python3" || name == "go" ||
		name == "php" || name == "php-cgi" || name == "ruby" || name == "java"
}

func isServerName(name string) bool {
	switch name {
	case "httpd", "apache", "apache2", "nginx", "tomcat", "tomcat9", "tomcat10", "caddy", "lighttpd":
		return true
	}
	return false
}

// knownWebPortSet：非专用 Web 进程（node/python/go）只在常见端口上做
// 通用 HTTP 识别，避免把每个临时端口都变成资产。
var knownWebPortSet = map[uint16]struct{}{
	80: {}, 443: {}, 3000: {}, 3001: {}, 5000: {}, 5001: {}, 5173: {},
	7001: {}, 8000: {}, 8008: {}, 8080: {}, 8081: {}, 8088: {}, 8090: {},
	8443: {}, 8888: {}, 9000: {}, 9090: {}, 9080: {},
}

// nonWebPortSet：已被其他类目认领的端口不再重复出通用 HTTP 资产。
var nonWebPortSet = map[uint16]struct{}{
	22: {}, 445: {}, 3389: {}, 5985: {}, 5986: {}, 5900: {}, 5800: {},
	3306: {}, 1433: {}, 5432: {}, 6379: {}, 27017: {}, 9200: {}, 15672: {},
	8123: {}, 11211: {}, 2375: {}, 2376: {}, 9229: {}, 4444: {}, 2179: {}, 2718: {},
}

// expandPath 展开 %VAR% 与 $VAR 两种 Windows 常见写法。
func expandPath(p string) string {
	p = strings.TrimSpace(p)
	if p == "" {
		return ""
	}
	p = rePercentEnv.ReplaceAllStringFunc(p, func(m string) string {
		name := strings.Trim(m, "%")
		if v := os.Getenv(name); v != "" {
			return v
		}
		return m
	})
	return os.ExpandEnv(p)
}

var rePercentEnv = regexp.MustCompile(`%[^%]+%`)
