package recon

// db.go：数据库/中间件识别（契约 §12.3 db 类）。
//
// 被动：监听端口 + 归属进程。主动（probe=true）严格只读：
//   - redis 发 PING，读到 +PONG 即无认证（不尝试 AUTH）；
//   - ES/Docker/ClickHouse/RabbitMQ 只 GET 固定端点；
//   - MySQL/MSSQL/PostgreSQL 只做 TCP 连接 + 读前 64 字节横幅，
//     不发任何登录包、不做口令尝试（协议握手都算越界）；
//   - MongoDB/Memcached 只确认监听，不发送任何协议数据。

import (
	"bytes"
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"zedr/internal/agent/state"
)

type dbProduct struct {
	Kind      string
	Title     string
	Ports     []uint16
	ProcNames []string
	ProbeKind string
}

var dbProducts = []dbProduct{
	{Kind: "mysql", Title: "MySQL / MariaDB", Ports: []uint16{3306}, ProcNames: []string{"mysqld", "mariadbd"}, ProbeKind: "mysql"},
	{Kind: "mssql", Title: "Microsoft SQL Server", Ports: []uint16{1433}, ProcNames: []string{"sqlservr"}, ProbeKind: "mssql"},
	{Kind: "postgresql", Title: "PostgreSQL", Ports: []uint16{5432}, ProcNames: []string{"postgres", "postmaster"}, ProbeKind: "postgres"},
	{Kind: "redis", Title: "Redis", Ports: []uint16{6379}, ProcNames: []string{"redis-server", "redis"}, ProbeKind: "redis"},
	{Kind: "mongodb", Title: "MongoDB", Ports: []uint16{27017}, ProcNames: []string{"mongod"}, ProbeKind: "mongodb"},
	{Kind: "elasticsearch", Title: "Elasticsearch", Ports: []uint16{9200}, ProcNames: []string{"elasticsearch"}, ProbeKind: "elasticsearch"},
	{Kind: "rabbitmq", Title: "RabbitMQ 管理台", Ports: []uint16{15672}, ProcNames: []string{"rabbitmq-server", "rabbitmq"}, ProbeKind: "rabbitmq"},
	{Kind: "clickhouse", Title: "ClickHouse HTTP", Ports: []uint16{8123}, ProcNames: []string{"clickhouse", "clickhouse-server"}, ProbeKind: "clickhouse"},
	{Kind: "memcached", Title: "Memcached", Ports: []uint16{11211}, ProcNames: []string{"memcached"}, ProbeKind: "memcached"},
	{Kind: "docker", Title: "Docker Engine API", Ports: []uint16{2375, 2376}, ProcNames: []string{"dockerd", "com.docker.backend"}, ProbeKind: "docker"},
}

// detectDB 是 db 类入口。
func detectDB(ctx context.Context, b *base) (Category, error) {
	cat := newCategory("db", CategoryTitle("db"))
	type group struct {
		prod  dbProduct
		pid   uint32
		ports []uint16
	}
	groups := make(map[string]*group, len(dbProducts))
	order := make([]string, 0, len(dbProducts))
	for _, prod := range dbProducts {
		for _, port := range prod.Ports {
			if len(b.byPort[port]) == 0 {
				continue
			}
			if len(b.tcpPorts([]uint16{port})) == 0 {
				continue // 数据库协议均基于 TCP；UDP 同名端口不算
			}
			pid := b.portListenerPID(port)
			key := fmt.Sprintf("%s|%d", prod.Kind, pid)
			g, ok := groups[key]
			if !ok {
				g = &group{prod: prod, pid: pid}
				groups[key] = g
				order = append(order, key)
			}
			g.ports = append(g.ports, port)
		}
	}

	// 进程名兜底：数据库改端口是常见运维动作（如 Redis 6380），
	// 只靠默认端口会漏；进程名是强指纹，端口从其监听表取。
	for _, row := range b.procs {
		for _, prod := range dbProducts {
			if !dbProcMatches(prod, row) {
				continue
			}
			key := fmt.Sprintf("%s|%d", prod.Kind, row.PID)
			if _, ok := groups[key]; ok {
				continue
			}
			ports := b.tcpPorts(b.portsForPID(row.PID))
			if len(ports) == 0 {
				ports = b.tcpPorts(b.existingPorts(prod.Ports))
			}
			groups[key] = &group{prod: prod, pid: row.PID, ports: ports}
			order = append(order, key)
		}
	}
	for _, key := range order {
		if ctx.Err() != nil {
			return cat, nil
		}
		g := groups[key]
		sort.Slice(g.ports, func(i, j int) bool { return g.ports[i] < g.ports[j] })
		item := b.dbAsset(ctx, &cat, g.prod, g.pid, g.ports)
		cat.Items = append(cat.Items, item)
	}
	sortItems(cat.Items)
	return cat, nil
}

// dbProcMatches 进程名精确匹配（不含 .exe）。
func dbProcMatches(prod dbProduct, row state.ProcRow) bool {
	name := procBaseName(row.Name)
	for _, n := range prod.ProcNames {
		if name == strings.ToLower(n) {
			return true
		}
	}
	return false
}

// dbAsset 组装一条数据库资产并按协议探测。
func (b *base) dbAsset(ctx context.Context, cat *Category, prod dbProduct, pid uint32, ports []uint16) AssetItem {
	details := map[string]any{
		"product":    prod.Kind,
		"auth_state": AuthUnknown,
		"version":    "",
		"banner":     "",
	}
	item := b.newAsset("db", prod.Kind, prod.Title, pid, ports, details)
	item.Exposure = passiveExposure(item.Listens, true)
	if len(ports) == 0 {
		return item
	}
	port := ports[0]
	ip := b.probeIP(port)
	// HTTP 型中间件给出可访问地址（TLS 的 2376 不构造 http URL）。
	switch prod.ProbeKind {
	case "elasticsearch", "clickhouse", "rabbitmq", "docker":
		if port != 2376 {
			item.Endpoint = endpointHTTP(ip, port)
		}
	}
	if b.probe == nil {
		// 纯被动：只按监听面给等级；非回环的数据库端口本身就是暴露面
		if anyNonLoopback(item.Listens) {
			addFinding(cat, &item, LevelHigh,
				"数据库/中间件端口监听非回环地址",
				fmt.Sprintf("%s 监听 %s:%d，网络可达；本工具未做口令校验，请确认访问控制", prod.Title, b.listenAddr(port), port))
		}
		return item
	}

	switch prod.ProbeKind {
	case "redis":
		b.probeRedis(ctx, cat, &item, ip, port, details)
	case "elasticsearch":
		b.probeES(ctx, cat, &item, ip, port, details)
	case "docker":
		b.probeDocker(ctx, cat, &item, ip, port, details)
	case "clickhouse":
		b.probeClickHouse(ctx, &item, ip, port, details)
	case "rabbitmq":
		b.probeRabbitMQ(ctx, &item, ip, port, details)
	case "mysql":
		b.probeBannerOnly(ctx, cat, &item, ip, port, details, "mysql", 2*time.Second)
	case "mssql":
		b.probeBannerOnly(ctx, cat, &item, ip, port, details, "mssql", 300*time.Millisecond)
	case "postgres":
		b.probeBannerOnly(ctx, cat, &item, ip, port, details, "postgres", 300*time.Millisecond)
	case "mongodb", "memcached":
		// 仅监听：不发送任何协议数据（这两个协议的口令尝试/命令
		// 都容易越界，v1 明确不做）。
		if anyNonLoopback(item.Listens) {
			addFinding(cat, &item, LevelMedium,
				"数据库/缓存端口监听非回环地址",
				fmt.Sprintf("%s 监听 %s:%d；仅确认监听，未做协议探测", prod.Title, b.listenAddr(port), port))
		}
	}
	return item
}

// listenAddr 取端口第一条监听行的地址（证据展示用）。
func (b *base) listenAddr(port uint16) string {
	for _, r := range b.byPort[port] {
		if r.LocalIP != "" {
			return r.LocalIP
		}
	}
	return "0.0.0.0"
}

func (b *base) probeRedis(ctx context.Context, cat *Category, item *AssetItem, ip string, port uint16, details map[string]any) {
	// Redis 不会主动说话，必须发 PING 才响应；tcpExchange 一次完成
	// "连接 + 写 PING + 读 64 字节"，不浪费预算做第二次连接。
	resp, err := b.probe.tcpExchange(ctx, ip, port, []byte("PING\r\n"), 64, probeTimeout)
	if err != nil {
		item.Exposure = Exposure{Level: LevelUnknown, Evidence: []string{"PING 探测失败: " + err.Error()}}
		return
	}
	text := strings.TrimSpace(string(resp))
	switch {
	case strings.Contains(text, "+PONG"):
		details["auth_state"] = AuthOpen
		item.Exposure = Exposure{
			Level:    LevelHigh,
			Evidence: []string{fmt.Sprintf("TCP %s:%d 发送 PING → %s", ip, port, text)},
		}
		addFinding(cat, item, LevelHigh, "Redis 未要求认证",
			"PING 直接返回 +PONG，任何本机/网络可达者可读写全部键；建议绑定回环并启用 requirepass")
	case strings.Contains(text, "NOAUTH") || strings.Contains(text, "WRONGPASS"):
		details["auth_state"] = AuthRequired
		item.Exposure = authExposure(AuthRequired, LevelHigh, item.Listens)
	default:
		item.Exposure = Exposure{Level: LevelUnknown, Evidence: []string{"PING 返回非预期响应: " + trimEvidence(text)}}
	}
}

func (b *base) probeES(ctx context.Context, cat *Category, item *AssetItem, ip string, port uint16, details map[string]any) {
	resp := b.probe.get(ctx, endpointHTTP(ip, port)+"/")
	if resp.Err != nil {
		item.Exposure = Exposure{Level: LevelUnknown, Evidence: []string{"探测失败: " + resp.Err.Error()}}
		return
	}
	switch resp.Status {
	case 200:
		if v := jsonNestedString(resp.Body, "version", "number"); v != "" {
			details["version"] = v
		}
		if jsonHasKey(resp.Body, "version") || jsonHasKey(resp.Body, "cluster_name") {
			details["auth_state"] = AuthOpen
			item.Exposure = Exposure{
				Level:    LevelHigh,
				Evidence: []string{fmt.Sprintf("GET / → 200，匿名返回集群信息（version=%v）", details["version"])},
			}
			addFinding(cat, item, LevelHigh, "Elasticsearch 匿名可访问",
				"GET / 未认证返回集群/版本信息；若开启脚本或动态索引可进一步扩大影响，建议启用 Security 并绑定回环")
			return
		}
		item.Exposure = Exposure{Level: LevelUnknown, Evidence: []string{"GET / → 200 但响应不是可识别 JSON"}}
	case 401, 403:
		details["auth_state"] = AuthRequired
		item.Exposure = authExposure(AuthRequired, LevelHigh, item.Listens)
	default:
		item.Exposure = Exposure{Level: LevelUnknown, Evidence: []string{fmt.Sprintf("GET / → %d", resp.Status)}}
	}
}

func (b *base) probeDocker(ctx context.Context, cat *Category, item *AssetItem, ip string, port uint16, details map[string]any) {
	if port == 2376 {
		// 2376 是 TLS 端口；本探测客户端只允许 http，不做 TLS 握手，
		// 如实标记 unknown，不假装"已检查"。
		item.Exposure = Exposure{Level: LevelUnknown, Evidence: []string{"2376 为 TLS API，本轮只做监听识别"}}
		return
	}
	resp := b.probe.get(ctx, endpointHTTP(ip, port)+"/version")
	if resp.Err != nil {
		item.Exposure = Exposure{Level: LevelUnknown, Evidence: []string{"探测失败: " + resp.Err.Error()}}
		return
	}
	switch resp.Status {
	case 200:
		// 只认 Docker 的 JSON 版本结构：2375 上可能有别的服务返回 200，
		// 不做形状校验会把普通 HTTP 服务误报成 critical 的 root 控制面。
		if !jsonHasKey(resp.Body, "ApiVersion") && !jsonHasKey(resp.Body, "Version") {
			item.Exposure = Exposure{Level: LevelUnknown, Evidence: []string{"GET /version → 200 但响应不是 Docker API JSON"}}
			return
		}
		if v := jsonString(resp.Body, "Version"); v != "" {
			details["version"] = v
		}
		details["auth_state"] = AuthOpen
		item.Exposure = Exposure{
			Level:    LevelCritical,
			Evidence: []string{fmt.Sprintf("GET /version → 200，Anonymous Docker API（version=%v）", details["version"])},
		}
		addFinding(cat, item, LevelCritical, "Docker API 未认证（root 等价控制面）",
			"GET /version 匿名 200；可创建特权容器挂载宿主文件系统，等同主机 root 控制权。建议关闭 2375 或仅 unix socket")
	case 401, 403:
		details["auth_state"] = AuthRequired
		item.Exposure = authExposure(AuthRequired, LevelCritical, item.Listens)
	default:
		item.Exposure = Exposure{Level: LevelUnknown, Evidence: []string{fmt.Sprintf("GET /version → %d", resp.Status)}}
	}
}

func (b *base) probeClickHouse(ctx context.Context, item *AssetItem, ip string, port uint16, details map[string]any) {
	resp := b.probe.get(ctx, endpointHTTP(ip, port)+"/ping")
	if resp.Err != nil {
		item.Exposure = Exposure{Level: LevelUnknown, Evidence: []string{"探测失败: " + resp.Err.Error()}}
		return
	}
	switch resp.Status {
	case 200:
		// /ping 是公开健康端点，200 不能证明查询接口无认证；如实 unknown。
		item.Exposure = Exposure{Level: LevelUnknown, Evidence: []string{"GET /ping → 200（健康端点，未验证查询权限）"}}
	case 401, 403:
		details["auth_state"] = AuthRequired
		item.Exposure = authExposure(AuthRequired, LevelHigh, item.Listens)
	default:
		item.Exposure = Exposure{Level: LevelUnknown, Evidence: []string{fmt.Sprintf("GET /ping → %d", resp.Status)}}
	}
}

func (b *base) probeRabbitMQ(ctx context.Context, item *AssetItem, ip string, port uint16, details map[string]any) {
	resp := b.probe.get(ctx, endpointHTTP(ip, port)+"/")
	if resp.Err != nil {
		item.Exposure = Exposure{Level: LevelUnknown, Evidence: []string{"探测失败: " + resp.Err.Error()}}
		return
	}
	switch resp.Status {
	case 200:
		// 管理台根页无论是否登录都会渲染登录表单；200 + 登录页 = 有认证。
		if looksLikeLoginPage(resp.Body, htmlTitle(resp.Body)) {
			details["auth_state"] = AuthRequired
			item.Exposure = authExposure(AuthRequired, LevelHigh, item.Listens)
			return
		}
		item.Exposure = Exposure{Level: LevelUnknown, Evidence: []string{"GET / → 200，未识别到登录页"}}
	case 401, 403:
		details["auth_state"] = AuthRequired
		item.Exposure = authExposure(AuthRequired, LevelHigh, item.Listens)
	default:
		item.Exposure = Exposure{Level: LevelUnknown, Evidence: []string{fmt.Sprintf("GET / → %d", resp.Status)}}
	}
}

// probeBannerOnly 只读 TCP 横幅，不做任何握手/口令尝试。
// PostgreSQL/MSSQL 不主动发横幅 → connected=true + 空 banner 是正常结果。
func (b *base) probeBannerOnly(ctx context.Context, cat *Category, item *AssetItem, ip string, port uint16, details map[string]any, kind string, readWait time.Duration) {
	banner, connected, readErr := b.probe.tcpBanner(ctx, ip, port, 64, readWait)
	if !connected {
		item.Exposure = Exposure{Level: LevelUnknown, Evidence: []string{"TCP 连接失败: " + errText(readErr)}}
		return
	}
	version := ""
	if len(banner) > 0 {
		details["banner"] = trimEvidence(string(banner))
		if kind == "mysql" {
			version = parseMySQLBanner(banner)
		}
		if version != "" {
			details["version"] = version
		}
	}
	if version == "" && readErr != nil {
		// 连接成功但对方不说话：协议正常（PG/MSSQL），记录读超时
		details["banner_note"] = "连接成功，服务端未主动发送横幅（" + errText(readErr) + "）"
	}
	item.Exposure = passiveExposure(item.Listens, true)
	if anyNonLoopback(item.Listens) {
		addFinding(cat, item, LevelHigh, "数据库端口监听非回环地址",
			fmt.Sprintf("%s 的 TCP %d 端口网络可达（version=%s）；本工具只读横幅，未做口令校验", item.Title, port, version))
	}
}

// parseMySQLBanner 解析 MySQL 握手包里的版本串：
// 第 1 字节 protocol version（10），随后 NUL 结尾的 server version。
func parseMySQLBanner(b []byte) string {
	if len(b) < 2 || b[0] != 10 {
		return ""
	}
	end := bytes.IndexByte(b[1:], 0)
	if end <= 0 {
		// 64 字节内没读到 NUL：截到可打印边界，避免把二进制塞进详情
		end = len(b) - 1
	}
	v := string(b[1 : 1+end])
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r > 0x7e {
			return -1
		}
		return r
	}, v)
}

// trimEvidence 截断并去除控制字符，避免把二进制横幅原样塞进 JSON。
func trimEvidence(s string) string {
	s = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == '\t' {
			return ' '
		}
		if r < 0x20 || r > 0x7e {
			return -1
		}
		return r
	}, s)
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}

// errText 安全取错误文本（nil → 空串），避免 nil 指针。
func errText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
