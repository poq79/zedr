package recon

// base.go：六类 detector 共用的基础关联数据。
//
// 成本纪律：Procs/Netstat 各只调用一次，之后全部在内存 join；任何
// detector 都不允许再拉全表（40 次探测预算之外，系统调用也要省）。
// base 在 Run 内只读（banner 缓存除外），detector 并发访问安全。

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/windows/registry"

	"zedr/internal/agent/state"
	"zedr/internal/agent/winapi"
	"zedr/internal/platform/redact"
)

// base 是一次侦查的只读关联视图 + 少量缓存。
// 绝不内嵌 atomic/锁按值传递：本结构只以 *base 传递（copylocks 纪律）。
type base struct {
	procs     []state.ProcRow
	byPID     map[uint32]state.ProcRow
	listeners []winapi.NetRow // 只保留 TCP LISTEN 与有端口的 UDP 行
	byPort    map[uint16][]winapi.NetRow
	byPIDPort map[uint32][]winapi.NetRow

	// probe 为 nil 表示纯被动模式；所有 detector 必须先判 nil。
	probe *probeClient

	// banner 缓存 + startedAt 缓存：多个 detector 可能查同一端口/进程，
	// 重复探测既浪费 40 次预算，也让结果出现时序差异。
	mu       sync.Mutex
	banners  map[string]bannerInfo
	started  map[uint32]string
	rdpCache *rdpSettings
}

// bannerInfo 是通用 HTTP 服务的根页指纹。
type bannerInfo struct {
	Status    int
	Server    string
	PoweredBy string
	Title     string
	Err       string
}

// newBase 建关联数据。Deps 函数可能来自 app 层的闭包，panic 不能
// 带崩整次侦查：safeRows 把 panic 收成空表并记 warning。
func newBase(d Deps) *base {
	b := &base{
		byPID:     make(map[uint32]state.ProcRow, 256),
		byPort:    make(map[uint16][]winapi.NetRow, 128),
		byPIDPort: make(map[uint32][]winapi.NetRow, 128),
		banners:   make(map[string]bannerInfo, 16),
		started:   make(map[uint32]string, 32),
	}
	if d.Probe {
		b.probe = newProbeClient(maxProbeRequests, probeTimeout)
	}

	procs := safeProcs(d)
	b.procs = procs
	for _, p := range procs {
		b.byPID[p.PID] = p
	}

	rows := safeNetstat(d)
	b.listeners = make([]winapi.NetRow, 0, len(rows))
	for _, r := range rows {
		if !isListenerRow(r) {
			continue
		}
		b.listeners = append(b.listeners, r)
		b.byPort[r.LocalPort] = append(b.byPort[r.LocalPort], r)
		b.byPIDPort[r.PID] = append(b.byPIDPort[r.PID], r)
	}
	return b
}

// safeProcs 调 Deps.Procs，recover 任意 panic。
func safeProcs(d Deps) (out []state.ProcRow) {
	if d.Procs == nil {
		return nil
	}
	defer func() {
		if rec := recover(); rec != nil {
			slog.Warn("recon_procs_panic", "panic", fmt.Sprint(rec))
			out = nil
		}
	}()
	return d.Procs()
}

// safeNetstat 调 Deps.Netstat，recover 任意 panic。
func safeNetstat(d Deps) (out []winapi.NetRow) {
	if d.Netstat == nil {
		return nil
	}
	defer func() {
		if rec := recover(); rec != nil {
			slog.Warn("recon_netstat_panic", "panic", fmt.Sprint(rec))
			out = nil
		}
	}()
	return d.Netstat()
}

// isListenerRow：TCP 只认 LISTEN；UDP 无连接状态，LocalPort>0 即绑定端点。
// 远端已建立连接不代表本机有服务在听，会把"客户端端口"误当资产。
func isListenerRow(r winapi.NetRow) bool {
	if r.LocalPort == 0 {
		return false
	}
	proto := strings.ToLower(r.Proto)
	if strings.HasPrefix(proto, "tcp") {
		return strings.EqualFold(r.State, "LISTEN")
	}
	return strings.HasPrefix(proto, "udp")
}

// listenerPorts 返回全部监听端口（升序去重）。
func (b *base) listenerPorts() []uint16 {
	seen := make(map[uint16]struct{}, len(b.byPort))
	out := make([]uint16, 0, len(b.byPort))
	for port := range b.byPort {
		if _, ok := seen[port]; ok {
			continue
		}
		seen[port] = struct{}{}
		out = append(out, port)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// portsForPID 返回某进程的监听端口（升序去重）。
func (b *base) portsForPID(pid uint32) []uint16 {
	rows := b.byPIDPort[pid]
	seen := make(map[uint16]struct{}, len(rows))
	out := make([]uint16, 0, len(rows))
	for _, r := range rows {
		if _, ok := seen[r.LocalPort]; ok {
			continue
		}
		seen[r.LocalPort] = struct{}{}
		out = append(out, r.LocalPort)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// existingPorts 返回 candidates 中当前确实有监听行的端口（保持入参顺序）。
func (b *base) existingPorts(candidates []uint16) []uint16 {
	out := make([]uint16, 0, len(candidates))
	for _, p := range candidates {
		if len(b.byPort[p]) > 0 {
			out = append(out, p)
		}
	}
	return out
}

// tcpPorts 只保留有 TCP 监听行的端口（HTTP/DB 探测只对 TCP 有意义）。
func (b *base) tcpPorts(ports []uint16) []uint16 {
	out := make([]uint16, 0, len(ports))
	for _, p := range ports {
		for _, r := range b.byPort[p] {
			if strings.HasPrefix(strings.ToLower(r.Proto), "tcp") {
				out = append(out, p)
				break
			}
		}
	}
	return out
}

// firstListeningPort 返回 ports 中第一个确实有 TCP 监听行的端口；没有返回 0。
// 配置里声明的端口（如 Tomcat Connector）不等于正在监听，endpoint 只能
// 基于真实监听行，否则会给出一个连不上的 URL；HTTP 只走 TCP，UDP 行不算。
func (b *base) firstListeningPort(ports []uint16) uint16 {
	for _, p := range ports {
		for _, r := range b.byPort[p] {
			if strings.HasPrefix(strings.ToLower(r.Proto), "tcp") {
				return p
			}
		}
	}
	return 0
}

// portListenerPID 取某端口第一个 TCP 监听行的 PID；没有则 0。
func (b *base) portListenerPID(port uint16) uint32 {
	for _, r := range b.byPort[port] {
		if strings.HasPrefix(strings.ToLower(r.Proto), "tcp") && r.PID != 0 {
			return r.PID
		}
	}
	return 0
}

// portRows 返回某端口的全部监听行（调用方只读，勿修改切片元素）。
func (b *base) portRows(port uint16) []winapi.NetRow {
	return b.byPort[port]
}

// listens 把端口列表转成线协议 listens[]。
//
// 同一端口可能同时有 IPv4(0.0.0.0) 与 IPv6(::) 两条监听行——都保留，
// 前端能据此看出"全接口暴露"；完全相同的 (proto,addr,port) 去重。
func (b *base) listens(ports []uint16) []Listen {
	out := make([]Listen, 0, len(ports))
	seen := make(map[string]struct{}, len(ports))
	for _, port := range ports {
		rows := b.byPort[port]
		if len(rows) == 0 {
			continue
		}
		for _, r := range rows {
			addr := r.LocalIP
			if addr == "" {
				addr = "0.0.0.0"
			}
			key := fmt.Sprintf("%s|%s|%d", r.Proto, addr, port)
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			out = append(out, Listen{Proto: strings.ToLower(r.Proto), Addr: addr, Port: port})
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Port != out[j].Port {
			return out[i].Port < out[j].Port
		}
		return out[i].Addr < out[j].Addr
	})
	return out
}

// process 返回进程展示视图；PID 0/不在快照 → nil（不伪造空进程）。
func (b *base) process(pid uint32) *Process {
	if pid == 0 {
		return nil
	}
	row, ok := b.byPID[pid]
	if !ok {
		return nil
	}
	p := &Process{
		PID:     pid,
		Name:    row.Name,
		Path:    row.Path,
		User:    row.User,
		Cmdline: redact.CmdLine(row.CmdLine),
	}
	if ts := b.startedAt(pid, row); ts != "" {
		p.StartedAt = ts
	}
	return p
}

// startedAt 取真实进程启动时刻；OpenProcess 失败时退回 FirstSeen
// （探针首次观测时间），两者都拿不到才留空。结果缓存：同一 PID 在
// 多个类目里出现时只查一次。
func (b *base) startedAt(pid uint32, row state.ProcRow) string {
	b.mu.Lock()
	if v, ok := b.started[pid]; ok {
		b.mu.Unlock()
		return v
	}
	b.mu.Unlock()

	out := ""
	if ts, err := winapi.ProcessStartTime(pid); err == nil && ts > 0 {
		out = time.Unix(ts, 0).UTC().Format(time.RFC3339)
	} else if !row.FirstSeen.IsZero() {
		out = row.FirstSeen.UTC().Format(time.RFC3339)
	}

	b.mu.Lock()
	b.started[pid] = out
	b.mu.Unlock()
	return out
}

// newAsset 组装 AssetItem：统一 ID、进程归属、监听列表、空数组口径。
// details 传 nil 时输出 {}；findings 由调用方用 addFinding 追加。
func (b *base) newAsset(category, kind, title string, pid uint32, ports []uint16, details map[string]any) AssetItem {
	if details == nil {
		details = map[string]any{}
	}
	return AssetItem{
		ID:       assetID(kind, pid, ports),
		Category: category,
		Kind:     kind,
		Title:    title,
		Process:  b.process(pid),
		Listens:  b.listens(ports),
		Exposure: Exposure{Level: LevelInfo, Evidence: []string{}},
		Details:  details,
		Findings: []string{},
	}
}

// assetID 稳定可复现：kind[-pid][-port]。同类同 PID 同端口不会出现两条；
// 无进程无端口的单例（如虚拟化平台）直接用 kind。
func assetID(kind string, pid uint32, ports []uint16) string {
	if len(ports) > 0 {
		return fmt.Sprintf("%s-%d-%d", kind, pid, ports[0])
	}
	if pid != 0 {
		return fmt.Sprintf("%s-%d", kind, pid)
	}
	return kind
}

// addFinding 同时写入资产级一句话列表与类目级结构化条目，避免两处
// 口径漂移（前端按类目 findings 统计，资产行按 findings 展示）。
func addFinding(cat *Category, item *AssetItem, level, title, detail string) {
	text := title
	if detail != "" {
		text += "：" + detail
	}
	if item != nil {
		item.Findings = append(item.Findings, text)
	}
	f := Finding{Level: level, Title: title, Detail: detail}
	if item != nil {
		f.AssetID = item.ID
	}
	cat.Findings = append(cat.Findings, f)
}

// passiveExposure 在无探测结论时按监听面给保守等级：
//   - 任一非回环地址 → medium（局域网可达，风险不由本工具臆断认证强度）；
//   - 仅回环 → low；
//   - 仅进程指纹无监听 → info。
func passiveExposure(listens []Listen, hasProcess bool) Exposure {
	ev := make([]string, 0, len(listens))
	for _, l := range listens {
		if !addrIsLoopback(l.Addr) {
			return Exposure{
				Level:    LevelMedium,
				Evidence: append(ev, fmt.Sprintf("监听 %s:%d（非回环，网络可达）", l.Addr, l.Port)),
			}
		}
		ev = append(ev, fmt.Sprintf("仅回环监听 %s:%d", l.Addr, l.Port))
	}
	if len(listens) > 0 {
		return Exposure{Level: LevelLow, Evidence: ev}
	}
	if hasProcess {
		return Exposure{Level: LevelInfo, Evidence: []string{"仅命中进程指纹，未发现监听端口"}}
	}
	return Exposure{Level: LevelInfo, Evidence: []string{}}
}

// authExposure 把认证状态映射成暴露等级（探测成功时使用）。
// open 的具体等级由类目决定（docker API = critical，AI = high）。
func authExposure(auth string, openLevel string, listens []Listen) Exposure {
	switch auth {
	case AuthOpen:
		return Exposure{Level: openLevel, Evidence: []string{"匿名访问成功，未要求认证"}}
	case AuthRequired:
		if anyNonLoopback(listens) {
			return Exposure{Level: LevelMedium, Evidence: []string{"要求认证，但监听非回环地址"}}
		}
		return Exposure{Level: LevelLow, Evidence: []string{"要求认证且仅回环可达"}}
	case AuthUnknown:
		return Exposure{Level: LevelUnknown, Evidence: []string{"探测未能判定认证状态"}}
	default:
		return Exposure{Level: LevelUnknown, Evidence: []string{}}
	}
}

// anyNonLoopback 判断监听列表里是否有非回环地址。
func anyNonLoopback(listens []Listen) bool {
	for _, l := range listens {
		if !addrIsLoopback(l.Addr) {
			return true
		}
	}
	return false
}

// addrIsLoopback 识别 127.0.0.0/8 与 ::1。
// 0.0.0.0/:: 不是 loopback（它们代表全接口，是暴露面证据本身）。
func addrIsLoopback(addr string) bool {
	ip := net.ParseIP(strings.Trim(addr, "[]"))
	return ip != nil && ip.IsLoopback()
}

// probeIP 选择探测目标地址：有 IPv4 监听行用 127.0.0.1，仅 IPv6 用 ::1。
// 只探回环（契约 §12.4），非回环监听也通过 127.0.0.1 访问本机服务。
func (b *base) probeIP(port uint16) string {
	hasV6 := false
	for _, r := range b.byPort[port] {
		ip := net.ParseIP(strings.Trim(r.LocalIP, "[]"))
		if ip == nil {
			continue
		}
		if ip.To4() != nil {
			return "127.0.0.1"
		}
		hasV6 = true
	}
	if hasV6 {
		return "::1"
	}
	return "127.0.0.1"
}

// endpointHTTP 构造可探测的回环 URL。
func endpointHTTP(ip string, port uint16) string {
	return "http://" + net.JoinHostPort(ip, fmt.Sprintf("%d", port))
}

// httpBanner 探测根页拿 Server/X-Powered-By/title（通用 HTTP 资产指纹）。
// 同一端口缓存一次：web 与 generic 可能同时命中同一监听端口。
func (b *base) httpBanner(ctx context.Context, ip string, port uint16) bannerInfo {
	key := fmt.Sprintf("%s|%d", ip, port)
	b.mu.Lock()
	if v, ok := b.banners[key]; ok {
		b.mu.Unlock()
		return v
	}
	b.mu.Unlock()

	bi := bannerInfo{}
	if b.probe == nil {
		bi.Err = "被动模式未探测"
	} else {
		resp := b.probe.get(ctx, endpointHTTP(ip, port)+"/")
		if resp.Err != nil {
			bi.Err = resp.Err.Error()
		} else {
			bi.Status = resp.Status
			bi.Server = resp.Header.Get("Server")
			bi.PoweredBy = resp.Header.Get("X-Powered-By")
			bi.Title = htmlTitle(resp.Body)
		}
	}

	b.mu.Lock()
	b.banners[key] = bi
	b.mu.Unlock()
	return bi
}

// rdpSettings 缓存 RDP 注册表读取结果（remote detector 内使用）。
type rdpSettings struct {
	NLAEnabled    bool
	SecurityLayer uint32
	FoundNLA      bool
	FoundLayer    bool
	Err           string
}

// readRDP 读 RDP-Tcp 的 NLA/SecurityLayer。
// 值缺失按 Windows 默认（NLA=1，SecurityLayer=1 Negotiate）；读取失败
// 也按默认并记录 Err——不能让一次权限不足把整个 remote 类打挂。
func (b *base) readRDP() rdpSettings {
	b.mu.Lock()
	if b.rdpCache != nil {
		v := *b.rdpCache
		b.mu.Unlock()
		return v
	}
	b.mu.Unlock()

	const rdpKey = `SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp`
	out := rdpSettings{NLAEnabled: true, SecurityLayer: 1}
	if v, found, err := winapi.RegReadDWORD(registry.LOCAL_MACHINE, rdpKey, "UserAuthentication"); err != nil {
		out.Err = "UserAuthentication: " + err.Error()
	} else if found {
		out.FoundNLA = true
		out.NLAEnabled = v != 0
	}
	if v, found, err := winapi.RegReadDWORD(registry.LOCAL_MACHINE, rdpKey, "SecurityLayer"); err != nil {
		if out.Err != "" {
			out.Err += "; "
		}
		out.Err += "SecurityLayer: " + err.Error()
	} else if found {
		out.FoundLayer = true
		out.SecurityLayer = v
	}

	b.mu.Lock()
	cp := out
	b.rdpCache = &cp
	b.mu.Unlock()
	return out
}
