// Command zedr-agent 是 Z-EDR 终端探针。
//
// 用法：
//
//	zedr-agent                 前台运行（适合调试，Ctrl+C 退出）
//	zedr-agent -service        作为 Windows 服务运行（由 SCM 启动时使用）
//	zedr-agent -install        安装为开机自启的 Windows 服务（需管理员）
//	zedr-agent -uninstall      卸载服务（需管理员）
//	zedr-agent -version        打印版本
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"

	agentapp "zedr/internal/agent/app"
	"zedr/internal/platform/config"
)

const serviceName = "ZEDRAgent"

// 退出码约定（运维平台/脚本按码分流，不解析 stderr 文案）：
// 0 成功；1 通用失败；2 权限不足（未以管理员运行）；3 服务状态冲突。
const (
	exitOK         = 0
	exitGeneral    = 1
	exitPermission = 2
	exitConflict   = 3
	exitConfig     = 4
)

// exitCodeOf 把服务操作错误归类为稳定退出码。
func exitCodeOf(err error) int {
	switch {
	case errors.Is(err, windows.ERROR_ACCESS_DENIED):
		return exitPermission
	case errors.Is(err, windows.ERROR_SERVICE_EXISTS) ||
		errors.Is(err, windows.ERROR_SERVICE_MARKED_FOR_DELETE):
		return exitConflict
	default:
		return exitGeneral
	}
}

// version 由构建脚本通过 -ldflags -X main.version 注入。
var version = "dev"

func main() {
	var (
		flagService   = flag.Bool("service", false, "以 Windows 服务方式运行")
		flagInstall   = flag.Bool("install", false, "安装为 Windows 服务")
		flagUninstall = flag.Bool("uninstall", false, "卸载 Windows 服务")
		flagPurge     = flag.Bool("purge", false, "配合 -uninstall：同时删除数据目录（基线/队列/本地令牌）")
		flagVersion   = flag.Bool("version", false, "打印版本")
		flagStatus    = flag.Bool("status", false, "查看本机探针运行状态（服务器/SSH 场景无需打开界面）")
		flagJSON      = flag.Bool("json", false, "配合 -status：输出机器可读 JSON（脚本/运维平台判断接入状态）")
		// 接入参数（配合 -install）：写入 exe 同目录 .env 后再装服务。
		// 服务模式 cwd 是 System32，环境变量无法随身携带，配置落盘是
		// 静默部署的关键——运维平台一条命令装完即接入。
		flagURL   = flag.String("url", "", "配合 -install：总控服务端地址（写入 .env 的 HG_AGENT_SERVER_URL）")
		flagToken = flag.String("token", "", "配合 -install：注册预共享令牌（写入 .env 的 HG_AGENT_ENROLL_TOKEN）")
		flagTags  = flag.String("tags", "", "配合 -install：逗号分隔主机标签（写入 .env 的 HG_AGENT_TAGS）")
	)
	flag.Parse()

	if *flagVersion {
		fmt.Printf("zedr-agent %s\n", version)
		return
	}

	if !*flagInstall && (*flagURL != "" || *flagToken != "" || *flagTags != "") {
		fmt.Fprintln(os.Stderr, "提示: -url/-token/-tags 仅在 -install 时生效，本次已忽略")
	}

	// -status：服务器与 SSH 场景的"看一眼"。桌面 UI 在 Server Core/无
	// WebView2 的机器上没有意义，而运维排查恰恰最常发生在那里。
	if *flagStatus {
		if err := printStatus(*flagJSON); err != nil {
			fmt.Fprintf(os.Stderr, "获取状态失败: %v\n（提示：探针必须在本机运行，本地接口 127.0.0.1:8843）\n", err)
			os.Exit(1)
		}
		return
	}

	// .env 仅用于开发调试；安装成服务后应改为系统环境变量
	if _, err := config.LoadDotEnv(); err != nil {
		fmt.Fprintf(os.Stderr, "读取 .env 失败: %v\n", err)
	}

	// 软内存上限必须在 app.New 之前生效：启动阶段（规则/IOC 加载、
	// 基线读取、离线队列恢复）同样在保护范围内。
	applyMemoryLimit()

	switch {
	case *flagInstall:
		// 接入参数先落盘再装服务：-install 的所有提示与检查都基于
		// 落盘后的有效配置，保证"装完是什么样，提示就是什么"。
		if err := persistInstallConfig(*flagURL, *flagToken, *flagTags); err != nil {
			fmt.Fprintf(os.Stderr, "写入接入配置失败: %v\n", err)
			os.Exit(exitConfig)
		}
		// 同步注入当前进程：LoadDotEnv 在 switch 之前已执行，落盘的新值
		// 不注入的话，下面的安装期提示会读到旧值。flag 语义上就是刚下
		// 达的配置，优先于既有环境（与服务端"系统环境变量优先于 .env"
		// 的差异已由 persistInstallConfig 内的冲突提示说明）。
		if *flagURL != "" {
			_ = os.Setenv("HG_AGENT_SERVER_URL", *flagURL)
		}
		if *flagToken != "" {
			_ = os.Setenv("HG_AGENT_ENROLL_TOKEN", *flagToken)
		}
		if err := installService(); err != nil {
			fmt.Fprintf(os.Stderr, "安装服务失败: %v\n", err)
			os.Exit(exitCodeOf(err))
		}
		printInstallSummary(effectiveEnroll())
		return
	case *flagUninstall:
		if err := uninstallService(); err != nil {
			fmt.Fprintf(os.Stderr, "卸载服务失败: %v\n", err)
			os.Exit(exitCodeOf(err))
		}
		fmt.Printf("服务 %s 已卸载\n", serviceName)
		if *flagPurge {
			dir := agentDataDir()
			if dir != "" {
				if err := os.RemoveAll(dir); err != nil {
					fmt.Fprintf(os.Stderr, "清理数据目录失败（%s）: %v\n", dir, err)
				} else {
					fmt.Printf("数据目录已清理: %s\n", dir)
				}
			}
		} else {
			fmt.Println("提示：数据目录（基线/离线队列）仍保留在 %LOCALAPPDATA%\\Z-EDR；确认无需取证时可用 -uninstall -purge 一并清除。")
		}
		return
	case *flagService:
		if err := svc.Run(serviceName, &serviceHandler{}); err != nil {
			fmt.Fprintf(os.Stderr, "服务运行失败: %v\n", err)
			os.Exit(1)
		}
		return
	}

	// 前台模式
	a, err := agentapp.New(version)
	if err != nil {
		fmt.Fprintf(os.Stderr, "启动失败: %v\n", err)
		os.Exit(1)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := a.Run(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "运行异常退出: %v\n", err)
		os.Exit(1)
	}
}

// applyMemoryLimit 按 HG_AGENT_MEM_LIMIT_MB 设置 Go 软内存上限（默认 256MB）。
//
// 为什么需要：Go 运行时的堆目标默认随分配增长，探针在资产盘点/哈希/
// 上报峰值叠加时会把进程提交量推高，系统级 OOM 会直接杀进程——fatal
// "out of memory" 不可捕获，也没有机会 flush 上报队列。软上限让 GC 在
// 接近该值时更激进回收，把长期驻留量收敛在量级内（单次大分配仍可能
// 突破，这是软限制的固有边界，不做夸大）。
//
// 0 表示不设置（保留 Go 默认）；非法值告警后回退默认值，绝不阻断启动。
func applyMemoryLimit() {
	const defaultMB = 256

	mb := defaultMB
	if raw := strings.TrimSpace(os.Getenv("HG_AGENT_MEM_LIMIT_MB")); raw != "" {
		n, err := strconv.Atoi(raw)
		switch {
		case err != nil:
			fmt.Fprintf(os.Stderr, "警告: HG_AGENT_MEM_LIMIT_MB=%q 不是整数，使用默认 %dMB\n", raw, defaultMB)
		case n < 0:
			fmt.Fprintf(os.Stderr, "警告: HG_AGENT_MEM_LIMIT_MB=%d 为负数，使用默认 %dMB\n", n, defaultMB)
		default:
			mb = n
		}
	}

	if mb == 0 {
		fmt.Fprintln(os.Stderr, "mem_limit_mb=0（未启用软内存上限，使用 Go 运行时默认）")
		return
	}
	debug.SetMemoryLimit(int64(mb) << 20)
	fmt.Fprintf(os.Stderr, "mem_limit_mb=%d\n", mb)
}

type serviceHandler struct{}

// Execute 实现 svc.Handler。
func (h *serviceHandler) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	const accepted = svc.AcceptStop | svc.AcceptShutdown
	changes <- svc.Status{State: svc.StartPending}

	a, err := agentapp.New(version)
	if err != nil {
		changes <- svc.Status{State: svc.Stopped}
		return false, 1
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := a.Run(ctx); err != nil {
			fmt.Fprintf(os.Stderr, "agent run failed: %v\n", err)
		}
	}()

	changes <- svc.Status{State: svc.Running, Accepts: accepted}

	for c := range r {
		switch c.Cmd {
		case svc.Interrogate:
			changes <- c.CurrentStatus
		case svc.Stop, svc.Shutdown:
			changes <- svc.Status{State: svc.StopPending}
			cancel()
			<-done
			return false, 0
		}
	}
	cancel()
	<-done
	return false, 0
}

func installService() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()

	// 幂等重装：服务已存在时先卸载再装。Delete 是"标记删除"，
	// 旧服务句柄（含 SCM 内部）未释放前 CreateService 会报
	// ERROR_SERVICE_MARKED_FOR_DELETE，所以删除后短促重试。
	if s, err := m.OpenService(serviceName); err == nil {
		fmt.Printf("检测到已有服务 %s，先卸载旧服务再重装\n", serviceName)
		_, _ = s.Control(svc.Stop)
		_ = s.Delete()
		s.Close()
		if err := waitServiceGone(m); err != nil {
			return fmt.Errorf("旧服务卸载未完成: %w", err)
		}
	}

	s, err := createServiceWithRetry(m, exe)
	if err != nil {
		return err
	}
	defer s.Close()

	// 延迟自启动：不与开机关键路径抢资源（办公机开机速度是用户对
	// 安全软件最直观的体感之一）。失败不阻断安装。
	_ = setDelayedAutostart(s.Handle)

	// 恢复策略：异常终止后自动重启。
	// 没有这一步，一次 taskkill /f 就能让防护永久失效，而系统看起来一切正常。
	if err := setServiceRecovery(s.Handle); err != nil {
		fmt.Fprintf(os.Stderr,
			"警告: %v\n  服务已安装，但异常终止后不会自动重启；\n"+
				"  可手动设置: sc failure %s reset= 86400 actions= restart/5000/restart/10000/restart/30000\n",
			err, serviceName)
	}

	// 配置来源提示：服务的工作目录是 System32，因此配置必须放在
	// 可执行文件同目录（或系统环境变量）里，否则会静默使用默认值。
	if _, err := config.LoadDotEnv(); err != nil {
		fmt.Fprintf(os.Stderr, "警告: 读取 .env 失败: %v\n", err)
	}

	return s.Start()
}

// createServiceWithRetry 创建服务；对"标记删除尚未完成"做最多 5 秒重试
// （幂等重装路径的前一条 Delete 生效需要时间），其余错误立即返回。
func createServiceWithRetry(m *mgr.Mgr, exe string) (*mgr.Service, error) {
	var lastErr error
	for i := 0; i < 10; i++ {
		s, err := m.CreateService(serviceName, exe, mgr.Config{
			DisplayName:  "Z-EDR 主机安全探针",
			Description:  "采集进程与血缘信息，执行多引擎恶意进程检测并上报总控服务端。",
			StartType:    mgr.StartAutomatic,
			ErrorControl: mgr.ErrorNormal,
		}, "-service")
		if err == nil {
			return s, nil
		}
		lastErr = err
		if !errors.Is(err, windows.ERROR_SERVICE_MARKED_FOR_DELETE) {
			return nil, err
		}
		time.Sleep(500 * time.Millisecond)
	}
	return nil, lastErr
}

// waitServiceGone 等待服务从 SCM 消失（标记删除完成），最多 5 秒。
func waitServiceGone(m *mgr.Mgr) error {
	for i := 0; i < 10; i++ {
		s, err := m.OpenService(serviceName)
		if err != nil {
			return nil // 打不开 = 已消失
		}
		s.Close()
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("服务 %s 未在 5 秒内完成卸载", serviceName)
}

// persistInstallConfig 把 -url/-token/-tags 写入 exe 同目录 .env（服务模式的
// 唯一配置来源，见 LoadDotEnv）。键级合并：只改提供的键，不动 .env 里的
// 其他配置；空值跳过（保持现状）。此后 LoadDotEnv 把它们注入本进程环境，
// effectiveEnroll 与服务运行读到的是同一份。
func persistInstallConfig(url, token, tags string) error {
	if url == "" && token == "" && tags == "" {
		return nil
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	envPath := filepath.Join(filepath.Dir(exe), ".env")

	updates := map[string]string{}
	if url != "" {
		if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
			return fmt.Errorf("-url 必须以 http:// 或 https:// 开头: %q", url)
		}
		updates["HG_AGENT_SERVER_URL"] = url
	}
	if token != "" {
		updates["HG_AGENT_ENROLL_TOKEN"] = token
	}
	if tags != "" {
		updates["HG_AGENT_TAGS"] = tags
	}

	lines := []string{}
	if raw, err := os.ReadFile(envPath); err == nil {
		lines = strings.Split(string(raw), "\n")
	}
	for i, ln := range lines {
		trimmed := strings.TrimSpace(ln)
		for k, v := range updates {
			if strings.HasPrefix(trimmed, k+"=") {
				lines[i] = k + "=" + v
				delete(updates, k)
				break
			}
		}
	}
	for k, v := range updates {
		lines = append(lines, k+"="+v)
	}
	// 系统环境变量优先于 .env（LoadDotEnv 不覆盖既有环境变量）：若目标机
	// 已设了同名系统变量，写进 .env 的值对服务进程不生效——必须在这里
	// 说破，否则是又一个"配置写了却没生效"的静默坑。
	written := map[string]string{
		"HG_AGENT_SERVER_URL":   url,
		"HG_AGENT_ENROLL_TOKEN": token,
		"HG_AGENT_TAGS":         tags,
	}
	for k, v := range written {
		if v == "" {
			continue
		}
		if old := os.Getenv(k); old != "" && old != v {
			fmt.Fprintf(os.Stderr,
				"警告: 系统环境变量 %s 已存在且与本次写入值不同；服务进程以系统环境变量为准，\n"+
					"  如需用新值请先删除系统变量或改用系统变量配置（setx /M %s ...）。\n", k, k)
		}
	}
	// 0600：文件里有注册凭据，收紧到管理员/本机可读。
	return os.WriteFile(envPath, []byte(strings.TrimRight(strings.Join(lines, "\n"), "\n")+"\n"), 0o600)
}

// effectiveEnroll 返回落盘后的有效接入配置（flag > .env/系统环境 > 默认），
// 与服务进程实际读到的值一致——安装期警告的依据。
func effectiveEnroll() (url, token string) {
	url = os.Getenv("HG_AGENT_SERVER_URL")
	token = os.Getenv("HG_AGENT_ENROLL_TOKEN")
	if url == "" {
		url = "http://127.0.0.1:8080" // 与 agentapp.LoadConfig 默认值一致
	}
	return url, token
}

// printInstallSummary 安装成功的"下一步"引导：修掉"服务装好了但不知道
// 为什么没上线"的首次安装卡点（本地模式是合法用法，用警告不阻断）。
func printInstallSummary(url, token string) {
	fmt.Printf("服务 %s 已安装并设为自动启动（延迟启动 + 崩溃自动恢复）\n", serviceName)
	switch {
	case token == "":
		fmt.Fprintf(os.Stderr,
			"\n⚠ 当前未配置注册令牌，探针将以【纯本地模式】运行：本机检测照常，但不会上报总控，管理台不会出现本机。\n"+
				"  如需接入总控：重跑 -install 并带 -url <服务端地址> -token <注册令牌>，\n"+
				"  令牌在管理台「主机终端 → 接入新主机」页或服务端 .env 的 HG_SERVER_ENROLL_TOKEN。\n")
	case strings.Contains(url, "127.0.0.1") || strings.Contains(url, "localhost"):
		fmt.Fprintf(os.Stderr,
			"\n⚠ 服务端地址是 %s（本机回环）。跨机部署时目标机器连不上这个地址，\n"+
				"  表现为服务在跑但永远不上线；请用总控所在机器的可达地址重跑 -install -url ...\n", url)
	default:
		fmt.Printf("接入总控: %s（装完约 30 秒内应出现在管理台「主机终端」页）\n", url)
		fmt.Println("验证: zedr-agent.exe -status（脚本用 -status -json）")
	}
}

func uninstallService() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()

	s, err := m.OpenService(serviceName)
	if err != nil {
		return fmt.Errorf("服务不存在: %w", err)
	}
	defer s.Close()

	_, _ = s.Control(svc.Stop)
	return s.Delete()
}

// agentDataDir 返回探针数据目录（与运行时 cfg.Path 的来源一致）。
func agentDataDir() string {
	if v := os.Getenv("HG_AGENT_DATA_DIR"); v != "" {
		return v
	}
	if v := os.Getenv("LOCALAPPDATA"); v != "" {
		return filepath.Join(v, "zedr")
	}
	return ""
}

// localTokenCandidates 返回本地 API 令牌的可能落点，按可能性排序。
// 为什么是列表：探针以不同身份运行时数据目录不同——前台/登录用户运行在
// 当前用户 %LOCALAPPDATA%；LocalSystem 服务运行在 systemprofile 的
// AppData\Local（服务环境 LOCALAPPDATA 存在但指向 systemprofile）；
// 极老版本或无 LOCALAPPDATA 的环境落在 ProgramData。运维用 -status 查
// 服务状态时（脚本是服务部署的标准验证路径），当前用户目录里没有服务
// 进程的令牌——只查一个目录会得到 401 误报"探针异常"。
func localTokenCandidates() []string {
	var dirs []string
	if v := os.Getenv("HG_AGENT_DATA_DIR"); v != "" {
		dirs = append(dirs, v)
	}
	if v := os.Getenv("LOCALAPPDATA"); v != "" {
		dirs = append(dirs, filepath.Join(v, "zedr"))
	}
	dirs = append(dirs,
		`C:\Windows\System32\config\systemprofile\AppData\Local\zedr`,
		`C:\ProgramData\zedr`,
	)
	return dirs
}

// fetchLocalStatus 依次尝试各候选令牌读取本地状态；全部失败返回 nil。
func fetchLocalStatus() *http.Response {
	for _, dir := range localTokenCandidates() {
		tok := ""
		if raw, err := os.ReadFile(filepath.Join(dir, "local.token")); err == nil {
			tok = strings.TrimSpace(string(raw))
		} else {
			continue
		}
		req, _ := http.NewRequest(http.MethodGet, "http://127.0.0.1:8843/api/local/status", nil)
		req.Header.Set("X-ZEDR-Token", tok)
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			// 接口不可达：换令牌也没用，直接结束（探针没在跑）。
			return nil
		}
		if res.StatusCode == 200 {
			return res
		}
		res.Body.Close()
		if res.StatusCode != 401 {
			// 非 401（如 5xx）：不是令牌问题，重试无意义。
			return res
		}
		// 401：令牌不匹配，试下一个候选目录。
	}
	return nil
}

// printStatus 输出版机状态（不依赖任何前端）。json=true 时输出机器可读
// JSON（脚本/运维平台按 online 字段闭环判断"装完是否上线"），否则人话。
func printStatus(asJSON bool) error {
	res := fetchLocalStatus()
	if res == nil {
		return fmt.Errorf("本地接口 127.0.0.1:8843 不可达（探针未运行？）")
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return fmt.Errorf("本地接口返回 %d", res.StatusCode)
	}

	var wrap struct {
		Data struct {
			AgentVersion      string  `json:"agent_version"`
			ProcCount         int     `json:"proc_count"`
			CPUPercent        float64 `json:"cpu_percent"`
			MemMB             float64 `json:"mem_mb"`
			RuleCount         int     `json:"rule_count"`
			IOCCount          int     `json:"ioc_count"`
			InventorySections int     `json:"inventory_sections"`
			BaselineSize      int     `json:"baseline_size"`
			FileWatch         bool    `json:"file_watch"`
			PersistCount      int     `json:"persist_count"`
			UptimeSec         int64   `json:"uptime_sec"`
			ScanInterval      string  `json:"scan_interval"`
			Online            bool    `json:"online"`
			Stats             struct {
				Scanned    int64 `json:"scanned"`
				Fired      int64 `json:"fired"`
				Suppressed int64 `json:"suppressed"`
			} `json:"stats"`
		} `json:"data"`
	}
	if err := json.NewDecoder(res.Body).Decode(&wrap); err != nil {
		return err
	}
	d := wrap.Data

	if asJSON {
		// 只保留脚本关心的字段，不透传本地接口的完整结构（口径稳定，
		// 加字段不破坏既有消费方）。
		return json.NewEncoder(os.Stdout).Encode(map[string]any{
			"online":        d.Online,
			"agent_version": d.AgentVersion,
			"proc_count":    d.ProcCount,
			"cpu_percent":   d.CPUPercent,
			"mem_mb":        d.MemMB,
			"rule_count":    d.RuleCount,
			"uptime_sec":    d.UptimeSec,
			"scan_interval": d.ScanInterval,
			"scanned":       d.Stats.Scanned,
			"fired":         d.Stats.Fired,
			"suppressed":    d.Stats.Suppressed,
		})
	}

	online := "未连接总控"
	if d.Online {
		online = "已连接总控"
	}
	fmt.Printf("Z-EDR 探针 %s · 运行 %d 分钟 · %s\n", d.AgentVersion, d.UptimeSec/60, online)
	fmt.Printf("  监控进程   : %d（扫描间隔 %s）\n", d.ProcCount, d.ScanInterval)
	fmt.Printf("  检测规则   : %d 条 · IOC %d 条 · 资产清单 %d 节\n", d.RuleCount, d.IOCCount, d.InventorySections)
	fmt.Printf("  资源占用   : CPU %.2f%% · 内存 %.1f MB\n", d.CPUPercent, d.MemMB)
	fmt.Printf("  行为监控   : 文件落地监控 %s · 自启动基线 %d 项\n", map[bool]string{true: "开", false: "关"}[d.FileWatch], d.PersistCount)
	fmt.Printf("  累计检测   : 扫描 %d 次 · 告警 %d · 抑制 %d\n", d.Stats.Scanned, d.Stats.Fired, d.Stats.Suppressed)
	return nil
}
