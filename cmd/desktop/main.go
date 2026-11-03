// Command zedr-ui 是 Z-EDR 的桌面端，一个二进制两种角色（对标 Portmaster 的
// UI / Notifier 拆分，见 docs.safing.io/portmaster/architecture/overview）：
//
//	zedr-ui              UI 进程：无边框面板窗口；窗口关闭=进程退出，
//	                     WebView2 内存随之释放（UI 不做后台活动——省资源原则）
//	zedr-ui -tray        Notifier 进程：轻量托盘常驻（状态提示/告警气球/
//	                     快捷菜单），登录自启动（HKCU Run key）
//
// 与探针（zedr-agent.exe，Core Service）的关系：
//   - 探针独立运行（服务化开机自启），UI/托盘都只是它 127.0.0.1:8843 的客户端；
//   - 探针关闭面板不受影响；"退出托盘"也只退托盘自身；
//   - 探针不会反向拉 UI（Session 0 隔离禁止服务弹 GUI）——"唤起"由登录
//     自启动实现：用户登录 → Run key 拉起托盘 → 托盘连接探针。
//
// 其他用法：
//
//	zedr-ui -url http://...     指定面板地址
//	zedr-ui -browser            强制用默认浏览器打开
//	zedr-ui -autostart on|off   设置/取消"登录时自启动托盘"（HKCU Run key）
package main

import (
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	webview2 "github.com/jchv/go-webview2"

	"zedr/internal/platform/config"
)

var version = "dev"

func main() {
	var (
		urlFlag      = flag.String("url", "", "面板地址（默认读 HG_AGENT_LOCAL_ADDR）")
		forceBrowser = flag.Bool("browser", false, "强制用默认浏览器打开")
		startAgent   = flag.Bool("start-agent", true, "探针未运行时尝试拉起同目录 zedr-agent.exe")
		trayFlag     = flag.Bool("tray", false, "托盘常驻模式（Notifier，不带面板窗口）")
		autostartFlg = flag.String("autostart", "", "on/off：设置或取消登录自启动托盘（HKCU Run key）")
		debug        = flag.Bool("debug", false, "开启 WebView2 调试端口")
		showVer      = flag.Bool("version", false, "打印版本")
	)
	flag.Parse()

	if *showVer {
		fmt.Printf("zedr-ui %s\n", version)
		return
	}

	// .env 只用于开发；正式部署请用系统环境变量
	_, _ = config.LoadDotEnv()

	target := panelURL(*urlFlag)

	// CLI 专项：设置自启动后立即退出（供运维脚本/测试调用）
	if *autostartFlg != "" {
		on := strings.EqualFold(*autostartFlg, "on") || strings.EqualFold(*autostartFlg, "true") || *autostartFlg == "1"
		if err := setAutostart(on); err != nil {
			fmt.Fprintf(os.Stderr, "设置自启动失败: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("登录自启动托盘已%s\n", map[bool]string{true: "开启", false: "关闭"}[on])
		return
	}

	if *trayFlag {
		runNotifier(target)
		return
	}
	runPanel(runPanelOpts{
		target:     target,
		debug:      *debug,
		startAgent: *startAgent,
		browser:    *forceBrowser,
	})
}

func panelURL(urlFlag string) string {
	target := urlFlag
	if target == "" {
		addr := os.Getenv("HG_AGENT_LOCAL_ADDR")
		if addr == "" {
			addr = "127.0.0.1:8843"
		}
		target = "http://" + addr + "/"
	}
	// 附带本地接口访问令牌。本地 API 已启用访问控制，不带令牌会拿到 401——
	// 宿主进程负责把令牌交给页面，页面存进 localStorage 后即从地址栏抹掉。
	if tok := readLocalToken(); tok != "" {
		sep := "?"
		if strings.Contains(target, "?") {
			sep = "&"
		}
		target = target + sep + "token=" + url.QueryEscape(tok)
	}
	return target
}

// runPanelOpts 是 UI 进程的输入。
type runPanelOpts struct {
	target     string
	debug      bool
	startAgent bool
	browser    bool
}

// runPanel 是 UI 进程：面板窗口开着它才活着，关窗即退出——
// WebView2 渲染器是内存大头，Portmaster 的 UI 同样宣称"无后台活动"。
func runPanel(opts runPanelOpts) {
	// 单实例：重复双击不做第二个进程，把已有面板调到前台
	if held, release := acquireMutex(panelMutexName); held {
		defer release()
	} else {
		activatePanelWindow()
		return
	}

	// 常驻托盘（Notifier）与 UI 是两个进程：面板开着时托盘也应在。
	// 托盘进程已存在则跳过；不存在则拉起（幂等）。
	ensureTrayProcess()

	// 等探针就绪；没在跑就拉起同目录 zedr-agent.exe（隐藏控制台）。
	if !waitAgent(opts.target, 3*time.Second) && opts.startAgent {
		if err := launchAgent(); err == nil {
			waitAgent(opts.target, 20*time.Second)
		}
	}

	if opts.browser {
		openBrowser(opts.target)
		return
	}

	w := webview2.NewWithOptions(webview2.WebViewOptions{
		Debug:     opts.debug,
		AutoFocus: true,
		WindowOptions: webview2.WindowOptions{
			Title:  "Z-EDR · 本机进程防护",
			Width:  1180,
			Height: 820,
			Center: true,
			IconId: 1, // go-winres 写入的应用图标（assets/brand/zedr.ico）
		},
	})
	if w == nil {
		fmt.Println("未检测到 WebView2 运行时，改用默认浏览器打开。")
		fmt.Println("（安装 Microsoft Edge WebView2 Runtime 后可获得原生窗口体验）")
		openBrowser(opts.target)
		return
	}
	defer w.Destroy()

	// 无边框：去系统标题栏，顶栏自绘（拖动走 CSS app-region，缩放走贴边热区）。
	makeFrameless(uintptr(w.Window()))

	// Bind 注入的 JS 在导航前就位，页面脚本启动时 window.zedrHost* 已存在。
	bindWindowActions(w)

	w.SetTitle("Z-EDR · 本机进程防护 v" + version)
	w.Navigate(opts.target)

	// 阻塞到窗口关闭；关闭=进程退出=WebView2 内存全部释放，托盘（另一个
	// 进程）继续提供常驻存在感。
	w.Run()
}

// ensureTrayProcess 若托盘（Notifier）进程未运行则拉起。
// 用互斥量判断而不是找窗口：托盘窗口本就不可见。
func ensureTrayProcess() {
	if held, release := acquireMutex(trayMutexName); held {
		// 我们抢到了锁说明托盘不在跑：立即释放并拉起
		release()
		self, err := os.Executable()
		if err != nil {
			return
		}
		cmd := exec.Command(self, "-tray")
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
		if err := cmd.Start(); err == nil {
			_ = cmd.Process.Release()
		}
	} else {
		release()
	}
}

// bindWindowActions 把窗口控制暴露给页面（无边框模式的自绘按钮）。
// 浏览器直开时这些全局函数不存在，页面会自动隐藏控制按钮。
func bindWindowActions(w webview2.WebView) {
	_ = w.Bind("zedrHostMinimize", func() {
		if frame != nil {
			frame.minimize()
		}
	})
	_ = w.Bind("zedrHostMaximizeToggle", func() bool {
		if frame == nil {
			return false
		}
		return frame.maximizeToggle()
	})
	_ = w.Bind("zedrHostClose", func() {
		// 关闭 = 面板进程退出：WebView2 内存随之释放；
		// 常驻存在感由独立的托盘进程负责，探针不受任何影响。
		if frame != nil {
			procDestroyWindow.Call(frame.hwnd)
		}
	})
	_ = w.Bind("zedrHostResizeEdge", resizeEdge)
}

// apiHTTPClient 返回禁用代理的 HTTP 客户端。
// 会话环境的 HTTP(S)_PROXY 会把 127.0.0.1 静默送进 502（AGENTS §5.3），
// 生产环境无代理时此设置也无副作用。
func apiHTTPClient() *http.Client {
	return &http.Client{
		Timeout:   3 * time.Second,
		Transport: &http.Transport{Proxy: nil},
	}
}

// waitAgent 轮询本地探针健康检查。
func waitAgent(target string, timeout time.Duration) bool {
	client := apiHTTPClient()
	deadline := time.Now().Add(timeout)
	healthURL := target + "health"
	if target[len(target)-1] != '/' {
		healthURL = target + "/health"
	}

	for time.Now().Before(deadline) {
		res, err := client.Get(healthURL)
		if err == nil {
			_ = res.Body.Close()
			if res.StatusCode == http.StatusOK {
				return true
			}
		}
		time.Sleep(400 * time.Millisecond)
	}
	return false
}

// launchAgent 尝试启动同目录下的探针。
func launchAgent() error {
	agentPath, err := siblingExe("zedr-agent.exe")
	if err != nil {
		return err
	}
	cmd := exec.Command(agentPath)
	cmd.Dir = filepath.Dir(agentPath)
	// 探针作为独立进程运行，不随面板退出而终止。
	// HideWindow + CREATE_NO_WINDOW：探针是后台服务，弹一个黑控制台窗口
	// 只会让用户以为"这是什么程序"然后关掉它。
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
	if err := cmd.Start(); err != nil {
		return err
	}
	_ = cmd.Process.Release()
	return nil
}

// siblingExe 返回与本程序同目录下的另一个 exe 路径。
func siblingExe(name string) (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	p := filepath.Join(filepath.Dir(exe), name)
	if _, err := os.Stat(p); err != nil {
		return "", fmt.Errorf("未找到 %s: %w", name, err)
	}
	return p, nil
}

// openBrowser 用系统默认程序打开 URL。
func openBrowser(url string) {
	if err := exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start(); err != nil {
		fmt.Fprintf(os.Stderr, "打开浏览器失败: %v\n请手动访问 %s\n", err, url)
	}
}

// readLocalToken 从数据目录读取本地接口访问令牌。
// 数据目录与探针保持一致：优先 HG_AGENT_DATA_DIR，否则 %LOCALAPPDATA%\zedr。
func readLocalToken() string {
	dir := os.Getenv("HG_AGENT_DATA_DIR")
	if dir == "" {
		if v := os.Getenv("LOCALAPPDATA"); v != "" {
			dir = filepath.Join(v, "zedr")
		} else {
			dir = `C://ProgramData//zedr`
		}
	}
	raw, err := os.ReadFile(filepath.Join(dir, "local.token"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(raw))
}
