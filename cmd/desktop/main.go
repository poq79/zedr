// Command secui 是 HostGuard 的桌面端（本机防护面板）。
//
// 形态：原生 Win32 窗口 + WebView2 渲染，无浏览器地址栏，像普通桌面应用。
// 若目标机器未安装 WebView2 运行时，自动退化为"用默认浏览器打开"。
//
// 用法：
//
//	secui                     打开桌面面板（自动连接本地探针）
//	secui -url http://...     指定面板地址
//	secui -browser            强制用默认浏览器打开（不创建窗口）
//	secui -start-agent        若探针未运行，尝试拉起同目录下的 secagent.exe
package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	webview2 "github.com/jchv/go-webview2"

	"hostguard/internal/platform/config"
)

var version = "dev"

const defaultURL = "http://127.0.0.1:8843/"

func main() {
	var (
		urlFlag    = flag.String("url", "", "面板地址（默认读 HG_AGENT_LOCAL_ADDR）")
		forceBrowser = flag.Bool("browser", false, "强制用默认浏览器打开")
		startAgent = flag.Bool("start-agent", true, "探针未运行时尝试拉起同目录 secagent.exe")
		debug      = flag.Bool("debug", false, "开启 WebView2 调试端口")
		showVer    = flag.Bool("version", false, "打印版本")
	)
	flag.Parse()

	if *showVer {
		fmt.Printf("secui %s\n", version)
		return
	}

	// .env 只用于开发；正式部署请用系统环境变量
	_, _ = config.LoadDotEnv()

	target := *urlFlag
	if target == "" {
		addr := os.Getenv("HG_AGENT_LOCAL_ADDR")
		if addr == "" {
			addr = "127.0.0.1:8843"
		}
		target = "http://" + addr + "/"
	}

	if !waitAgent(target, 3*time.Second) && *startAgent {
		if err := launchAgent(); err == nil {
			fmt.Println("已尝试启动本地探针，等待其就绪…")
			waitAgent(target, 20*time.Second)
		}
	}

	if *forceBrowser {
		openBrowser(target)
		return
	}

	w := webview2.NewWithOptions(webview2.WebViewOptions{
		Debug:     *debug,
		AutoFocus: true,
		WindowOptions: webview2.WindowOptions{
			Title:  "HostGuard · 本机进程防护",
			Width:  1180,
			Height: 820,
			Center: true,
		},
	})
	if w == nil {
		fmt.Println("未检测到 WebView2 运行时，改用默认浏览器打开。")
		fmt.Println("（安装 Microsoft Edge WebView2 Runtime 后可获得原生窗口体验）")
		openBrowser(target)
		return
	}
	defer w.Destroy()

	w.SetTitle("HostGuard · 本机进程防护 v" + version)
	w.Navigate(target)
	w.Run()
}

// waitAgent 轮询本地探针健康检查。
func waitAgent(target string, timeout time.Duration) bool {
	client := &http.Client{Timeout: 1500 * time.Millisecond}
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
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	agentPath := filepath.Join(filepath.Dir(exe), "secagent.exe")
	if _, err := os.Stat(agentPath); err != nil {
		return fmt.Errorf("未找到 secagent.exe: %w", err)
	}
	cmd := exec.Command(agentPath)
	cmd.Dir = filepath.Dir(exe)
	// 探针作为独立进程运行，不随面板退出而终止
	if err := cmd.Start(); err != nil {
		return err
	}
	_ = cmd.Process.Release()
	return nil
}

// openBrowser 用系统默认程序打开 URL。
func openBrowser(url string) {
	if err := exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start(); err != nil {
		fmt.Fprintf(os.Stderr, "打开浏览器失败: %v\n请手动访问 %s\n", err, url)
	}
}
