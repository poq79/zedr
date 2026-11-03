package main

// Notifier 进程（zedr-ui -tray）：对标 Portmaster 的 Tray Notifier——
// 一个 5-15MB 的轻量常驻进程，职责只有三件：
//  1. 在场感：托盘图标 + 状态提示（探针在不在、连没连上总控）
//  2. 通知：严重告警弹出系统气球通知（探针在 Session 0 不能直接弹 UI，
//     这正是业界把 Notifier 拆成用户会话进程的原因）
//  3. 快捷操作：打开面板 / 立即扫描 / 启动探针 / 自启动开关 / 服务安装
//
// 它刻意不带 WebView2（内存大头在渲染器）；面板是另一个进程，按需打开。
// 生命周期：登录自启动（HKCU Run key）→ 常驻 → "退出托盘"才结束。
// 探针是否运行与它完全解耦——只是状态显示会变。

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	trayMutexName = `Local\zedr-ui-tray`
	panelMutexName = `Local\zedr-ui-panel`
)

// 菜单项 ID（TrackPopupMenuEx TPM_RETURNCMD 返回值）
const (
	menuOpenPanel   = 1
	menuScan        = 2
	menuStartAgent  = 3
	menuAutostart   = 4
	menuInstallSvc  = 5
	menuQuit        = 6
)

const (
	niifInfo    = 0x1
	niifWarning = 0x2
	niifError   = 0x3
	mfChecked   = 0x00000008
)

type notifier struct {
	hwnd       uintptr
	hicon      uintptr
	added      bool
	url        string
	localToken string
	// seen 记录已弹过气球的告警 ID：轮询去重，同一告警只打扰一次
	seen map[string]bool
}

// activeTray 单实例：托盘窗口的 WndProc 是静态回调，用包级变量回跳。
var activeTray *notifier

// runNotifier 是 Notifier 进程的主函数，阻塞到"退出托盘"。
func runNotifier(target string) {
	if held, release := acquireMutex(trayMutexName); !held {
		// 已有托盘实例在跑，静默退出
		release()
		return
	} else {
		defer release()
	}

	n := &notifier{url: target, seen: map[string]bool{}}
	if !n.createWindow() {
		log.Println("tray: create_window_failed")
		return
	}
	// ID 1 = go-winres 写入的应用图标；0,0 表示取默认尺寸（32px）
	n.hicon = loadIconResource(1, 0, 0)
	if n.hicon == 0 {
		n.hicon = loadIconResource(1, 16, 16)
	}
	if n.hicon == 0 {
		log.Println("tray: icon_load_failed")
		return
	}
	if !n.add() {
		log.Println("tray: shell_notifyicon_add_failed")
		return
	}
	defer n.remove()

	// 状态轮询（tooltip）与告警轮询（气球）放后台 goroutine；
	// Shell_NotifyIcon 的 NIM_MODIFY 跨线程调用是安全的。
	n.refreshToken()
	go n.pollStatus()
	go n.pollAlerts()

	// 消息循环：托盘窗口的回调消息都从这里派发
	var m msg
	for {
		r, _, _ := procGetMessageW.Call(uintptr(unsafe.Pointer(&m)), 0, 0, 0)
		if r == 0 {
			return // WM_QUIT
		}
		procTranslateMessage.Call(uintptr(unsafe.Pointer(&m)))
		procDispatchMessageW.Call(uintptr(unsafe.Pointer(&m)))
	}
}

func (n *notifier) createWindow() bool {
	className, _ := syscall.UTF16PtrFromString("zedr_tray")
	wc := wndClassExW{
		CbSize:        uint32(unsafe.Sizeof(wndClassExW{})),
		LpfnWndProc:   windows.NewCallback(trayWndProc),
		HInstance:     windows.Handle(moduleHandle()),
		LpszClassName: className,
	}
	procRegisterClassExW.Call(uintptr(unsafe.Pointer(&wc)))

	hwnd, _, _ := procCreateWindowExW.Call(0,
		uintptr(unsafe.Pointer(className)),
		uintptr(unsafe.Pointer(utf16("Z-EDR 托盘"))),
		0, 0, 0, 0, 0, 0, 0,
		uintptr(wc.HInstance), 0)
	// 只看句柄：LazyProc.Call 的 err 是残留的 LastErr，成功时也常非 nil
	if hwnd == 0 {
		return false
	}
	n.hwnd = hwnd
	activeTray = n
	return true
}

func (n *notifier) nid() notifyIconDataW {
	return notifyIconDataW{CbSize: uint32(unsafe.Sizeof(notifyIconDataW{})), HWnd: n.hwnd, UID: 1}
}

func (n *notifier) add() bool {
	nid := n.nid()
	nid.UFlags = nifMessage | nifIcon | nifTip
	nid.UCallbackMessage = wmTrayCallback
	nid.HIcon = n.hicon
	tip, _ := syscall.UTF16FromString("Z-EDR · 正在连接探针…")
	copyTip(nid.SzTip[:], tip)
	r, _, _ := procShellNotifyIconW.Call(nimAdd, uintptr(unsafe.Pointer(&nid)))
	if r == 0 {
		return false
	}
	// 版本 3：回调 lParam 变成鼠标消息本身，处理直观
	nid2 := n.nid()
	nid2.UVersion = notifyIconVersion
	_, _, _ = procShellNotifyIconW.Call(nimSetVersion, uintptr(unsafe.Pointer(&nid2)))
	n.added = true
	return true
}

func (n *notifier) remove() {
	if !n.added {
		return
	}
	nid := n.nid()
	_, _, _ = procShellNotifyIconW.Call(nimDelete, uintptr(unsafe.Pointer(&nid)))
	n.added = false
}

func copyTip(dst []uint16, src []uint16) {
	for i := range dst {
		if i >= len(src) {
			break
		}
		dst[i] = src[i]
	}
}

// setTip 更新托盘悬停提示（状态对外可见的窗口）。
func (n *notifier) setTip(text string) {
	if !n.added {
		return
	}
	nid := n.nid()
	nid.UFlags = nifTip
	tip, _ := syscall.UTF16FromString(text)
	copyTip(nid.SzTip[:], tip)
	_, _, _ = procShellNotifyIconW.Call(nimModify, uintptr(unsafe.Pointer(&nid)))
}

// balloon 弹系统气球通知（Windows 10+ 显示为 toast）。
func (n *notifier) balloon(title, text string, flag uint32) {
	if !n.added {
		return
	}
	nid := n.nid()
	nid.UFlags = nifInfo
	t, _ := syscall.UTF16FromString(title)
	copyTip(nid.SzInfoTitle[:], t)
	x, _ := syscall.UTF16FromString(text)
	copyTip(nid.SzInfo[:], x)
	nid.DwInfoFlags = flag
	_, _, _ = procShellNotifyIconW.Call(nimModify, uintptr(unsafe.Pointer(&nid)))
}

// trayWndProc 托盘隐藏窗口的过程。static 回调要求签名固定 uintptr 三参。
func trayWndProc(hwnd, msg, wp, lp uintptr) uintptr {
	switch msg {
	case wmTrayCallback:
		if activeTray != nil {
			activeTray.onTrayCallback(lp)
		}
		return 0
	case wmClose:
		// 托盘没有"关闭"概念：必须经菜单"退出托盘"，防止误触失去在场感
		return 0
	case wmDestroy:
		procPostQuitMessage.Call(0)
		return 0
	}
	r, _, _ := procDefWindowProcW.Call(hwnd, msg, wp, lp)
	return r
}

// onTrayCallback 处理托盘鼠标事件（VERSION=3：wParam=UID，lParam=鼠标消息）。
func (n *notifier) onTrayCallback(lParam uintptr) {
	const (
		wmLButtonUp     = 0x0202
		wmLButtonDblClk = 0x0203
		wmRButtonUp     = 0x0205
	)
	switch lParam {
	case wmLButtonUp, wmLButtonDblClk:
		n.openPanel()
	case wmRButtonUp:
		n.popupMenu()
	}
}

func (n *notifier) popupMenu() {
	menu, _, _ := procCreatePopupMenu.Call()
	if menu == 0 {
		return
	}
	defer procDestroyMenu.Call(menu)
	appendItem := func(id uintptr, text string, checked bool) {
		flags := uintptr(mfString)
		if checked {
			flags |= mfChecked
		}
		procAppendMenuW.Call(menu, flags, id, uintptr(unsafe.Pointer(utf16(text))))
	}
	appendItem(menuOpenPanel, "打开面板", false)
	appendItem(menuScan, "立即扫描", false)
	// 探针没在跑才给"启动探针"入口（健康探测 800ms，菜单弹出前的一次性成本）
	if !probeHealth(n.url) {
		appendItem(menuStartAgent, "启动探针", false)
	}
	procAppendMenuW.Call(menu, mfSeparator, 0, 0)
	appendItem(menuAutostart, "登录时自动启动托盘", autostartEnabled())
	appendItem(menuInstallSvc, "安装探针服务（开机自启，需管理员）", false)
	procAppendMenuW.Call(menu, mfSeparator, 0, 0)
	appendItem(menuQuit, "退出托盘（探针继续运行）", false)

	// KB135788：TrackPopupMenu 前必须 SetForegroundWindow，否则点外面菜单不消失
	procSetForegroundWindow.Call(n.hwnd)
	cmd, _, _ := procTrackPopupMenuEx.Call(menu, tpmRetURNCMD|tpmRightButton|tpmNoDefault, 0, 0, n.hwnd, 0)
	procPostMessageW.Call(n.hwnd, wmNull, 0, 0)
	switch cmd {
	case menuOpenPanel:
		n.openPanel()
	case menuScan:
		n.triggerScan()
	case menuStartAgent:
		_ = launchAgent()
	case menuAutostart:
		_ = setAutostart(!autostartEnabled())
	case menuInstallSvc:
		if agentPath, err := siblingExe("zedr-agent.exe"); err == nil {
			_ = runElevated(agentPath, "-install")
		}
	case menuQuit:
		n.remove()
		procPostQuitMessage.Call(0)
	}
}

// openPanel 面板已在则调到前台，否则拉起新的 UI 进程。
// 面板是独立进程：开多少次、关多少次都不影响托盘与探针。
func (n *notifier) openPanel() {
	if panelRunning() {
		activatePanelWindow()
		return
	}
	if self, err := os.Executable(); err == nil {
		// UI 进程自身就是 GUI 子系统（-H=windowsgui），无控制台可闪；
		// HideWindow 仅为防御性设置，对 GUI 子系统无副作用。
		cmd := exec.Command(self)
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
		if err := cmd.Start(); err == nil {
			_ = cmd.Process.Release()
		}
	}
}

// triggerScan 复用本地 API 访问令牌触发一次全量重扫。
func (n *notifier) triggerScan() {
	if n.token() == "" {
		return
	}
	client := apiHTTPClient()
	req, err := http.NewRequest(http.MethodPost, strings.TrimRight(n.url, "/")+"/api/local/rescan", nil)
	if err != nil {
		return
	}
	req.Header.Set("X-ZEDR-Token", n.token())
	resp, err := client.Do(req)
	if err != nil {
		log.Println("tray_scan_failed", "err", err)
		return
	}
	_ = resp.Body.Close()
}

// refreshToken 若令牌未加载则重读（探针晚于托盘启动时令牌文件才出现）。
func (n *notifier) refreshToken() {
	if n.token() == "" {
		n.loadToken()
	}
}

// ---- 轮询 ---------------------------------------------------------------

// pollStatus 每 5 秒读一次探针状态，映射成一句人话放进托盘提示。
func (n *notifier) pollStatus() {
	lastText := ""
	for {
		time.Sleep(5 * time.Second)
		n.refreshToken()
		text := "Z-EDR · 探针未运行（托盘菜单可启动）"
		if n.token() == "" {
			text = "Z-EDR · 探针未运行（托盘菜单可启动）"
		} else if s, ok := n.fetchStatus(); ok {
			switch {
			case s.Online:
				text = "Z-EDR · 防护运行中（已连接总控）"
			case s.Enrolled:
				text = "Z-EDR · 总控离线，本机防护继续"
			default:
				text = "Z-EDR · 本机防护运行中（未配置总控）"
			}
		}
		if text != lastText {
			n.setTip(text)
			lastText = text
		}
	}
}

// pollAlerts 每 10 秒扫一次最近告警，出现新的 critical/high 弹气球。
// 面板打开时页面自己会轮询并 toast；这里兜的是"面板关着"的场景——
// 这正是 Notifier 存在的意义：探针在 Session 0 弹不了通知。
func (n *notifier) pollAlerts() {
	for {
		time.Sleep(10 * time.Second)
		n.refreshToken()
		if n.token() == "" {
			continue
		}
		type alertItem struct {
			ID          string `json:"id"`
			Title       string `json:"title"`
			Severity    string `json:"severity"`
			Score       int    `json:"score"`
			ProcessName string `json:"process_name"`
		}
		client := apiHTTPClient()
		resp, err := client.Get(strings.TrimRight(n.url, "/") + "/api/local/alerts?limit=10")
		if err != nil {
			continue
		}
		var body struct {
			Data struct {
				Items []alertItem `json:"items"`
			} `json:"data"`
		}
		err = json.NewDecoder(resp.Body).Decode(&body)
		_ = resp.Body.Close()
		if err != nil {
			continue
		}
		for _, a := range body.Data.Items {
			if a.Severity != "critical" && a.Severity != "high" {
				continue
			}
			if n.seen[a.ID] {
				continue
			}
			n.seen[a.ID] = true
			if len(n.seen) > 200 {
				// 防止长会话下 map 无限膨胀：简单截断，漏掉的只是去重键
				n.seen = map[string]bool{a.ID: true}
			}
			flag := uint32(niifWarning)
			if a.Severity == "critical" {
				flag = niifError
			}
			text := fmt.Sprintf("%s · %d 分", a.ProcessName, a.Score)
			n.balloon("新告警："+a.Title, text, flag)
			break // 一次只弹最上面一条，避免告警风暴连环打扰
		}
	}
}

func (n *notifier) fetchStatus() (statusSnapshot, bool) {
	type statusBody struct {
		Data statusSnapshot `json:"data"`
	}
	client := apiHTTPClient()
	resp, err := client.Get(strings.TrimRight(n.url, "/") + "/api/local/status")
	if err != nil {
		return statusSnapshot{}, false
	}
	var sb statusBody
	err = json.NewDecoder(resp.Body).Decode(&sb)
	_ = resp.Body.Close()
	if err != nil {
		return statusSnapshot{}, false
	}
	return sb.Data, true
}

// statusSnapshot 只取 Notifier 用得到的字段。
type statusSnapshot struct {
	Online   bool `json:"online"`
	Enrolled bool `json:"enrolled"`
}

func (n *notifier) token() string   { return n.localToken }
func (n *notifier) loadToken()      { n.localToken = readLocalToken() }

func probeHealth(url string) bool {
	client := apiHTTPClient()
	client.Timeout = 800 * time.Millisecond
	resp, err := client.Get(strings.TrimRight(url, "/") + "/health")
	if err != nil {
		return false
	}
	_ = resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}
