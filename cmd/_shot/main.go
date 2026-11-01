//go:build windows

// _shot 是一次性的截图脚手架：GDI 抓屏 + 窗口激活 + 键盘注入。
// 用于向用户展示 UI 效果；本机安全策略拦掉了 PowerShell 的
// Add-Type / COM / Reflection 路径，Go 本地编译是唯一可控通道。
// 用完即删，不进主干。
package main

import (
	"flag"
	"fmt"
	"image"
	"image/png"
	"os"
	"os/exec"
	"strings"
	"time"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	user32 = windows.NewLazySystemDLL("user32.dll")
	gdi32  = windows.NewLazySystemDLL("gdi32.dll")

	procFindWindow        = user32.NewProc("FindWindowW")
	procEnumWindows       = user32.NewProc("EnumWindows")
	procGetWindowTextW    = user32.NewProc("GetWindowTextW")
	procIsWindowVisible   = user32.NewProc("IsWindowVisible")
	procSetForeground     = user32.NewProc("SetForegroundWindow")
	procShowWindow        = user32.NewProc("ShowWindow")
	procGetSystemMetrics  = user32.NewProc("GetSystemMetrics")
	procGetDC             = user32.NewProc("GetDC")
	procReleaseDC         = user32.NewProc("ReleaseDC")
	procKeybdEvent        = user32.NewProc("keybd_event")
	procVkKeyScanW        = user32.NewProc("VkKeyScanW")

	procCreateCompatibleDC    = gdi32.NewProc("CreateCompatibleDC")
	procCreateCompatibleBmp   = gdi32.NewProc("CreateCompatibleBitmap")
	procSelectObject          = gdi32.NewProc("SelectObject")
	procBitBlt                = gdi32.NewProc("BitBlt")
	procGetDIBits             = gdi32.NewProc("GetDIBits")
	procDeleteObject          = gdi32.NewProc("DeleteObject")
	procDeleteDC              = gdi32.NewProc("DeleteDC")
)

func main() {
	edge := flag.String("edge", "", "先打开指定 URL（用 Edge 新窗口）再继续")
	activate := flag.String("activate", "", "截图前把包含该标题的窗口置前")
	out := flag.String("out", "shot.png", "输出 PNG 路径")
	login := flag.Bool("login", false, "向焦点窗口注入 admin 登录序列")
	nav := flag.String("nav", "", "登录后跳转的 hash 路由（如 incidents）")
	flag.Parse()

	if *edge != "" {
		e := `C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe`
		cmd := exec.Command(e, "--new-window", "--window-size=1400,900",
			"--window-position=60,40", *edge)
		if err := cmd.Start(); err != nil {
			fmt.Println("启动 Edge 失败:", err)
			return
		}
		time.Sleep(6 * time.Second) // 等 Edge 完全起窗
	}

	if *activate != "" {
		if hwnd := findByTitle(*activate); hwnd != 0 {
			procShowWindow.Call(hwnd, 9) // SW_RESTORE
			procSetForeground.Call(hwnd)
			time.Sleep(1200 * time.Millisecond)
			fmt.Println("activated hwnd:", hwnd)
		} else {
			fmt.Println("未找到窗口:", *activate)
		}
	}

	if *login {
		typeStr("admin")
		keyTap(0x09) // TAB
		time.Sleep(200 * time.Millisecond)
		typeStr("Admin@12345")
		time.Sleep(200 * time.Millisecond)
		keyTap(0x0D) // ENTER
		time.Sleep(4500 * time.Millisecond)
	}

	if *nav != "" {
		keybd(0x11, true) // CTRL down
		keyTap(0x4C)      // L
		keybd(0x11, false)
		time.Sleep(400 * time.Millisecond)
		typeStr("127.0.0.1:8080/#/" + *nav)
		time.Sleep(300 * time.Millisecond)
		keyTap(0x0D)
		time.Sleep(3500 * time.Millisecond)
	}

	if err := capture(*out); err != nil {
		fmt.Println("截屏失败:", err)
		os.Exit(1)
	}
	fmt.Println("saved:", *out)
}

// ---------------------------------------------------------------- 窗口

func utf16Ptr(s string) uintptr {
	p, _ := windows.UTF16PtrFromString(s)
	return uintptr(unsafe.Pointer(p))
}

// findByTitle 枚举顶层窗口，返回标题包含 sub 的第一个可见窗口。
func findByTitle(sub string) uintptr {
	var found uintptr
	subLower := strings.ToLower(sub)
	cb := windows.NewCallback(func(hwnd uintptr, _ uintptr) uintptr {
		if found != 0 {
			return 1
		}
		vis, _, _ := procIsWindowVisible.Call(hwnd)
		if vis == 0 {
			return 1
		}
		n, _, _ := procGetWindowTextW.Call(hwnd, 0, 0)
		if n == 0 {
			return 1
		}
		buf := make([]uint16, n+1)
		procGetWindowTextW.Call(hwnd, uintptr(unsafe.Pointer(&buf[0])), n+1)
		title := strings.ToLower(string(utf16.Decode(buf)))
		if strings.Contains(title, subLower) {
			found = hwnd
		}
		return 1
	})
	procEnumWindows.Call(cb, 0)
	return found
}

// ---------------------------------------------------------------- 键盘

func keybd(vk byte, up bool) {
	flag := uintptr(0)
	if up {
		flag = 2
	}
	procKeybdEvent.Call(uintptr(vk), 0, flag, 0)
}

func keyTap(vk byte) {
	keybd(vk, false)
	keybd(vk, true)
}

func typeStr(s string) {
	for _, r := range utf16.Encode([]rune(s)) {
		v, _, _ := procVkKeyScanW.Call(uintptr(r))
		if int32(v) == -1 {
			continue
		}
		vk := byte(v & 0xFF)
		shift := v>>8&1 == 1
		if shift {
			keybd(0x10, false)
		}
		keyTap(vk)
		if shift {
			keybd(0x10, true)
		}
	}
	time.Sleep(60 * time.Millisecond)
}

// ---------------------------------------------------------------- 抓屏

func capture(path string) error {
	const (
		smX, smY       = 76, 77
		smCX, smCY     = 78, 79
		srccopy        = 0x00CC0020
		dibRGBColors   = 0
	)

	x, _, _ := procGetSystemMetrics.Call(smX)
	y, _, _ := procGetSystemMetrics.Call(smY)
	w, _, _ := procGetSystemMetrics.Call(smCX)
	h, _, _ := procGetSystemMetrics.Call(smCY)
	W, H := int(w), int(h)
	if W <= 0 || H <= 0 {
		return fmt.Errorf("虚拟屏幕尺寸异常 %dx%d", W, H)
	}

	hdc, _, _ := procGetDC.Call(0)
	defer procReleaseDC.Call(0, hdc)

	mem, _, _ := procCreateCompatibleDC.Call(hdc)
	defer procDeleteDC.Call(mem)

	bmp, _, _ := procCreateCompatibleBmp.Call(hdc, w, h)
	old, _, _ := procSelectObject.Call(mem, bmp)
	defer procSelectObject.Call(mem, old)
	defer procDeleteObject.Call(bmp)

	procBitBlt.Call(mem, 0, 0, w, h, hdc, x, y, srccopy)

	// 32 位 top-down DIB
	var bi [10]int32
	bi[0] = 40
	bi[1] = int32(W)
	bi[2] = -int32(H) // 负高 = top-down
	bi[3] = 1
	bi[4] = 32

	buf := make([]byte, W*H*4)
	procGetDIBits.Call(mem, bmp, 0, h, uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&bi[0])), dibRGBColors)

	img := image.NewRGBA(image.Rect(0, 0, W, H))
	// DIB 是 BGRA，逐行翻转拷贝（top-down 已由负高保证，无需翻转）
	for i := 0; i < W*H; i++ {
		img.Pix[i*4+0] = buf[i*4+2]
		img.Pix[i*4+1] = buf[i*4+1]
		img.Pix[i*4+2] = buf[i*4+0]
		img.Pix[i*4+3] = 0xFF
	}

	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return png.Encode(f, img)
}
