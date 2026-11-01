package winapi

import (
	"fmt"
	"os"
	"strings"
	"sync"

	"golang.org/x/sys/windows/registry"
)

var (
	osInfoOnce sync.Once
	osName     string
	osBuild    string
)

// OSVersion 返回可读的系统版本，例如 "Windows 11 Pro 23H2 (Build 22631)"。
func OSVersion() string {
	osInfoOnce.Do(func() {
		k, err := registry.OpenKey(registry.LOCAL_MACHINE,
			`SOFTWARE\Microsoft\Windows NT\CurrentVersion`, registry.QUERY_VALUE)
		if err != nil {
			osName = "Windows"
			return
		}
		defer k.Close()

		product, _, _ := k.GetStringValue("ProductName")
		display, _, _ := k.GetStringValue("DisplayVersion")
		build, _, _ := k.GetStringValue("CurrentBuild")
		ubr, _, _ := k.GetIntegerValue("UBR")

		// Windows 11 的注册表 ProductName 仍是 "Windows 10"，按 build 号纠正
		if build != "" {
			var b int
			_, _ = fmt.Sscanf(build, "%d", &b)
			if b >= 22000 {
				product = strings.Replace(product, "Windows 10", "Windows 11", 1)
			}
		}

		parts := []string{product}
		if display != "" {
			parts = append(parts, display)
		}
		osName = strings.TrimSpace(strings.Join(parts, " "))
		if build != "" {
			osBuild = fmt.Sprintf("Build %s.%d", build, ubr)
		}
	})
	if osBuild != "" {
		return osName + " (" + osBuild + ")"
	}
	return osName
}

// Hostname 返回主机名。
func Hostname() string {
	h, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return h
}

// CurrentUser 返回当前进程账号。
func CurrentUser() string {
	u, err := ProcessUser(uint32(os.Getpid()))
	if err != nil {
		return ""
	}
	return u
}

// VolumeOf 返回路径所在卷标（如 "C:"），用于区分系统盘与移动介质。
func VolumeOf(path string) string {
	if len(path) >= 2 && path[1] == ':' {
		return strings.ToUpper(path[:2])
	}
	if strings.HasPrefix(path, `\\`) {
		return "UNC"
	}
	return ""
}
