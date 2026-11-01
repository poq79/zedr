package detect

import (
	"os"
	"strings"
	"sync"

	"zedr/internal/agent/winapi"
)

var (
	rootOnce sync.Once
	rootPath string
)

// systemRoot 返回 Windows 目录（小写），用于判断模块是否来自系统目录。
func systemRoot() string {
	rootOnce.Do(func() {
		rootPath = strings.ToLower(strings.TrimRight(os.Getenv("SystemRoot"), `\`))
		if rootPath == "" {
			rootPath = `c:\windows`
		}
	})
	return rootPath
}

// isPublic 判断远端地址是否为公网。
func isPublic(ip string) bool {
	return winapi.IsPublicRemote(ip)
}
