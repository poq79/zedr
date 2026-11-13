//go:build windows

package detect

import (
	"os"
	"strings"
	"sync"
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
