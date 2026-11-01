// Package localapi 内嵌桌面 UI 静态资源。
package localapi

import (
	"embed"
	"io/fs"
)

//go:embed all:static
var embedded embed.FS

// FS 返回以 static 为根的文件系统。
func FS() fs.FS {
	sub, err := fs.Sub(embedded, "static")
	if err != nil {
		return nil
	}
	return sub
}
