// Package web 内嵌管理台静态资源，编译进二进制，无需额外部署前端。
package web

import (
	"embed"
	"io/fs"
)

//go:embed all:static
var embedded embed.FS

// FS 返回以 static 为根的文件系统，供 http.FileServer 直接使用。
func FS() fs.FS {
	sub, err := fs.Sub(embedded, "static")
	if err != nil {
		return nil
	}
	return sub
}
