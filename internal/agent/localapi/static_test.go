package localapi

import (
	"io/fs"
	"strings"
	"testing"
)

// 本地 UI 与探针的认证头必须同名。
// 项目改名的教训：前端还发旧头时页面能打开，但所有接口 401，
// 表现成"界面空白"而不是编译失败，回归成本很高。
func TestStaticUsesCurrentAuthHeader(t *testing.T) {
	raw, err := fs.ReadFile(FS(), "app.js")
	if err != nil {
		t.Fatalf("read embedded app.js: %v", err)
	}
	js := string(raw)
	if !strings.Contains(js, "X-ZEDR-Token") {
		t.Fatal("app.js 必须发送 X-ZEDR-Token")
	}
	if strings.Contains(js, "X-HG-Token") {
		t.Fatal("app.js 仍引用已废弃的 X-HG-Token")
	}
}

func TestStaticAssetsPresent(t *testing.T) {
	for _, name := range []string{
		"index.html",
		"styles.css",
		"app.js",
		"fonts/geist-sans-latin-400-normal.woff2",
		"fonts/geist-mono-latin-400-normal.woff2",
	} {
		if _, err := fs.Stat(FS(), name); err != nil {
			t.Fatalf("embed 缺少静态资源 %s: %v", name, err)
		}
	}
}
