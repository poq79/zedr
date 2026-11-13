//go:build windows
// +build windows

package hygiene

import (
	"os"
	"path/filepath"
	"sort"

	"golang.org/x/sys/windows/registry"
)

// BrowserExt/BrowserPolicy/BrowserReport 类型、riskyChromiumPerms、
// chromiumProfiles/scanChromium/readChromiumManifest/localizeName、
// firefoxProfileExts、dirExists/fileExists 定义在 hygiene_types.go
// （Chromium/Firefox 的 profile 内布局双平台一致，扫描逻辑共享）。

// chromiumBrowsers 声明要扫的 Chromium 系浏览器及其用户数据目录。
var chromiumBrowsers = []struct {
	id  string
	dir string // 相对 %LOCALAPPDATA%
}{
	{"chrome", `Google\Chrome\User Data`},
	{"edge", `Microsoft\Edge\User Data`},
}

// BrowserAudit 扫描浏览器扩展与策略。
//
// 覆盖范围：Chrome/Edge（Chromium 系，扫 Extensions 目录的 manifest）+
// Firefox（读 extensions.json）。启停状态刻意不标：Chromium 新版本把
// 启停记录放在带 HMAC 的 Secure Preferences 里，离线读它既不可靠也
// 没必要——清单与权限面才是本体检的价值。
func BrowserAudit() BrowserReport {
	out := BrowserReport{Extensions: []BrowserExt{}, Policies: []BrowserPolicy{}, Scanned: []string{}}

	local := localAppData()
	for _, b := range chromiumBrowsers {
		root := filepath.Join(local, filepath.FromSlash(b.dir))
		if !dirExists(root) {
			continue
		}
		out.Scanned = append(out.Scanned, b.id)
		out.Extensions = append(out.Extensions, scanChromium(b.id, root)...)
	}
	if appData() != "" {
		root := filepath.Join(appData(), "Mozilla", "Firefox")
		if dirExists(root) {
			out.Scanned = append(out.Scanned, "firefox")
			out.Extensions = append(out.Extensions, scanFirefox(root)...)
		}
	}
	out.Policies = append(out.Policies, chromiumPolicies()...)

	sort.Slice(out.Extensions, func(i, j int) bool {
		if out.Extensions[i].Browser != out.Extensions[j].Browser {
			return out.Extensions[i].Browser < out.Extensions[j].Browser
		}
		return out.Extensions[i].Name < out.Extensions[j].Name
	})
	return out
}

func scanFirefox(firefoxRoot string) []BrowserExt {
	out := []BrowserExt{}
	profRoot := filepath.Join(firefoxRoot, "Profiles")
	profs, err := os.ReadDir(profRoot)
	if err != nil {
		return out
	}
	for _, p := range profs {
		if !p.IsDir() {
			continue
		}
		for _, ext := range firefoxProfileExts(filepath.Join(profRoot, p.Name())) {
			// profile 名在解析函数之外补齐：同一段 extensions.json 解析
			// 逻辑被 Linux 侧复用，两平台 profile 目录层级不同。
			ext.Browser = "firefox"
			ext.Profile = p.Name()
			out = append(out, ext)
		}
	}
	return out
}

// chromiumPolicies 检查"策略强装扩展"。
//
// ExtensionInstallForcelist 里的扩展会随浏览器启动静默装入且用户无法
// 卸载——企业 IT 正常用它做管控，但同样是流氓软件与红队公认的持久化
// 位置，值得用户知情。
func chromiumPolicies() []BrowserPolicy {
	out := []BrowserPolicy{}
	for _, b := range []struct{ id, key string }{
		{"chrome", `SOFTWARE\Policies\Google\Chrome\ExtensionInstallForcelist`},
		{"edge", `SOFTWARE\Policies\Microsoft\Edge\ExtensionInstallForcelist`},
	} {
		k, err := registry.OpenKey(registry.LOCAL_MACHINE, b.key, registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		names, err := k.ReadValueNames(-1)
		k.Close()
		if err != nil || len(names) == 0 {
			continue
		}
		out = append(out, BrowserPolicy{
			Browser: b.id,
			Key:     b.key,
			Detail:  "策略强制安装的扩展列表（用户不可卸载）",
			Count:   len(names),
		})
	}
	return out
}

func localAppData() string {
	if v := os.Getenv("LOCALAPPDATA"); v != "" {
		return v
	}
	return ""
}

func appData() string {
	if v := os.Getenv("APPDATA"); v != "" {
		return v
	}
	return ""
}
