package hygiene

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/sys/windows/registry"
)

// BrowserExt 是一个浏览器扩展条目。
type BrowserExt struct {
	Browser string `json:"browser"` // chrome | edge | firefox
	Profile string `json:"profile"`
	ID      string `json:"id"`
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
	// HostWide 是"能看到你打开的所有网页"信号：<all_urls> 或通配 host 权限。
	HostWide bool `json:"host_wide"`
	// RiskyPerms 列出值得注意的权限（nativeMessaging/debugger/proxy 等），
	// 有扩展能改系统代理、读剪贴板、与本机任意程序通信——都是真实攻击面。
	RiskyPerms []string `json:"risky_perms,omitempty"`
}

// BrowserPolicy 是一条浏览器策略命中（企业下发正常，恶意下发是持久化手法）。
type BrowserPolicy struct {
	Browser string `json:"browser"`
	Key     string `json:"key"`
	Detail  string `json:"detail"`
	Count   int    `json:"count"`
}

// BrowserReport 是浏览器扩展审计结果。
type BrowserReport struct {
	Extensions []BrowserExt    `json:"extensions"`
	Policies   []BrowserPolicy `json:"policies"`
	// Scanned 说明扫了哪些浏览器；没有的不列——诚实缺席。
	Scanned []string `json:"scanned"`
}

// riskyChromiumPerms 是值得单独标注的 Chromium 扩展权限。
var riskyChromiumPerms = map[string]bool{
	"nativeMessaging": true, "debugger": true, "proxy": true,
	"management": true, "clipboardRead": true, "privacy": true,
	"declarativeNetRequest": true, "webRequest": true, "webRequestBlocking": true,
}

// chromiumBrowsers 声明要扫的 Chromium 系浏览器及其用户数据目录。
var chromiumBrowsers = []struct {
	id   string
	dir  string // 相对 %LOCALAPPDATA%
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

// chromiumProfiles 找出真实存在的 profile 目录：含 Preferences 的
// 一级子目录（Default、Profile 1…）。"System Profile"/"Guest Profile"
// 同样符合形态，一并扫描——它们同样能装扩展。
func chromiumProfiles(root string) []string {
	ents, err := os.ReadDir(root)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range ents {
		if !e.IsDir() {
			continue
		}
		if fileExists(filepath.Join(root, e.Name(), "Preferences")) {
			out = append(out, e.Name())
		}
	}
	sort.Strings(out)
	return out
}

func scanChromium(browser, root string) []BrowserExt {
	out := []BrowserExt{}
	for _, prof := range chromiumProfiles(root) {
		extRoot := filepath.Join(root, prof, "Extensions")
		ids, err := os.ReadDir(extRoot)
		if err != nil {
			continue
		}
		for _, idEnt := range ids {
			if !idEnt.IsDir() {
				continue
			}
			ext := BrowserExt{Browser: browser, Profile: prof, ID: idEnt.Name()}
			// 同一扩展可能有多个版本目录，取字典序最大（Chromium 安装
			// 新版本不清旧目录，字典序最大即当前生效版本）。
			vers, _ := os.ReadDir(filepath.Join(extRoot, idEnt.Name()))
			var verName string
			for _, v := range vers {
				if v.IsDir() && v.Name() > verName {
					verName = v.Name()
				}
			}
			if verName == "" {
				continue
			}
			ext.Version = verName
			readChromiumManifest(filepath.Join(extRoot, idEnt.Name(), verName), &ext)
			out = append(out, ext)
		}
	}
	return out
}

// readChromiumManifest 解析 manifest.json：名称（处理 __MSG_ 本地化）、
// 宽主机权限、敏感权限。
func readChromiumManifest(dir string, ext *BrowserExt) {
	raw, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		ext.Name = "(manifest 不可读)"
		return
	}
	var m struct {
		Name            string   `json:"name"`
		DefaultLocale   string   `json:"default_locale"`
		Permissions     []string `json:"permissions"`
		HostPermissions []string `json:"host_permissions"`
		OptionalPerms   []string `json:"optional_permissions"`
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		ext.Name = "(manifest 解析失败)"
		return
	}
	ext.Name = localizeName(dir, m.Name, m.DefaultLocale)

	all := append(append([]string{}, m.Permissions...), m.OptionalPerms...)
	for _, p := range all {
		if riskyChromiumPerms[p] {
			ext.RiskyPerms = append(ext.RiskyPerms, p)
		}
	}
	for _, h := range append(append([]string{}, m.HostPermissions...), all...) {
		if h == "<all_urls>" || h == "*://*/" || h == "http://*/" || h == "https://*/" {
			ext.HostWide = true
		}
	}
}

// localizeName 解析 __MSG_key__ 形式的名称：按 default_locale、en、en_US
// 顺序找 messages.json。找不到保留原样——不是错误。
func localizeName(dir, name, defaultLocale string) string {
	if !strings.HasPrefix(name, "__MSG_") || !strings.HasSuffix(name, "__") {
		return name
	}
	key := strings.TrimSuffix(strings.TrimPrefix(name, "__MSG_"), "__")
	locales := []string{defaultLocale, "en", "en_US"}
	for _, loc := range locales {
		if loc == "" {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, "_locales", loc, "messages.json"))
		if err != nil {
			continue
		}
		var msgs map[string]struct {
			Message string `json:"message"`
		}
		if json.Unmarshal(raw, &msgs) != nil {
			continue
		}
		// 消息键大小写不敏感（Chromium 实际按小写匹配）
		for k, m := range msgs {
			if strings.EqualFold(k, key) && m.Message != "" {
				return m.Message
			}
		}
	}
	return name
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
		raw, err := os.ReadFile(filepath.Join(profRoot, p.Name(), "extensions.json"))
		if err != nil {
			continue
		}
		var entries []struct {
			ID      string `json:"id"`
			Version string `json:"version"`
			Active  bool   `json:"active"`
			// userDisabled 区分用户手动停用与默认启用
			UserDisabled bool `json:"userDisabled"`
			Visible      bool `json:"visible"`
			DefaultLocale struct {
				Name string `json:"name"`
			} `json:"defaultLocale"`
			Permissions struct {
				Origins []string `json:"origins"`
				APIs    []string `json:"apis"`
			} `json:"permissions"`
		}
		if json.Unmarshal(raw, &entries) != nil {
			continue
		}
		for _, e := range entries {
			name := strings.TrimSpace(e.DefaultLocale.Name)
			if name == "" && e.ID == "" {
				continue
			}
			ext := BrowserExt{
				Browser: "firefox", Profile: p.Name(), ID: e.ID,
				Name:    firstNonEmpty(name, e.ID),
				Version: e.Version,
			}
			for _, o := range e.Permissions.Origins {
				if o == "<all_urls>" || strings.HasPrefix(o, "*://") {
					ext.HostWide = true
				}
			}
			for _, a := range e.Permissions.APIs {
				if riskyChromiumPerms[a] {
					ext.RiskyPerms = append(ext.RiskyPerms, a)
				}
			}
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

func dirExists(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.IsDir()
}

func fileExists(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && !fi.IsDir()
}
