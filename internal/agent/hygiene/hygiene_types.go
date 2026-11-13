// Package hygiene 提供本地面板的"泛安全体检"数据：已安装软件、安全配置
// 姿势、网络暴露面、浏览器扩展、自启动项审计。
//
// 定位与检测引擎互补：检测引擎回答"现在正在发生什么攻击"，本包回答
// "这台机器长期处于什么状态"。全部采集只读（Windows：注册表 QUERY_VALUE、
// 文件系统读、WinVerifyTrust；Linux：/proc 与 /etc 只读解析），没有任何
// 写操作入口——本地面板的用户看到的是体检报告和手动处置指引，不是
// 一键修复按钮（产品原则见 AGENTS.md §3.8：检测优先，响应动作保持默认关闭）。
//
// 所有入口按需调用（打开对应视图时），不在扫描循环里运行；
// 签名/版本信息读取有 (path,size,mtime) 缓存，重复打开视图近零成本。
//
// 文件分层：本文件是双平台共享的类型定义与纯逻辑（无构建标签）；
// hygiene*.go（windows 标签）是 Windows 采集实现，hygiene_linux.go 是
// Linux 采集实现。两侧必须提供同名导出符号（Apps/Posture/Exposure/
// BrowserAudit/NewAuditor/Auditor.Audit），app/localapi 依赖它们。
package hygiene

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

// ---------------------------------------------------------------- 文件画像

// fileMeta 是一个可执行文件的体检画像（签名 + 版本资源 + 存在性）。
// Windows 上 SigState/Signer/Company/Description 来自 Authenticode 与
// 版本资源；Linux v1 只填 Exists（无等价签名基础设施，诚实留空——
// 字段保持同形状，服务端/前端零分叉）。
type fileMeta struct {
	Exists      bool   `json:"exists"`
	Signed      bool   `json:"signed"`
	SigState    string `json:"sig_state"` // valid | unsigned | untrusted | ...
	Signer      string `json:"signer,omitempty"`
	Company     string `json:"company,omitempty"`
	Description string `json:"description,omitempty"`
}

// fileCache 按 (path,size,mtime) 缓存文件画像。WinVerifyTrust 单次
// 数毫秒到数十毫秒，一次驻留体检可能枚举上百个文件，没有缓存的话
// 每次打开视图都是一次全量重验。Linux 上只做 Stat，缓存同样省掉
// 重复路径解析。
type fileCache struct {
	mu sync.Mutex
	m  map[string]fileMeta
}

func newFileCache() *fileCache {
	return &fileCache{m: make(map[string]fileMeta)}
}

// limit 是缓存条目上限：自启动项 + 软件资产通常几百个文件；超过说明
// 键在快速变化（软件正在装卸），整表重置即可，不是错误。
const cacheLimit = 4096

// probeFile 读取一个文件的体检画像，带 (path,size,mtime) 缓存。
// inspectFile 是平台实现（windows 标签 / linux 标签各一份）。
func (c *fileCache) probeFile(path string) fileMeta {
	if path == "" {
		return fileMeta{}
	}
	key := path
	if fi, err := os.Stat(path); err == nil {
		key = path + "|" + itoa(fi.Size()) + "|" + itoa(fi.ModTime().UnixNano())
	}

	c.mu.Lock()
	if hit, ok := c.m[key]; ok {
		c.mu.Unlock()
		return hit
	}
	c.mu.Unlock()

	meta := inspectFile(path)

	c.mu.Lock()
	if len(c.m) >= cacheLimit {
		c.m = make(map[string]fileMeta)
	}
	c.m[key] = meta
	c.mu.Unlock()
	return meta
}

func itoa(n int64) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [21]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

// ---------------------------------------------------------------- 软件资产

// InstalledApp 是一个已安装软件条目。
//
// 数据面：Windows 来自三处 Uninstall 注册表键 + Appx 机器级注册表
// （刻意不用 WMI Win32_Product——它会触发 MSI 自修复，违反只读纪律）；
// Linux 来自 dpkg status 文件 / rpm 查询 / /usr/local 与 /opt 目录清单
// （见 hygiene_linux.go 的采集口径注释）。
type InstalledApp struct {
	Name      string `json:"name"`
	Version   string `json:"version,omitempty"`
	Publisher string `json:"publisher,omitempty"`
	// InstallDate 是安装日期原串（Windows 通常 yyyymmdd）；缺失留空。
	InstallDate string `json:"install_date,omitempty"`
	SizeKB      uint64 `json:"size_kb,omitempty"`
	Location    string `json:"location,omitempty"`
	// Source: win32 | store | dpkg | rpm | dir
	Source string `json:"source"`
	// Hidden 是"从卸载列表里藏起来"的信号：SystemComponent=1 的条目
	// 不会出现在系统"应用和功能"里——正常软件极少这样做，捆装/流氓
	// 软件常用来躲卸载入口。NoRemove=1 表示连卸载按钮都被藏了。
	// Linux 采集源没有这两个语义，恒 false。
	Hidden   bool `json:"hidden"`
	NoRemove bool `json:"no_remove"`
}

// ---------------------------------------------------------------- 安全姿势

// Check 是一条体检项。State 用三色语义（对齐 Windows 安全中心的绿/黄/红
// 惯例）：ok=正常，warn=需关注，err=高风险；info=无法判断/仅陈述事实。
// 刻意不做数字总分——"92 分"式的评分无法解释每一分的来源，只会制造
// 虚假安全感；这里每一项都必须自带"为什么"和"怎么办"。
type Check struct {
	ID     string `json:"id"`
	Group  string `json:"group"` // config | update | privacy
	Title  string `json:"title"`
	State  string `json:"state"` // ok | warn | err | info
	Value  string `json:"value"`
	Why    string `json:"why"`
	Advice string `json:"advice,omitempty"`
}

// ---------------------------------------------------------------- 驻留画像

// PersistAudit 是一个自启动项的体检画像。
//
// 对标 Sysinternals Autoruns 的着色逻辑（粉=无描述/无签名，黄=文件
// 缺失），但只读：这里不提供禁用入口——禁用是写操作，产品原则要求
// 保持"检测优先、处置默认关闭"。用户看到画像与处置指引，动作留给
// 用户自己。
type PersistAudit struct {
	Key      string `json:"key"`
	Kind     string `json:"kind"`
	Location string `json:"location"`
	Name     string `json:"name,omitempty"`
	Command  string `json:"command"`
	Enabled  bool   `json:"enabled"`
	RunAs    string `json:"run_as,omitempty"`
	Elevated bool   `json:"elevated"`
	Trigger  string `json:"trigger,omitempty"`
	// ExePath 是从 Command 里定位出的可执行文件；定位不到留空。
	ExePath string   `json:"exe_path,omitempty"`
	File    fileMeta `json:"file"`
	// InBaseline 为 false 表示该条目还没有进入持久化基线——通常只是
	// 探针还没跑完下一个扫描周期；若长时间为 false，说明这是新出现的
	// 自启动点，值得看一眼。
	InBaseline bool     `json:"in_baseline"`
	Flags      []string `json:"flags,omitempty"`
}

// 审计 flags 取值。
const (
	FlagUnsigned    = "unsigned"     // 文件存在但没有可信签名（Autoruns 粉）
	FlagFileMissing = "file_missing" // 指向的文件已不存在（Autoruns 黄）
	FlagNoInfo      = "no_info"      // 无发布者且无描述（Autoruns 粉）
	FlagElevated    = "elevated"     // 以最高权限运行
	FlagNew         = "new"          // 尚未进入持久化基线
)

// Auditor 是带文件画像缓存的驻留审计器。
//
// 为什么不做成函数：缓存要跨请求存活（打开视图→切换→再打开不应重新
// 验签全部文件），生命周期应与 Agent 一致。Windows 的现场枚举在
// audit.go（winapi.EnumeratePersistence）；Linux 的数据注入在
// hygiene_linux.go（AuditItems，persist 基线条目 → 画像）。
type Auditor struct {
	cache *fileCache
}

// ---------------------------------------------------------------- 网络暴露面

// Listener 是一个本机监听端点及其进程归属。
type Listener struct {
	Proto   string `json:"proto"`
	Addr    string `json:"addr"` // ip:port
	Port    uint16 `json:"port"`
	Scope   string `json:"scope"` // loopback | lan | any —— 暴露面的关键维度
	Process string `json:"process,omitempty"`
}

// HostEntry 是 hosts 文件里一条非注释映射。
type HostEntry struct {
	IP       string `json:"ip"`
	Hostname string `json:"hostname"`
}

// HostsReport 是 hosts 文件体检结果。
type HostsReport struct {
	Entries  []HostEntry `json:"entries"`
	Readable bool        `json:"readable"`
	Note     string      `json:"note,omitempty"`
}

// ProxyReport 是系统代理配置。
type ProxyReport struct {
	Enabled       bool   `json:"enabled"`
	Server        string `json:"server,omitempty"`
	AutoConfigURL string `json:"auto_config_url,omitempty"`
	Override      string `json:"override,omitempty"`
}

// ExposureReport 是网络暴露面快照：谁能连到这台机器的什么。
type ExposureReport struct {
	Listeners []Listener  `json:"listeners"`
	Hosts     HostsReport `json:"hosts"`
	Proxy     ProxyReport `json:"proxy"`
}

// listenerScope 判定一个监听地址的可达范围。
// any（0.0.0.0/::）= 所有网卡可达，局域网内任何设备都能连到；
// lan = 绑定在具体内网地址；loopback = 仅本机可达（最安全）。
func listenerScope(ip string) string {
	switch ip {
	case "0.0.0.0", "::":
		return "any"
	case "127.0.0.1", "::1":
		return "loopback"
	default:
		return "lan"
	}
}

// readHostsFile 解析指定路径的 hosts 文件；拆出路径参数供双平台与测试
// 使用（Windows hostsPath()、Linux /etc/hosts）。
//
// 默认 hosts 只有 localhost 映射与注释；任何额外条目都值得用户看一眼
// ——把杀毒/银行/更新域名指到别处是经典的劫持手法。本机无法离线验证
// "指得对不对"，所以只列条目并说明这一点，不做虚判定。
func readHostsFile(path string) HostsReport {
	rep := HostsReport{}
	f, err := os.Open(path)
	if err != nil {
		rep.Note = "无法读取 hosts 文件（权限或路径异常）"
		return rep
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		rep.Entries = append(rep.Entries, HostEntry{IP: fields[0], Hostname: fields[1]})
	}
	rep.Readable = true
	return rep
}

// ---------------------------------------------------------------- 浏览器扩展

// BrowserExt 是一个浏览器扩展条目。
type BrowserExt struct {
	Browser string `json:"browser"` // chrome | edge | chromium | firefox
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

// scanChromium 扫描一个 Chromium 系浏览器的用户数据目录（Windows 与
// Linux 目录布局一致：root/<profile>/Extensions/<id>/<version>/manifest.json）。
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

// firefoxProfileExts 解析单个 Firefox profile 目录的 extensions.json
// （Windows 与 Linux 的 profile 内布局一致，差异只在 profile 目录的
// 上级路径：Windows 是 %APPDATA%\Mozilla\Firefox\Profiles\*，
// Linux 是 ~/.mozilla/firefox/*）。
func firefoxProfileExts(profileDir string) []BrowserExt {
	raw, err := os.ReadFile(filepath.Join(profileDir, "extensions.json"))
	if err != nil {
		return nil
	}
	var entries []struct {
		ID      string `json:"id"`
		Version string `json:"version"`
		Active  bool   `json:"active"`
		// userDisabled 区分用户手动停用与默认启用
		UserDisabled  bool `json:"userDisabled"`
		Visible       bool `json:"visible"`
		DefaultLocale struct {
			Name string `json:"name"`
		} `json:"defaultLocale"`
		Permissions struct {
			Origins []string `json:"origins"`
			APIs    []string `json:"apis"`
		} `json:"permissions"`
	}
	if json.Unmarshal(raw, &entries) != nil {
		return nil
	}
	out := []BrowserExt{}
	for _, e := range entries {
		name := strings.TrimSpace(e.DefaultLocale.Name)
		if name == "" && e.ID == "" {
			continue
		}
		ext := BrowserExt{ID: e.ID, Name: firstNonEmpty(name, e.ID), Version: e.Version}
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
	return out
}

// ---------------------------------------------------------------- 通用小工具

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
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
