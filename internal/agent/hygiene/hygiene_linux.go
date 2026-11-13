//go:build linux

package hygiene

// hygiene_linux.go — 泛安全体检五视图的 Linux 采集实现。
//
// **未在 Linux 实机验证**（本机无 Linux 测试环境）：本文件按
// /proc、/etc、XDG 目录的文档化布局实现，验证口径 = GOOS=linux
// 交叉编译 + linuxparse.go/persistaudit.go 纯逻辑单测（Windows 上跑）。
// 实机校准项（首日在真实 Linux 上要复核的）：/proc/net/tcp6 地址
// 字节序还原、dpkg status 分段解析对发行版魔改的兼容、浏览器
// profile 目录布局。
//
// 纪律与 Windows 版同一条宪法：全部只读（os.Open/os.ReadDir/os.Stat），
// 不执行任何写操作，不提供一键修复；外部命令只用 exec.Command 直参
// （不经过 shell 拼接），且只允许查询类（rpm -qa）。
//
// 导出符号与 Windows 版同名同签名：Apps/Posture/Exposure/BrowserAudit/
// NewAuditor/Auditor.Audit（app/localapi 的 Backend 契约依赖）。

import (
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"zedr/internal/agent/persist"
)

// ---------------------------------------------------------------- 驻留画像

// NewAuditor 创建审计器（与 Windows 同签名；文件画像缓存在
// hygiene_types.go 的 fileCache，双平台共享）。
func NewAuditor() *Auditor {
	return &Auditor{cache: newFileCache()}
}

// inspectFile 无缓存读取：Linux v1 只有存在性画像。没有 Windows
// Authenticode 的等价物（包签名校验需要 dpkg-verify/rpm -V 级别的
// 生态上下文，v1 不做——fileMeta 的 Signed/SigState 诚实留零值）。
func inspectFile(path string) fileMeta {
	meta := fileMeta{}
	fi, err := os.Stat(path)
	meta.Exists = err == nil && !fi.IsDir()
	return meta
}

// Audit 实时枚举自启动项并画像——Linux v1 无现场枚举器，返回空视图。
//
// 数据注入路径：组合根把 persist 基线条目（persist.Monitor.Items() 或
// persist 包 Linux 枚举结果）映射成 PersistSource 后调
// Auditor.AuditSources（persistaudit.go，纯逻辑，Windows 上有单测）。
// 这里保留同名方法是为了 app/localapi 的 Backend 契约在双平台可编译；
// 返回空切片（而非 nil）维持 JSON 输出 [] 的口径。
func (a *Auditor) Audit(baselineKeys map[string]bool) []PersistAudit {
	_ = baselineKeys // 基线外判定在 AuditSources 里做；空视图下无意义
	return []PersistAudit{}
}

// AuditPersistItems 是组合根的便捷入口：直接消费 persist 包的条目。
// persist.PersistItem 与 PersistSource 字段一一对应（见 persistaudit.go
// 的解耦说明——这里是唯一的映射点，persist 侧字段变更只改这一处）。
func (a *Auditor) AuditPersistItems(items []persist.PersistItem, baselineKeys map[string]bool) []PersistAudit {
	src := make([]PersistSource, 0, len(items))
	for _, it := range items {
		src = append(src, PersistSource{
			Key:      it.Key,
			Kind:     it.Type,
			Location: it.Location,
			Name:     it.Name,
			Command:  it.Command,
			Enabled:  it.Enabled,
			Elevated: it.Elevated,
			RunAs:    it.RunAs,
			Trigger:  it.Trigger,
		})
	}
	return a.AuditSources(src, baselineKeys)
}

// ---------------------------------------------------------------- 软件资产

// rpmQf 是 rpm -qa 的查询格式：name/version/size 三列，TAB 分隔。
// 用 --qf 而非解析 human 文本，是因为 rpm 默认输出格式随发行版配置漂移。
const rpmQf = "%{NAME}\\t%{VERSION}\\t%{SIZE}\\n"

// Apps 枚举已安装软件。采集优先级：包管理器（dpkg status 文件 / rpm -qa）
// 是真实软件面；/usr/local 与 /opt 目录清单是"绕过包管理器装的散装
// 程序"——恰恰是攻防里更值得看一眼的东西，所以虽然口径粗糙也要列。
// 单个来源失败降级继续，不让整个视图空白。
func Apps() []InstalledApp {
	apps := []InstalledApp{}

	// dpkg 系：直接读 status 文件（dpkg -l 依赖 dpkg 在 PATH 且列宽
	// 截断名字，读文件反而更稳更全）
	if data, err := os.ReadFile("/var/lib/dpkg/status"); err == nil {
		apps = append(apps, parseDpkgStatus(data)...)
	} else {
		slog.Warn("hygiene_apps_source_failed", "source", "dpkg", "err", err.Error())
	}

	// rpm 系：优先 rpm -qa（BerkeleyDB 的 /var/lib/rpm/Packages 二进制
	// 格式离线解析成本高且随 rpm 版本漂移，v1 不做——诚实边界）
	if out, err := exec.Command("rpm", "-qa", "--qf", rpmQf).Output(); err == nil {
		apps = append(apps, parseRpmQA(out)...)
	} else {
		slog.Info("hygiene_apps_source_unavailable", "source", "rpm", "hint", "rpm 不在 PATH 或非 rpm 系发行版，跳过")
	}

	apps = append(apps, dirApps("/usr/local/bin")...)
	apps = append(apps, optApps()...)

	sort.Slice(apps, func(i, j int) bool {
		if apps[i].Name != apps[j].Name {
			return apps[i].Name < apps[j].Name
		}
		return apps[i].Version < apps[j].Version
	})
	return apps
}

// dirApps 枚举一个散装可执行目录（/usr/local/bin）。文件名即"软件名"，
// 版本未知留空——不猜。
func dirApps(dir string) []InstalledApp {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	out := make([]InstalledApp, 0, len(ents))
	for i, e := range ents {
		if i >= dirAppsLimit {
			slog.Warn("hygiene_apps_dir_truncated", "dir", dir, "limit", dirAppsLimit)
			break
		}
		if e.IsDir() {
			continue
		}
		app := InstalledApp{Name: e.Name(), Location: filepath.Join(dir, e.Name()), Source: "dir"}
		if fi, err := e.Info(); err == nil {
			app.SizeKB = uint64(fi.Size()) / 1024
		}
		out = append(out, app)
	}
	return out
}

// optApps 枚举 /opt 一级目录（第三方/自装软件的惯例落点）。
func optApps() []InstalledApp {
	ents, err := os.ReadDir("/opt")
	if err != nil {
		return nil
	}
	out := make([]InstalledApp, 0, len(ents))
	for i, e := range ents {
		if i >= dirAppsLimit {
			slog.Warn("hygiene_apps_dir_truncated", "dir", "/opt", "limit", dirAppsLimit)
			break
		}
		if !e.IsDir() {
			continue
		}
		out = append(out, InstalledApp{
			Name:     e.Name(),
			Location: filepath.Join("/opt", e.Name()),
			Source:   "dir",
		})
	}
	return out
}

// ---------------------------------------------------------------- 安全姿势

// Posture 汇总 Linux 安全配置体检。采集源全部是 /etc 下配置文件——
// 与 Windows 版（注册表）口径对齐的地方在于判定结构（Check 三色 +
// Why + Advice），不在检查项清单（两平台的风险面本来就不同）。
func Posture() []Check {
	checks := make([]Check, 0, 8)
	checks = append(checks,
		checkSshdRootLogin(),
		checkSshdPasswordAuth(),
		checkSudoNopasswd(),
		checkPasswordPolicy(),
		checkWorldWritableEtc(),
	)
	return checks
}

// sshdConfigPath 是 sshd 主配置的标准位置。Include 指令的子配置
// （/etc/ssh/sshd_config.d/*）v1 不跟随——很多发行版（Debian 12+）
// 把真实配置放在那里，这是当前最大的口径缺口，诚实标注：
// 读取主文件 + 显式检查 sshd_config.d 目录里是否有覆盖项。
func checkSshdRootLogin() Check {
	c := Check{ID: "sshd_root_login", Group: "config", Title: "SSH root 登录",
		Why: " PermitRootLogin yes 时，暴露的 SSH 端口直接接受 root 口令/密钥爆破，是互联网上被扫得最狠的入口之一。"}
	val, ok, note := sshdEffective("permitrootlogin")
	switch {
	case !ok:
		c.State, c.Value = "info", "无法判断（未发现 sshd_config"+note+"）"
	case val == "yes":
		c.State, c.Value, c.Advice = "warn", "允许 root 直接登录",
			"在 /etc/ssh/sshd_config 设 PermitRootLogin prohibit-password 或 no，并重启 sshd。"
	case val == "prohibit-password", val == "without-password":
		c.State, c.Value = "ok", "仅密钥登录（prohibit-password）"
	default:
		c.State, c.Value = "ok", "已禁止（"+val+"）"
	}
	return c
}

func checkSshdPasswordAuth() Check {
	c := Check{ID: "sshd_password_auth", Group: "config", Title: "SSH 口令认证",
		Why: "PasswordAuthentication 开着时，暴露的 SSH 端口可以被在线爆破；密钥-only 是目前公认的最低标准。"}
	val, ok, note := sshdEffective("passwordauthentication")
	switch {
	case !ok:
		c.State, c.Value = "info", "未显式配置（OpenSSH 默认 yes）"+note
	case val == "yes":
		c.State, c.Value, c.Advice = "warn", "允许口令登录",
			"在 /etc/ssh/sshd_config 设 PasswordAuthentication no（先确认密钥可登录），并重启 sshd。"
	default:
		c.State, c.Value = "ok", "仅密钥认证"
	}
	return c
}

// sshdEffective 读 sshd_config 里某键的生效值。返回值解释：
// ok=false 表示"无法判断"（文件缺失或键未出现——两者语义不同但处置
// 相同：不冒充测量结果），note 带原因供 Value 拼接。
func sshdEffective(key string) (val string, ok bool, note string) {
	data, err := os.ReadFile("/etc/ssh/sshd_config")
	if err != nil {
		return "", false, "（未安装 SSH 服务或配置不可读）"
	}
	m := parseSshdEffective(data)
	v, found := m[key]
	if !found {
		// sshd_config.d 覆盖目录：Debian 12+/Ubuntu 22.04+ 的默认配置
		// 常落在那里，主文件缺席≠服务没配
		if v, ok := sshdDirOverride(key); ok {
			return v, true, ""
		}
		return "", false, "；键未显式配置，按 OpenSSH 内置默认"
	}
	return v, true, ""
}

// sshdDirOverride 扫 /etc/ssh/sshd_config.d/*.conf 的第一层覆盖值。
// 同样只认"第一次出现"语义；子配置按文件名序合并——真实 sshd 的
// Include 合并顺序是主文件 Include 指令位置决定，离线无法完全还原，
// 这里给的是"明面值"，Value/Advice 里如实按配置文本判定。
func sshdDirOverride(key string) (string, bool) {
	ents, err := os.ReadDir("/etc/ssh/sshd_config.d")
	if err != nil {
		return "", false
	}
	names := make([]string, 0, len(ents))
	for _, e := range ents {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".conf") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	for _, n := range names {
		if data, err := os.ReadFile(filepath.Join("/etc/ssh/sshd_config.d", n)); err == nil {
			if v, ok := parseSshdEffective(data)[key]; ok {
				return v, true
			}
		}
	}
	return "", false
}

func checkSudoNopasswd() Check {
	c := Check{ID: "sudo_nopasswd", Group: "config", Title: "sudo 免密提权（NOPASSWD）",
		Why: "NOPASSWD 条目让指定命令不再有口令闸门——任何拿到该会话的进程（包括被入侵的应用）都能静默提权。"}
	lines := readAllLines("/etc/sudoers")
	for _, p := range sudoersDropins() {
		lines = append(lines, readAllLines(p)...)
	}
	if len(lines) == 0 {
		c.State, c.Value = "info", "无法判断（sudoers 不可读，通常需要 root）"
		return c
	}
	n := countSudoNopasswd(lines)
	if n == 0 {
		c.State, c.Value = "ok", "无 NOPASSWD 免密条目"
		return c
	}
	c.State, c.Value, c.Advice = "warn",
		fmt.Sprintf("%d 条 NOPASSWD 条目", n),
		"核对 /etc/sudoers 与 /etc/sudoers.d/*：仅对确需自动化提权的命令放行，收窄到具体命令路径。"
	return c
}

// sudoersDropins 列出 /etc/sudoers.d 下的文件（跳过以 . 开头的禁用项，
// 与 sudoers(5) 的 @includedir 语义一致）。
func sudoersDropins() []string {
	ents, err := os.ReadDir("/etc/sudoers.d")
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range ents {
		if e.IsDir() || strings.HasPrefix(e.Name(), ".") || strings.Contains(e.Name(), "~") {
			continue
		}
		out = append(out, filepath.Join("/etc/sudoers.d", e.Name()))
	}
	sort.Strings(out)
	return out
}

func checkPasswordPolicy() Check {
	c := Check{ID: "password_policy", Group: "config", Title: "口令有效期策略（login.defs）",
		Why: "PASS_MAX_DAYS 过长意味着一个泄露的口令可以无限期继续使用；本项与 PAM 模块的实际约束互补（后者在 /etc/pam.d）。"}
	data, err := os.ReadFile("/etc/login.defs")
	if err != nil {
		c.State, c.Value = "info", "无法判断（login.defs 不可读）"
		return c
	}
	m := parseLoginDefs(data)
	maxDays := m["PASS_MAX_DAYS"]
	minDays := m["PASS_MIN_DAYS"]
	minLen := m["PASS_MIN_LEN"]
	parts := []string{
		"PASS_MAX_DAYS=" + orUnset(maxDays),
		"PASS_MIN_DAYS=" + orUnset(minDays),
		"PASS_MIN_LEN=" + orUnset(minLen),
	}
	c.Value = strings.Join(parts, "，")
	// login.defs 只约束 shadow 工具新建用户时的默认值，不追溯既有账户
	//——所以只对明显过松的默认值给 warn，不做虚假的"全局强度"判断。
	if n, err := strconv.Atoi(orZero(maxDays)); err == nil && n > 90 {
		c.State, c.Advice = "warn", "建议把 PASS_MAX_DAYS 收到 90 以内（login.defs 只影响新建用户，存量账户用 chage 逐个调整）。"
		return c
	}
	c.State = "info"
	c.Value += "；本机体检不联网核对 PAM 实际约束，仅陈述 login.defs 默认值"
	return c
}

func checkWorldWritableEtc() Check {
	c := Check{ID: "world_writable_etc", Group: "config", Title: "/etc 世界可写文件",
		Why: "/etc 下的配置决定系统服务怎么跑；任何人对配置目录有写权限，就等于有了一条静默改持久化/改服务命令的路径。"}
	// V1 口径：只扫 /etc（任务定义的最保守集合）。/tmp、/var/tmp、
	// /dev/shm 的世界可写面更大但动态性极强（瞬时文件噪声高），
	// 放到后续版本带白名单基线后再开。
	var bad []string
	err := filepath.WalkDir("/etc", func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil // 权限不足/已删除的条目跳过，不中断
		}
		if d.IsDir() {
			return nil
		}
		if fi, err := d.Info(); err == nil && modeWorldWritable(fi.Mode()) {
			bad = append(bad, path)
		}
		return nil
	})
	if err != nil {
		c.State, c.Value = "info", "无法判断（/etc 遍历失败）"
		return c
	}
	sort.Strings(bad)
	if len(bad) == 0 {
		c.State, c.Value = "ok", "无世界可写文件"
		return c
	}
	shown := bad
	if len(shown) > 5 {
		shown = shown[:5]
	}
	c.State, c.Value, c.Advice = "warn",
		fmt.Sprintf("%d 个世界可写文件（%s…）", len(bad), strings.Join(shown, ", ")),
		"核查这些文件为什么对 other 开放写权限（chmod o-w）；陌生文件应直接下线。"
	return c
}

// ---------------------------------------------------------------- 网络暴露面

// Exposure 采集网络暴露面。pidName 由调用方注入（进程名归属属于探针的
// 进程视图，与本包解耦，语义同 Windows 版）；/proc/net 的行只有 socket
// inode，进程归属经 /proc/[pid]/fd 反查后再用 pidName 命名。
func Exposure(pidName map[uint32]string) ExposureReport {
	exp := ExposureReport{Hosts: readHostsFile("/etc/hosts"), Proxy: readProxyEnv()}

	var rows []linuxNetRow
	for _, src := range []struct{ file, proto string }{
		{"/proc/net/tcp", "tcp"}, {"/proc/net/tcp6", "tcp"},
		{"/proc/net/udp", "udp"}, {"/proc/net/udp6", "udp"},
	} {
		if data, err := os.ReadFile(src.file); err == nil {
			rows = append(rows, parseProcNet(src.proto, string(data))...)
		}
	}
	inodePID := scanSocketInodes()

	seen := make(map[string]bool, 32)
	for _, r := range rows {
		// TCP 只认 LISTEN（st=0A）；UDP 无连接状态，有本地端口即端点
		//（与 Windows 版 isListenerRow 同口径）
		if r.Proto == "tcp" && r.State != procTCPListenHex {
			continue
		}
		addr := fmt.Sprintf("%s:%d", r.LocalIP, r.LocalPort)
		key := addr + r.Proto
		if seen[key] {
			continue
		}
		seen[key] = true
		pid := inodePID[r.Inode]
		name := ""
		if pid != 0 {
			name = pidName[pid]
		}
		exp.Listeners = append(exp.Listeners, Listener{
			Proto:   r.Proto,
			Addr:    addr,
			Port:    r.LocalPort,
			Scope:   listenerScope(r.LocalIP),
			Process: name,
		})
	}
	sort.Slice(exp.Listeners, func(i, j int) bool {
		// 暴露面从大到小：any > lan > loopback，同级按端口号（Windows 版同序）
		w := map[string]int{"any": 0, "lan": 1, "loopback": 2}
		if w[exp.Listeners[i].Scope] != w[exp.Listeners[j].Scope] {
			return w[exp.Listeners[i].Scope] < w[exp.Listeners[j].Scope]
		}
		return exp.Listeners[i].Port < exp.Listeners[j].Port
	})
	return exp
}

// scanSocketInodes 反查 socket inode → PID：遍历 /proc/[pid]/fd 的
// "socket:[inode]" 符号链接。这是本视图最贵的一步（O(进程×fd)），
// 但体检是按需触发（打开暴露面视图才跑），不在扫描循环里。
func scanSocketInodes() map[uint64]uint32 {
	out := make(map[uint64]uint32, 64)
	ents, err := os.ReadDir("/proc")
	if err != nil {
		return out
	}
	for _, e := range ents {
		if !e.IsDir() {
			continue
		}
		pid, err := strconv.ParseUint(e.Name(), 10, 32)
		if err != nil {
			continue
		}
		fds, err := os.ReadDir("/proc/" + e.Name() + "/fd")
		if err != nil {
			continue // 权限不足或进程已退出
		}
		for _, fd := range fds {
			link, err := os.Readlink("/proc/" + e.Name() + "/fd/" + fd.Name())
			if err != nil {
				continue
			}
			// 形态："socket:[12345]"
			if !strings.HasPrefix(link, "socket:[") || !strings.HasSuffix(link, "]") {
				continue
			}
			inode, err := strconv.ParseUint(link[8:len(link)-1], 10, 64)
			if err != nil {
				continue
			}
			// 同一 socket 可能被多个进程共享（fork）；先到先得，不做
			// "唯一持有者"的虚假判定
			if _, ok := out[inode]; !ok {
				out[inode] = uint32(pid)
			}
		}
	}
	return out
}

// readProxyEnv 读 Linux 的"事实代理"：环境变量。Linux 没有统一的系统
// 代理存储（GNOME/KDE 各一套 gsettings/dconf，桌面外不生效），CLI 与
// 服务进程普遍只认环境变量——v1 只报这个口径，桌面代理不覆盖（诚实边界）。
func readProxyEnv() ProxyReport {
	rep := ProxyReport{}
	for _, k := range []string{"http_proxy", "HTTP_PROXY", "https_proxy", "HTTPS_PROXY", "all_proxy", "ALL_PROXY"} {
		if v := os.Getenv(k); v != "" {
			rep.Enabled = true
			if rep.Server == "" {
				rep.Server = k + "=" + v
			} else {
				rep.Server += " " + k + "=" + v
			}
		}
	}
	if v := os.Getenv("no_proxy"); v != "" {
		rep.Override = v
	} else if v := os.Getenv("NO_PROXY"); v != "" {
		rep.Override = v
	}
	return rep
}

// ---------------------------------------------------------------- 浏览器扩展

// linuxChromiumBrowsers 声明要扫的 Chromium 系浏览器及 XDG 配置目录。
// profile 内布局与 Windows 完全一致（scanChromium 共享）。
var linuxChromiumBrowsers = []struct {
	id  string
	dir string // 相对 $HOME
}{
	{"chrome", ".config/google-chrome"},
	{"chromium", ".config/chromium"},
}

// BrowserAudit 扫描浏览器扩展与策略（Linux 口径）。
//
// 覆盖：Chrome/Chromium（XDG 配置目录的 Extensions manifest）+ Firefox
// （~/.mozilla/firefox/*/extensions.json，profile 内布局与 Windows 一致，
// 共享 firefoxProfileExts）+ ~/.mozilla/extensions 全局目录（老式全局
// 扩展落点，只有 ID 没有 manifest，Name 用 ID 顶替并如实保留空版本）。
// 策略面：/etc 各浏览器的 policies/managed 目录——企业管控与恶意下发
// 共用同一落点，与 Windows 的注册表 Forcelist 对齐。
func BrowserAudit() BrowserReport {
	out := BrowserReport{Extensions: []BrowserExt{}, Policies: []BrowserPolicy{}, Scanned: []string{}}

	home, err := os.UserHomeDir()
	if err == nil && home != "" {
		for _, b := range linuxChromiumBrowsers {
			root := filepath.Join(home, b.dir)
			if !dirExists(root) {
				continue
			}
			out.Scanned = append(out.Scanned, b.id)
			out.Extensions = append(out.Extensions, scanChromium(b.id, root)...)
		}

		firefoxRoot := filepath.Join(home, ".mozilla", "firefox")
		if dirExists(firefoxRoot) {
			out.Scanned = append(out.Scanned, "firefox")
			out.Extensions = append(out.Extensions, scanFirefoxLinux(firefoxRoot)...)
		}
		globalExt := filepath.Join(home, ".mozilla", "extensions")
		if dirExists(globalExt) {
			out.Extensions = append(out.Extensions, globalFirefoxExts(globalExt)...)
		}
	}

	out.Policies = append(out.Policies, chromiumPoliciesLinux()...)

	sort.Slice(out.Extensions, func(i, j int) bool {
		if out.Extensions[i].Browser != out.Extensions[j].Browser {
			return out.Extensions[i].Browser < out.Extensions[j].Browser
		}
		return out.Extensions[i].Name < out.Extensions[j].Name
	})
	return out
}

// scanFirefoxLinux 枚举 ~/.mozilla/firefox 下的 profile（与 Windows 的
// Profiles\* 层级不同，Linux 的 profile 目录直接在 firefox/ 下）。
func scanFirefoxLinux(firefoxRoot string) []BrowserExt {
	profs, err := os.ReadDir(firefoxRoot)
	if err != nil {
		return nil
	}
	var out []BrowserExt
	for _, p := range profs {
		if !p.IsDir() {
			continue
		}
		for _, ext := range firefoxProfileExts(filepath.Join(firefoxRoot, p.Name())) {
			ext.Browser = "firefox"
			ext.Profile = p.Name()
			out = append(out, ext)
		}
	}
	return out
}

// globalFirefoxExts 枚举 ~/.mozilla/extensions 的全局扩展 ID 目录。
// 老式落点（xpi 手工安装），没有 manifest 可解析——Name 用 ID 顶替，
// Version 留空，如实呈现"存在但信息不可得"。
func globalFirefoxExts(dir string) []BrowserExt {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []BrowserExt
	for _, e := range ents {
		if !e.IsDir() {
			continue
		}
		out = append(out, BrowserExt{Browser: "firefox", Profile: "(global)", ID: e.Name(), Name: e.Name()})
	}
	return out
}

// linuxPolicyDirs 是各 Chromium 系浏览器的机器级策略目录。Key 直接用
// 目录路径（Linux 没有注册表键可引用）。
func chromiumPoliciesLinux() []BrowserPolicy {
	out := []BrowserPolicy{}
	for _, b := range []struct {
		id  string
		dir string
	}{
		{"chrome", "/etc/opt/chrome/policies/managed"},
		{"chromium", "/etc/chromium/policies/managed"},
	} {
		ents, err := os.ReadDir(b.dir)
		if err != nil {
			continue
		}
		n := 0
		for _, e := range ents {
			if !e.IsDir() && strings.HasSuffix(e.Name(), ".json") {
				n++
			}
		}
		if n == 0 {
			continue
		}
		out = append(out, BrowserPolicy{
			Browser: b.id,
			Key:     b.dir,
			Detail:  "机器级策略 JSON（ExtensionInstallForcelist 等强管控配置的落点，用户不可卸载其中的扩展）",
			Count:   n,
		})
	}
	return out
}

// ---------------------------------------------------------------- 小工具

// readAllLines 读一个文件的全部行；读不到返回 nil（调用方据空切片
// 降级）。node 只读打开。
func readAllLines(path string) []string {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	return strings.Split(string(data), "\n")
}

func orUnset(s string) string {
	if s == "" {
		return "未设置"
	}
	return s
}

func orZero(s string) string {
	if s == "" {
		return "0"
	}
	return s
}
