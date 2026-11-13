//go:build linux

package persist

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
)

// Linux 持久化类型枚举（Linux 专属 Type 值；基线 key 与 Windows 侧
// 独立成库，无升级风暴风险——新 agent 全新基线）。
const (
	PersistCron      = "cron"               // /etc/crontab、/etc/cron.d/*、用户 crontab（T1053.003）
	PersistSystemd   = "systemd_unit"       // 系统级/用户级 service/timer（T1543.002）
	PersistShellProf = "shell_profile"      // ~/.bashrc ~/.profile /etc/profile.d/*（T1037）
	PersistSSHKey    = "ssh_authorized_key" // authorized_keys 追加（T1098.004）
	PersistLDPreload = "ld_preload"         // /etc/ld.so.preload（T1574.006）
	PersistAutostart = "autostart_desktop"  // XDG autostart .desktop（T1547.014）
	PersistRCLocal   = "rc_local"           // /etc/rc.local（T1037）
)

// enumeratePersistence 枚举 Linux 持久化项。全部只读解析文本配置，
// 不执行任何外部命令。未在 Linux 实机验证；解析口径按各发行版惯例
// （Debian/RedHat 通吃的路径集合，缺省目录静默跳过）。
func enumeratePersistence() ([]PersistItem, []string) {
	var out []PersistItem
	var errs []string
	add := func(items []PersistItem, err error) {
		if err != nil {
			errs = append(errs, err.Error())
			return
		}
		out = append(out, items...)
	}

	add(enumCron())
	add(enumSystemdUnits())
	add(enumShellProfiles())
	add(enumSSHKeys())
	add(enumLDPreload())
	add(enumAutostart())
	add(enumRCLocal())
	return out, errs
}

// keyOf 生成基线 key：类型 + 位置 + 名称的稳定组合（与 Windows 侧
// "同一位置同名项=同一对象"口径一致）。
func keyOf(typ, location, name string) string {
	return typ + "|" + location + "|" + name
}

// enumCron 扫 /etc/crontab、/etc/cron.d/* 与 root 用户的 crontab。
// 普通用户 crontab 在 /var/spool/cron/crontabs/（Debian）或
// /var/spool/cron/（RedHat），root 才能读——读不到就跳过（诚实边界）。
func enumCron() ([]PersistItem, error) {
	var out []PersistItem
	var errs []string
	add := func(items []PersistItem, err error) {
		if err != nil {
			errs = append(errs, err.Error())
			return
		}
		out = append(out, items...)
	}

	add(cronFile("/etc/crontab", "/etc/crontab"))
	if entries, err := os.ReadDir("/etc/cron.d"); err == nil {
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			add(cronFile(filepath.Join("/etc/cron.d", e.Name()), e.Name()))
		}
	}
	for _, sp := range []string{"/var/spool/cron/crontabs", "/var/spool/cron"} {
		if entries, err := os.ReadDir(sp); err == nil {
			for _, e := range entries {
				add(cronFile(filepath.Join(sp, e.Name()), "user:"+e.Name()))
			}
		}
	}
	if len(errs) > 0 {
		return out, aggErrs("cron", errs)
	}
	return out, nil
}

// cronFile 解析单个 crontab 文件：跳过注释/环境行，取调度字段后的命令。
func cronFile(path, loc string) ([]PersistItem, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []PersistItem
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		// 6 字段（分 时 日 月 周 命令）为常见格式；/etc/crontab 与
		// cron.d 多一列用户名（分 时 日 月 周 用户 命令）
		var cmd string
		switch {
		case len(fields) >= 7 && loc == "/etc/crontab" || len(fields) >= 7 && strings.Contains(path, "/cron.d/"):
			cmd = strings.Join(fields[6:], " ")
			out = append(out, PersistItem{
				Key: keyOf(PersistCron, loc, fields[6]), Type: PersistCron,
				Location: loc, Name: fields[6], Command: cmd, Enabled: true,
				Trigger: "定时", RunAs: fields[5], Elevated: fields[5] == "root",
			})
		case len(fields) >= 6:
			cmd = strings.Join(fields[5:], " ")
			out = append(out, PersistItem{
				Key: keyOf(PersistCron, loc, cmd), Type: PersistCron,
				Location: loc, Name: cmd, Command: cmd, Enabled: true,
				Trigger: "定时",
			})
		}
		_ = cmd
	}
	return out, nil
}

// enumSystemdUnits 扫系统级与用户级单元目录，抽取 ExecStart/ExecRestart。
// 只解析文本；systemctl 依赖 D-Bus 运行态，离线/容器里不存在，不依赖它。
func enumSystemdUnits() ([]PersistItem, error) {
	var out []PersistItem
	dirs := []string{
		"/etc/systemd/system",
		"/usr/lib/systemd/system",
		"/etc/systemd/user",
		"/usr/lib/systemd/user",
	}
	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() || (!strings.HasSuffix(e.Name(), ".service") && !strings.HasSuffix(e.Name(), ".timer")) {
				continue
			}
			path := filepath.Join(dir, e.Name())
			data, err := os.ReadFile(path)
			if err != nil {
				continue
			}
			var execs []string
			for _, line := range strings.Split(string(data), "\n") {
				if v, ok := strings.CutPrefix(strings.TrimSpace(line), "ExecStart="); ok {
					execs = append(execs, v)
				}
			}
			if len(execs) == 0 {
				continue
			}
			for _, ex := range execs {
				out = append(out, PersistItem{
					Key: keyOf(PersistSystemd, dir, e.Name()+"#"+ex), Type: PersistSystemd,
					Location: dir, Name: e.Name(), Command: ex, Enabled: true,
					Trigger: "开机", Elevated: dir == "/usr/lib/systemd/system" || dir == "/etc/systemd/system",
				})
			}
		}
	}
	return out, nil
}

// enumShellProfiles 扫登录 shell 的配置文件。追加到这些文件的命令
// 在每个交互 shell 里执行——textbook 持久化位。
func enumShellProfiles() ([]PersistItem, error) {
	var out []PersistItem
	home, _ := os.UserHomeDir()
	files := []string{"/etc/profile", "/etc/bash.bashrc", "/etc/zsh/zprofile"}
	if home != "" {
		files = append(files,
			filepath.Join(home, ".bashrc"), filepath.Join(home, ".profile"),
			filepath.Join(home, ".bash_profile"), filepath.Join(home, ".zshrc"))
	}
	for _, p := range files {
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(data), "\n") {
			t := strings.TrimSpace(line)
			if t == "" || strings.HasPrefix(t, "#") {
				continue
			}
			// 只关注"执行外部命令"的行：curl/wget/base64/su 拉起等。
			// export/alias/PATH 调整是正常配置，不进基线（噪声）。
			if strings.HasPrefix(t, "curl ") || strings.HasPrefix(t, "wget ") ||
				strings.Contains(t, "| sh") || strings.Contains(t, "| bash") ||
				strings.HasPrefix(t, "base64 ") {
				out = append(out, PersistItem{
					Key: keyOf(PersistShellProf, p, t), Type: PersistShellProf,
					Location: p, Name: t, Command: t, Enabled: true,
					Trigger: "登录",
				})
			}
		}
	}
	return out, nil
}

// enumSSHKeys 枚举 authorized_keys（key 追加 = 账户持久化）。
func enumSSHKeys() ([]PersistItem, error) {
	var out []PersistItem
	home, _ := os.UserHomeDir()
	sshDirs := []string{"/root/.ssh", "/etc/ssh"}
	if home != "" {
		sshDirs = append(sshDirs, filepath.Join(home, ".ssh"))
	}
	for _, dir := range sshDirs {
		data, err := os.ReadFile(filepath.Join(dir, "authorized_keys"))
		if err != nil {
			continue
		}
		for i, line := range strings.Split(string(data), "\n") {
			t := strings.TrimSpace(line)
			if t == "" || strings.HasPrefix(t, "#") {
				continue
			}
			// 只取 key 类型+指纹级摘要做名称，完整 key 不进基线（体积/隐私）
			parts := strings.Fields(t)
			name := "key"
			if len(parts) >= 2 {
				name = parts[0] + " " + parts[1][:min(len(parts[1]), 16)] + "…"
			}
			out = append(out, PersistItem{
				Key: keyOf(PersistSSHKey, dir, t), Type: PersistSSHKey,
				Location: dir, Name: name, Command: t, Enabled: true,
				Trigger: "登录",
			})
			_ = i
		}
	}
	return out, nil
}

// enumLDPreload 读 /etc/ld.so.preload——每个动态链接进程都会加载它，
// 一行即全局注入（用户态最高价值持久化位之一）。
func enumLDPreload() ([]PersistItem, error) {
	data, err := os.ReadFile("/etc/ld.so.preload")
	if err != nil {
		return nil, nil // 文件不存在=无 preload，正常态
	}
	var out []PersistItem
	for _, line := range strings.Split(string(data), "\n") {
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		out = append(out, PersistItem{
			Key: keyOf(PersistLDPreload, "/etc/ld.so.preload", t), Type: PersistLDPreload,
			Location: "/etc/ld.so.preload", Name: t, Command: t, Enabled: true,
			Trigger: "开机",
		})
	}
	return out, nil
}

// enumAutostart 扫 XDG autostart 的 .desktop。
func enumAutostart() ([]PersistItem, error) {
	var out []PersistItem
	home, _ := os.UserHomeDir()
	dirs := []string{"/etc/xdg/autostart"}
	if home != "" {
		dirs = append(dirs, filepath.Join(home, ".config/autostart"))
	}
	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if !strings.HasSuffix(e.Name(), ".desktop") {
				continue
			}
			path := filepath.Join(dir, e.Name())
			data, err := os.ReadFile(path)
			if err != nil {
				continue
			}
			for _, line := range strings.Split(string(data), "\n") {
				if v, ok := strings.CutPrefix(strings.TrimSpace(line), "Exec="); ok {
					out = append(out, PersistItem{
						Key: keyOf(PersistAutostart, dir, e.Name()+"#"+v), Type: PersistAutostart,
						Location: dir, Name: e.Name(), Command: v, Enabled: true,
						Trigger: "登录",
					})
				}
			}
		}
	}
	return out, nil
}

// enumRCLocal 读 /etc/rc.local（SysV 兼容层，仍在广泛使用）。
func enumRCLocal() ([]PersistItem, error) {
	data, err := os.ReadFile("/etc/rc.local")
	if err != nil {
		return nil, nil
	}
	var out []PersistItem
	for _, line := range strings.Split(string(data), "\n") {
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "#") || t == "exit 0" {
			continue
		}
		out = append(out, PersistItem{
			Key: keyOf(PersistRCLocal, "/etc/rc.local", t), Type: PersistRCLocal,
			Location: "/etc/rc.local", Name: t, Command: t, Enabled: true,
			Trigger: "开机",
		})
	}
	return out, nil
}

func aggErrs(prefix string, errs []string) error {
	if len(errs) == 0 {
		return nil
	}
	return &aggErr{prefix: prefix, msgs: errs}
}

type aggErr struct {
	prefix string
	msgs   []string
}

func (e *aggErr) Error() string { return e.prefix + ": " + strings.Join(e.msgs, "; ") }

// commandPath 从 Linux 命令行还原可执行路径：取第一个空白分隔 token，
// 去引号；绝对路径原样，裸名交由 fileExists 失败路径处理（不猜 PATH）。
func commandPath(cmd string) string {
	s := strings.TrimSpace(cmd)
	if s == "" {
		return ""
	}
	if strings.HasPrefix(s, "\"") || strings.HasPrefix(s, "'") {
		q := s[0]
		if end := strings.IndexByte(s[1:], q); end >= 0 {
			return s[1 : end+1]
		}
	}
	return strings.Fields(s)[0]
}

// 可写目录（Linux 口径）：/tmp、/dev/shm、用户 home 是落地首选。
var pathMarkers = []string{
	"/tmp/", "/var/tmp/", "/dev/shm/", "/home/", "/root/", "/run/user/",
	"/downloads/",
}

// uncPaths：Linux 无 UNC 语义。
var uncPaths = false

// 危险命令解释器（Linux 口径）：shell 管道拉起是最常见形态。
var interpreterMarkers = []string{
	"bash", "/bin/sh", "sh -c", "zsh", "python", "perl", "nc ", "ncat",
	"socat", "curl", "wget", "openssl",
}

// 隐藏/编码参数特征（Linux 口径）。
var hiddenArgMarkers = []string{
	"base64 -d", "base64 --decode", "| sh", "| bash", "/dev/tcp/",
	"openssl enc", "xxd -r", "printf '\\x", "eval $(",
}

// addPrivilegeScore 权限/触发组合加分（Linux：systemd 系统级单元 + 开机触发）。
func addPrivilegeScore(it PersistItem, add func(int, string)) {
	if it.Elevated && it.Type == PersistSystemd {
		add(4, "系统级 systemd 单元（root 权限运行）")
	}
}

// mitreFor 把 Linux 持久化类型映射到 ATT&CK 技术编号。
func mitreFor(typ string) []string {
	switch typ {
	case PersistCron:
		return []string{"T1053.003"}
	case PersistSystemd:
		return []string{"T1543.002"}
	case PersistShellProf, PersistRCLocal:
		return []string{"T1037"}
	case PersistSSHKey:
		return []string{"T1098.004"}
	case PersistLDPreload:
		return []string{"T1574.006"}
	case PersistAutostart:
		return []string{"T1547.014"}
	default:
		return []string{"T1547"}
	}
}

// labelFor 返回便于人读的位置描述（Linux 类型）。
func labelFor(typ string) string {
	switch typ {
	case PersistCron:
		return "计划任务(cron)"
	case PersistSystemd:
		return "systemd 单元"
	case PersistShellProf:
		return "shell 配置文件"
	case PersistSSHKey:
		return "SSH 授权密钥"
	case PersistLDPreload:
		return "动态链接预加载"
	case PersistAutostart:
		return "桌面自启动项"
	case PersistRCLocal:
		return "rc.local 启动脚本"
	default:
		return typ
	}
}
