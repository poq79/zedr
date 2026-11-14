//go:build linux

// baseline_linux.go：/baseline 的 Linux 实现（IO 壳）。
//
// 十项检查全部是只读文件解析/状态读取，零命令执行（与 Windows 版"读
// 事实不下结论"同铁律）：sshd 配置、sudoers、login.defs/profile、
// limits.conf、AppArmor/SELinux 状态、防火墙机制存在与启用态、主机私钥
// 权限、passwd/shadow 账户事实、自动更新痕迹。判定逻辑与契约形状在
// baseline_linuxparse.go（中性，Windows 上单测锁口径）。
//
// 降级口径：单文件不可读 → 对应检查项落 info（"无法判断"），绝不拿
// 默认值冒充实测——score.total 恒等于条目数，前端能看到"有项没判出来"。
//
// 未在 Linux 实机验证（待 Kali 复验）；验证口径 = GOOS=linux 交叉编译 +
// baseline_linuxparse.go 纯逻辑单测（testdata 夹具）。
package liveapi

// baseline_linux.go：安全基线检查（Linux 口径，10 项）。

import (
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"zedr/internal/platform/httpx"
)

// HandleBaseline 返回 GET /baseline 的 Linux handler（包级构造函数，
// 与 Windows 版同签名，liveapi.New 统一接线）。
func HandleBaseline() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		httpx.WriteJSON(w, r, http.StatusOK,
			buildLinuxBaselineResult(collectLinuxBaselineFacts(), time.Now()))
	}
}

// fileLines 读文件为行切片；不可读返回 (nil, false)——调用方据此把
// 对应检查落 info/降级。
func fileLines(path string) ([]string, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}
	return strings.Split(string(data), "\n"), true
}

// fileExists 是"存在即 true"的探测（目录与文件都算——存在性语义）。
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// collectLinuxBaselineFacts 收集十项检查的全部事实原料。单文件读失败
// 逐段降级（事实结构体的对应字段落零值），不放大为端点失败。
func collectLinuxBaselineFacts() *linuxBaselineFacts {
	f := &linuxBaselineFacts{}

	// ---- SSH 配置：drop-ins（字典序）在前、主配置在后。依据：Debian/
	// RHEL 的 sshd_config 首行都是 Include sshd_config.d/*.conf，sshd
	// 指令 first-match-wins → drop-in 里的显式配置生效。主配置不存在时
	// SshdPresent=false（判定层落 info）。
	const sshdMain = "/etc/ssh/sshd_config"
	if _, err := os.Stat(sshdMain); err == nil {
		f.SshdPresent = true
	}
	if ents, err := os.ReadDir("/etc/ssh/sshd_config.d"); err == nil {
		var names []string
		for _, e := range ents {
			if !e.IsDir() && strings.HasSuffix(e.Name(), ".conf") {
				names = append(names, e.Name())
			}
		}
		sort.Strings(names)
		for _, n := range names {
			if lines, ok := fileLines(filepath.Join("/etc/ssh/sshd_config.d", n)); ok {
				f.SshdConfigs = append(f.SshdConfigs, strings.Join(lines, "\n"))
			}
		}
	}
	if f.SshdPresent {
		if lines, ok := fileLines(sshdMain); ok {
			f.SshdConfigs = append(f.SshdConfigs, strings.Join(lines, "\n"))
		}
	}

	// ---- sudoers：主文件不可读 → SudoersReadable=false（判定走 info）；
	// sudoers.d 片段仍尽力收集（能拿到多少拿多少）。
	lines, ok := fileLines("/etc/sudoers")
	f.SudoersReadable = ok
	f.SudoersLines = append(f.SudoersLines, lines...)
	if ents, err := os.ReadDir("/etc/sudoers.d"); err == nil {
		var names []string
		for _, e := range ents {
			if !e.IsDir() && !strings.HasSuffix(e.Name(), "~") {
				names = append(names, e.Name())
			}
		}
		sort.Strings(names)
		for _, n := range names {
			if l, ok := fileLines(filepath.Join("/etc/sudoers.d", n)); ok {
				f.SudoersLines = append(f.SudoersLines, l...)
			}
		}
	}

	// ---- umask / limits
	f.LoginDefs = readOptionalFile("/etc/login.defs")
	f.Profile = readOptionalFile("/etc/profile")
	if lines, ok := fileLines("/etc/security/limits.conf"); ok {
		f.LimitsLines = append(f.LimitsLines, lines...)
	}
	if ents, err := os.ReadDir("/etc/security/limits.d"); err == nil {
		var names []string
		for _, e := range ents {
			if !e.IsDir() && strings.HasSuffix(e.Name(), ".conf") {
				names = append(names, e.Name())
			}
		}
		sort.Strings(names)
		for _, n := range names {
			if l, ok := fileLines(filepath.Join("/etc/security/limits.d", n)); ok {
				f.LimitsLines = append(f.LimitsLines, l...)
			}
		}
	}

	// ---- MAC 状态：AppArmor 内核参数（"Y"/"N"）+ SELinux 配置
	if data, err := os.ReadFile("/sys/module/apparmor/parameters/enabled"); err == nil {
		f.AppArmorEnabled = strings.TrimSpace(string(data))
	}
	f.SELinuxConfig = readOptionalFile("/etc/selinux/config")

	// ---- 防火墙：ufw 配置 / firewalld enable 链接 / iptables 持久化文件
	f.UfwConf = readOptionalFile("/etc/ufw/ufw.conf")
	f.FirewalldEnabled = fileExists("/etc/systemd/system/multi-user.target.wants/firewalld.service") ||
		fileExists("/etc/systemd/system/dbus-org.fedoraproject.FirewallD1.service")
	for _, p := range []string{"/etc/iptables/rules.v4", "/etc/sysconfig/iptables"} {
		if fileExists(p) {
			f.IptablesRulesFile = p
			break
		}
	}

	// ---- SSH 主机私钥权限（Lstat：权限是文件自身事实，不跟随链接目标）
	if ents, err := os.ReadDir("/etc/ssh"); err == nil {
		for _, e := range ents {
			if e.IsDir() || !strings.HasPrefix(e.Name(), "ssh_host_") ||
				!strings.HasSuffix(e.Name(), "_key") {
				continue // 只收私钥（_key），.pub 是公钥无所谓权限
			}
			info, err := os.Lstat(filepath.Join("/etc/ssh", e.Name()))
			if err != nil {
				continue
			}
			f.HostKeys = append(f.HostKeys, linuxHostKey{
				Name: e.Name(),
				Perm: uint32(info.Mode().Perm()),
			})
		}
	}

	// ---- 账户事实
	f.Passwd = readOptionalFile("/etc/passwd")
	f.Shadow = readOptionalFile("/etc/shadow")

	// ---- 自动更新痕迹
	f.AptSystem = fileExists("/var/lib/apt")
	f.AptAutoUpdates = fileExists("/var/lib/apt/periodic") ||
		fileExists("/etc/systemd/system/timers.target.wants/apt-daily-upgrade.timer")
	f.DnfSystem = fileExists("/usr/lib/systemd/system/dnf-automatic.timer") || fileExists("/etc/dnf")
	f.DnfAutoTimer = fileExists("/etc/systemd/system/timers.target.wants/dnf-automatic.timer")

	return f
}
