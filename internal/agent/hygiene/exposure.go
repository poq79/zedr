//go:build windows
// +build windows

package hygiene

import (
	"bufio"
	"fmt"
	"os"
	"sort"
	"strings"

	"golang.org/x/sys/windows/registry"

	"zedr/internal/agent/winapi"
)

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

// Exposure 采集网络暴露面。pidName 由调用方注入（进程名归属属于
// 探针的进程状态，不属于本包），查不到进程名留空——诚实缺席。
func Exposure(pidName map[uint32]string) ExposureReport {
	exp := ExposureReport{Hosts: readHosts(), Proxy: readProxy()}

	rows, err := winapi.GetNetstat()
	if err != nil {
		return exp
	}
	seen := make(map[string]bool, 32)
	for _, r := range rows {
		isTCPListen := r.Proto == "tcp" && r.State == "LISTEN"
		isUDP := r.Proto == "udp"
		if !isTCPListen && !isUDP {
			continue
		}
		addr := fmt.Sprintf("%s:%d", r.LocalIP, r.LocalPort)
		if seen[addr+r.Proto] {
			continue
		}
		seen[addr+r.Proto] = true
		exp.Listeners = append(exp.Listeners, Listener{
			Proto:   r.Proto,
			Addr:    addr,
			Port:    r.LocalPort,
			Scope:   listenerScope(r.LocalIP),
			Process: pidName[r.PID],
		})
	}
	sort.Slice(exp.Listeners, func(i, j int) bool {
		// 暴露面从大到小：any > lan > loopback，同级按端口号
		w := map[string]int{"any": 0, "lan": 1, "loopback": 2}
		if w[exp.Listeners[i].Scope] != w[exp.Listeners[j].Scope] {
			return w[exp.Listeners[i].Scope] < w[exp.Listeners[j].Scope]
		}
		return exp.Listeners[i].Port < exp.Listeners[j].Port
	})
	return exp
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

// readHosts 解析 hosts 文件的非注释条目。
//
// 默认 hosts 只有 localhost 映射与注释；任何额外条目都值得用户看一眼
// ——把杀毒/银行/更新域名指到别处是经典的劫持手法。本机无法离线验证
// "指得对不对"，所以只列条目并说明这一点，不做虚判定。
func readHosts() HostsReport {
	return readHostsFile(hostsPath())
}

// readHostsFile 解析指定路径的 hosts 文件；拆出路径参数供测试使用。
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

// readProxy 读取 WinINET 系统代理（浏览器与多数应用使用的那套）。
// 本机跑本地代理（如 127.0.0.1 的调试/科学工具）是正常场景，所以
// 有代理只做事实陈述，由用户判断是否自己配的。
func readProxy() ProxyReport {
	rep := ProxyReport{}
	k, err := registry.OpenKey(registry.CURRENT_USER,
		`SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings`, registry.QUERY_VALUE)
	if err != nil {
		return rep
	}
	defer k.Close()
	if v, _, err := k.GetIntegerValue("ProxyEnable"); err == nil {
		rep.Enabled = v != 0
	}
	rep.Server, _, _ = k.GetStringValue("ProxyServer")
	rep.AutoConfigURL, _, _ = k.GetStringValue("AutoConfigURL")
	rep.Override, _, _ = k.GetStringValue("ProxyOverride")
	return rep
}
