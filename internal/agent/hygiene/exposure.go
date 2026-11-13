//go:build windows
// +build windows

package hygiene

import (
	"fmt"
	"sort"

	"golang.org/x/sys/windows/registry"

	"zedr/internal/agent/winapi"
)

// Listener/HostEntry/HostsReport/ProxyReport/ExposureReport 类型、
// listenerScope 与 readHostsFile 定义在 hygiene_types.go（双平台共享）。

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

// listenerScope / readHostsFile 定义在 hygiene_types.go（双平台共享）。

// readHosts 解析 hosts 文件的非注释条目。
//
// 默认 hosts 只有 localhost 映射与注释；任何额外条目都值得用户看一眼
// ——把杀毒/银行/更新域名指到别处是经典的劫持手法。本机无法离线验证
// "指得对不对"，所以只列条目并说明这一点，不做虚判定。
func readHosts() HostsReport {
	return readHostsFile(hostsPath())
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
