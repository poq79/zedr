package recon

// virt.go：容器/虚拟化平台识别（契约 §12.3 virt 类）。
//
// 这一类基本是"环境事实"：Hyper-V/WSL/Docker Desktop/VMware/VirtualBox
// 的存在本身不是漏洞，但会影响隔离边界与主机资源。因此 exposure 以
// info 为主；只有虚拟化控制端口监听非回环地址时才升到 low/medium。
//
// 识别以进程为主（这些后端不一定监听 TCP），details 里保留 backend_pid
// 与同类进程数，便于和三方排查工具交叉定位。

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"zedr/internal/agent/state"
)

type virtProduct struct {
	Kind      string
	Title     string
	ProcNames []string
	CmdRe     *regexp.Regexp
	Ports     []uint16
	Note      string
}

var virtProducts = []virtProduct{
	{
		Kind: "hyper-v", Title: "Hyper-V", Ports: []uint16{2179},
		ProcNames: []string{"vmms", "vmwp"},
		CmdRe:     regexp.MustCompile(`(?i)(^|[\\/\s"])vmms(\.exe)?([\s"]|$)`),
	},
	{
		Kind: "wsl", Title: "WSL / WSL2",
		ProcNames: []string{"wslservice", "vmmem", "vmmemwsl", "vmmemwsvc", "wslhost", "lxss"},
		CmdRe:     regexp.MustCompile(`(?i)wslservice|vmmemwsl|vmmemwsvc|vmmem|wslhost|lxss`),
	},
	{
		Kind: "docker-desktop", Title: "Docker Desktop / Engine",
		ProcNames: []string{"com.docker.backend", "dockerd", "docker desktop", "com.docker.service"},
		CmdRe:     regexp.MustCompile(`(?i)com\.docker\.|dockerd|docker desktop`),
	},
	{
		Kind: "vmware", Title: "VMware",
		ProcNames: []string{"vmware-vmx", "vmware", "vmware-authd"},
		CmdRe:     regexp.MustCompile(`(?i)vmware-vmx|vmware-authd`),
	},
	{
		Kind: "virtualbox", Title: "VirtualBox", Ports: []uint16{2718},
		ProcNames: []string{"vboxsvc", "virtualbox", "vboxheadless"},
		CmdRe:     regexp.MustCompile(`(?i)vboxsvc|virtualbox|vboxheadless`),
	},
}

// detectVirt 是 virt 类入口。
func detectVirt(ctx context.Context, b *base) (Category, error) {
	cat := newCategory("virt", CategoryTitle("virt"))
	for _, prod := range virtProducts {
		if ctx.Err() != nil {
			return cat, nil
		}
		pids := make([]uint32, 0, 4)
		for _, row := range b.procs {
			if virtMatches(prod, row) {
				pids = append(pids, row.PID)
			}
		}
		ports := b.existingPorts(prod.Ports)
		if len(pids) == 0 && len(ports) == 0 {
			continue
		}
		var pid uint32
		if len(pids) > 0 {
			pid = pids[0]
			for _, p := range pids {
				if p < pid {
					pid = p
				}
			}
		} else {
			// 没有进程指纹（权限不足/服务在会话 0）时退回监听端口归属。
			pid = b.portListenerPID(ports[0])
		}
		// 把代表进程自身的监听端口并入（例如 vmms 监听 2179）。
		ports = mergePorts(ports, b.tcpPorts(b.portsForPID(pid)))

		details := map[string]any{
			"product":       prod.Kind,
			"backend_pid":   pid,
			"process_count": len(pids),
			"pids":          pids,
		}
		item := b.newAsset("virt", prod.Kind, prod.Title, pid, ports, details)
		item.Exposure = Exposure{Level: LevelInfo, Evidence: []string{fmt.Sprintf("平台进程在运行（backend_pid=%d，共 %d 个进程）", pid, len(pids))}}
		if anyNonLoopback(item.Listens) {
			item.Exposure = Exposure{Level: LevelLow, Evidence: []string{"虚拟化控制端口监听非回环地址"}}
			addFinding(&cat, &item, LevelLow, "虚拟化控制端口监听非回环地址",
				prod.Title+" 的管理/控制端口对网络可达；确认防火墙规则与访问来源")
		}
		cat.Items = append(cat.Items, item)
	}
	sortItems(cat.Items)
	return cat, nil
}

// virtMatches 进程名精确或命令行正则。
func virtMatches(prod virtProduct, row state.ProcRow) bool {
	name := procBaseName(row.Name)
	for _, n := range prod.ProcNames {
		if name == strings.ToLower(n) {
			return true
		}
	}
	return prod.CmdRe != nil && prod.CmdRe.MatchString(row.CmdLine)
}

// mergePorts 合并端口并去重保序。
func mergePorts(a, b []uint16) []uint16 {
	seen := make(map[uint16]struct{}, len(a)+len(b))
	out := make([]uint16, 0, len(a)+len(b))
	for _, list := range [][]uint16{a, b} {
		for _, p := range list {
			if _, ok := seen[p]; ok {
				continue
			}
			seen[p] = struct{}{}
			out = append(out, p)
		}
	}
	return out
}
