//go:build linux

// services_linux.go：/services 的 Linux 实现（IO 壳）。
//
// 枚举 systemd *.service unit：目录集合复用 persistence_linux.go 的
// systemdUnitDirs（/etc > /run > /usr/lib 优先级），enabled 判定与资产
// 清单 services 节（linuxinv）同口径——/etc/systemd/system/*.wants/ 下
// 存在链接 = 开机自启（systemctl is-enabled 的静态近似）。与 linuxinv
// 是两份实现的原因同 persist 包：linuxinv 不在本轮所有权内，且其导出面
// 服务于资产快照（hash 稳定语义），本端点要的是调查面的一次性快照；
// 词汇口径（enabled/disabled、User= 不冒填）两边对齐，测试互为参照。
//
// 同名 unit 去重按目录优先级 first-wins（/etc 管理员覆盖语义）；
// state/start_mode 的 Windows 词汇映射与诚实边界见 services_linuxparse.go。
//
// 未在 Linux 实机验证（待 Kali 复验）；验证口径 = GOOS=linux 交叉编译 +
// services_linuxparse.go 纯逻辑单测。
package liveapi

// services_linux.go：服务实时全量（systemd unit 口径，不含内核模块——
// Linux 侧模块排查归 /drivers 的对等面，v1 不做）。

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"zedr/internal/platform/httpx"
)

// enumLinuxServices 收集全部 *.service unit 的原料。单文件读失败跳过
// （权限差异/竞态是常态），两个 unit 目录都空（非 systemd 发行版）返回
// 空表——诚实呈现"无 systemd 服务面"而不是报错放大。
func enumLinuxServices() []linuxServiceRaw {
	// enabled 集合：/etc/systemd/system/*.wants/ 下的链接名（与
	// linuxinv servicesSection 同口径：systemctl is-enabled 对系统级
	// unit 的主要判定依据的静态版本）。
	enabled := map[string]bool{}
	if ents, err := os.ReadDir("/etc/systemd/system"); err == nil {
		for _, e := range ents {
			if !e.IsDir() || !strings.HasSuffix(e.Name(), ".wants") {
				continue
			}
			if wants, err := os.ReadDir(filepath.Join("/etc/systemd/system", e.Name())); err == nil {
				for _, w := range wants {
					enabled[w.Name()] = true
				}
			}
		}
	}

	var out []linuxServiceRaw
	seen := map[string]bool{}
	for _, dir := range systemdUnitDirs {
		ents, err := os.ReadDir(dir)
		if err != nil {
			continue // 目录不存在（极简镜像）不是错误
		}
		for _, e := range ents {
			// 只收顶层 .service（.wants/.requires 子目录里的链接指向的
			// 就是顶层这些 unit，重复计数没有信息增量——linuxinv 同口径）
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".service") {
				continue
			}
			name := strings.TrimSuffix(e.Name(), ".service")
			if seen[name] {
				continue
			}
			seen[name] = true
			path := filepath.Join(dir, e.Name())
			data, err := os.ReadFile(path)
			if err != nil {
				continue
			}
			info := parseLinuxUnit(data)
			out = append(out, linuxServiceRaw{
				Name:        name,
				Description: info.Description,
				ExecStart:   info.ExecStart,
				User:        info.User,
				UnitPath:    path,
				Enabled:     enabled[e.Name()],
			})
		}
	}
	return out
}

func (s *server) handleServices(w http.ResponseWriter, r *http.Request) {
	filter := r.URL.Query().Get("filter")
	// state 传空/缺省即跳过过滤（列全量）；传值与服务状态精确匹配
	//（大小写不敏感）——Linux 可用值为 enabled/disabled，传 Windows
	// 词汇 running/stopped 只会得到空集，这是诚实结果而非错误。
	state := r.URL.Query().Get("state")
	limit := queryInt(r, "limit", linuxSvcDefaultLimit, 1, linuxSvcMaxLimit)

	httpx.WriteJSON(w, r, http.StatusOK,
		buildLinuxServicesResult(enumLinuxServices(), filter, state, limit))
}
