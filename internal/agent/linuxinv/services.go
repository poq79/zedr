package linuxinv

// services.go — services 节：systemd unit 离线盘点。
//
// 口径（诚实边界）：不调用 systemctl（D-Bus 依赖运行态的 systemd，
// 容器/救援环境没有），enabled/disabled 按 /etc/systemd/system 下
// *.target.wants/ 的符号链接推断——这是 systemctl is-enabled 对
// 系统级 unit 的主要判定依据的静态版本。运行态（running/stopped）
// 离线拿不到，state 字段填的是 enabled 口径，与 Windows 节的
// running/stopped 词汇不同——消费方看值即知口径，不混淆。

import (
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// invService 字段名对齐 Windows invService 线协议（name/display_name/
// state/start_mode/path_name/account）。account 恒空：unit 文件的
// User= 只对部分 unit 存在，且 root 是默认——v1 不填默认值冒充。
type invService struct {
	Name        string `json:"name"`
	DisplayName string `json:"display_name,omitempty"`
	State       string `json:"state"`
	StartMode   string `json:"start_mode"`
	PathName    string `json:"path_name"`
	Account     string `json:"account,omitempty"`
}

// systemdUnitDirs 是系统级 unit 目录，/etc 覆盖 /usr/lib（admin override
// 语义：同名 unit 以 /etc 的为准）。
var systemdUnitDirs = []string{
	"/etc/systemd/system",
	"/usr/lib/systemd/system",
}

// servicesSection 组装 services 节。范围取舍：只收顶层 .service——
// timer 的调度面（OnCalendar/OnUnitActiveSec）与 cron 同语义，先放
// tasks 节口径里不双报；timer 单独成节的必要性留给后续批次评估
// （persist 包的 Linux 枚举器已经覆盖 systemd_unit/timer 的检测面）。
func servicesSection() (any, error) {
	// enabled 集合：/etc/systemd/system/*.target.wants/ 下的链接名
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

	out := make([]invService, 0, 128)
	seen := make(map[string]bool, 128)
	// 先 /etc 后 /usr/lib：同名 unit /etc 优先（seen 去重）。
	for _, dir := range systemdUnitDirs {
		ents, err := os.ReadDir(dir)
		if err != nil {
			continue // 目录不存在（极简镜像）不是错误，换下一个
		}
		names := make([]string, 0, len(ents))
		for _, e := range ents {
			// 只收顶层 .service 文件；.wants/.requires 子目录里的链接
			// 指向的就是顶层这些 unit，重复计数没有信息增量。
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".service") {
				continue
			}
			names = append(names, e.Name())
		}
		sort.Strings(names)
		for _, n := range names {
			if seen[n] {
				continue
			}
			seen[n] = true
			path := filepath.Join(dir, n)
			svc := invService{
				Name:      strings.TrimSuffix(n, ".service"),
				State:     "disabled",
				StartMode: "systemd",
				PathName:  path,
			}
			if enabled[n] {
				svc.State = "enabled"
			}
			svc.DisplayName = unitDescription(path)
			out = append(out, svc)
		}
	}

	if len(out) == 0 {
		// 非 systemd 发行版（Alpine/OpenRC）两个目录都为空：报错跳过
		// 而不是输出"零服务"——那是对系统形态的错误陈述。
		return nil, errNoSystemdUnits
	}

	// 按 name 排序保证 hash 稳定（Windows 组合根同一条纪律）。
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// errNoSystemdUnits 是 services 节的"非 systemd 系统"哨兵错误。
var errNoSystemdUnits = errors.New("两个 systemd unit 目录均无 .service 单元（非 systemd 发行版或极简镜像）")

// unitDescription 读 unit 文件 [Unit] 段的 Description=。读不到留空
// ——display_name 是展示增强，不值得为它把节标成失败。
func unitDescription(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return parseUnitDescription(data)
}

// parseUnitDescription 从 unit 文本提取 Description=（纯函数，单测在
// Windows 上跑）。
func parseUnitDescription(data []byte) string {
	inUnit := false
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(strings.TrimRight(raw, "\r"))
		if strings.HasPrefix(line, "[") {
			inUnit = strings.HasPrefix(line, "[Unit]")
			continue
		}
		if !inUnit || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "Description=") {
			return strings.TrimSpace(line[len("Description="):])
		}
	}
	return ""
}
