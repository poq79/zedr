package linuxinv

// packages.go — packages 节：Linux 包清单（Windows 节没有的等价物；
// Windows 侧软件面由 hygiene Apps 提供）。服务端无同名节，形状自定但
// 遵守 snake_case 线协议风格；条目主键 = name（若服务端后续接条目级
// diff，keyFn 用 name）。

import (
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
)

// packagesTopN 是 payload 里携带的条目上限。包清单动辄两三千条
// （桌面 Debian 全量 ~4000），整包入 payload 会让每轮差量突变时背上
// 数百 KB——清单节的价值在"总数 + 榜样"而不是全量枚举（全量走
// hygiene Apps / 实时隧道），截断在 payload 里注明。
const packagesTopN = 200

// invPackage 是 packages 节的单条条目。
type invPackage struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
	SizeKB  uint64 `json:"size_kb,omitempty"`
}

// packagesSection 组装 packages 节。
//
// 数据源优先级：dpkg status 文件（读文件比 dpkg -l 稳：不依赖 PATH、
// 无列宽截断）> rpm -qa 一次直参查询（rpm 数据库是 BerkeleyDB 二进制，
// 离线解析随 rpm 版本漂移，v1 不做）。两者都不可用 = 未知发行版
// （Alpine apk / Arch pacman v1 未接），返回 manager:"unknown" + notes
// 说明——不报 error，让服务端能看到"这台机器没有已识别的包管理器"
// 这个事实本身。
func packagesSection() (any, error) {
	if data, err := os.ReadFile("/var/lib/dpkg/status"); err == nil {
		pkgs := parseDpkgStatus(data)
		return packagesPayload("dpkg", pkgs, nil), nil
	}

	// rpm 系：exec.Command 直参（纪律：不经 shell 拼接）；输出上限由
	// --qf 格式控制，行数即包数，无注入面。
	if out, err := exec.Command("rpm", "-qa", "--qf", "%{NAME}\\t%{VERSION}\\t%{SIZE}\\n").Output(); err == nil {
		return packagesPayload("rpm", parseRpmQA(out), nil), nil
	} else if exitErr, ok := err.(*exec.ExitError); ok {
		return packagesPayload("unknown", nil,
			[]string{"rpm 查询失败: " + exitErr.String()}), nil
	}

	return packagesPayload("unknown", nil,
		[]string{"未发现 dpkg status 与 rpm；Alpine apk/Arch pacman 等包管理器 v1 未支持"}), nil
}

// packagesPayload 汇总节 payload：总数 + 按名称排序的 topN。
func packagesPayload(manager string, pkgs []invPackage, notes []string) map[string]any {
	sort.Slice(pkgs, func(i, j int) bool { return pkgs[i].Name < pkgs[j].Name })
	total := len(pkgs)
	top := pkgs
	if total > packagesTopN {
		top = pkgs[:packagesTopN]
		if notes == nil {
			notes = []string{}
		}
		notes = append(notes, fmt.Sprintf("条目超过 %d，payload 只含名称序前 %d 条", packagesTopN, packagesTopN))
	}
	if notes == nil {
		notes = []string{}
	}
	return map[string]any{
		"manager": manager,
		"total":   total,
		"top":     top,
		"notes":   notes,
	}
}

// invPackage 解析中间结构（与 hygiene.InstalledApp 分开：清单节不需要
// publisher/location，payload 越瘦越好）。

// parseDpkgStatus 解析 /var/lib/dpkg/status。只取 "install ok installed"
// 状态段落——dpkg 把卸载残留（deinstall/config-files）留在文件里，
// 那不是已安装软件。
func parseDpkgStatus(data []byte) []invPackage {
	type para struct {
		pkg       invPackage
		installed bool
	}
	var out []invPackage
	var cur *para
	flush := func() {
		if cur != nil && cur.installed && cur.pkg.Name != "" {
			out = append(out, cur.pkg)
		}
		cur = nil
	}
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimRight(raw, "\r")
		if line == "" {
			flush()
			continue
		}
		// 续行（以空格开头的 Description 正文）：不参与字段提取
		if line[0] == ' ' || line[0] == '\t' {
			continue
		}
		i := strings.IndexByte(line, ':')
		if i < 0 {
			continue
		}
		key, val := line[:i], strings.TrimSpace(line[i+1:])
		switch key {
		case "Package":
			flush()
			cur = &para{pkg: invPackage{Name: val}}
		case "Version":
			if cur != nil {
				cur.pkg.Version = val
			}
		case "Installed-Size":
			if cur != nil {
				if n, err := strconv.ParseUint(val, 10, 64); err == nil {
					cur.pkg.SizeKB = n // dpkg 的 Installed-Size 本身就是 KiB
				}
			}
		case "Status":
			if cur != nil {
				f := strings.Fields(val)
				cur.installed = len(f) == 3 && f[0] == "install" && f[2] == "installed"
			}
		}
	}
	flush()
	return out
}

// parseRpmQA 解析 rpm -qa --qf 输出（name\tversion\tsize 行）。
func parseRpmQA(data []byte) []invPackage {
	var out []invPackage
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimRight(raw, "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		f := strings.Split(line, "\t")
		if len(f) < 2 || f[0] == "" {
			continue
		}
		pkg := invPackage{Name: f[0], Version: f[1]}
		if len(f) >= 3 {
			if n, err := strconv.ParseUint(strings.TrimSpace(f[2]), 10, 64); err == nil {
				pkg.SizeKB = n / 1024 // rpm 的 SIZE 是字节
			}
		}
		out = append(out, pkg)
	}
	return out
}
