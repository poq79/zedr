// 本文件 NEUTRAL：/services Linux 口径的线协议投影（过滤/排序/截断，
// 无 IO）。IO 壳在 services_linux.go。
//
// 未在 Linux 实机验证（待 Kali 复验）；验证口径 = GOOS=linux 交叉编译 +
// 本文件单测在 Windows 上运行。
package liveapi

// services_linuxparse.go：systemd unit → Windows 服务语义字段的投影。

import (
	"sort"
	"strings"
)

// linuxSvcDefaultLimit/Max 与 Windows services.go 的 svcDefaultLimit /
// svcMaxLimit 同值同语义（限流上限双平台一致，契约口径不变）。
const (
	linuxSvcDefaultLimit = 200
	linuxSvcMaxLimit     = 500
)

// linuxServiceItem 与 Windows services.go 的 serviceItem 逐字段对齐。
// state/start_mode 的语义映射（诚实口径，note 随响应说明）：
//   - state：恒为 enabled/disabled（启用口径），不是 Windows 的
//     running/stopped——离线只读拿不到运行态（systemctl/D-Bus 是运行中
//     管理器的运行时接口，只读纪律不执行命令也不引 D-Bus 依赖）；词汇
//     与资产清单 services 节（linuxinv）一致，同一台主机两个视图答案
//     不打架；
//   - start_mode：映射进 Windows 词汇——wants 链接存在（开机自启）=
//     "auto"（对应 Windows auto），否则 "disabled"（不会开机自启）。
//     systemd 的 static（无 [Install]、只能被其他 unit 拉起）与 disabled
//     在"不进开机序列"这一点上对调查语义相同，二分归并（linuxinv 同
//     口径）；manual/boot/system 三个 Windows 档位 Linux 无对等，不硬凑；
//   - path_name：ExecStart 完整命令行（对应 Windows"二进制命令行含参数"
//     语义）；无 ExecStart 的 unit（dbus 激活等）回退 unit 文件路径，
//     调查者可直达原文；
//   - account：[Service] User= 显式值；空 = 未显式配置（默认 root 不冒填，
//     linuxinv 同口径）。
type linuxServiceItem struct {
	Name        string `json:"name"`
	DisplayName string `json:"display_name"`
	State       string `json:"state"`
	StartMode   string `json:"start_mode"`
	PathName    string `json:"path_name"`
	Account     string `json:"account"`
}

// linuxServiceRaw 是 IO 壳产出的单 unit 原料。
type linuxServiceRaw struct {
	Name        string // unit 名（去 .service 后缀，如 sshd）
	Description string
	ExecStart   string // 完整命令行；空 = unit 无 ExecStart
	User        string
	UnitPath    string
	Enabled     bool // /etc/systemd/system/*.target.wants/ 存在链接
}

// buildLinuxServicesResult 是 /services 的纯投影：filter（服务名或显示名
// 子串，大小写不敏感，Windows 同口径）→ 按 name 排序 → 截断。响应为
// Windows services 同形状 map + Linux 特有 note（state 词汇口径说明）。
func buildLinuxServicesResult(raws []linuxServiceRaw, filter, state string, limit int) map[string]any {
	filter = strings.ToLower(strings.TrimSpace(filter))
	state = strings.ToLower(strings.TrimSpace(state))

	all := make([]linuxServiceItem, 0, len(raws))
	for _, r := range raws {
		item := linuxServiceItem{
			Name:        r.Name,
			DisplayName: r.Description,
			State:       "disabled",
			StartMode:   "disabled",
			PathName:    r.UnitPath,
			Account:     r.User,
		}
		if r.Enabled {
			item.State = "enabled"
			item.StartMode = "auto"
		}
		if r.ExecStart != "" {
			item.PathName = r.ExecStart
		}
		all = append(all, item)
	}

	matched := make([]linuxServiceItem, 0, len(all))
	for _, sv := range all {
		if filter != "" &&
			!strings.Contains(strings.ToLower(sv.Name), filter) &&
			!strings.Contains(strings.ToLower(sv.DisplayName), filter) {
			continue
		}
		if state != "" && !strings.EqualFold(sv.State, state) {
			continue
		}
		matched = append(matched, sv)
	}

	// 按 name 排序保证输出稳定（与资产清单 services 节同纪律）。
	sort.Slice(matched, func(i, j int) bool { return matched[i].Name < matched[j].Name })

	truncated := len(matched) > limit
	if truncated {
		matched = matched[:limit]
	}
	if matched == nil {
		matched = []linuxServiceItem{}
	}
	return map[string]any{
		"items":     matched,
		"total":     len(all),
		"truncated": truncated,
		"note": "state 为启用口径（enabled=开机自启），不是运行态；运行态需 systemctl，" +
			"只读探针不执行命令（与资产清单 services 节同口径）",
	}
}
