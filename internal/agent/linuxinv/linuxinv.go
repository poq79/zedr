// Package linuxinv 把 Linux 版资产清单节注册到探针的 inventory.Manager。
//
// 节的形状对照 app 层 Windows 节（internal/agent/app 的 invSystemSection
// 等，字段名即线协议 snake_case），服务端按 (agent_id, name, hash) 做
// 节级幂等——Linux 侧同名节接入同一条差量管线，服务端零分叉。
//
// 本包不带构建标签（双平台编译）：节快照函数读 /proc、/etc、/var/lib，
// 这些路径在 Windows 上不存在 → 快照函数返回 error → Manager 跳过该节。
// 这是刻意设计：纯解析逻辑的单测（fixture 内联）可以在 Windows 上跑全，
// 见本目录 _test.go。注册动作只发生在 Linux 组合根（app 的 Linux 面向
// app_linux.go 接线），Windows 组合根不会调用本包。
//
// 纪律：全部只读（os.ReadFile/os.ReadDir/os.ReadDir + Readlink）；
// 不执行外部命令，除了 packages 节在非 dpkg 系机器上允许一次
// exec.Command("rpm","-qa",...) 直参查询（不经过 shell）。
//
// **未在 Linux 实机验证**（本机无 Linux 测试环境）：/proc 与配置文件的
// 解析口径按 proc(5) 与发行版惯例实现；实机首日校准项见各节注释。
package linuxinv

import (
	"log/slog"

	"zedr/internal/agent/inventory"
)

// AgentVersion 是 agent 节的探针版本号，由组合根在 RegisterAll 之前
// 赋值（通常来自 build 时 -ldflags -X 注入的 main.version）。用包级
// 变量而不是 RegisterAll 参数：版本是"进程级一次注入"的静态量，
// 与日志器同性质；RegisterAll 的调用契约保持三参（startup 注入点）。
var AgentVersion string

// RegisterAll 把 Linux 版资产清单节注册到 Manager。
//
// startup 节依赖 persist 基线（persist.Monitor 在 app 层，本包不 import
// 它避免依赖纠缠）——由调用方注入 provider。startup 为 nil 时跳过该节
// （诚实缺席，不注册一个永远报错的节）。
//
// 与 Windows 组合根（app.inventoryLoop）的节清单对照：
//
//	Windows            Linux 本包
//	system             system（os-release/kernel/boot_id 等价物）
//	adapters           ——（v1 未做：netlink 接口枚举待后续批次）
//	listeners          listeners（/proc/net + inode→PID）
//	services           services（systemd unit 离线盘点）
//	tasks              tasks（cron）
//	startup            startup（注入 persist 基线）
//	agent              agent（version/uptime，其余字段需 app 状态，未接线）
//	defender/firewall  ——（Windows 安全产品语义，Linux 无等价物，不伪造）
//	accounts           users（可登录账户 + sudo 组，对齐 accounts 语义）
//	（Windows 无）      packages（dpkg/rpm 包清单——Linux 特有节）
func RegisterAll(m *inventory.Manager, log *slog.Logger, startup func() (any, error)) {
	if log == nil {
		log = slog.Default()
	}
	m.Register("system", sysSection)
	m.Register("listeners", listenersSection)
	m.Register("packages", packagesSection)
	m.Register("services", servicesSection)
	m.Register("tasks", tasksSection)
	m.Register("agent", agentSection)
	m.Register("users", usersSection)
	if startup != nil {
		m.Register("startup", startup)
	}
}
