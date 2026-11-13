package persist

// PersistItem 是一条持久化项（自启动）的跨平台形状：Windows 枚举器
// （注册表/服务/计划任务）与 Linux 枚举器（cron/systemd/ssh profile…）
// 各自生产同形状数据，基线/diff/评分/告警链路零分叉。
//
// Type 取值按 OS 各有枚举（Windows 见 winapi.Persist* 常量；Linux 见
// enum_linux.go 的 Persist* 常量）——Key 跨采集周期稳定的唯一标识，
// 同一位置同名项才视为同一对象。
type PersistItem struct {
	// Key 是跨采集周期稳定的唯一标识：同一位置同名项才视为同一对象。
	Key string
	// Type 取值见 PersistType* 常量。
	Type string
	// Location 是注册表路径 / 目录 / 单元文件路径。
	Location string
	Name     string
	// Command 是原始命令行或镜像路径。
	Command string
	Enabled bool

	// 以下为附加信息（计划任务/systemd 场景），不参与基线 key。
	RunAs    string // 运行账号
	Elevated bool   // 是否以最高权限运行
	Trigger  string // 触发方式：开机/登录/定时
}
