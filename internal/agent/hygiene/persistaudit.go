package hygiene

// persistaudit.go — 驻留画像的"数据注入 + 组装"纯逻辑（无构建标签）。
//
// Windows 的现场枚举在 audit.go（winapi.EnumeratePersistence 直采）；
// Linux v1 的 hygiene 包不做现场枚举——持久化枚举器在 persist 包
// （Linux 侧 enumeratePersistence 是私有函数），由组合根把条目映射成
// PersistSource 注入本文件，避免视图包与基线包的依赖纠缠。
// 本文件零 I/O，单测在 Windows 上即可跑全。

import (
	"sort"
	"strings"
)

// PersistSource 是 Linux 驻留画像的一条数据输入（组合根从 persist
// 基线/枚举结果映射而来）。刻意与 persist.PersistItem 解耦：本包不
// import persist，persist 侧字段增删不传染到体检视图。
type PersistSource struct {
	Key      string // 基线主键（与 persist 基线同 key，InBaseline 据此判定）
	Kind     string // 持久化类型（cron/systemd_unit/…）
	Location string // 文件/目录/任务路径
	Name     string
	Command  string
	Enabled  bool
	Elevated bool
	RunAs    string
	Trigger  string
}

// AuditSources 把注入的持久化条目逐项画像。这是 Windows Auditor.Audit
// 的注入式等价物：同样的 Autoruns 着色思路，同样的只读纪律。
func (a *Auditor) AuditSources(sources []PersistSource, baselineKeys map[string]bool) []PersistAudit {
	out := make([]PersistAudit, 0, len(sources))
	for _, it := range sources {
		au := PersistAudit{
			Key:        it.Key,
			Kind:       it.Kind,
			Location:   it.Location,
			Name:       it.Name,
			Command:    it.Command,
			Enabled:    it.Enabled,
			RunAs:      it.RunAs,
			Elevated:   it.Elevated,
			Trigger:    it.Trigger,
			InBaseline: baselineKeys[it.Key],
		}
		au.ExePath = linuxExePath(it.Command)
		if au.ExePath != "" {
			au.File = a.cache.probeFile(au.ExePath)
		}
		au.Flags = auditLinuxFlags(au)
		out = append(out, au)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}

// linuxExePath 从命令行提取可执行文件路径。Linux 命令行的第一段是
// 惯例上的可执行位置（ExecStart=/usr/sbin/x --flag）；只认绝对路径，
// 相对名/带 shell 语法的命令不猜——诚实缺席好过指错文件。
func linuxExePath(cmd string) string {
	cmd = strings.TrimSpace(cmd)
	// ExecStart 有引号形态（"/usr/sbin/x" --flag），先剥引号再判绝对路径
	if strings.HasPrefix(cmd, `"`) {
		if end := strings.IndexByte(cmd[1:], '"'); end >= 0 {
			cmd = cmd[1 : 1+end]
		} else {
			return "" // 引号未闭合，无法定位
		}
	}
	if !strings.HasPrefix(cmd, "/") {
		return ""
	}
	if i := strings.IndexAny(cmd, " \t"); i > 0 {
		return cmd[:i]
	}
	return cmd
}

// auditLinuxFlags 是 Linux 侧的着色逻辑（Windows 版 auditFlags 在
// audit.go）。与 Windows 版的差异是刻意裁剪：
//   - unsigned/no_info 不标——Linux v1 没有等价的包签名校验基础设施，
//     fileMeta 只有存在性；整列都会命中"无签名"，标了就是纯噪声；
//   - file_missing（文件已删但驻留点还在——计划任务指向消失路径是最
//     经典的痕迹遗留）与 new（基线外新条目）两个信号完整保留。
func auditLinuxFlags(au PersistAudit) []string {
	var flags []string
	if au.ExePath != "" && !au.File.Exists {
		flags = append(flags, FlagFileMissing)
	}
	if au.Elevated {
		flags = append(flags, FlagElevated)
	}
	if !au.InBaseline {
		flags = append(flags, FlagNew)
	}
	return flags
}
