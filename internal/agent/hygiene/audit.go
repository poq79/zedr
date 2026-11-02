package hygiene

import (
	"sort"
	"strings"

	"zedr/internal/agent/winapi"
)

// PersistAudit 是一个自启动项的体检画像。
//
// 对标 Sysinternals Autoruns 的着色逻辑（粉=无描述/无签名，黄=文件
// 缺失），但只读：这里不提供禁用入口——禁用是写操作，产品原则要求
// 保持"检测优先、处置默认关闭"。用户看到画像与处置指引，动作留给
// 用户自己。
type PersistAudit struct {
	Key      string   `json:"key"`
	Kind     string   `json:"kind"`
	Location string   `json:"location"`
	Name     string   `json:"name,omitempty"`
	Command  string   `json:"command"`
	Enabled  bool     `json:"enabled"`
	RunAs    string   `json:"run_as,omitempty"`
	Elevated bool     `json:"elevated"`
	Trigger  string   `json:"trigger,omitempty"`
	// ExePath 是从 Command 里定位出的可执行文件；定位不到留空。
	ExePath string   `json:"exe_path,omitempty"`
	File    fileMeta `json:"file"`
	// InBaseline 为 false 表示该条目还没有进入持久化基线——通常只是
	// 探针还没跑完下一个扫描周期；若长时间为 false，说明这是新出现的
	// 自启动点，值得看一眼。
	InBaseline bool      `json:"in_baseline"`
	Flags      []string  `json:"flags,omitempty"`
}

// 审计 flags 取值。
const (
	FlagUnsigned    = "unsigned"     // 文件存在但没有可信签名（Autoruns 粉）
	FlagFileMissing = "file_missing" // 指向的文件已不存在（Autoruns 黄）
	FlagNoInfo      = "no_info"      // 无发布者且无描述（Autoruns 粉）
	FlagElevated    = "elevated"     // 以最高权限运行
	FlagNew         = "new"          // 尚未进入持久化基线
)

// Auditor 是带文件画像缓存的驻留审计器。
//
// 为什么不做成函数：缓存要跨请求存活（打开视图→切换→再打开不应重新
// 验签全部文件），生命周期应与 Agent 一致。
type Auditor struct {
	cache *fileCache
}

// NewAuditor 创建审计器。
func NewAuditor() *Auditor {
	return &Auditor{cache: newFileCache()}
}

// Audit 实时枚举全部自启动项并逐项画像。
//
// 注意这是"当前真实状态"（现场枚举），与 /api/local/persist 返回的
// 基线快照互补：基线回答"相对上次扫描变了什么"，这里回答"现在每个
// 自启动点指向什么、可不可信"。
func (a *Auditor) Audit(baselineKeys map[string]bool) []PersistAudit {
	items, _ := winapi.EnumeratePersistence()
	out := make([]PersistAudit, 0, len(items))
	for _, it := range items {
		au := PersistAudit{
			Key:        it.Key,
			Kind:       it.Type,
			Location:   it.Location,
			Name:       it.Name,
			Command:    it.Command,
			Enabled:    it.Enabled,
			RunAs:      it.RunAs,
			Elevated:   it.Elevated,
			Trigger:    it.Trigger,
			InBaseline: baselineKeys[it.Key],
		}
		au.ExePath = exeFromCommand(it.Command)
		if au.ExePath != "" {
			au.File = a.cache.probeFile(au.ExePath)
		}
		au.Flags = auditFlags(au)
		out = append(out, au)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}

func auditFlags(au PersistAudit) []string {
	var flags []string
	if au.ExePath != "" {
		switch {
		case !au.File.Exists:
			flags = append(flags, FlagFileMissing)
		case au.File.SigState == "bad_digest":
			// 有签名但内容被篡改是最高危信号，借用 unsigned 位并在
			// sig_state 字段里保留精确原因给 UI 展示
			flags = append(flags, FlagUnsigned)
		case !au.File.Signed && isMSIXPath(au.ExePath):
			// WindowsApps 下的 MSIX 包文件不做裸 Authenticode 内嵌签名，
			// WinVerifyTrust 会返回"无签名"——那是采集口径的盲区，不是
			// 风险信号，降级为"无信息"避免对系统组件刷红
			flags = append(flags, FlagNoInfo)
		case !au.File.Signed:
			flags = append(flags, FlagUnsigned)
		case au.File.Company == "" && au.File.Description == "" && au.File.Signer == "":
			flags = append(flags, FlagNoInfo)
		}
	}
	if au.Elevated {
		flags = append(flags, FlagElevated)
	}
	if !au.InBaseline {
		flags = append(flags, FlagNew)
	}
	return flags
}

// isMSIXPath 判断路径是否在 MSIX 包存放区（C:\Program Files\WindowsApps
// 或用户级 WindowsApps）。
func isMSIXPath(path string) bool {
	p := strings.ToLower(path)
	return strings.Contains(p, `\windowsapps\`)
}

// verifySignature / readVersionInfo 是对 winapi 的薄封装，集中在此
// 便于测试替身替换（hygiene_test.go 里用变量注入）。
var (
	verifySignature  = func(path string) winapi.SignatureResult { return winapi.VerifySignature(path) }
	readVersionInfo  = func(path string) *winapi.VersionInfo {
		vi, err := winapi.ReadVersionInfo(path)
		if err != nil {
			return nil
		}
		return vi
	}
)
