//go:build windows
// +build windows

package hygiene

import (
	"sort"
	"strings"

	"zedr/internal/agent/winapi"
)

// PersistAudit / Auditor 类型与 flags 常量定义在 hygiene_types.go
// （双平台共享）；本文件是 Windows 现场枚举实现。

// NewAuditor 创建审计器。
func NewAuditor() *Auditor {
	return &Auditor{cache: newFileCache()}
}

// Audit 实时枚举全部自启动项并逐项画像。
//
// 注意这是"当前真实状态"（现场枚举），与 /api/local/persist 返回的
// 基线快照互补：基线回答"相对上次扫描变了什么"，这里回答"现在每个
// 自启动点指向什么、可不可信"。Linux 同名方法见 hygiene_linux.go
// （v1 无现场枚举器，走注入式 AuditItems）。
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
	verifySignature = func(path string) winapi.SignatureResult { return winapi.VerifySignature(path) }
	readVersionInfo = func(path string) *winapi.VersionInfo {
		vi, err := winapi.ReadVersionInfo(path)
		if err != nil {
			return nil
		}
		return vi
	}
)
