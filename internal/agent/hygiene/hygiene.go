//go:build windows
// +build windows

package hygiene

import (
	"os"
	"path/filepath"
	"strings"
)

// 本文件是 Windows 侧的文件画像实现：命令行可执行定位、Authenticode
// 验签与版本资源读取。类型定义与双平台共享逻辑在 hygiene_types.go
// （无构建标签），Linux 实现在 hygiene_linux.go。

// exeFromCommand 从命令行/镜像路径里提取可执行文件路径。
//
// 自启动项的 Command 有多种形态，都要处理：
//   - 引号包裹："C:\Program Files\App\a.exe" -flag
//   - 带参数无引号：C:\Windows\system32\svchost.exe -k netsvcs
//   - 纯路径：C:\tool\t.exe
//   - 服务镜像路径的内核写法：\SystemRoot\system32\drivers\x.sys、
//     \??\C:\..., System32\drivers\x.sys（相对 %SystemRoot%）、%windir%\...
//
// 无引号形态无法从语法上区分"路径里的空格"和"参数分隔符"，所以按
// 逐段回退尝试文件存在性：命中最长的存在前缀就是可执行文件。找不到
// 返回空串——诚实缺席，调用方按"无法定位文件"处理而不是猜。
func exeFromCommand(cmd string) string {
	cmd = strings.TrimSpace(cmd)
	if cmd == "" {
		return ""
	}
	if cmd[0] == '"' {
		if end := strings.IndexByte(cmd[1:], '"'); end >= 0 {
			return cmd[1 : 1+end]
		}
		return ""
	}
	cmd = normalizeSysPath(cmd)
	if isFile(cmd) {
		return cmd
	}
	rest := cmd
	for {
		sp := strings.LastIndexByte(rest, ' ')
		if sp <= 0 {
			return ""
		}
		rest = rest[:sp]
		if isFile(rest) {
			return rest
		}
	}
}

// normalizeSysPath 把服务/驱动注册表里的几种非标准路径写法折算成
// 真实文件系统路径，让驻留体检能对系统组件给出签名画像而不是空白。
func normalizeSysPath(p string) string {
	root := systemRoot()
	switch {
	case strings.HasPrefix(p, `\SystemRoot\`), strings.HasPrefix(p, `\SYSTEMROOT\`):
		return root + p[len(`\SystemRoot`):]
	case strings.HasPrefix(p, `%windir%\`), strings.HasPrefix(p, `%WINDIR%\`), strings.HasPrefix(p, `%SystemRoot%\`):
		if i := strings.IndexByte(p, '\\'); i >= 0 {
			return root + p[i:]
		}
	case strings.HasPrefix(p, `\??\`):
		return strings.TrimPrefix(p, `\??\`)
	case strings.HasPrefix(p, `System32\`), strings.HasPrefix(p, `system32\`), strings.HasPrefix(p, `SYSTEM32\`), strings.HasPrefix(p, `SystemDrivers\`):
		return root + `\` + p
	}
	return p
}

func isFile(p string) bool {
	abs := len(p) >= 3 && p[1] == ':' && p[2] == '\\' || strings.HasPrefix(p, `\\`)
	if !abs {
		return false
	}
	fi, err := os.Stat(p)
	return err == nil && !fi.IsDir()
}

// inspectFile 无缓存读取：存在性 + Authenticode + 版本资源。
func inspectFile(path string) fileMeta {
	meta := fileMeta{}
	fi, err := os.Stat(path)
	meta.Exists = err == nil && !fi.IsDir()
	if !meta.Exists {
		return meta
	}
	sig := verifySignature(path)
	meta.Signed = sig.Signed
	meta.SigState = sig.State
	meta.Signer = sig.Signer
	if vi := readVersionInfo(path); vi != nil {
		meta.Company = vi.Company
		meta.Description = vi.Description
	}
	return meta
}

// systemRoot 返回 %SystemRoot%（hosts 等系统路径的基准）。
func systemRoot() string {
	if v := os.Getenv("SystemRoot"); v != "" {
		return v
	}
	return `C:\Windows`
}

// hostsPath 是 hosts 文件的标准位置。
func hostsPath() string {
	return filepath.Join(systemRoot(), "System32", "drivers", "etc", "hosts")
}

// verifySignature / readVersionInfo 测试替身变量定义在 audit.go
//（与现场枚举实现同文件，便于测试注入）。
