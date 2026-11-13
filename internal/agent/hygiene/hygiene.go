//go:build windows
// +build windows

// Package hygiene 提供本地面板的"泛安全体检"数据：已安装软件、安全配置
// 姿势、网络暴露面、浏览器扩展、自启动项审计。
//
// 定位与检测引擎互补：检测引擎回答"现在正在发生什么攻击"，本包回答
// "这台机器长期处于什么状态"。全部采集只读（注册表 QUERY_VALUE、
// 文件系统读、WinVerifyTrust），没有任何写操作入口——本地面板的用户
// 看到的是体检报告和手动处置指引，不是一键修复按钮（产品原则见
// AGENTS.md §3.8：检测优先，响应动作保持默认关闭）。
//
// 所有入口按需调用（打开对应视图时），不在扫描循环里运行；
// 签名/版本信息读取有 (path,size,mtime) 缓存，重复打开视图近零成本。
package hygiene

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
)

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

// fileMeta 是一个可执行文件的体检画像（签名 + 版本资源 + 存在性）。
type fileMeta struct {
	Exists      bool   `json:"exists"`
	Signed      bool   `json:"signed"`
	SigState    string `json:"sig_state"` // valid | unsigned | untrusted | ...
	Signer      string `json:"signer,omitempty"`
	Company     string `json:"company,omitempty"`
	Description string `json:"description,omitempty"`
}

// fileCache 按 (path,size,mtime) 缓存文件画像。WinVerifyTrust 单次
// 数毫秒到数十毫秒，一次驻留体检可能枚举上百个文件，没有缓存的话
// 每次打开视图都是一次全量重验。
type fileCache struct {
	mu sync.Mutex
	m  map[string]fileMeta
}

func newFileCache() *fileCache {
	return &fileCache{m: make(map[string]fileMeta)}
}

// limit 是缓存条目上限：自启动项 + 软件资产通常几百个文件；超过说明
// 键在快速变化（软件正在装卸），整表重置即可，不是错误。
const cacheLimit = 4096

// probeFile 读取一个文件的体检画像，带 (path,size,mtime) 缓存。
func (c *fileCache) probeFile(path string) fileMeta {
	if path == "" {
		return fileMeta{}
	}
	key := path
	if fi, err := os.Stat(path); err == nil {
		key = path + "|" + itoa(fi.Size()) + "|" + itoa(fi.ModTime().UnixNano())
	}

	c.mu.Lock()
	if hit, ok := c.m[key]; ok {
		c.mu.Unlock()
		return hit
	}
	c.mu.Unlock()

	meta := inspectFile(path)

	c.mu.Lock()
	if len(c.m) >= cacheLimit {
		c.m = make(map[string]fileMeta)
	}
	c.m[key] = meta
	c.mu.Unlock()
	return meta
}

func itoa(n int64) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [21]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
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
