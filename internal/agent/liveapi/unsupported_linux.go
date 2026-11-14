//go:build linux

// unsupported_linux.go：Linux 探针上 Windows 专属端点的诚实 501。
//
// 为什么是 501 而不是 404：路由必须存在（liveapi.New 按 livecatalog 锁定
// 全目录注册，缺 handler 直接 panic），501 让中心端/前端能区分"端点不存在"
// 与"探针平台未实现该能力"；每条响应带一句诚实说明（apperr message），
// 不让调用方猜。所有 here 列出的能力都是 NT/LSA/PE 语义，Linux 没有对等
// 语义硬凑只会输出失真数据——诚实 501 是设计决定，不是未完成（边界见
// RESEARCH-LINUX-AGENT §3）。
//
// 有对等语义的端点（accounts/sessions/services/tasks/netinfo/baseline）
// 已在本包各自的 *_linux.go 实现真身；/persistence、/recon 等此前批次
// 已覆盖。能力矩阵总览见 platform_linux.go 头注释。
//
// 未在 Linux 实机验证（本机无 Linux 测试环境）；验证口径 = GOOS=linux
// 交叉编译 + catalog 注册锁单测（Windows 侧既有）+ 各实现文件的中性
// 解析单测。
package liveapi

// unsupported_linux.go：平台不支持端点存根。

import (
	"net/http"

	"zedr/internal/platform/apperr"
	"zedr/internal/platform/httpx"
)

// errLinuxUnsupported 构造平台不支持错误（501 + 一句诚实说明）。
// Public 必须置位：探针侧 httpx.WriteError 对 ≥500 且非 Public 的错误
// 统一脱敏成"服务内部错误，请稍后重试"，这句行动指引会被吞掉——501 的
// message 本身就是给操作员的边界说明（2026-11-14 Kali 实测复现）。
func errLinuxUnsupported(what, why string) error {
	return &apperr.Error{
		Code:    apperr.Code("not_implemented"),
		Message: what + " 是 Windows 专属能力，Linux 探针未实现（诚实边界）：" + why,
		Status:  http.StatusNotImplemented,
		Public:  true,
	}
}

// stubHandler 生成统一形态的 501 handler。
func stubHandler(what, why string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		httpx.WriteError(w, r, errLinuxUnsupported(what, why))
	}
}

// ---- Windows 专属端点存根（*server 方法，签名与 Windows 实现一致）----

func (s *server) handleRegistry(w http.ResponseWriter, r *http.Request) {
	httpx.WriteError(w, r, errLinuxUnsupported("注册表查询", "注册表是 NT 内核配置存储，Linux 无对等语义"))
}

func (s *server) handleEvtLog(w http.ResponseWriter, r *http.Request) {
	httpx.WriteError(w, r, errLinuxUnsupported("Windows 事件日志查询", "ETW/事件日志是 Windows 专属遥测面"))
}

func (s *server) handleDrivers(w http.ResponseWriter, r *http.Request) {
	httpx.WriteError(w, r, errLinuxUnsupported("内核驱动列表", "EnumDeviceDrivers 是 NT 语义；内核模块排查 v1 不做（用户态探针边界）"))
}

func (s *server) handleUSN(w http.ResponseWriter, r *http.Request) {
	httpx.WriteError(w, r, errLinuxUnsupported("USN journal 回溯", "USN 是 NTFS 变更日志；Linux 侧运行期文件事件由 inotify 管线覆盖"))
}

func (s *server) handleADS(w http.ResponseWriter, r *http.Request) {
	httpx.WriteError(w, r, errLinuxUnsupported("NTFS 备用数据流", "ADS/MotW 是 NTFS 专属语义"))
}

func (s *server) handleAnalyze(w http.ResponseWriter, r *http.Request) {
	httpx.WriteError(w, r, errLinuxUnsupported("PE 二进制分析", "熵/导入表/imphash 为 PE 语义；ELF 分析 v1 不做（诚实 501）"))
}

func (s *server) handleHandles(w http.ResponseWriter, r *http.Request) {
	httpx.WriteError(w, r, errLinuxUnsupported("句柄表枚举", "NtQuerySystemInformation 句柄语义为 Windows 专属"))
}

func (s *server) handleHandleOwners(w http.ResponseWriter, r *http.Request) {
	httpx.WriteError(w, r, errLinuxUnsupported("文件句柄占用者反查", "全系统句柄扫描是 Windows 专属语义"))
}

func (s *server) handleThreads(w http.ResponseWriter, r *http.Request) {
	httpx.WriteError(w, r, errLinuxUnsupported("线程起始地址枚举", "线程起始地址/模块归属判定依赖 Windows 模块表语义"))
}

func (s *server) handleMemScan(w http.ResponseWriter, r *http.Request) {
	httpx.WriteError(w, r, errLinuxUnsupported("内存区域扫描", "VirtualQueryEx 区域语义为 Windows 专属"))
}
