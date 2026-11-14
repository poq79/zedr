//go:build linux

// sessions_linux.go：/sessions 的 Linux 实现（IO 壳）。
//
// 数据来源 /var/run/utmp（二进制，纯 Go 解析，见 sessions_linuxparse.go）。
// 与 Windows 版（LSA LogonSession 枚举）的分工不变：/accounts 看账户目录，
// /sessions 看"此刻谁登录着"。utmp 的覆盖面 = utmp 写入器（login/sshd/
// xdm 等）登记的会话；无 utmp（容器/裁剪系统）或布局对不上时返回空表
// + note（诚实降级，绝不按错误布局硬解乱码）。
//
// 未在 Linux 实机验证（待 Kali 复验）；验证口径 = GOOS=linux 交叉编译 +
// sessions_linuxparse.go 纯逻辑单测（手工构造记录字节）。
package liveapi

// sessions_linux.go：当前活动登录会话（utmp 口径）。

import (
	"net/http"
	"os"

	"zedr/internal/platform/httpx"
)

// utmpPath 是登录会话登记文件（Debian/RHEL 惯例路径一致；写死的单一
// 路径，/var/lib/... 等历史位置 v1 不做探测）。
const utmpPath = "/var/run/utmp"

func (s *server) handleSessions(w http.ResponseWriter, r *http.Request) {
	data, err := os.ReadFile(utmpPath)
	if err != nil {
		// 文件不存在（无 login 记录面）与不可读（权限裁剪）都不是
		// 探针错误：空表 + note，不 500——调查者需要的是"这台机器上
		// 没有可见的 utmp 会话记录"这个事实本身。
		httpx.WriteJSON(w, r, http.StatusOK, buildLinuxSessionsResult(nil,
			"utmp 不可读（"+utmpPath+"："+err.Error()+"）：返回空会话表"))
		return
	}

	items, ok := parseUtmpActiveSessions(data)
	if !ok {
		// 布局对不上：非 x86_64/i386 glibc 口径（musl/大端/未来 ABI 变化）。
		// 整表放弃是设计决定——按错误偏移解出的"用户名"是比空表更糟的
		// 失真数据。
		httpx.WriteJSON(w, r, http.StatusOK, buildLinuxSessionsResult(nil,
			"utmp 记录布局与本探针支持的 glibc x86_64/i386 口径不符：放弃解析（诚实边界）"))
		return
	}

	note := ""
	if len(items) == 0 {
		note = "utmp 无活跃会话记录（ut_type=USER_PROCESS 为 0 条；重启后无人登录或容器环境属正常）"
	}
	httpx.WriteJSON(w, r, http.StatusOK, buildLinuxSessionsResult(items, note))
}
