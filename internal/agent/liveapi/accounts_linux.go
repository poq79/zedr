//go:build linux

// accounts_linux.go：/accounts 的 Linux 实现（IO 壳）。
//
// 数据来源全部是本机账户/策略文件的只读解析：/etc/passwd（账户表）、
// /etc/group（管理员组归属）、/etc/shadow（口令老化/过期；root 可读，
// 探针以 root systemd 运行通常可读）、/etc/login.defs（PASS_* 策略键）。
// 与 Windows 版（NetAPI 枚举）的语义映射与逐字段决策见
// accounts_linuxparse.go 头注释；解析逻辑在中性文件（Windows 上单测
// 锁口径），本文件只做文件读取与降级拼装。
//
// 降级口径：单文件不可读只收窄对应段（note 说明），绝不整页 500——
// 与 Windows 版"管理员/策略失败保留用户表"同一取舍。
//
// 未在 Linux 实机验证（待 Kali 复验）；验证口径 = GOOS=linux 交叉编译 +
// accounts_linuxparse.go 纯逻辑单测（testdata 夹具）。
package liveapi

// accounts_linux.go：账户与会话 Tab 的账户清单（Linux 口径）。

import (
	"net/http"
	"os"
	"time"

	"zedr/internal/platform/httpx"
)

// HandleAccounts 返回 GET /accounts 的 Linux handler（包级构造函数，
// 与 Windows 版同签名，liveapi.New 统一接线）。
func HandleAccounts() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		httpx.WriteJSON(w, r, http.StatusOK, buildLinuxAccountsResult(linuxAccountsRaw{
			Passwd:    readOptionalFile("/etc/passwd"),
			Group:     readOptionalFile("/etc/group"),
			Shadow:    readOptionalFile("/etc/shadow"),
			LoginDefs: readOptionalFile("/etc/login.defs"),
			Now:       time.Now(),
		}))
	}
}

// readOptionalFile 读"缺了不算错"的配置文件：不存在/不可读返回 nil，
// 由投影层逐段降级。错误细节不区分（ENOENT 与 EACCES 对调查面都是
// "这段拿不到"，note 统一表述），避免把 errno 泄进响应体。
func readOptionalFile(path string) []byte {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	return data
}
